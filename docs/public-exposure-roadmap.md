# Public Exposure Hardening Roadmap

This document is a roadmap, not a statement of current implementation.

It answers a narrow question:

- What functionality would `narrowd` need in order to be robust when exposed to the public internet?
- Assume the authenticated user is fully trusted.
- Assume the attacker does not have a stolen valid private key.

That means this roadmap is focused on:

- pre-authentication denial-of-service resistance
- pre-authentication resource exhaustion
- pre-authentication exploit containment
- clear operational visibility during internet scanning and attack traffic

It is not focused on:

- restricting a valid authenticated user
- damage from a stolen private key
- blast radius of intentionally broad shell/SFTP/forwarding access after auth
- general ecosystem maturity or audit history

## Conservative Target Profile

Recommended starting parameters for a single human operator, not a large shared service:

- `max_unauth_connections_global = 16`
- `max_unauth_connections_per_ip = 3`
- `max_unauth_connections_per_subnet = 8` for IPv4 `/24` and IPv6 `/64`
- `new_connections_per_minute_per_ip = 12`
- `new_connections_burst_per_ip = 4`
- `login_grace_time = 15s`
- `client_banner_timeout = 5s`
- `kex_start_timeout = 5s`
- `max_auth_attempts = 4`
- `auth_rejection_delay = 2s`
- `temporary_ban_threshold = 8` auth failures in `10m`
- `temporary_ban_duration = 15m`
- `authorized_keys_max_size = 256 KiB`
- `authorized_keys_max_entries = 128`
- `allowed_user_key_algorithms = [ssh-ed25519, sk-ssh-ed25519@openssh.com]`
- `allowed_host_key_algorithms = [ssh-ed25519]`
- `inactivity_timeout = 15m`
- `keepalive_interval = 30s`
- `keepalive_max = 3`
- `channel_buffer_size = 32`
- `event_buffer_size = 16`
- `window_size = 1048576`
- `maximum_packet_size = 32768`

These are intentionally conservative for a single-user daemon. If they ever become operationally annoying, that is a sign they should be made configurable rather than removed.

## Checklist Roadmap

### 1. Connection Admission Control

- [x] Stop using `run_on_address` directly for public exposure. Own the TCP accept loop and hand accepted streams into `russh::server::run_stream` only after admission checks.
- [x] Track unauthenticated connections globally.
- [x] Track unauthenticated connections per source IP.
- [x] Track unauthenticated connections per source subnet.
- [x] Reject new connections once the global unauthenticated cap is reached.
- [x] Reject new connections once the per-IP cap is reached.
- [x] Reject new connections once the per-subnet cap is reached.
- [x] Add a token-bucket rate limiter for new TCP connections per IP.
- [x] Add short temporary bans after repeated authentication failures from the same IP.
- [x] Expire stale counters automatically so the daemon does not grow unbounded IP state.

Suggested implementation notes:

- Use a small shared admission state keyed by IP and subnet.
- Release admission slots on auth success, disconnect, or pre-auth timeout.
- Prefer cheap rejection before spending CPU on SSH parsing.

Attack styles mitigated:

- internet-wide scanner sweeps
- connection slot exhaustion
- cheap repeated handshake probes from one IP
- low-effort bot attacks from a small IP pool

### 2. Hard Pre-Auth Timeouts

- [x] Add an absolute `LoginGraceTime` equivalent of `15s` from TCP accept to successful authentication.
- [x] Add a `5s` timeout to receive the client SSH identification string.
- [ ] Add a `5s` timeout from banner exchange to key-exchange start.
- [x] Keep the timeout absolute. Do not let the client extend it indefinitely by trickling bytes.
- [x] Close pre-auth connections that stall during banner, KEX, or authentication.

Suggested implementation notes:

- Apply deadlines from the outer connection supervisor, not only inside individual handler callbacks.
- Treat slow trickle progress the same as no progress.

Attack styles mitigated:

- slowloris-style pre-auth hold-open attacks
- banner trickle attacks
- KEX trickle attacks
- unauthenticated socket hoarding

### 3. Uniform Authentication Cost

- [x] Use a non-zero rejection delay for the initial auth-method probe.
- [x] Keep rejection delay uniform for unknown usernames, unknown keys, and wrong signatures.
- [x] Set `max_auth_attempts = 4`.
- [x] Do not do materially more work for malformed or unknown keys than for ordinary failures.

Suggested implementation notes:

- Keep `auth_rejection_time_initial` aligned with the normal rejection delay.
- Use the same fast path for "wrong username" and "wrong key" outcomes.

Attack styles mitigated:

- cheap auth-method probing
- username existence timing probes
- uneven-cost auth spam

### 4. In-Memory Authorized Keys Cache

- [x] Parse `authorized_keys` once and keep the accepted keys in memory.
- [x] Store a direct lookup structure keyed by public key bytes or fingerprint.
- [x] Enforce `authorized_keys_max_size = 256 KiB`.
- [x] Enforce `authorized_keys_max_entries = 128`.
- [x] Reject duplicate entries during cache build.
- [x] Keep the existing fail-closed behavior for entries with OpenSSH key options.
- [ ] Reload on explicit signal, or on file mtime change with debounce.
- [ ] If reload fails, keep the last known-good cache instead of replacing it with a broken one.

Suggested implementation notes:

- Never re-read and re-parse the file on every auth attempt.
- Surface the current cache generation and last reload status in logs or metrics.

Attack styles mitigated:

- auth-path disk I/O amplification
- CPU amplification by repeated key parsing
- repeated invalid auth attempts that force filesystem work

### 5. Narrow Crypto and Auth Surface

- [x] Explicitly set the `russh` server auth method set to only the methods `narrowd` wants to support.
- [x] Explicitly configure the preferred KEX, cipher, MAC, and host-key algorithms instead of relying on defaults.
- [x] Accept only modern user key algorithms by default.
- [x] Keep Ed25519 as the default host key type.
- [x] Drop legacy key types from the default public-exposure profile.

Recommended default allowlists:

- user keys: `ssh-ed25519`, `sk-ssh-ed25519@openssh.com`
- host keys: `ssh-ed25519`

Attack styles mitigated:

- protocol downgrade attempts
- legacy-algorithm probing
- widening the parser and validation surface more than necessary

### 6. Bounded Buffers and Runtime Resources

- [x] Set `channel_buffer_size = 32`.
- [x] Set `event_buffer_size = 16`.
- [x] Set `window_size = 1048576`.
- [x] Keep `maximum_packet_size = 32768` unless a smaller tested value is chosen.
- [x] Set `inactivity_timeout = 15m`.
- [x] Set `keepalive_interval = 30s`.
- [x] Set `keepalive_max = 3`.
- [x] Set `nodelay = true` for interactive behavior, but do not treat it as a security control.

Suggested implementation notes:

- Every queue or per-connection buffer should have a visible bound.
- If a client cannot keep up, apply backpressure or disconnect instead of accumulating unbounded state.

Attack styles mitigated:

- memory growth from stalled or abusive connections
- resource pinning by half-dead clients
- slow accumulation of idle session state

### 7. Log and Metrics Hardening

- [x] Rate-limit warning logs per IP and per reason.
- [x] Aggregate repeated failures into summary events instead of emitting one warning per packet or per failed attempt.
- [ ] Record counters for current unauthenticated connections.
- [ ] Record counters for rejected connections by reason.
- [ ] Record counters for auth failures by IP.
- [ ] Record counters for temporary bans issued.
- [ ] Record counters for pre-auth timeouts.
- [ ] Record counters for malformed packet disconnects.
- [ ] Record counters for cache reload success and failure.
- [ ] Emit structured fields such as peer IP, reason, username, and elapsed pre-auth time.

Suggested implementation notes:

- Logging must not become its own denial-of-service vector.
- Metrics should be cheap enough to emit under scan traffic.

Attack styles mitigated:

- log-flood attacks
- operator blindness during scanning or attack spikes
- difficulty distinguishing bugs from malicious traffic

### 8. Pre-Auth Exploit Containment

- [ ] Split the daemon into at least two trust domains: a pre-auth listener/auth process and a post-auth session executor process.
- [ ] Use a Unix socket or similar IPC to hand off "authenticated and approved" session requests.
- [ ] Ensure the pre-auth side cannot directly spawn shells, open PTYs, or touch user session state.
- [ ] Run the pre-auth side with `no_new_privs`.
- [ ] Apply seccomp or equivalent syscall filtering to the pre-auth side.
- [ ] Make the pre-auth side filesystem access read-only except for what is strictly needed.
- [ ] Limit address families on the pre-auth side to what it actually needs.
- [ ] Keep the post-auth side out of the network parser's direct process boundary.

Suggested implementation notes:

- This is the single biggest functional hardening against "attacker has no key but finds a parser bug".
- Without this split, a pre-auth RCE lands directly inside the same process that later launches shells.

Attack styles mitigated:

- pre-auth parser RCE
- pre-auth memory corruption leading directly to account compromise
- filesystem abuse from a compromised network-facing parser

### 9. Panic and Crash Isolation

- [x] Make sure one bad connection cannot crash the whole daemon.
- [x] Isolate per-connection failures so malformed input results in connection teardown, not process exit.
- [x] Add a small outer supervisor that logs connection-level crashes and keeps the main listener alive.
- [ ] Prefer dropping the offending connection over attempting complicated recovery inside corrupted connection state.

Attack styles mitigated:

- malformed packet crash attempts
- targeted connection-level panic triggers
- whole-daemon availability loss from one bad session

## Attack Styles This Roadmap Is Intended To Handle

These are the attack classes the completed roadmap is meant to mitigate well:

- internet background scanning and banner probing
- repeated invalid public-key auth attempts
- repeated invalid username attempts
- slow trickle pre-auth connections
- per-IP connection floods
- small botnet connection floods
- auth-path disk I/O amplification
- log amplification and log flooding
- malformed packet crash attempts
- pre-auth parser exploitation with containment of blast radius

These are only partially addressed even after the roadmap is implemented:

- widely distributed botnets that stay under per-IP thresholds
- very large connection floods that saturate host CPU before network-level filtering reacts
- attacks that require upstream filtering, SYN cookies, or DDoS protection outside the application

These are explicitly out of scope for this roadmap:

- stolen valid private keys
- malicious or compromised authenticated users
- post-auth abuse of intentionally broad shell, SFTP, or forwarding permissions

## Suggested Implementation Order

- [x] Phase 1: connection admission control
- [x] Phase 2: hard pre-auth timeouts
- [x] Phase 3: in-memory `authorized_keys` cache
- [x] Phase 4: narrow crypto and auth surface
- [x] Phase 5: bounded buffers and log hardening
- [ ] Phase 6: pre-auth exploit containment split
- [ ] Phase 7: panic isolation and attack-focused integration tests

## Testing Expectations For The Hardened Design

- [x] integration test for global unauthenticated connection cap
- [ ] integration test for per-IP unauthenticated cap
- [x] integration test for per-IP rate limiting and ban expiry
- [x] integration test for slow banner timeout
- [ ] integration test for slow KEX timeout
- [x] integration test for absolute login grace timeout
- [ ] integration test that auth attempts do not touch disk after cache warm-up
- [ ] integration test for cache reload success and failed-reload fallback
- [ ] integration test for malformed auth spam not producing unbounded logs
- [x] integration test that a crashing connection does not kill the listener
