# narrowd

`narrowd` is a security-hardened, single-user SSH daemon written in Rust and
built on `russh`. It gives one local account everything needed for remote work:
an interactive shell, command execution, SFTP, and TCP forwarding through
standard `ssh` and `scp` clients.

Its focused model is the point. `narrowd` leaves out multi-user account
management, legacy protocols, and policy machinery it does not need. The
result is a compact remote-access service with modern cryptography, bounded
pre-authentication resource use, and a separate post-authentication executor
process on Unix.

## Highlights

- public-key authentication against one `authorized_keys` file
- interactive shell as the daemon process user
- `exec` requests through a configurable shell wrapper (`ExecMode`)
- SFTP backed by the local filesystem
- local and remote TCP forwarding
- automatic `authorized_keys` reload with last-known-good fallback
- user-scoped deployment on Linux and Windows

## Deliberate scope

`narrowd` is purpose-built for one trusted user, not a reduced clone of a
multi-user `sshd`. Its deliberately small scope keeps operation and review
straightforward:

- one local account per daemon instance; use `su` after login if local policy
  permits switching users
- configuration changes take effect after a restart
- no legacy SCP protocol; current `scp` clients use SFTP by default
- no X11 forwarding; use Waypipe over a TCP tunnel instead

## Security model

Every accepted key is trusted to act as the daemon process user. A successful
login therefore receives shell, `exec`, SFTP, and forwarding access with that
account's permissions. This explicit trust boundary is the foundation of the
single-user design.

- **Exact identity mapping.** The SSH login username must match the daemon
  process user's account name. Other usernames are rejected rather than
  silently mapped to that account.
- **Modern cryptography.** The public-exposure profile accepts Ed25519 host
  keys and Ed25519-family user keys, a narrow set of modern KEX algorithms,
  ciphers, and MACs, and no SSH compression.
- **Built-in admission controls.** Global, per-IP, and per-subnet connection
  caps, per-IP rate limiting, temporary bans after repeated authentication
  failures, short banner and KEX timeouts, and an absolute login deadline bound
  unauthenticated resource use.
- **Process separation on Unix.** A dedicated executor owns shells, PTYs, SFTP
  state, and forwarding sockets. The network-facing SSH parser communicates
  with it over a constrained control channel.
- **Parser sandboxing on Linux.** After spawning the executor, the parser
  applies `no_new_privs`, a default-deny seccomp allowlist, and a Landlock
  filesystem sandbox. It cannot execute programs and sees only the read-only
  `authorized_keys` directory tree, while authenticated sessions retain the
  account's normal local capabilities. This path requires Landlock support
  from the running kernel.
- **Resilient key reloads.** The in-memory `authorized_keys` cache reloads
  automatically after file changes. A failed reload is logged while the last
  known-good cache remains active.
- **Account-level SFTP.** SFTP follows the daemon user's filesystem
  permissions. It is not chrooted or limited to a separate subtree, because a
  trusted key already has shell access as the same account.
- **Plain allow-or-deny keys.** Entries with OpenSSH options such as
  `command=`, `from=`, or forwarding restrictions are rejected completely
  rather than treated as unrestricted keys.
- **Trusted forwarding.** TCP forwarding is deliberately permissive when
  enabled, so accepted keys can use the host as a tunnel endpoint.

## Positioning versus OpenSSH

For unrestricted shell access to the same local account, `narrowd` and OpenSSH
grant broadly comparable post-authentication permissions. The difference is in
their focus: `narrowd` offers a compact single-user design with a tightly
controlled pre-authentication surface, while OpenSSH offers a far broader
policy and compatibility surface backed by decades of audit and operational
history.

OpenSSH remains a mature, heavily reviewed implementation, but its history also
shows the security cost of that breadth:

- the 2024
  [`regreSSHion` signal-handler race](https://www.openssh.com/txt/release-9.8)
  made unauthenticated root code execution possible on some systems after a
  2006 fix was accidentally lost during a logging refactor;
- an experimental
  [client roaming feature](https://www.openssh.com/txt/release-7.1p2), enabled
  by default despite having no released server counterpart, could disclose
  client memory including private keys;
- [forwarded `ssh-agent` access](https://www.openssh.com/txt/release-9.3p2)
  could be combined with PKCS#11 shared-library loading to execute code on the
  client; and
- protocol, policy, and legacy-tool interactions have caused weaknesses such
  as the [Terrapin attack](https://www.openssh.com/txt/release-9.6),
  [forwarding settings](https://www.openssh.com/security.html) that did not
  enforce all documented restrictions, and
  [unexpected local file writes by `scp`](https://www.openssh.com/txt/release-8.0).

These problems did not have one root cause. Some involved C memory or
asynchronous-signal safety, while others came from protocol details, legacy
compatibility, powerful forwarding features, helper processes, or the large
configuration matrix. OpenSSH mitigates these risks with extensive review,
privilege separation, sandboxing, conservative defaults, and a long record of
rapid fixes. Its history is therefore an argument both for its maturity and
for keeping an SSH service no larger than its actual job requires.

`narrowd` also benefits from Rust's safety model. OpenSSH is primarily
implemented in C; in safe Rust, ownership and the type system rule out broad
classes of use-after-free, double-free, and data-race bugs at compile time,
while bounds checks prevent out-of-range indexing from becoming unchecked
memory corruption. These guarantees reduce the memory-corruption surface of a
network-facing daemon without relying on review alone. Rust is not a security
guarantee: `unsafe` code, native dependencies, protocol mistakes, and logic
flaws still require careful review. It does, however, give `narrowd` a strong
implementation-level safety baseline.

For `narrowd`'s stated use case—occasional remote access to a personal machine,
development box, lab host, or VM—the smaller model is fully sufficient when
every accepted key is trusted to act as the local account and the service and
host are kept up to date. This is especially valuable for occasional operators
and less-experienced administrators: the strong baseline does not depend on
mastering OpenSSH's full policy language or remembering to disable unrelated
subsystems. With fewer features and fewer ways to weaken the intended model
accidentally, a well-maintained `narrowd` deployment can achieve a stronger
effective security posture than an OpenSSH installation operated without
comparable SSH expertise.

That is a comparison of realistic deployments, not a claim that `narrowd` is
universally safer than current OpenSSH in expert hands. Choose `narrowd` when
its trusted-key, single-user model matches the deployment. Choose OpenSSH when
you need multi-user administration, per-key restrictions, legacy
compatibility, or an implementation mandated by policy or compliance.

## Where `narrowd` fits

- personal remote access to your own machine, dev box, lab host, or VM, whether
  reached over a LAN, VPN, or a deliberately exposed SSH port
- occasional operation by people who need dependable personal SSH access
  without becoming experts in a general-purpose SSH policy engine
- setups where every accepted key is fully trusted to act as the daemon process
  user
- environments where unrestricted shell and port forwarding are desired
  features rather than policy violations
- sensitive infrastructure protected by an additional trust boundary such as
  Tailscale, WireGuard, a VPN, or a strict source-IP firewall

## Where another SSH server fits better

- a general-purpose internet-facing SSH service for multiple users
- systems that rely on `authorized_keys` restrictions or fine-grained SSH policy enforcement instead of plain allow-or-deny keys
- locked-down SFTP-only environments, chrooted file access, or reduced-blast-radius account separation
- environments that require a formally audited SSH implementation or OpenSSH's
  long operational track record

For the detailed threat model and completed public-exposure hardening checklist
under the "attacker has no stolen key" assumption, see
[`docs/public-exposure-roadmap.md`](docs/public-exposure-roadmap.md).

## Quality and security checks

- GitHub Actions covers formatting, clippy, rustdoc with warnings denied, Linux
  tests on stable and beta, Windows tests on stable, a macOS build check, and a
  Debian package smoke test.
- Security automation also includes `cargo audit`, `cargo deny`, CodeQL analysis,
  and GitHub dependency review on pull requests. Dependency review fails closed
  when the repository dependency graph is unavailable.
- `cargo audit` runs without advisory suppressions, and CI asserts that the
  vulnerable RSA crate does not re-enter the resolved dependency graph.

## Quick start

```bash
cargo run -- --print-sample-config
cargo run -- --check-config
cargo run
```

By default `narrowd` looks for `~/.config/narrowd/narrowd.conf`, generates an
Ed25519 host key if one does not exist yet, and authenticates against
`~/.ssh/authorized_keys`.

## Local Debian package

```bash
./scripts/build-deb.sh
sudo apt install ./target/debian/narrowd_*.deb
mkdir -p ~/.config/narrowd
cp /usr/share/doc/narrowd/examples/narrowd.conf.example ~/.config/narrowd/narrowd.conf
sudo loginctl enable-linger "$USER"
systemctl --user enable --now narrowd.service
```

The generated package is intentionally set up for a `systemd --user` service,
not a root-owned system daemon. The packaged launcher refuses to start as
`root`, so the SSH session, SFTP access, and port forwarding all run with the
permissions of the target login account. `no_new_privs` is applied by the main
`narrowd` process itself after it has started the separate post-auth executor
process. The packaged user service intentionally does not use
`RestrictAddressFamilies=` because systemd applies that with seccomp, which
forces `NoNewPrivs=1` onto the whole service tree and would break post-auth
tools such as `sudo`.

## Windows MSIX user-session install

```powershell
powershell -ExecutionPolicy Bypass -File .\Build-NarrowdMsix.ps1
powershell -ExecutionPolicy Bypass -File .\Install-NarrowdMsix.ps1
```

For the purpose of the MSIX mode, how it differs from the Session 0 service,
and how automatic Windows logon fits in when you want the user session to come
up on its own after boot, see
[`docs/windows-session-modes.md`](docs/windows-session-modes.md).

The MSIX build produces a signed package and companion certificate under
`target\msix`. Installing it registers a per-user startup task, so `narrowd`
starts automatically in the signed-in user's own session after the next
logon instead of running in Session 0 as a machine service. The package keeps
its config, host key, and logs under `%LOCALAPPDATA%\narrowd`, and the first
launch writes a default config that points `AuthorizedKeysFile` at
`%USERPROFILE%\.ssh\authorized_keys`, uses `ExecMode powershell`, and listens
on TCP `2223` by default.

The packaged manifest also declares the default inbound TCP `2223` firewall
rule. If you later change the port in `%LOCALAPPDATA%\narrowd\narrowd.conf`,
adjust the firewall rule manually so it matches the new port.

## Legacy Windows service install (administrator, Session 0)

```powershell
cargo build --release
powershell -ExecutionPolicy Bypass -File .\Install-Narrowd.ps1
```

See [`docs/windows-session-modes.md`](docs/windows-session-modes.md) for when
to choose this Session 0 service versus the MSIX user-session mode.

That older installer still exists when you explicitly want a native Windows
service with `Log on as a service`, but the MSIX route is the better fit for a
user-session daemon that should come up automatically when the user logs in.

## RDP over SSH tunnel

```bash
ssh -N -T -o ExitOnForwardFailure=yes \
  -L 127.0.0.1:13389:127.0.0.1:3389 \
  -p 2222 \
  your-login-user@narrowd-host
```

Then connect your RDP client to `127.0.0.1:13389`.

If the Windows machine is not the same host that runs `narrowd`, replace the
target side of the `-L` argument with the address that is reachable from the
`narrowd` host, for example `-L 127.0.0.1:13389:10.0.0.50:3389`.
