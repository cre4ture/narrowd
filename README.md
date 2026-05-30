# narrowd

`narrowd` is a small, single-user Rust SSH daemon built around `russh`.

It is designed as a `ssh`- and `scp`-compatible lightweight remote-access daemon for one Unix account.
But its explicitly NOT a full drop-in replacement for a hardened multi-user `sshd`.

License: MIT. See [`LICENSE`](LICENSE).

Current MVP surface:

- public-key auth against one `authorized_keys` file
- interactive shell as the daemon process user
- `exec` requests via `bash -lc`
- SFTP subsystem backed by the local filesystem
- local and remote TCP forwarding

Not implemented yet:

- config reload

Explicit NON-Goals:

- multi-user account/session management (instead, use `su` to change user in terminal when logged in)
- support of any legacy or outdated functionality (use modern alternatives instead)
  - legacy SCP protocol (modern `scp` tool uses sftp already by default)
  - X11 forwarding (use waypipe and TCP tunnel instead)

Security model / exposure guidance:

- A successful login gets shell, `exec`, SFTP, and forwarding access as the daemon process user. This is intentional for the single-user design.
- The SSH login username must exactly match the daemon process user's account name. Other usernames are rejected instead of being silently mapped to the daemon user.
- The public exposure profile only accepts modern Ed25519-family SSH keys for both the host key and user authentication keys.
- The public exposure profile also keeps a narrow SSH transport surface: modern KEX only, modern ciphers/MACs only, and no SSH compression.
- Pre-auth resource controls are built in for public exposure: global/per-IP/per-subnet unauthenticated connection caps, per-IP new-connection rate limiting, temporary bans after repeated auth failures, a short client-banner timeout, and an absolute login grace deadline that also covers KEX stalls.
- Post-auth OS work runs in a separate executor process. The network-facing SSH parser process no longer directly spawns shells, opens PTYs, touches SFTP state, or binds/connects forwarding sockets itself.
- In the main `narrowd` binary, `no_new_privs` is applied only after the executor process has been spawned. That keeps the pre-auth parser constrained while still allowing post-auth shells to use normal local privilege-escalation tools such as `sudo` if the underlying system would otherwise permit them.
- On Linux, the pre-auth process also installs a small seccomp filter and a Landlock filesystem sandbox after startup. That denies `exec` and most new network/process-creation syscalls in the parser process and limits its filesystem view to read-only access under the `authorized_keys` directory tree. This hardened path requires Landlock support from the running kernel.
- The `authorized_keys` cache is kept in memory and reloaded automatically on file changes with a small debounce. If a reload fails, `narrowd` keeps serving from the last known-good in-memory cache and logs the failure.
- SFTP is not chrooted or confined to a separate subtree. It follows the filesystem permissions of the daemon process user. If that same user is intentionally allowed shell access, this does not expand privileges beyond that account.
- `authorized_keys` is used for key matching, but `narrowd` only accepts plain key lines. Entries that include OpenSSH key options such as `command=`, `from=`, or no-forwarding flags are completely rejected instead of being interpreted as unrestricted keys.
- TCP forwarding is deliberately permissive when enabled. This is useful for trusted personal access, but it also means accepted keys can use the host as a tunnel endpoint.
- This is still an MVP and has not had the maturity, audit history, or defense-in-depth work of OpenSSH.

Compared to an unrestricted OpenSSH login for the same Unix user:

- The post-authentication impact is broadly similar. A stolen private key is bad in both cases if that key is supposed to grant unrestricted access to the same account.
- Broad shell access, broad forwarding, and unrestricted file access are not unique to `narrowd` if those same capabilities are intentionally enabled in OpenSSH.
- The main security difference is not the permission scope after login. It is the amount of hardening around the internet-facing SSH service itself.
- OpenSSH benefits from a much longer audit history, more operational hardening, and more defense-in-depth. `narrowd` is simpler and intentionally less featureful, but it does not yet have that maturity.
- In practice, this means that choosing `narrowd` over unrestricted OpenSSH is mostly accepting more implementation-maturity risk, not intentionally granting a larger set of user-level permissions.

Reasonable use cases:

- personal remote access to your own machine, dev box, lab host, or VM
- access protected by another trust boundary such as Tailscale, WireGuard, a VPN, or a strict source-IP firewall
- setups where every accepted key is fully trusted to act as the daemon process user
- environments where unrestricted shell and port forwarding are desired features rather than policy violations

Use cases where `narrowd` is not a good fit:

- a general-purpose internet-facing SSH service for multiple users
- systems that rely on `authorized_keys` restrictions or fine-grained SSH policy enforcement instead of plain allow-or-deny keys
- locked-down SFTP-only environments, chrooted file access, or reduced-blast-radius account separation
- high-sensitivity or public-facing production systems where you would normally choose OpenSSH for its hardening and long operational track record

For a concrete checklist of public-internet hardening work under the
"attacker has no stolen key" threat model, see
[`docs/public-exposure-roadmap.md`](docs/public-exposure-roadmap.md).

CI / repository automation:

- GitHub Actions covers formatting, clippy, rustdoc with warnings denied, Linux tests on stable and beta, a macOS build check, and a Debian package smoke test.
- Security automation also includes `cargo audit`, CodeQL analysis, and GitHub dependency review on pull requests.
- The committed `cargo audit` policy intentionally ignores `RUSTSEC-2023-0071` only because `narrowd`'s public-exposure profile rejects RSA host and user keys entirely. If RSA support is ever added, that exception should be removed and reevaluated immediately.

Quick start:

```bash
cargo run -- --print-sample-config
cargo run -- --check-config
cargo run
```

By default `narrowd` looks for `~/.config/narrowd/narrowd.conf`, generates an
Ed25519 host key if one does not exist yet, and authenticates against
`~/.ssh/authorized_keys`.

Local Debian package:

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
permissions of the target login account. The packaged user service restricts
address families to `AF_UNIX`, `AF_INET`, and `AF_INET6`. `no_new_privs` is
applied by the main `narrowd` process itself after it has started the separate
post-auth executor process.

RDP over SSH tunnel:

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
