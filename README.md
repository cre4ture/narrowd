# narrowd

`narrowd` is a small, single-user Rust SSH daemon built around `russh`.

It is designed as a lightweight remote-access daemon for one Unix account, NOT
as a drop-in replacement for a hardened multi-user `sshd`.

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

Quick start:

```bash
cargo run -- --print-sample-config
cargo run -- --check-config
cargo run
```

By default `narrowd` looks for `~/.config/narrowd/narrowd.conf`, generates an
Ed25519 host key if one does not exist yet, and authenticates against
`~/.ssh/authorized_keys`.
