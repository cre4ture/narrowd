# narrowd

`narrowd` is a small, single-user Rust SSH daemon built around `russh`.

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

Quick start:

```bash
cargo run -- --print-sample-config
cargo run -- --check-config
cargo run
```

By default `narrowd` looks for `~/.config/narrowd/narrowd.conf`, generates an
Ed25519 host key if one does not exist yet, and authenticates against
`~/.ssh/authorized_keys`.
