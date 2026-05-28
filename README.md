# narrowd

`narrowd` is a small, single-user Rust SSH daemon built around `russh`.

Current MVP surface:

- public-key auth against one `authorized_keys` file
- interactive shell as the daemon process user
- `exec` requests via `bash -lc`
- SFTP subsystem backed by the local filesystem
- local and remote TCP forwarding

Not implemented yet:

- X11 forwarding
- config reload
- multi-user account/session management
- legacy SCP protocol compatibility

Quick start:

```bash
cargo run -- --print-sample-config
cargo run -- --check-config
cargo run
```

By default `narrowd` looks for `~/.config/narrowd/narrowd.conf`, generates an
Ed25519 host key if one does not exist yet, and authenticates against
`~/.ssh/authorized_keys`.
