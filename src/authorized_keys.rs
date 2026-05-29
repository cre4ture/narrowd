use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use russh::keys::ssh_key::{self, AuthorizedKeys};

#[derive(Clone, Debug)]
pub struct AuthorizedKeysCache {
    accepted_keys: HashSet<Vec<u8>>,
    ignored_entries: usize,
}

impl AuthorizedKeysCache {
    pub fn load(path: &Path, max_size: usize, max_entries: usize) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        if text.len() > max_size {
            bail!(
                "authorized keys file {} exceeds configured size limit of {} bytes",
                path.display(),
                max_size
            );
        }

        Self::from_text(&text, max_entries)
    }

    pub fn empty() -> Self {
        Self {
            accepted_keys: HashSet::new(),
            ignored_entries: 0,
        }
    }

    pub fn contains(&self, public_key: &ssh_key::PublicKey) -> Result<bool> {
        let key_bytes = public_key
            .to_bytes()
            .context("failed to serialize offered public key")?;
        Ok(self.accepted_keys.contains(&key_bytes))
    }

    pub fn ignored_entries(&self) -> usize {
        self.ignored_entries
    }

    #[cfg(test)]
    pub fn key_count(&self) -> usize {
        self.accepted_keys.len()
    }

    fn from_text(text: &str, max_entries: usize) -> Result<Self> {
        let mut accepted_keys = HashSet::new();
        let mut ignored_entries = 0;

        for (index, entry) in AuthorizedKeys::new(text).enumerate() {
            if index >= max_entries {
                bail!("authorized keys file exceeds configured entry limit of {max_entries}");
            }

            let entry =
                entry.map_err(|err| anyhow!("failed to parse authorized_keys entry: {err}"))?;
            if !entry.config_opts().is_empty() {
                ignored_entries += 1;
                continue;
            }

            let key_bytes = entry
                .public_key()
                .to_bytes()
                .context("failed to serialize authorized public key")?;
            if !accepted_keys.insert(key_bytes) {
                bail!("authorized keys file contains a duplicate plain key entry");
            }
        }

        Ok(Self {
            accepted_keys,
            ignored_entries,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAIN_ED25519_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti user@example.com";
    const OPTIONED_RSA_ENTRY: &str = "from=\"10.0.0.?,*.example.com\",no-X11-forwarding ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC0WRHtxuxefSJhpIxGq4ibGFgwYnESPm8C3JFM88A1JJLoprenklrd7VJ+VH3Ov/bQwZwLyRU5dRmfR/SWTtIPWs7tToJVayKKDB+/qoXmM5ui/0CU2U4rCdQ6PdaCJdC7yFgpPL8WexjWN06+eSIKYz1AAXbx9rRv1iasslK/KUqtsqzVliagI6jl7FPO2GhRZMcso6LsZGgSxuYf/Lp0D/FcBU8GkeOo1Sx5xEt8H8bJcErtCe4Blb8JxcW6EXO3sReb4z+zcR07gumPgFITZ6hDA8sSNuvo/AlWg0IKTeZSwHHVknWdQqDJ0uczE837caBxyTZllDNIGkBjCIIOFzuTT76HfYc/7CTTGk07uaNkUFXKN79xDiFOX8JQ1ZZMZvGOTwWjuT9CqgdTvQRORbRWwOYv3MH8re9ykw3Ip6lrPifY7s6hOaAKry/nkGPMt40m1TdiW98MTIpooE7W+WXu96ax2l2OJvxX8QR7l+LFlKnkIEEJd/ItF1G22UmOjkVwNASTwza/hlY+8DoVvEmwum/nMgH2TwQT3bTQzF9s9DOJkH4d8p4Mw4gEDjNx0EgUFA91ysCAeUMQQyIvuR8HXXa+VcvhOOO5mmBcVhxJ3qUOJTyDBsT0932Zb4mNtkxdigoVxu+iiwk0vwtvKwGVDYdyMP5EAQeEIP1t0w== user4@example.com";
    const DUPLICATE_KEYS: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti user@example.com\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti second@example.com\n";

    #[test]
    fn accepts_plain_keys_and_ignores_optioned_entries() {
        let cache = AuthorizedKeysCache::from_text(
            &format!("{PLAIN_ED25519_KEY}\n{OPTIONED_RSA_ENTRY}\n"),
            8,
        )
        .unwrap();

        let offered_key: ssh_key::PublicKey = PLAIN_ED25519_KEY.parse().unwrap();
        assert!(cache.contains(&offered_key).unwrap());
        assert_eq!(cache.key_count(), 1);
        assert_eq!(cache.ignored_entries(), 1);
    }

    #[test]
    fn rejects_duplicate_plain_keys() {
        let err = AuthorizedKeysCache::from_text(DUPLICATE_KEYS, 8).unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn rejects_too_many_entries() {
        let err = AuthorizedKeysCache::from_text(PLAIN_ED25519_KEY, 0).unwrap_err();
        assert!(err.to_string().contains("entry limit"));
    }
}
