use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result, anyhow, bail};
use russh::keys::ssh_key::{self, AuthorizedKeys};

#[derive(Clone, Debug)]
pub struct AuthorizedKeysStore {
    inner: Arc<RwLock<AuthorizedKeysState>>,
}

impl AuthorizedKeysStore {
    pub fn load(
        path: PathBuf,
        max_size: usize,
        max_entries: usize,
        reload_interval: Duration,
    ) -> Result<Self> {
        let (cache, fingerprint) = AuthorizedKeysCache::load(&path, max_size, max_entries)?;
        Ok(Self::new(AuthorizedKeysState::loaded(
            path,
            max_size,
            max_entries,
            reload_interval,
            cache,
            fingerprint,
        )))
    }

    pub fn empty_missing(
        path: PathBuf,
        max_size: usize,
        max_entries: usize,
        reload_interval: Duration,
    ) -> Self {
        Self::new(AuthorizedKeysState::missing(
            path,
            max_size,
            max_entries,
            reload_interval,
        ))
    }

    fn new(state: AuthorizedKeysState) -> Self {
        Self {
            inner: Arc::new(RwLock::new(state)),
        }
    }

    pub fn refresh_if_due(&self) -> Result<Option<AuthorizedKeysReloadEvent>> {
        let now = Instant::now();
        let mut state = self.inner.write().expect("authorized keys lock poisoned");
        state.refresh_if_due(now)
    }

    pub fn contains(&self, public_key: &ssh_key::PublicKey) -> Result<bool> {
        let state = self.inner.read().expect("authorized keys lock poisoned");
        state.cache.contains(public_key)
    }

    pub fn status(&self) -> AuthorizedKeysStatus {
        let state = self.inner.read().expect("authorized keys lock poisoned");
        AuthorizedKeysStatus {
            generation: state.generation,
            ignored_entries: state.cache.ignored_entries(),
            last_reload_status: state.last_reload_status.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedKeysStatus {
    pub generation: u64,
    pub ignored_entries: usize,
    pub last_reload_status: AuthorizedKeysReloadStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorizedKeysReloadStatus {
    Loaded,
    Missing,
    Failed(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorizedKeysReloadEvent {
    Loaded {
        generation: u64,
        ignored_entries: usize,
    },
    Missing,
    Failed(String),
}

#[derive(Debug)]
struct AuthorizedKeysState {
    path: PathBuf,
    max_size: usize,
    max_entries: usize,
    reload_interval: Duration,
    cache: AuthorizedKeysCache,
    generation: u64,
    observed_fingerprint: AuthorizedKeysFingerprint,
    last_failed_reload_fingerprint: Option<AuthorizedKeysFingerprint>,
    last_reload_status: AuthorizedKeysReloadStatus,
    next_reload_check_at: Instant,
}

impl AuthorizedKeysState {
    fn loaded(
        path: PathBuf,
        max_size: usize,
        max_entries: usize,
        reload_interval: Duration,
        cache: AuthorizedKeysCache,
        fingerprint: AuthorizedKeysFingerprint,
    ) -> Self {
        Self {
            path,
            max_size,
            max_entries,
            reload_interval,
            cache,
            generation: 1,
            observed_fingerprint: fingerprint,
            last_failed_reload_fingerprint: None,
            last_reload_status: AuthorizedKeysReloadStatus::Loaded,
            next_reload_check_at: Instant::now() + reload_interval,
        }
    }

    fn missing(
        path: PathBuf,
        max_size: usize,
        max_entries: usize,
        reload_interval: Duration,
    ) -> Self {
        Self {
            path,
            max_size,
            max_entries,
            reload_interval,
            cache: AuthorizedKeysCache::empty(),
            generation: 0,
            observed_fingerprint: AuthorizedKeysFingerprint::MISSING,
            last_failed_reload_fingerprint: None,
            last_reload_status: AuthorizedKeysReloadStatus::Missing,
            next_reload_check_at: Instant::now() + reload_interval,
        }
    }

    fn refresh_if_due(&mut self, now: Instant) -> Result<Option<AuthorizedKeysReloadEvent>> {
        if now < self.next_reload_check_at {
            return Ok(None);
        }
        self.next_reload_check_at = now + self.reload_interval;

        let current_fingerprint = AuthorizedKeysFingerprint::from_path(&self.path)?;
        if current_fingerprint == self.observed_fingerprint {
            return Ok(None);
        }
        if self
            .last_failed_reload_fingerprint
            .as_ref()
            .is_some_and(|fingerprint| *fingerprint == current_fingerprint)
        {
            return Ok(None);
        }

        match AuthorizedKeysCache::load(&self.path, self.max_size, self.max_entries) {
            Ok((cache, fingerprint)) => {
                self.cache = cache;
                self.generation = self.generation.saturating_add(1);
                self.observed_fingerprint = fingerprint;
                self.last_failed_reload_fingerprint = None;
                self.last_reload_status = AuthorizedKeysReloadStatus::Loaded;
                Ok(Some(AuthorizedKeysReloadEvent::Loaded {
                    generation: self.generation,
                    ignored_entries: self.cache.ignored_entries(),
                }))
            }
            Err(_) if matches!(current_fingerprint, AuthorizedKeysFingerprint::MISSING) => {
                self.observed_fingerprint = AuthorizedKeysFingerprint::MISSING;
                self.last_failed_reload_fingerprint = None;
                self.last_reload_status = AuthorizedKeysReloadStatus::Missing;
                Ok(Some(AuthorizedKeysReloadEvent::Missing))
            }
            Err(err) => {
                let message = err.to_string();
                self.last_failed_reload_fingerprint = Some(current_fingerprint);
                self.last_reload_status = AuthorizedKeysReloadStatus::Failed(message.clone());
                Ok(Some(AuthorizedKeysReloadEvent::Failed(message)))
            }
        }
    }
}

#[derive(Clone, Debug)]
struct AuthorizedKeysCache {
    accepted_keys: HashSet<Vec<u8>>,
    ignored_entries: usize,
}

impl AuthorizedKeysCache {
    fn load(
        path: &Path,
        max_size: usize,
        max_entries: usize,
    ) -> Result<(Self, AuthorizedKeysFingerprint)> {
        let mut file = std::fs::File::open(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let metadata = file
            .metadata()
            .with_context(|| format!("failed to stat {}", path.display()))?;
        if metadata.len() > max_size as u64 {
            bail!(
                "authorized keys file {} exceeds configured size limit of {} bytes",
                path.display(),
                max_size
            );
        }
        let mut text = String::new();
        file.read_to_string(&mut text)
            .with_context(|| format!("failed to read {}", path.display()))?;

        let cache = Self::from_text(&text, max_entries)?;
        let fingerprint = AuthorizedKeysFingerprint::from_metadata(&metadata);
        Ok((cache, fingerprint))
    }

    fn empty() -> Self {
        Self {
            accepted_keys: HashSet::new(),
            ignored_entries: 0,
        }
    }

    fn contains(&self, public_key: &ssh_key::PublicKey) -> Result<bool> {
        let key_bytes = public_key
            .to_bytes()
            .context("failed to serialize offered public key")?;
        Ok(self.accepted_keys.contains(&key_bytes))
    }

    fn ignored_entries(&self) -> usize {
        self.ignored_entries
    }

    #[cfg(test)]
    fn key_count(&self) -> usize {
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthorizedKeysFingerprint {
    modified: Option<SystemTime>,
    len: Option<u64>,
    missing: bool,
}

impl AuthorizedKeysFingerprint {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            modified: metadata.modified().ok(),
            len: Some(metadata.len()),
            missing: false,
        }
    }

    fn from_path(path: &Path) -> Result<Self> {
        match std::fs::metadata(path) {
            Ok(metadata) => Ok(Self::from_metadata(&metadata)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self::MISSING),
            Err(err) => Err(err).with_context(|| format!("failed to stat {}", path.display())),
        }
    }

    const MISSING: Self = Self {
        modified: None,
        len: None,
        missing: true,
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    const PLAIN_ED25519_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti user@example.com";
    const SECOND_ED25519_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKkBZe9F+Q52g8f+k38RXvJY8A8+P9MNm+8cTxS55U8W second@example.com";
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

    #[test]
    fn reloads_after_file_change() {
        let tempdir = TempDir::new().unwrap();
        let path = tempdir.path().join("authorized_keys");
        fs::write(&path, format!("{PLAIN_ED25519_KEY}\n")).unwrap();

        let store =
            AuthorizedKeysStore::load(path.clone(), 1024, 8, Duration::from_millis(0)).unwrap();
        let first_key: ssh_key::PublicKey = PLAIN_ED25519_KEY.parse().unwrap();
        let second_key: ssh_key::PublicKey = SECOND_ED25519_KEY.parse().unwrap();
        assert!(store.contains(&first_key).unwrap());
        assert!(!store.contains(&second_key).unwrap());

        std::thread::sleep(Duration::from_millis(20));
        fs::write(&path, format!("{SECOND_ED25519_KEY}\n")).unwrap();

        let event = store.refresh_if_due().unwrap();
        assert_eq!(
            event,
            Some(AuthorizedKeysReloadEvent::Loaded {
                generation: 2,
                ignored_entries: 0
            })
        );
        assert!(!store.contains(&first_key).unwrap());
        assert!(store.contains(&second_key).unwrap());
    }

    #[test]
    fn keeps_last_known_good_cache_when_reload_fails() {
        let tempdir = TempDir::new().unwrap();
        let path = tempdir.path().join("authorized_keys");
        fs::write(&path, format!("{PLAIN_ED25519_KEY}\n")).unwrap();

        let store =
            AuthorizedKeysStore::load(path.clone(), 1024, 8, Duration::from_millis(0)).unwrap();
        let first_key: ssh_key::PublicKey = PLAIN_ED25519_KEY.parse().unwrap();
        let second_key: ssh_key::PublicKey = SECOND_ED25519_KEY.parse().unwrap();

        std::thread::sleep(Duration::from_millis(20));
        fs::write(
            &path,
            format!("{PLAIN_ED25519_KEY}\n{PLAIN_ED25519_KEY}\ninvalid line without a key\n"),
        )
        .unwrap();

        let event = store.refresh_if_due().unwrap();
        assert!(matches!(event, Some(AuthorizedKeysReloadEvent::Failed(_))));
        assert!(store.contains(&first_key).unwrap());
        assert!(!store.contains(&second_key).unwrap());
        assert_eq!(
            store.status().last_reload_status,
            AuthorizedKeysReloadStatus::Failed(
                "authorized keys file contains a duplicate plain key entry".to_string()
            )
        );
        assert_eq!(store.refresh_if_due().unwrap(), None);

        std::thread::sleep(Duration::from_millis(20));
        fs::write(&path, format!("{SECOND_ED25519_KEY}\n")).unwrap();

        let event = store.refresh_if_due().unwrap();
        assert!(matches!(
            event,
            Some(AuthorizedKeysReloadEvent::Loaded { generation: 2, .. })
        ));
        assert!(!store.contains(&first_key).unwrap());
        assert!(store.contains(&second_key).unwrap());
    }

    #[test]
    fn delays_reload_until_debounce_interval_passes() {
        let tempdir = TempDir::new().unwrap();
        let path = tempdir.path().join("authorized_keys");
        fs::write(&path, format!("{PLAIN_ED25519_KEY}\n")).unwrap();

        let store =
            AuthorizedKeysStore::load(path.clone(), 1024, 8, Duration::from_secs(60)).unwrap();
        let first_key: ssh_key::PublicKey = PLAIN_ED25519_KEY.parse().unwrap();
        let second_key: ssh_key::PublicKey = SECOND_ED25519_KEY.parse().unwrap();

        std::thread::sleep(Duration::from_millis(20));
        fs::write(&path, format!("{SECOND_ED25519_KEY}\n")).unwrap();

        assert_eq!(store.refresh_if_due().unwrap(), None);
        assert!(store.contains(&first_key).unwrap());
        assert!(!store.contains(&second_key).unwrap());
    }
}
