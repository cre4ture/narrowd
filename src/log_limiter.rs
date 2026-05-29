use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct LogLimiter {
    inner: Arc<Mutex<LogLimiterState>>,
}

impl LogLimiter {
    pub fn new(window: Duration, max_entries: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(LogLimiterState::new(window, max_entries))),
        }
    }

    pub fn check(&self, key: LogKey) -> LogDecision {
        self.check_at(key, Instant::now())
    }

    fn check_at(&self, key: LogKey, now: Instant) -> LogDecision {
        let mut state = self.inner.lock().expect("log limiter lock poisoned");
        state.check(key, now)
    }

    pub fn window(&self) -> Duration {
        self.inner
            .lock()
            .expect("log limiter lock poisoned")
            .config
            .window
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LogKey {
    pub peer_ip: Option<IpAddr>,
    pub category: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogDecision {
    Emit { suppressed: usize },
    Suppress,
}

#[derive(Debug)]
struct LogLimiterState {
    config: LogLimiterConfig,
    entries: HashMap<LogKey, LogEntry>,
    last_cleanup: Instant,
}

impl LogLimiterState {
    fn new(window: Duration, max_entries: usize) -> Self {
        Self {
            config: LogLimiterConfig {
                window,
                max_entries,
            },
            entries: HashMap::new(),
            last_cleanup: Instant::now(),
        }
    }

    fn check(&mut self, key: LogKey, now: Instant) -> LogDecision {
        self.maybe_cleanup(now);

        match self.entries.get_mut(&key) {
            Some(entry) => {
                if now.duration_since(entry.last_emitted_at) >= self.config.window {
                    let suppressed = entry.suppressed;
                    entry.last_emitted_at = now;
                    entry.suppressed = 0;
                    LogDecision::Emit { suppressed }
                } else {
                    entry.suppressed = entry.suppressed.saturating_add(1);
                    LogDecision::Suppress
                }
            }
            None => {
                self.entries.insert(
                    key,
                    LogEntry {
                        last_emitted_at: now,
                        suppressed: 0,
                    },
                );
                LogDecision::Emit { suppressed: 0 }
            }
        }
    }

    fn maybe_cleanup(&mut self, now: Instant) {
        if self.entries.len() <= self.config.max_entries
            && now.duration_since(self.last_cleanup) < self.config.window
        {
            return;
        }

        let retention = self.config.window.saturating_mul(2);
        self.entries
            .retain(|_, entry| now.duration_since(entry.last_emitted_at) <= retention);
        self.last_cleanup = now;

        if self.entries.len() <= self.config.max_entries {
            return;
        }

        let mut entries = self
            .entries
            .iter()
            .map(|(key, entry)| (*key, entry.last_emitted_at))
            .collect::<Vec<_>>();
        entries.sort_by_key(|(_, last_emitted_at)| *last_emitted_at);

        let to_remove = self.entries.len().saturating_sub(self.config.max_entries);
        for (key, _) in entries.into_iter().take(to_remove) {
            self.entries.remove(&key);
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct LogLimiterConfig {
    window: Duration,
    max_entries: usize,
}

#[derive(Clone, Copy, Debug)]
struct LogEntry {
    last_emitted_at: Instant,
    suppressed: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn key(octet: u8) -> LogKey {
        LogKey {
            peer_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet))),
            category: "auth-failure",
        }
    }

    #[test]
    fn suppresses_duplicates_within_window_and_reports_summary() {
        let limiter = LogLimiter::new(Duration::from_secs(30), 64);
        let now = Instant::now();

        assert_eq!(
            limiter.check_at(key(1), now),
            LogDecision::Emit { suppressed: 0 }
        );
        assert_eq!(
            limiter.check_at(key(1), now + Duration::from_secs(1)),
            LogDecision::Suppress
        );
        assert_eq!(
            limiter.check_at(key(1), now + Duration::from_secs(31)),
            LogDecision::Emit { suppressed: 1 }
        );
    }

    #[test]
    fn evicts_old_entries_when_map_grows() {
        let limiter = LogLimiter::new(Duration::from_secs(10), 2);
        let now = Instant::now();

        assert_eq!(
            limiter.check_at(key(1), now),
            LogDecision::Emit { suppressed: 0 }
        );
        assert_eq!(
            limiter.check_at(key(2), now + Duration::from_secs(1)),
            LogDecision::Emit { suppressed: 0 }
        );
        assert_eq!(
            limiter.check_at(key(3), now + Duration::from_secs(25)),
            LogDecision::Emit { suppressed: 0 }
        );

        let state = limiter.inner.lock().unwrap();
        assert!(state.entries.len() <= 2);
        assert!(!state.entries.contains_key(&key(1)));
    }
}
