use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
pub struct ServerMetrics {
    inner: Arc<MetricsState>,
}

impl ServerMetrics {
    pub fn new(max_auth_failure_ips: usize) -> Self {
        Self {
            inner: Arc::new(MetricsState::new(max_auth_failure_ips)),
        }
    }

    pub fn preauth_connection_opened(&self) {
        self.inner
            .current_unauthenticated_connections
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn preauth_connection_closed(&self) {
        self.inner
            .current_unauthenticated_connections
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(1))
            })
            .ok();
    }

    pub fn record_rejected_connection(&self, reason: &'static str) {
        let mut counters = self
            .inner
            .rejected_connections_by_reason
            .lock()
            .expect("metrics lock poisoned");
        *counters.entry(reason).or_default() += 1;
    }

    pub fn record_auth_failure(&self, peer_ip: Option<IpAddr>, temporary_ban_issued: bool) {
        if let Some(peer_ip) = peer_ip {
            let mut counters = self
                .inner
                .auth_failures_by_ip
                .lock()
                .expect("metrics lock poisoned");
            if let Some(counter) = counters.get_mut(&peer_ip) {
                *counter += 1;
            } else if counters.len() < self.inner.max_auth_failure_ips {
                counters.insert(peer_ip, 1);
            } else {
                self.inner
                    .auth_failure_ip_overflow
                    .fetch_add(1, Ordering::Relaxed);
            }
        }

        if temporary_ban_issued {
            self.inner
                .temporary_bans_issued
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_preauth_timeout(&self) {
        self.inner.preauth_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_malformed_disconnect(&self) {
        self.inner
            .malformed_packet_disconnects
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_reload_success(&self) {
        self.inner
            .authorized_keys_reload_successes
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_reload_failure(&self) {
        self.inner
            .authorized_keys_reload_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    #[allow(dead_code)]
    pub fn snapshot(&self) -> MetricsSnapshot {
        let rejected_connections_by_reason = self
            .inner
            .rejected_connections_by_reason
            .lock()
            .expect("metrics lock poisoned")
            .iter()
            .map(|(reason, count)| ((*reason).to_string(), *count))
            .collect::<BTreeMap<_, _>>();
        let auth_failures_by_ip = self
            .inner
            .auth_failures_by_ip
            .lock()
            .expect("metrics lock poisoned")
            .iter()
            .map(|(ip, count)| (ip.to_string(), *count))
            .collect::<BTreeMap<_, _>>();

        MetricsSnapshot {
            current_unauthenticated_connections: self
                .inner
                .current_unauthenticated_connections
                .load(Ordering::Relaxed),
            rejected_connections_by_reason,
            auth_failures_by_ip,
            auth_failure_ip_overflow: self.inner.auth_failure_ip_overflow.load(Ordering::Relaxed),
            temporary_bans_issued: self.inner.temporary_bans_issued.load(Ordering::Relaxed),
            preauth_timeouts: self.inner.preauth_timeouts.load(Ordering::Relaxed),
            malformed_packet_disconnects: self
                .inner
                .malformed_packet_disconnects
                .load(Ordering::Relaxed),
            authorized_keys_reload_successes: self
                .inner
                .authorized_keys_reload_successes
                .load(Ordering::Relaxed),
            authorized_keys_reload_failures: self
                .inner
                .authorized_keys_reload_failures
                .load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug)]
struct MetricsState {
    current_unauthenticated_connections: AtomicUsize,
    rejected_connections_by_reason: Mutex<HashMap<&'static str, u64>>,
    auth_failures_by_ip: Mutex<HashMap<IpAddr, u64>>,
    max_auth_failure_ips: usize,
    auth_failure_ip_overflow: AtomicU64,
    temporary_bans_issued: AtomicU64,
    preauth_timeouts: AtomicU64,
    malformed_packet_disconnects: AtomicU64,
    authorized_keys_reload_successes: AtomicU64,
    authorized_keys_reload_failures: AtomicU64,
}

impl MetricsState {
    fn new(max_auth_failure_ips: usize) -> Self {
        Self {
            current_unauthenticated_connections: AtomicUsize::new(0),
            rejected_connections_by_reason: Mutex::new(HashMap::new()),
            auth_failures_by_ip: Mutex::new(HashMap::new()),
            max_auth_failure_ips,
            auth_failure_ip_overflow: AtomicU64::new(0),
            temporary_bans_issued: AtomicU64::new(0),
            preauth_timeouts: AtomicU64::new(0),
            malformed_packet_disconnects: AtomicU64::new(0),
            authorized_keys_reload_successes: AtomicU64::new(0),
            authorized_keys_reload_failures: AtomicU64::new(0),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub struct MetricsSnapshot {
    pub current_unauthenticated_connections: usize,
    pub rejected_connections_by_reason: BTreeMap<String, u64>,
    pub auth_failures_by_ip: BTreeMap<String, u64>,
    pub auth_failure_ip_overflow: u64,
    pub temporary_bans_issued: u64,
    pub preauth_timeouts: u64,
    pub malformed_packet_disconnects: u64,
    pub authorized_keys_reload_successes: u64,
    pub authorized_keys_reload_failures: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn tracks_security_counters() {
        let metrics = ServerMetrics::new(8);

        metrics.preauth_connection_opened();
        metrics.record_rejected_connection("banner-timeout");
        metrics.record_auth_failure(Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))), false);
        metrics.record_auth_failure(Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))), true);
        metrics.record_preauth_timeout();
        metrics.record_malformed_disconnect();
        metrics.record_cache_reload_success();
        metrics.record_cache_reload_failure();
        metrics.preauth_connection_closed();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.current_unauthenticated_connections, 0);
        assert_eq!(
            snapshot
                .rejected_connections_by_reason
                .get("banner-timeout"),
            Some(&1)
        );
        assert_eq!(snapshot.auth_failures_by_ip.get("10.0.0.2"), Some(&2));
        assert_eq!(snapshot.temporary_bans_issued, 1);
        assert_eq!(snapshot.preauth_timeouts, 1);
        assert_eq!(snapshot.malformed_packet_disconnects, 1);
        assert_eq!(snapshot.authorized_keys_reload_successes, 1);
        assert_eq!(snapshot.authorized_keys_reload_failures, 1);
    }

    #[test]
    fn bounds_auth_failure_ips_and_tracks_overflow() {
        let metrics = ServerMetrics::new(1);

        metrics.record_auth_failure(Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))), false);
        metrics.record_auth_failure(Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))), false);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.auth_failures_by_ip.len(), 1);
        assert_eq!(snapshot.auth_failure_ip_overflow, 1);
    }
}
