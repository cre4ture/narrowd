use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::AppConfig;

#[derive(Clone, Debug)]
pub struct AdmissionConfig {
    pub max_unauth_connections_global: usize,
    pub max_unauth_connections_per_ip: usize,
    pub max_unauth_connections_per_subnet: usize,
    pub new_connections_per_minute_per_ip: usize,
    pub new_connections_burst_per_ip: usize,
    pub auth_failure_ban_threshold: usize,
    pub auth_failure_ban_window: Duration,
    pub auth_failure_ban_duration: Duration,
}

impl AdmissionConfig {
    pub fn from_app_config(config: &AppConfig) -> Self {
        Self {
            max_unauth_connections_global: config.max_unauth_connections_global,
            max_unauth_connections_per_ip: config.max_unauth_connections_per_ip,
            max_unauth_connections_per_subnet: config.max_unauth_connections_per_subnet,
            new_connections_per_minute_per_ip: config.new_connections_per_minute_per_ip,
            new_connections_burst_per_ip: config.new_connections_burst_per_ip,
            auth_failure_ban_threshold: config.auth_failure_ban_threshold,
            auth_failure_ban_window: config.auth_failure_ban_window,
            auth_failure_ban_duration: config.auth_failure_ban_duration,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AdmissionController {
    inner: Arc<Mutex<AdmissionState>>,
}

impl AdmissionController {
    pub fn new(config: AdmissionConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(AdmissionState::new(config))),
        }
    }

    pub fn try_acquire(&self, peer_ip: IpAddr) -> Result<AdmissionGuard, RejectReason> {
        self.try_acquire_at(peer_ip, Instant::now())
    }

    pub fn try_acquire_at(
        &self,
        peer_ip: IpAddr,
        now: Instant,
    ) -> Result<AdmissionGuard, RejectReason> {
        let subnet = subnet_key(peer_ip);
        let mut state = self.inner.lock().expect("admission lock poisoned");
        state.try_acquire(peer_ip, subnet, now)?;
        drop(state);

        Ok(AdmissionGuard {
            controller: self.clone(),
            peer_ip,
            subnet,
            released: false,
        })
    }

    pub fn record_auth_failure(&self, peer_ip: IpAddr) -> bool {
        self.record_auth_failure_at(peer_ip, Instant::now())
    }

    pub fn record_auth_failure_at(&self, peer_ip: IpAddr, now: Instant) -> bool {
        let mut state = self.inner.lock().expect("admission lock poisoned");
        state.record_auth_failure(peer_ip, now)
    }

    fn release(&self, peer_ip: IpAddr, subnet: SubnetKey) {
        let mut state = self.inner.lock().expect("admission lock poisoned");
        state.release(peer_ip, subnet, Instant::now());
    }
}

#[derive(Debug)]
pub struct AdmissionGuard {
    controller: AdmissionController,
    peer_ip: IpAddr,
    subnet: SubnetKey,
    released: bool,
}

impl AdmissionGuard {
    pub fn mark_authenticated(mut self) {
        self.release();
    }

    fn release(&mut self) {
        if self.released {
            return;
        }

        self.controller.release(self.peer_ip, self.subnet);
        self.released = true;
    }
}

impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        self.release();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectReason {
    TooManyUnauthenticatedConnections,
    TooManyUnauthenticatedConnectionsForIp,
    TooManyUnauthenticatedConnectionsForSubnet,
    ConnectionRateLimited,
    TemporarilyBanned,
}

impl fmt::Display for RejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::TooManyUnauthenticatedConnections => {
                "global unauthenticated connection limit reached"
            }
            Self::TooManyUnauthenticatedConnectionsForIp => {
                "per-IP unauthenticated connection limit reached"
            }
            Self::TooManyUnauthenticatedConnectionsForSubnet => {
                "per-subnet unauthenticated connection limit reached"
            }
            Self::ConnectionRateLimited => "connection rate limited",
            Self::TemporarilyBanned => {
                "peer temporarily banned after repeated authentication failures"
            }
        };
        f.write_str(label)
    }
}

#[derive(Debug)]
struct AdmissionState {
    config: AdmissionConfig,
    unauthenticated_connections: usize,
    per_subnet: HashMap<SubnetKey, usize>,
    per_peer: HashMap<IpAddr, PeerState>,
}

impl AdmissionState {
    fn new(config: AdmissionConfig) -> Self {
        Self {
            config,
            unauthenticated_connections: 0,
            per_subnet: HashMap::new(),
            per_peer: HashMap::new(),
        }
    }

    fn try_acquire(
        &mut self,
        peer_ip: IpAddr,
        subnet: SubnetKey,
        now: Instant,
    ) -> Result<(), RejectReason> {
        self.cleanup_peer(peer_ip, now);

        let peer = self
            .per_peer
            .entry(peer_ip)
            .or_insert_with(|| PeerState::new(self.config.new_connections_burst_per_ip, now));

        if peer.is_banned(now) {
            return Err(RejectReason::TemporarilyBanned);
        }

        if !peer.connection_bucket.try_consume(
            self.config.new_connections_per_minute_per_ip,
            self.config.new_connections_burst_per_ip,
            now,
        ) {
            return Err(RejectReason::ConnectionRateLimited);
        }

        if self.unauthenticated_connections >= self.config.max_unauth_connections_global {
            return Err(RejectReason::TooManyUnauthenticatedConnections);
        }

        if peer.unauthenticated_connections >= self.config.max_unauth_connections_per_ip {
            return Err(RejectReason::TooManyUnauthenticatedConnectionsForIp);
        }

        let subnet_connections = self.per_subnet.get(&subnet).copied().unwrap_or_default();
        if subnet_connections >= self.config.max_unauth_connections_per_subnet {
            return Err(RejectReason::TooManyUnauthenticatedConnectionsForSubnet);
        }

        self.unauthenticated_connections += 1;
        peer.unauthenticated_connections += 1;
        *self.per_subnet.entry(subnet).or_default() += 1;
        Ok(())
    }

    fn record_auth_failure(&mut self, peer_ip: IpAddr, now: Instant) -> bool {
        self.cleanup_peer(peer_ip, now);
        let peer = self
            .per_peer
            .entry(peer_ip)
            .or_insert_with(|| PeerState::new(self.config.new_connections_burst_per_ip, now));

        prune_before(
            &mut peer.auth_failures,
            now - self.config.auth_failure_ban_window,
        );
        peer.auth_failures.push_back(now);
        if peer.auth_failures.len() >= self.config.auth_failure_ban_threshold {
            peer.auth_failures.clear();
            peer.banned_until = Some(now + self.config.auth_failure_ban_duration);
            true
        } else {
            false
        }
    }

    fn release(&mut self, peer_ip: IpAddr, subnet: SubnetKey, now: Instant) {
        if self.unauthenticated_connections > 0 {
            self.unauthenticated_connections -= 1;
        }

        if let Some(count) = self.per_subnet.get_mut(&subnet) {
            if *count > 1 {
                *count -= 1;
            } else {
                self.per_subnet.remove(&subnet);
            }
        }

        if let Some(peer) = self.per_peer.get_mut(&peer_ip) {
            if peer.unauthenticated_connections > 0 {
                peer.unauthenticated_connections -= 1;
            }
        }

        self.cleanup_peer(peer_ip, now);
    }

    fn cleanup_peer(&mut self, peer_ip: IpAddr, now: Instant) {
        let Some(peer) = self.per_peer.get_mut(&peer_ip) else {
            return;
        };

        if peer.banned_until.is_some_and(|until| until <= now) {
            peer.banned_until = None;
        }
        prune_before(
            &mut peer.auth_failures,
            now - self.config.auth_failure_ban_window,
        );

        if peer.unauthenticated_connections == 0
            && peer.banned_until.is_none()
            && peer.auth_failures.is_empty()
        {
            self.per_peer.remove(&peer_ip);
        }
    }
}

#[derive(Debug)]
struct PeerState {
    unauthenticated_connections: usize,
    auth_failures: VecDeque<Instant>,
    banned_until: Option<Instant>,
    connection_bucket: TokenBucket,
}

impl PeerState {
    fn new(burst_limit: usize, now: Instant) -> Self {
        Self {
            unauthenticated_connections: 0,
            auth_failures: VecDeque::new(),
            banned_until: None,
            connection_bucket: TokenBucket::new(burst_limit, now),
        }
    }

    fn is_banned(&self, now: Instant) -> bool {
        self.banned_until.is_some_and(|until| until > now)
    }
}

#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(burst_limit: usize, now: Instant) -> Self {
        Self {
            tokens: burst_limit as f64,
            last_refill: now,
        }
    }

    fn try_consume(&mut self, limit_per_minute: usize, burst_limit: usize, now: Instant) -> bool {
        let refill_rate_per_second = limit_per_minute as f64 / 60.0;
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        self.tokens = (self.tokens + elapsed * refill_rate_per_second).min(burst_limit as f64);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct SubnetKey {
    addr: IpAddr,
    prefix_len: u8,
}

fn subnet_key(peer_ip: IpAddr) -> SubnetKey {
    match peer_ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            SubnetKey {
                addr: IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], 0)),
                prefix_len: 24,
            }
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            SubnetKey {
                addr: IpAddr::V6(Ipv6Addr::new(
                    segments[0],
                    segments[1],
                    segments[2],
                    segments[3],
                    0,
                    0,
                    0,
                    0,
                )),
                prefix_len: 64,
            }
        }
    }
}

fn prune_before(values: &mut VecDeque<Instant>, oldest_allowed: Instant) {
    while values.front().is_some_and(|value| *value < oldest_allowed) {
        values.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> AdmissionConfig {
        AdmissionConfig {
            max_unauth_connections_global: 4,
            max_unauth_connections_per_ip: 2,
            max_unauth_connections_per_subnet: 3,
            new_connections_per_minute_per_ip: 12,
            new_connections_burst_per_ip: 2,
            auth_failure_ban_threshold: 3,
            auth_failure_ban_window: Duration::from_secs(30),
            auth_failure_ban_duration: Duration::from_secs(60),
        }
    }

    #[test]
    fn enforces_per_ip_limit_until_guard_released() {
        let controller = AdmissionController::new(test_config());
        let now = Instant::now();
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        let guard1 = controller.try_acquire_at(peer, now).unwrap();
        let guard2 = controller
            .try_acquire_at(peer, now + Duration::from_millis(1))
            .unwrap();
        let reject = controller
            .try_acquire_at(peer, now + Duration::from_secs(10))
            .unwrap_err();

        assert_eq!(reject, RejectReason::TooManyUnauthenticatedConnectionsForIp);

        drop(guard1);
        controller
            .try_acquire_at(peer, now + Duration::from_secs(5))
            .unwrap();
        drop(guard2);
    }

    #[test]
    fn enforces_rate_limit_and_refills_over_time() {
        let controller = AdmissionController::new(test_config());
        let now = Instant::now();
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));

        let first = controller.try_acquire_at(peer, now).unwrap();
        let second = controller
            .try_acquire_at(peer, now + Duration::from_millis(1))
            .unwrap();
        let reject = controller
            .try_acquire_at(peer, now + Duration::from_millis(2))
            .unwrap_err();

        assert_eq!(reject, RejectReason::ConnectionRateLimited);

        drop(first);
        drop(second);

        controller
            .try_acquire_at(peer, now + Duration::from_secs(10))
            .unwrap();
    }

    #[test]
    fn bans_after_repeated_auth_failures_and_expires() {
        let controller = AdmissionController::new(test_config());
        let now = Instant::now();
        let peer = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

        assert!(!controller.record_auth_failure_at(peer, now));
        assert!(!controller.record_auth_failure_at(peer, now + Duration::from_secs(1)));
        assert!(controller.record_auth_failure_at(peer, now + Duration::from_secs(2)));

        let reject = controller
            .try_acquire_at(peer, now + Duration::from_secs(3))
            .unwrap_err();
        assert_eq!(reject, RejectReason::TemporarilyBanned);

        controller
            .try_acquire_at(peer, now + Duration::from_secs(65))
            .unwrap();
    }

    #[test]
    fn enforces_per_subnet_limit() {
        let controller = AdmissionController::new(test_config());
        let now = Instant::now();

        let _a = controller
            .try_acquire_at(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), now)
            .unwrap();
        let _b = controller
            .try_acquire_at(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), now)
            .unwrap();
        let _c = controller
            .try_acquire_at(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), now)
            .unwrap();

        let reject = controller
            .try_acquire_at(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)), now)
            .unwrap_err();
        assert_eq!(
            reject,
            RejectReason::TooManyUnauthenticatedConnectionsForSubnet
        );
    }
}
