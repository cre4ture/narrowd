use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::io::{Error as IoError, ErrorKind, Read, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc as std_mpsc};
use std::task::{Context as TaskContext, Poll};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use getrandom::rand_core::UnwrapErr;
use log::{debug, error, info, warn};
use nix::sys::signal::{Signal, kill, killpg};
use nix::unistd::{Pid, User, getuid};
use portable_pty::{
    Child as PtyChild, ChildKiller, CommandBuilder, MasterPty, PtySize, native_pty_system,
};
use russh::keys::{Algorithm, PrivateKey, ssh_key};
use russh::server::{self, Auth, Msg, Session};
use russh::{Channel, ChannelId, ChannelMsg, MethodKind, MethodSet, Sig};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{ChildStdin, Command};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Instant as TokioInstant, Sleep, timeout};

use crate::admission::{AdmissionConfig, AdmissionController, AdmissionGuard};
use crate::authorized_keys::AuthorizedKeysCache;
use crate::config::AppConfig;
use crate::log_limiter::{LogDecision, LogKey, LogLimiter};
use crate::sftp::LocalSftp;

pub async fn run(config: AppConfig) -> Result<()> {
    let state = Arc::new(AppState::bootstrap(config)?);

    info!(
        "starting narrowd on {}:{} with host key {}",
        state.config.listen_address,
        state.config.port,
        state.config.host_key.display()
    );

    let listener =
        TcpListener::bind((state.config.listen_address.as_str(), state.config.port)).await?;
    run_with_listener(state, listener).await
}

pub async fn run_on_listener(config: AppConfig, listener: TcpListener) -> Result<()> {
    let state = Arc::new(AppState::bootstrap(config)?);
    run_with_listener(state, listener).await
}

async fn run_with_listener(state: Arc<AppState>, listener: TcpListener) -> Result<()> {
    let ssh_config = Arc::new(build_ssh_config(&state));

    loop {
        let (socket, peer_addr) = listener.accept().await?;
        let state = Arc::clone(&state);
        let ssh_config = Arc::clone(&ssh_config);

        tokio::spawn(async move {
            if let Err(err) = serve_connection(state, ssh_config, socket, peer_addr).await {
                warn!("connection from {peer_addr} ended with error: {err:#}");
            }
        });
    }
}

struct AppState {
    config: AppConfig,
    host_key: PrivateKey,
    daemon_username: String,
    home_dir: PathBuf,
    authorized_keys: AuthorizedKeysCache,
    admission: AdmissionController,
    log_limiter: LogLimiter,
}

impl AppState {
    fn bootstrap(config: AppConfig) -> Result<Self> {
        let home_dir = dirs::home_dir().context("unable to determine home directory")?;
        let host_key = load_or_generate_host_key(&config.host_key)?;
        let daemon_username = daemon_username()?;
        let authorized_keys = match AuthorizedKeysCache::load(
            &config.authorized_keys_file,
            config.authorized_keys_max_size,
            config.authorized_keys_max_entries,
        ) {
            Ok(cache) => cache,
            Err(err) if !config.authorized_keys_file.exists() => {
                warn!(
                    "authorized keys file {} does not exist yet; all public-key auth will be rejected until it is created",
                    config.authorized_keys_file.display()
                );
                debug!(
                    "authorized keys file {} missing: {err}",
                    config.authorized_keys_file.display()
                );
                AuthorizedKeysCache::empty()
            }
            Err(err) => return Err(err),
        };

        if host_key.algorithm() != ssh_key::Algorithm::Ed25519 {
            anyhow::bail!(
                "host key {} must be an Ed25519 key for the public exposure profile",
                config.host_key.display()
            );
        }

        if authorized_keys.ignored_entries() > 0 {
            warn!(
                "ignoring {} authorized_keys entr{} with unsupported options in {}; narrowd accepts only plain key lines",
                authorized_keys.ignored_entries(),
                if authorized_keys.ignored_entries() == 1 {
                    "y"
                } else {
                    "ies"
                },
                config.authorized_keys_file.display()
            );
        }

        Ok(Self {
            admission: AdmissionController::new(AdmissionConfig::from_app_config(&config)),
            log_limiter: LogLimiter::new(Duration::from_secs(30), 4096),
            config,
            host_key,
            daemon_username,
            home_dir,
            authorized_keys,
        })
    }

    fn is_authorized(&self, offered_key: &ssh_key::PublicKey) -> Result<bool> {
        self.authorized_keys.contains(offered_key)
    }

    fn warn_limited(&self, peer: Option<SocketAddr>, category: &'static str, message: String) {
        let decision = self.log_limiter.check(LogKey {
            peer_ip: peer.map(|peer| peer.ip()),
            category,
        });

        if let LogDecision::Emit { suppressed } = decision {
            if suppressed == 0 {
                warn!("{message}");
            } else {
                warn!(
                    "{message}; suppressed {suppressed} similar messages in the last {:?}",
                    self.log_limiter.window()
                );
            }
        }
    }
}

struct PreauthContext {
    admission_guard: Option<AdmissionGuard>,
    auth_success_tx: Option<oneshot::Sender<()>>,
    authenticated: Arc<AtomicBool>,
}

impl PreauthContext {
    fn new(
        admission_guard: AdmissionGuard,
        auth_success_tx: oneshot::Sender<()>,
        authenticated: Arc<AtomicBool>,
    ) -> Self {
        Self {
            admission_guard: Some(admission_guard),
            auth_success_tx: Some(auth_success_tx),
            authenticated,
        }
    }

    fn mark_authenticated(&mut self) {
        self.authenticated.store(true, Ordering::Relaxed);

        if let Some(guard) = self.admission_guard.take() {
            guard.mark_authenticated();
        }

        if let Some(tx) = self.auth_success_tx.take() {
            let _ = tx.send(());
        }
    }
}

struct LoginGraceStream<S> {
    inner: S,
    deadline: TokioInstant,
    authenticated: Arc<AtomicBool>,
    timer: Pin<Box<Sleep>>,
}

impl<S> LoginGraceStream<S> {
    fn new(inner: S, deadline: TokioInstant, authenticated: Arc<AtomicBool>) -> Self {
        Self {
            inner,
            deadline,
            authenticated,
            timer: Box::pin(tokio::time::sleep_until(deadline)),
        }
    }

    fn is_authenticated(&self) -> bool {
        self.authenticated.load(Ordering::Relaxed)
    }

    fn preauth_timeout_error() -> IoError {
        IoError::new(
            ErrorKind::TimedOut,
            "login grace time exceeded before authentication completed",
        )
    }

    fn poll_deadline(&mut self, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        if self.is_authenticated() {
            return Poll::Pending;
        }

        if TokioInstant::now() >= self.deadline {
            return Poll::Ready(Err(Self::preauth_timeout_error()));
        }

        match self.timer.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(Self::preauth_timeout_error())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S> AsyncRead for LoginGraceStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.is_authenticated() {
            return Pin::new(&mut self.inner).poll_read(cx, buf);
        }

        if TokioInstant::now() >= self.deadline {
            return Poll::Ready(Err(Self::preauth_timeout_error()));
        }

        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => self.poll_deadline(cx),
        }
    }
}

impl<S> AsyncWrite for LoginGraceStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.is_authenticated() {
            return Pin::new(&mut self.inner).poll_write(cx, buf);
        }

        if TokioInstant::now() >= self.deadline {
            return Poll::Ready(Err(Self::preauth_timeout_error()));
        }

        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => match self.poll_deadline(cx) {
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) => Poll::Ready(Ok(0)),
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        if self.is_authenticated() {
            return Pin::new(&mut self.inner).poll_flush(cx);
        }

        if TokioInstant::now() >= self.deadline {
            return Poll::Ready(Err(Self::preauth_timeout_error()));
        }

        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => self.poll_deadline(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn serve_connection(
    state: Arc<AppState>,
    ssh_config: Arc<server::Config>,
    socket: TcpStream,
    peer_addr: SocketAddr,
) -> Result<()> {
    let admission_guard = match state.admission.try_acquire(peer_addr.ip()) {
        Ok(guard) => guard,
        Err(reason) => {
            state.warn_limited(
                Some(peer_addr),
                reason.category(),
                format!("rejected connection from {peer_addr}: {reason}"),
            );
            return Ok(());
        }
    };

    if ssh_config.nodelay {
        if let Err(err) = socket.set_nodelay(true) {
            warn!("failed to enable TCP_NODELAY for {peer_addr}: {err}");
        }
    }

    let accepted_at = TokioInstant::now();
    let login_deadline = accepted_at + state.config.login_grace_time;
    let (auth_success_tx, mut auth_success_rx) = oneshot::channel();
    let authenticated = Arc::new(AtomicBool::new(false));
    let handler = ClientHandler::new(
        Arc::clone(&state),
        Some(peer_addr),
        PreauthContext::new(admission_guard, auth_success_tx, Arc::clone(&authenticated)),
    );
    let stream = LoginGraceStream::new(socket, login_deadline, authenticated);

    let running = match timeout(
        state.config.client_banner_timeout,
        server::run_stream(ssh_config, stream, handler),
    )
    .await
    {
        Ok(Ok(session)) => session,
        Ok(Err(err)) => {
            if is_login_grace_timeout(&err) {
                state.warn_limited(
                    Some(peer_addr),
                    "login-grace-timeout",
                    format!(
                        "closing pre-auth connection from {peer_addr} after login grace timeout of {:?}",
                        state.config.login_grace_time
                    ),
                );
            } else {
                debug!("SSH setup from {peer_addr} failed before authentication: {err:#}");
            }
            return Ok(());
        }
        Err(_) => {
            state.warn_limited(
                Some(peer_addr),
                "banner-timeout",
                format!(
                    "timed out waiting for SSH banner from {peer_addr} after {:?}",
                    state.config.client_banner_timeout
                ),
            );
            return Ok(());
        }
    };

    tokio::pin!(running);

    tokio::select! {
        result = &mut auth_success_rx => {
            if result.is_ok() {
                info!(
                    "authentication completed for {peer_addr} in {:?}",
                    accepted_at.elapsed()
                );
            }

            running.await?;
        }
        result = &mut running => {
            if let Err(ref err) = result {
                if is_login_grace_timeout(err) {
                    state.warn_limited(
                        Some(peer_addr),
                        "login-grace-timeout",
                        format!(
                            "closing pre-auth connection from {peer_addr} after login grace timeout of {:?}",
                            state.config.login_grace_time
                        ),
                    );
                }
            }
            result?;
        }
    }

    Ok(())
}

#[derive(Debug, Eq, Hash, PartialEq)]
struct ForwardKey {
    address: String,
    port: u32,
}

struct PendingChannel {
    channel: Channel<Msg>,
    pty: Option<PtyRequest>,
    env: BTreeMap<String, String>,
}

#[derive(Clone)]
struct PtyRequest {
    term: String,
    size: PtySize,
}

struct ClientHandler {
    state: Arc<AppState>,
    peer: Option<SocketAddr>,
    preauth: PreauthContext,
    pending_channels: HashMap<ChannelId, PendingChannel>,
    remote_forwards: HashMap<ForwardKey, tokio::task::JoinHandle<()>>,
    requested_user: Option<String>,
}

impl ClientHandler {
    fn new(state: Arc<AppState>, peer: Option<SocketAddr>, preauth: PreauthContext) -> Self {
        Self {
            state,
            peer,
            preauth,
            pending_channels: HashMap::new(),
            remote_forwards: HashMap::new(),
            requested_user: None,
        }
    }

    fn authorize_key(&mut self, user: &str, public_key: &ssh_key::PublicKey) -> Result<Auth> {
        self.requested_user = Some(user.to_string());
        if !login_user_matches_daemon(user, &self.state.daemon_username) {
            self.record_auth_failure(
                user,
                "auth-reject-username",
                &format!(
                    "requested login user does not match daemon user {}",
                    self.state.daemon_username
                ),
            );
            return Ok(Auth::reject());
        }

        if !is_user_key_algorithm_allowed(&public_key.algorithm()) {
            self.record_auth_failure(
                user,
                "auth-reject-key-algorithm",
                &format!(
                    "unsupported public key algorithm {:?}",
                    public_key.algorithm()
                ),
            );
            return Ok(Auth::reject());
        }

        if self.state.is_authorized(public_key)? {
            info!(
                "accepted public key for requested user {user} from {}",
                peer_label(self.peer)
            );
            Ok(Auth::Accept)
        } else {
            self.record_auth_failure(
                user,
                "auth-reject-unknown-key",
                "public key not present in authorized_keys cache",
            );
            Ok(Auth::reject())
        }
    }

    fn channel_mut(&mut self, channel: ChannelId) -> Result<&mut PendingChannel> {
        self.pending_channels
            .get_mut(&channel)
            .ok_or_else(|| anyhow!("unknown channel {channel:?}"))
    }

    fn take_channel(&mut self, channel: ChannelId) -> Result<PendingChannel> {
        self.pending_channels
            .remove(&channel)
            .ok_or_else(|| anyhow!("unknown channel {channel:?}"))
    }

    fn record_auth_failure(&self, user: &str, category: &'static str, reason: &str) {
        let Some(peer_ip) = self.peer.map(|peer| peer.ip()) else {
            self.state.warn_limited(
                self.peer,
                category,
                format!("rejected authentication for requested user {user}: {reason}"),
            );
            return;
        };

        let banned = self.state.admission.record_auth_failure(peer_ip);
        let suffix = if banned {
            "; peer temporarily banned"
        } else {
            ""
        };
        self.state.warn_limited(
            self.peer,
            category,
            format!(
                "rejected authentication for requested user {user} from {}: {reason}{suffix}",
                peer_label(self.peer)
            ),
        );
    }
}

impl Drop for ClientHandler {
    fn drop(&mut self) {
        for (_, task) in self.remote_forwards.drain() {
            task.abort();
        }
    }
}

impl server::Handler for ClientHandler {
    type Error = anyhow::Error;

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        public_key: &ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.authorize_key(user, public_key)
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.authorize_key(user, public_key)
    }

    async fn auth_password(&mut self, user: &str, _password: &str) -> Result<Auth, Self::Error> {
        self.record_auth_failure(
            user,
            "auth-reject-password",
            "password authentication is disabled",
        );
        Ok(Auth::reject())
    }

    async fn auth_succeeded(&mut self, _session: &mut Session) -> Result<(), Self::Error> {
        self.preauth.mark_authenticated();
        info!(
            "session authenticated for requested user {} from {}",
            self.requested_user.as_deref().unwrap_or("<unknown>"),
            peer_label(self.peer)
        );
        Ok(())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        info!(
            "opened session channel {:?} from {}",
            channel.id(),
            peer_label(self.peer)
        );
        self.pending_channels.insert(
            channel.id(),
            PendingChannel {
                channel,
                pty: None,
                env: BTreeMap::new(),
            },
        );
        Ok(true)
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        if !self.state.config.allow_tcp_forwarding {
            warn!("direct-tcpip denied by config");
            return Ok(false);
        }

        let Some(port) = u16::try_from(port_to_connect).ok() else {
            warn!("direct-tcpip denied due to invalid target port {port_to_connect}");
            return Ok(false);
        };

        match TcpStream::connect((host_to_connect, port)).await {
            Ok(stream) => {
                info!(
                    "direct-tcpip {}:{} from {}:{} on channel {:?}",
                    host_to_connect,
                    port_to_connect,
                    originator_address,
                    originator_port,
                    channel.id()
                );
                tokio::spawn(async move {
                    if let Err(err) = proxy_stream(channel.into_stream(), stream).await {
                        debug!("direct-tcpip proxy ended: {err}");
                    }
                });
                Ok(true)
            }
            Err(err) => {
                warn!(
                    "direct-tcpip connect {}:{} failed: {err}",
                    host_to_connect, port_to_connect
                );
                Ok(false)
            }
        }
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !is_env_allowed(variable_name) {
            warn!("rejected env {variable_name} on channel {channel:?}");
            session.channel_failure(channel)?;
            return Ok(());
        }

        self.channel_mut(channel)?
            .env
            .insert(variable_name.to_string(), variable_value.to_string());
        session.channel_success(channel)?;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.state.config.permit_tty {
            session.channel_failure(channel)?;
            return Ok(());
        }

        self.channel_mut(channel)?.pty = Some(PtyRequest {
            term: term.to_string(),
            size: PtySize {
                rows: clamp_dimension(row_height),
                cols: clamp_dimension(col_width),
                pixel_width: clamp_dimension(pix_width),
                pixel_height: clamp_dimension(pix_height),
            },
        });
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let pending = self.take_channel(channel)?;
        match launch_shell(Arc::clone(&self.state), pending).await {
            Ok(()) => {
                session.channel_success(channel)?;
            }
            Err(err) => {
                error!("failed to start shell on channel {channel:?}: {err:#}");
                session.channel_failure(channel)?;
            }
        }
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.state.config.permit_exec {
            session.channel_failure(channel)?;
            return Ok(());
        }

        let pending = self.take_channel(channel)?;
        let command = String::from_utf8_lossy(data).to_string();
        match launch_exec(Arc::clone(&self.state), pending, command).await {
            Ok(()) => {
                session.channel_success(channel)?;
            }
            Err(err) => {
                error!("failed to start exec on channel {channel:?}: {err:#}");
                session.channel_failure(channel)?;
            }
        }
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name != "sftp" || !self.state.config.sftp_enabled {
            session.channel_failure(channel)?;
            return Ok(());
        }

        let pending = self.take_channel(channel)?;
        let sftp = LocalSftp::new(self.state.home_dir.clone());
        session.channel_success(channel)?;
        russh_sftp::server::run(pending.channel.into_stream(), sftp).await;
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.pending_channels.remove(&channel);
        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        if !self.state.config.allow_remote_forwarding {
            warn!("tcpip-forward denied by config");
            return Ok(false);
        }

        let bind_host = if self.state.config.gateway_ports {
            if address.is_empty() {
                "0.0.0.0"
            } else {
                address
            }
        } else {
            "127.0.0.1"
        };

        let requested_port = u16::try_from(*port).context("invalid tcpip-forward port")?;
        let bind_addr = tokio::net::lookup_host((bind_host, requested_port))
            .await
            .context("failed to resolve tcpip-forward bind address")?
            .next()
            .ok_or_else(|| anyhow!("no bind address for tcpip-forward request"))?;

        let listener = match TcpListener::bind(bind_addr).await {
            Ok(listener) => listener,
            Err(err) => {
                warn!("failed to bind remote forward {bind_host}:{requested_port}: {err}");
                return Ok(false);
            }
        };

        let local_addr = listener
            .local_addr()
            .context("failed to inspect listener address")?;
        *port = u32::from(local_addr.port());
        let key = ForwardKey {
            address: address.to_string(),
            port: *port,
        };

        if self.remote_forwards.contains_key(&key) {
            warn!(
                "duplicate tcpip-forward request for {}:{}",
                key.address, key.port
            );
            return Ok(false);
        }

        let handle = session.handle();
        let connected_address = if address.is_empty() {
            bind_host.to_string()
        } else {
            address.to_string()
        };
        let connected_port = *port;

        info!(
            "accepted remote forward {}:{} (bound as {})",
            connected_address, connected_port, local_addr
        );

        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, origin)) = listener.accept().await else {
                    break;
                };

                let handle = handle.clone();
                let connected_address = connected_address.clone();
                tokio::spawn(async move {
                    match handle
                        .channel_open_forwarded_tcpip(
                            connected_address,
                            connected_port,
                            origin.ip().to_string(),
                            u32::from(origin.port()),
                        )
                        .await
                    {
                        Ok(channel) => {
                            if let Err(err) = proxy_stream(channel.into_stream(), stream).await {
                                debug!("forwarded-tcpip proxy ended: {err}");
                            }
                        }
                        Err(err) => {
                            debug!("failed to open forwarded-tcpip channel: {err}");
                        }
                    }
                });
            }
        });

        self.remote_forwards.insert(key, task);
        Ok(true)
    }

    async fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let key = ForwardKey {
            address: address.to_string(),
            port,
        };

        if let Some(task) = self.remote_forwards.remove(&key) {
            task.abort();
            info!("cancelled remote forward {}:{}", address, port);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

async fn launch_shell(state: Arc<AppState>, pending: PendingChannel) -> Result<()> {
    if pending.pty.is_some() {
        launch_pty_process(state, pending, None).await
    } else {
        launch_piped_process(state, pending, None).await
    }
}

async fn launch_exec(state: Arc<AppState>, pending: PendingChannel, command: String) -> Result<()> {
    if pending.pty.is_some() {
        launch_pty_process(state, pending, Some(command)).await
    } else {
        launch_piped_process(state, pending, Some(command)).await
    }
}

struct PtyLaunch {
    master: Box<dyn MasterPty + Send>,
    reader: Box<dyn Read + Send>,
    writer: Box<dyn Write + Send>,
    child: Box<dyn PtyChild + Send + Sync>,
    killer: Box<dyn ChildKiller + Send + Sync>,
    process_group: Option<i32>,
}

enum PtyControl {
    Write(Vec<u8>),
    Resize(PtySize),
    Signal(Sig),
    Eof,
    Close,
}

async fn launch_pty_process(
    state: Arc<AppState>,
    pending: PendingChannel,
    command: Option<String>,
) -> Result<()> {
    let pty = pending.pty.clone().unwrap_or(PtyRequest {
        term: "xterm-256color".to_string(),
        size: PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        },
    });

    let env = build_child_env(&state, &pending.env, Some(&pty.term));
    let shell = state.config.shell.clone();
    let cwd = state.home_dir.clone();

    let mut launch = tokio::task::spawn_blocking(move || -> Result<PtyLaunch> {
        let pty_system = native_pty_system();
        let pair = pty_system.openpty(pty.size).context("failed to open PTY")?;

        let mut builder = CommandBuilder::new(&shell);
        builder.cwd(&cwd);
        for (key, value) in env {
            builder.env(key, value);
        }
        if let Some(command) = command {
            builder.arg("-lc");
            builder.arg(command);
        }

        let child = pair
            .slave
            .spawn_command(builder)
            .context("failed to spawn PTY child")?;
        let killer = child.clone_killer();
        let reader = pair
            .master
            .try_clone_reader()
            .context("failed to clone PTY reader")?;
        let writer = pair
            .master
            .take_writer()
            .context("failed to take PTY writer")?;
        let process_group = pair.master.process_group_leader();

        Ok(PtyLaunch {
            master: pair.master,
            reader,
            writer,
            child,
            killer,
            process_group,
        })
    })
    .await
    .context("PTY spawn task failed")??;

    let (mut chan_read, chan_write) = pending.channel.split();
    let (output_tx, mut output_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (exit_tx, mut exit_rx) = oneshot::channel::<u32>();
    let (control_tx, control_rx) = std_mpsc::channel::<PtyControl>();

    thread::spawn(move || run_pty_reader(launch.reader, output_tx));
    thread::spawn(move || {
        run_pty_control(
            control_rx,
            launch.master,
            launch.writer,
            launch.killer,
            launch.process_group,
        )
    });
    thread::spawn(move || {
        let code = launch
            .child
            .wait()
            .map(|status| status.exit_code())
            .unwrap_or(255);
        let _ = exit_tx.send(code);
    });

    tokio::spawn(async move {
        let input_task = tokio::spawn(async move {
            while let Some(message) = chan_read.wait().await {
                match message {
                    ChannelMsg::Data { data } => {
                        if control_tx.send(PtyControl::Write(data.to_vec())).is_err() {
                            break;
                        }
                    }
                    ChannelMsg::Signal { signal } => {
                        let _ = control_tx.send(PtyControl::Signal(signal));
                    }
                    ChannelMsg::WindowChange {
                        col_width,
                        row_height,
                        pix_width,
                        pix_height,
                    } => {
                        let _ = control_tx.send(PtyControl::Resize(PtySize {
                            rows: clamp_dimension(row_height),
                            cols: clamp_dimension(col_width),
                            pixel_width: clamp_dimension(pix_width),
                            pixel_height: clamp_dimension(pix_height),
                        }));
                    }
                    ChannelMsg::Eof => {
                        let _ = control_tx.send(PtyControl::Eof);
                    }
                    ChannelMsg::Close => {
                        let _ = control_tx.send(PtyControl::Close);
                        break;
                    }
                    _ => {}
                }
            }

            let _ = control_tx.send(PtyControl::Close);
        });

        let mut child_exit = None;
        let mut output_closed = false;

        loop {
            if output_closed && child_exit.is_some() {
                break;
            }

            tokio::select! {
                maybe_chunk = output_rx.recv(), if !output_closed => {
                    match maybe_chunk {
                        Some(chunk) => {
                            if chan_write.data_bytes(chunk).await.is_err() {
                                break;
                            }
                        }
                        None => output_closed = true,
                    }
                }
                result = &mut exit_rx, if child_exit.is_none() => {
                    child_exit = Some(result.unwrap_or(255));
                }
            }
        }

        if let Some(code) = child_exit {
            let _ = chan_write.exit_status(code).await;
        }
        let _ = chan_write.eof().await;
        let _ = chan_write.close().await;
        let _ = input_task.await;
    });

    Ok(())
}

async fn launch_piped_process(
    state: Arc<AppState>,
    pending: PendingChannel,
    command: Option<String>,
) -> Result<()> {
    let mut process = Command::new(&state.config.shell);
    process.current_dir(&state.home_dir);
    process.stdin(Stdio::piped());
    process.stdout(Stdio::piped());
    process.stderr(Stdio::piped());
    process.kill_on_drop(true);

    for (key, value) in build_child_env(&state, &pending.env, None) {
        process.env(key, value);
    }

    if let Some(command) = command {
        process.arg("-lc");
        process.arg(command);
    }

    let mut child = process.spawn().context("failed to spawn child process")?;
    let pid = child.id().context("child process has no pid")?;
    let stdin = child.stdin.take().context("missing child stdin")?;
    let stdout = child.stdout.take().context("missing child stdout")?;
    let stderr = child.stderr.take().context("missing child stderr")?;
    let (mut chan_read, chan_write) = pending.channel.split();
    let (output_tx, mut output_rx) = mpsc::unbounded_channel::<ProcessOutput>();
    let (exit_tx, mut exit_rx) = oneshot::channel::<u32>();

    tokio::spawn(read_process_stream(
        stdout,
        ProcessStream::Stdout,
        output_tx.clone(),
    ));
    tokio::spawn(read_process_stream(
        stderr,
        ProcessStream::Stderr,
        output_tx,
    ));
    tokio::spawn(async move {
        let code = child.wait().await.map(exit_status_code).unwrap_or(255);
        let _ = exit_tx.send(code);
    });

    tokio::spawn(async move {
        let input_task = tokio::spawn(async move {
            handle_piped_input(pid, &mut chan_read, stdin).await;
        });

        let mut child_exit = None;
        let mut output_closed = false;

        loop {
            if output_closed && child_exit.is_some() {
                break;
            }

            tokio::select! {
                maybe_output = output_rx.recv(), if !output_closed => {
                    match maybe_output {
                        Some(ProcessOutput::Stdout(data)) => {
                            if chan_write.data_bytes(data).await.is_err() {
                                let _ = send_signal_to_pid(pid, Signal::SIGKILL);
                                break;
                            }
                        }
                        Some(ProcessOutput::Stderr(data)) => {
                            if chan_write.extended_data_bytes(1, data).await.is_err() {
                                let _ = send_signal_to_pid(pid, Signal::SIGKILL);
                                break;
                            }
                        }
                        None => output_closed = true,
                    }
                }
                result = &mut exit_rx, if child_exit.is_none() => {
                    child_exit = Some(result.unwrap_or(255));
                }
            }
        }

        if let Some(code) = child_exit {
            let _ = chan_write.exit_status(code).await;
        }
        let _ = chan_write.eof().await;
        let _ = chan_write.close().await;
        let _ = input_task.await;
    });

    Ok(())
}

enum ProcessStream {
    Stdout,
    Stderr,
}

enum ProcessOutput {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
}

async fn handle_piped_input(
    pid: u32,
    chan_read: &mut russh::ChannelReadHalf,
    mut stdin: ChildStdin,
) {
    while let Some(message) = chan_read.wait().await {
        match message {
            ChannelMsg::Data { data } => {
                if stdin.write_all(&data).await.is_err() {
                    break;
                }
            }
            ChannelMsg::Signal { signal } => {
                if let Some(mapped) = map_signal(&signal) {
                    let _ = send_signal_to_pid(pid, mapped);
                }
            }
            ChannelMsg::Eof => {
                let _ = stdin.shutdown().await;
            }
            ChannelMsg::Close => {
                let _ = send_signal_to_pid(pid, Signal::SIGKILL);
                break;
            }
            _ => {}
        }
    }

    let _ = stdin.shutdown().await;
}

async fn read_process_stream<R>(
    mut stream: R,
    which: ProcessStream,
    output_tx: mpsc::UnboundedSender<ProcessOutput>,
) where
    R: AsyncRead + Unpin + Send + 'static,
{
    let mut buffer = vec![0_u8; 8192];

    loop {
        match stream.read(&mut buffer).await {
            Ok(0) => break,
            Ok(read) => {
                let chunk = buffer[..read].to_vec();
                let message = match which {
                    ProcessStream::Stdout => ProcessOutput::Stdout(chunk),
                    ProcessStream::Stderr => ProcessOutput::Stderr(chunk),
                };
                if output_tx.send(message).is_err() {
                    break;
                }
            }
            Err(err) => {
                debug!("process stream read ended: {err}");
                break;
            }
        }
    }
}

async fn proxy_stream(mut channel: russh::ChannelStream<Msg>, mut stream: TcpStream) -> Result<()> {
    tokio::io::copy_bidirectional(&mut channel, &mut stream)
        .await
        .map(|_| ())
        .map_err(Into::into)
}

fn run_pty_reader(mut reader: Box<dyn Read + Send>, output_tx: mpsc::UnboundedSender<Vec<u8>>) {
    let mut buffer = vec![0_u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                if output_tx.send(buffer[..read].to_vec()).is_err() {
                    break;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => {
                debug!("PTY reader ended: {err}");
                break;
            }
        }
    }
}

fn run_pty_control(
    control_rx: std_mpsc::Receiver<PtyControl>,
    master: Box<dyn MasterPty + Send>,
    writer: Box<dyn Write + Send>,
    mut killer: Box<dyn ChildKiller + Send + Sync>,
    process_group: Option<i32>,
) {
    let mut writer = Some(writer);

    while let Ok(message) = control_rx.recv() {
        match message {
            PtyControl::Write(data) => {
                if let Some(writer) = writer.as_mut() {
                    if writer.write_all(&data).is_err() || writer.flush().is_err() {
                        break;
                    }
                }
            }
            PtyControl::Resize(size) => {
                let _ = master.resize(size);
            }
            PtyControl::Signal(signal) => {
                if let Some(mapped) = map_signal(&signal) {
                    if let Some(group) = process_group {
                        let _ = send_signal_to_process_group(group, mapped);
                    }
                }
            }
            PtyControl::Eof => {
                writer.take();
            }
            PtyControl::Close => {
                writer.take();
                let _ = killer.kill();
                break;
            }
        }
    }
}

fn load_or_generate_host_key(path: &PathBuf) -> Result<PrivateKey> {
    if path.exists() {
        return PrivateKey::read_openssh_file(path)
            .with_context(|| format!("failed to read host key {}", path.display()));
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let mut rng = UnwrapErr(getrandom::SysRng);
    let key =
        PrivateKey::random(&mut rng, Algorithm::Ed25519).context("failed to generate host key")?;
    key.write_openssh_file(path, ssh_key::LineEnding::LF)
        .with_context(|| format!("failed to write host key {}", path.display()))?;
    info!("generated new host key at {}", path.display());
    Ok(key)
}

fn build_ssh_config(state: &AppState) -> server::Config {
    server::Config {
        methods: MethodSet::from(&[MethodKind::PublicKey][..]),
        auth_rejection_time: state.config.auth_rejection_time,
        auth_rejection_time_initial: Some(state.config.auth_rejection_time),
        keys: vec![state.host_key.clone()],
        preferred: public_exposure_preferred(),
        max_auth_attempts: state.config.max_auth_attempts,
        inactivity_timeout: Some(state.config.inactivity_timeout),
        keepalive_interval: Some(state.config.keepalive_interval),
        keepalive_max: state.config.keepalive_max,
        nodelay: state.config.nodelay,
        channel_buffer_size: state.config.channel_buffer_size,
        event_buffer_size: state.config.event_buffer_size,
        window_size: state.config.window_size,
        maximum_packet_size: state.config.maximum_packet_size,
        ..Default::default()
    }
}

fn build_child_env(
    state: &AppState,
    requested_env: &BTreeMap<String, String>,
    term: Option<&str>,
) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();

    for (key, value) in requested_env {
        if is_env_allowed(key) {
            env.insert(key.clone(), value.clone());
        }
    }

    env.entry("HOME".to_string())
        .or_insert_with(|| state.home_dir.to_string_lossy().into_owned());
    env.entry("USER".to_string())
        .or_insert_with(|| state.daemon_username.clone());
    env.entry("LOGNAME".to_string())
        .or_insert_with(|| state.daemon_username.clone());
    env.entry("SHELL".to_string())
        .or_insert_with(|| state.config.shell.to_string_lossy().into_owned());

    if let Some(term) = term {
        env.entry("TERM".to_string())
            .or_insert_with(|| term.to_string());
    }

    env
}

fn daemon_username() -> Result<String> {
    let uid = getuid();
    let user = User::from_uid(uid)
        .context("failed to resolve daemon user from current uid")?
        .ok_or_else(|| anyhow!("no passwd entry for daemon uid {}", uid.as_raw()))?;
    Ok(user.name)
}

fn login_user_matches_daemon(requested_user: &str, daemon_username: &str) -> bool {
    requested_user == daemon_username
}

fn is_user_key_algorithm_allowed(algorithm: &ssh_key::Algorithm) -> bool {
    matches!(
        algorithm,
        ssh_key::Algorithm::Ed25519 | ssh_key::Algorithm::SkEd25519
    )
}

fn public_exposure_preferred() -> russh::Preferred {
    let mut preferred = russh::Preferred::default();
    preferred.kex = Cow::Owned(vec![
        russh::kex::MLKEM768X25519_SHA256,
        russh::kex::CURVE25519,
        russh::kex::CURVE25519_PRE_RFC_8731,
        russh::kex::EXTENSION_SUPPORT_AS_SERVER,
        russh::kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
    ]);
    preferred.key = Cow::Owned(vec![
        ssh_key::Algorithm::Ed25519,
        ssh_key::Algorithm::SkEd25519,
    ]);
    preferred.cipher = Cow::Owned(vec![
        russh::cipher::CHACHA20_POLY1305,
        russh::cipher::AES_256_GCM,
        russh::cipher::AES_256_CTR,
        russh::cipher::AES_128_CTR,
    ]);
    preferred.mac = Cow::Owned(vec![
        russh::mac::HMAC_SHA512_ETM,
        russh::mac::HMAC_SHA256_ETM,
        russh::mac::HMAC_SHA512,
        russh::mac::HMAC_SHA256,
    ]);
    preferred.compression = Cow::Owned(vec![russh::compression::NONE]);
    preferred
}

fn is_env_allowed(name: &str) -> bool {
    name == "TERM"
        || name == "COLORTERM"
        || name == "LANG"
        || name == "TZ"
        || name.starts_with("LC_")
}

fn peer_label(peer: Option<std::net::SocketAddr>) -> String {
    peer.map(|peer| peer.to_string())
        .unwrap_or_else(|| "<unknown peer>".to_string())
}

fn is_login_grace_timeout(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io_err| {
                io_err.kind() == ErrorKind::TimedOut
                    && io_err
                        .to_string()
                        .contains("login grace time exceeded before authentication completed")
            })
    })
}

fn clamp_dimension(value: u32) -> u16 {
    let value = value.max(1);
    value.min(u16::MAX as u32) as u16
}

fn map_signal(signal: &Sig) -> Option<Signal> {
    match signal {
        Sig::ABRT => Some(Signal::SIGABRT),
        Sig::ALRM => Some(Signal::SIGALRM),
        Sig::FPE => Some(Signal::SIGFPE),
        Sig::HUP => Some(Signal::SIGHUP),
        Sig::ILL => Some(Signal::SIGILL),
        Sig::INT => Some(Signal::SIGINT),
        Sig::KILL => Some(Signal::SIGKILL),
        Sig::PIPE => Some(Signal::SIGPIPE),
        Sig::QUIT => Some(Signal::SIGQUIT),
        Sig::SEGV => Some(Signal::SIGSEGV),
        Sig::TERM => Some(Signal::SIGTERM),
        Sig::USR1 => Some(Signal::SIGUSR1),
        Sig::Custom(_) => None,
    }
}

fn send_signal_to_pid(pid: u32, signal: Signal) -> Result<()> {
    kill(Pid::from_raw(pid as i32), signal).context("failed to signal child")
}

fn send_signal_to_process_group(group: i32, signal: Signal) -> Result<()> {
    killpg(Pid::from_raw(group), signal).context("failed to signal child process group")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_matching_login_usernames() {
        assert!(login_user_matches_daemon("uli", "uli"));
        assert!(!login_user_matches_daemon("root", "uli"));
    }

    #[test]
    fn allows_only_modern_user_key_algorithms() {
        assert!(is_user_key_algorithm_allowed(&ssh_key::Algorithm::Ed25519));
        assert!(is_user_key_algorithm_allowed(
            &ssh_key::Algorithm::SkEd25519
        ));
        assert!(!is_user_key_algorithm_allowed(&ssh_key::Algorithm::Dsa));
        assert!(!is_user_key_algorithm_allowed(&ssh_key::Algorithm::Rsa {
            hash: None
        }));
    }

    #[test]
    fn builds_public_exposure_ssh_config_from_app_config() {
        let mut config = AppConfig::defaults().unwrap();
        config.max_auth_attempts = 7;
        config.auth_rejection_time = std::time::Duration::from_secs(4);
        config.keepalive_interval = std::time::Duration::from_secs(42);
        config.keepalive_max = 5;
        config.channel_buffer_size = 24;
        config.event_buffer_size = 12;
        config.window_size = 123_456;
        config.maximum_packet_size = 16_384;
        config.nodelay = false;

        let host_key =
            PrivateKey::random(&mut UnwrapErr(getrandom::SysRng), Algorithm::Ed25519).unwrap();
        let state = AppState {
            admission: AdmissionController::new(AdmissionConfig::from_app_config(&config)),
            config,
            host_key,
            daemon_username: "uli".to_string(),
            home_dir: PathBuf::from("/tmp"),
            authorized_keys: AuthorizedKeysCache::empty(),
            log_limiter: LogLimiter::new(Duration::from_secs(30), 64),
        };

        let ssh_config = build_ssh_config(&state);

        assert_eq!(
            ssh_config.methods,
            MethodSet::from(&[MethodKind::PublicKey][..])
        );
        assert_eq!(
            ssh_config.auth_rejection_time,
            std::time::Duration::from_secs(4)
        );
        assert_eq!(
            ssh_config.auth_rejection_time_initial,
            Some(std::time::Duration::from_secs(4))
        );
        assert_eq!(ssh_config.max_auth_attempts, 7);
        assert_eq!(
            ssh_config.keepalive_interval,
            Some(std::time::Duration::from_secs(42))
        );
        assert_eq!(ssh_config.keepalive_max, 5);
        assert_eq!(ssh_config.channel_buffer_size, 24);
        assert_eq!(ssh_config.event_buffer_size, 12);
        assert_eq!(ssh_config.window_size, 123_456);
        assert_eq!(ssh_config.maximum_packet_size, 16_384);
        assert!(!ssh_config.nodelay);
        assert_eq!(
            ssh_config.preferred.kex.as_ref(),
            &[
                russh::kex::MLKEM768X25519_SHA256,
                russh::kex::CURVE25519,
                russh::kex::CURVE25519_PRE_RFC_8731,
                russh::kex::EXTENSION_SUPPORT_AS_SERVER,
                russh::kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
            ]
        );
        assert_eq!(
            ssh_config.preferred.key.as_ref(),
            &[ssh_key::Algorithm::Ed25519, ssh_key::Algorithm::SkEd25519,]
        );
        assert_eq!(
            ssh_config.preferred.cipher.as_ref(),
            &[
                russh::cipher::CHACHA20_POLY1305,
                russh::cipher::AES_256_GCM,
                russh::cipher::AES_256_CTR,
                russh::cipher::AES_128_CTR,
            ]
        );
        assert_eq!(
            ssh_config.preferred.mac.as_ref(),
            &[
                russh::mac::HMAC_SHA512_ETM,
                russh::mac::HMAC_SHA256_ETM,
                russh::mac::HMAC_SHA512,
                russh::mac::HMAC_SHA256,
            ]
        );
        assert_eq!(
            ssh_config.preferred.compression.as_ref(),
            &[russh::compression::NONE]
        );
    }
}

#[cfg(unix)]
fn exit_status_code(status: std::process::ExitStatus) -> u32 {
    use std::os::unix::process::ExitStatusExt;

    status
        .code()
        .map(|code| code as u32)
        .or_else(|| status.signal().map(|signal| 128 + signal as u32))
        .unwrap_or(255)
}

#[cfg(not(unix))]
fn exit_status_code(status: std::process::ExitStatus) -> u32 {
    status.code().map(|code| code as u32).unwrap_or(255)
}
