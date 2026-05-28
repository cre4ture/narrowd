use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, mpsc as std_mpsc};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use getrandom::rand_core::UnwrapErr;
use log::{debug, error, info, warn};
use nix::sys::signal::{Signal, kill, killpg};
use nix::unistd::Pid;
use portable_pty::{
    Child as PtyChild, ChildKiller, CommandBuilder, MasterPty, PtySize, native_pty_system,
};
use russh::keys::{Algorithm, PrivateKey, ssh_key};
use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId, ChannelMsg, Sig};
use ssh_key::AuthorizedKeys;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{ChildStdin, Command};
use tokio::sync::{mpsc, oneshot};

use crate::config::AppConfig;
use crate::sftp::LocalSftp;

pub async fn run(config: AppConfig) -> Result<()> {
    let state = Arc::new(AppState::bootstrap(config)?);
    let bind_target = (state.config.listen_address.as_str(), state.config.port);

    info!(
        "starting narrowd on {}:{} with host key {}",
        state.config.listen_address,
        state.config.port,
        state.config.host_key.display()
    );

    let mut server = NarrowServer {
        state: Arc::clone(&state),
    };

    let ssh_config = server::Config {
        auth_rejection_time: Duration::from_secs(3),
        auth_rejection_time_initial: Some(Duration::ZERO),
        keys: vec![state.host_key.clone()],
        ..Default::default()
    };

    server
        .run_on_address(Arc::new(ssh_config), bind_target)
        .await
        .map_err(Into::into)
}

struct AppState {
    config: AppConfig,
    host_key: PrivateKey,
    home_dir: PathBuf,
}

impl AppState {
    fn bootstrap(config: AppConfig) -> Result<Self> {
        let home_dir = dirs::home_dir().context("unable to determine home directory")?;
        let host_key = load_or_generate_host_key(&config.host_key)?;

        if !config.authorized_keys_file.exists() {
            warn!(
                "authorized keys file {} does not exist yet; all public-key auth will be rejected until it is created",
                config.authorized_keys_file.display()
            );
        }

        Ok(Self {
            config,
            host_key,
            home_dir,
        })
    }

    fn is_authorized(&self, offered_key: &ssh_key::PublicKey) -> Result<bool> {
        let entries = match AuthorizedKeys::read_file(&self.config.authorized_keys_file) {
            Ok(entries) => entries,
            Err(err) if !self.config.authorized_keys_file.exists() => {
                debug!(
                    "authorized keys file {} missing: {err}",
                    self.config.authorized_keys_file.display()
                );
                return Ok(false);
            }
            Err(err) => {
                return Err(anyhow!(
                    "failed to read {}: {err}",
                    self.config.authorized_keys_file.display()
                ));
            }
        };

        Ok(entries
            .iter()
            .any(|entry| entry.public_key().key_data() == offered_key.key_data()))
    }
}

#[derive(Clone)]
struct NarrowServer {
    state: Arc<AppState>,
}

impl server::Server for NarrowServer {
    type Handler = ClientHandler;

    fn new_client(&mut self, peer: Option<std::net::SocketAddr>) -> Self::Handler {
        ClientHandler::new(Arc::clone(&self.state), peer)
    }
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
    peer: Option<std::net::SocketAddr>,
    pending_channels: HashMap<ChannelId, PendingChannel>,
    remote_forwards: HashMap<ForwardKey, tokio::task::JoinHandle<()>>,
    requested_user: Option<String>,
}

impl ClientHandler {
    fn new(state: Arc<AppState>, peer: Option<std::net::SocketAddr>) -> Self {
        Self {
            state,
            peer,
            pending_channels: HashMap::new(),
            remote_forwards: HashMap::new(),
            requested_user: None,
        }
    }

    fn authorize_key(&mut self, user: &str, public_key: &ssh_key::PublicKey) -> Result<Auth> {
        self.requested_user = Some(user.to_string());
        if self.state.is_authorized(public_key)? {
            info!(
                "accepted public key for requested user {user} from {}",
                peer_label(self.peer)
            );
            Ok(Auth::Accept)
        } else {
            warn!(
                "rejected public key for requested user {user} from {}",
                peer_label(self.peer)
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
        warn!(
            "password auth rejected for requested user {user} from {}",
            peer_label(self.peer)
        );
        Ok(Auth::reject())
    }

    async fn auth_succeeded(&mut self, _session: &mut Session) -> Result<(), Self::Error> {
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
        .or_insert_with(current_username);
    env.entry("LOGNAME".to_string())
        .or_insert_with(current_username);
    env.entry("SHELL".to_string())
        .or_insert_with(|| state.config.shell.to_string_lossy().into_owned());

    if let Some(term) = term {
        env.entry("TERM".to_string())
            .or_insert_with(|| term.to_string());
    }

    env
}

fn current_username() -> String {
    std::env::var("USER").unwrap_or_else(|_| "narrowd".to_string())
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
