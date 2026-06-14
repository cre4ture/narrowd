use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Stdio;
#[cfg(unix)]
use std::process::{Child, Command as StdCommand};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc as std_mpsc};
use std::thread;

#[cfg(unix)]
use std::io::{IoSlice, IoSliceMut};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
#[cfg(unix)]
use std::os::unix::net::UnixStream as StdUnixStream;
#[cfg(unix)]
use std::os::unix::process::CommandExt;

use anyhow::{Context, Result, anyhow};
use log::debug;
#[cfg(unix)]
use log::warn;

#[cfg(unix)]
use nix::cmsg_space;
#[cfg(unix)]
use nix::fcntl::{FcntlArg, FdFlag, fcntl};
#[cfg(unix)]
use nix::libc;
#[cfg(unix)]
use nix::sys::signal::{Signal, kill, killpg};
#[cfg(unix)]
use nix::sys::socket::{
    AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType, recvmsg,
    sendmsg, socketpair,
};
#[cfg(unix)]
use nix::unistd::{Pid, dup};

use portable_pty::{
    Child as PtyChild, ChildKiller, CommandBuilder, MasterPty, PtySize, native_pty_system,
};
use russh::Sig;
use russh::server;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{ChildStdin, Command};
use tokio::sync::{mpsc, oneshot};

use crate::config::ExecMode;
use crate::sftp::LocalSftp;

/// On Unix the executor runs in a separate process and communicates via a Unix
/// domain socket pair.  On other platforms it runs in-process and the "service
/// stream" is an in-memory duplex channel.
#[cfg(unix)]
pub type ServiceStream = tokio::net::UnixStream;

#[cfg(not(unix))]
pub type ServiceStream = tokio::io::DuplexStream;

#[cfg(unix)]
const CONTROL_FD: RawFd = 3;
#[cfg(unix)]
const MAX_CONTROL_MESSAGE_SIZE: usize = 64 * 1024;
const MAX_SESSION_MESSAGE_SIZE: usize = 1024 * 1024;

fn encode_message<T: Serialize>(message: &T, context: &'static str) -> Result<Vec<u8>> {
    serde_json::to_vec(message).context(context)
}

fn decode_message<T>(payload: &[u8], context: &'static str) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_slice(payload).context(context)
}

#[derive(Clone)]
pub struct ExecutorClient {
    inner: Arc<ExecutorClientInner>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProcessRequest {
    pub pty: Option<SerializablePtyRequest>,
    pub env: BTreeMap<String, String>,
    pub command: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SerializablePtyRequest {
    pub term: String,
    pub size: SerializablePtySize,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct SerializablePtySize {
    pub rows: u16,
    pub cols: u16,
    pub pixel_width: u16,
    pub pixel_height: u16,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum ExecutorSignal {
    Abrt,
    Alrm,
    Fpe,
    Hup,
    Ill,
    Int,
    Kill,
    Pipe,
    Quit,
    Segv,
    Term,
    Usr1,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum ProcessInput {
    Data(Vec<u8>),
    Signal(ExecutorSignal),
    Resize(SerializablePtySize),
    Eof,
    Close,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum ProcessOutput {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    ExitStatus(u32),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ExecutorHello {
    home_dir: PathBuf,
    shell: PathBuf,
    exec_mode: ExecMode,
}

pub struct StartedRemoteForward {
    pub token: u64,
    pub bound_port: u32,
}

// ─── Unix-only IPC machinery ─────────────────────────────────────────────────

#[cfg(unix)]
#[derive(Clone, Debug, Deserialize, Serialize)]
enum ExecutorRequest {
    Hello(ExecutorHello),
    StartProcess {
        request_id: u64,
        request: ProcessRequest,
    },
    StartSftp {
        request_id: u64,
    },
    ConnectTcp {
        request_id: u64,
        host: String,
        port: u16,
    },
    StartRemoteForward {
        request_id: u64,
        token: u64,
        bind_address: String,
        bind_port: u16,
    },
    CancelRemoteForward {
        request_id: u64,
        token: u64,
    },
}

#[cfg(unix)]
#[derive(Debug, Deserialize, Serialize)]
enum ExecutorResponse {
    HelloAck,
    RequestOk {
        request_id: u64,
        detail: ResponseDetail,
    },
    RequestErr {
        request_id: u64,
        message: String,
    },
    RemoteForwardIncoming {
        token: u64,
        originator_address: String,
        originator_port: u32,
    },
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
enum ResponseDetail {
    Empty,
    BoundPort(u16),
}

#[cfg(unix)]
struct ControlReader {
    fd: OwnedFd,
}

#[cfg(unix)]
struct ControlWriter {
    fd: OwnedFd,
}

#[cfg(unix)]
struct TransportPacket<T> {
    message: T,
    attached_fd: Option<OwnedFd>,
}

#[cfg(unix)]
struct RemoteForwardEvent {
    token: u64,
    originator_address: String,
    originator_port: u32,
    stream_fd: OwnedFd,
}

#[cfg(unix)]
struct ExecutorState {
    writer: Arc<Mutex<ControlWriter>>,
    hello: Option<ExecutorHello>,
    remote_forwards: HashMap<u64, tokio::task::JoinHandle<()>>,
}

// ─── Unix executor entry point (child process) ───────────────────────────────

#[cfg(unix)]
pub async fn run_from_control_fd(control_fd: RawFd) -> Result<()> {
    let control_fd = unsafe { OwnedFd::from_raw_fd(control_fd) };
    let read_fd = dup(&control_fd).context("failed to duplicate executor control fd for reads")?;
    let write_fd =
        dup(&control_fd).context("failed to duplicate executor control fd for writes")?;
    drop(control_fd);

    let (request_tx, mut request_rx) =
        mpsc::unbounded_channel::<(ExecutorRequest, Option<OwnedFd>)>();

    thread::spawn(move || {
        let mut reader = ControlReader { fd: read_fd };
        loop {
            let packet = match reader.recv::<ExecutorRequest>() {
                Ok(packet) => packet,
                Err(err) => {
                    debug!("executor control reader stopped: {err:#}");
                    break;
                }
            };

            if request_tx
                .send((packet.message, packet.attached_fd))
                .is_err()
            {
                break;
            }
        }
    });

    let writer = Arc::new(Mutex::new(ControlWriter { fd: write_fd }));
    let mut state = ExecutorState {
        writer,
        hello: None,
        remote_forwards: HashMap::new(),
    };

    while let Some((request, attached_fd)) = request_rx.recv().await {
        match request {
            ExecutorRequest::Hello(hello) => {
                state.hello = Some(hello);
                state.send_response(&ExecutorResponse::HelloAck, None)?;
            }
            ExecutorRequest::StartProcess {
                request_id,
                request,
            } => {
                let result = state.start_process(request, attached_fd).await;
                state.send_request_result(request_id, result.map(|_| ResponseDetail::Empty))?;
            }
            ExecutorRequest::StartSftp { request_id } => {
                let result = state.start_sftp(attached_fd).await;
                state.send_request_result(request_id, result.map(|_| ResponseDetail::Empty))?;
            }
            ExecutorRequest::ConnectTcp {
                request_id,
                host,
                port,
            } => {
                let result = state.connect_tcp(host, port, attached_fd).await;
                state.send_request_result(request_id, result.map(|_| ResponseDetail::Empty))?;
            }
            ExecutorRequest::StartRemoteForward {
                request_id,
                token,
                bind_address,
                bind_port,
            } => {
                let result = state
                    .start_remote_forward(token, bind_address, bind_port)
                    .await;
                state.send_request_result(request_id, result.map(ResponseDetail::BoundPort))?;
            }
            ExecutorRequest::CancelRemoteForward { request_id, token } => {
                let result = state.cancel_remote_forward(token);
                state.send_request_result(request_id, result.map(|_| ResponseDetail::Empty))?;
            }
        }
    }

    Ok(())
}

// ─── Unix ExecutorClient (separate child process via socket pair) ─────────────

#[cfg(unix)]
struct ExecutorClientInner {
    writer: Mutex<ControlWriter>,
    pending: Mutex<HashMap<u64, oneshot::Sender<ExecutorResponse>>>,
    remote_forwards: Mutex<HashMap<u64, RemoteForwardRegistration>>,
    next_request_id: AtomicU64,
    next_forward_token: AtomicU64,
    child: Mutex<Option<Child>>,
}

#[cfg(unix)]
#[derive(Clone)]
struct RemoteForwardRegistration {
    session_handle: server::Handle,
    connected_address: String,
    connected_port: u32,
}

#[cfg(unix)]
impl ExecutorClient {
    pub fn spawn(
        shell: PathBuf,
        exec_mode: ExecMode,
        home_dir: PathBuf,
        program_override: Option<OsString>,
    ) -> Result<Self> {
        let (parent_fd, child_fd) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::empty(),
        )
        .context("failed to create executor control socket pair")?;
        set_cloexec(&parent_fd)?;
        set_cloexec(&child_fd)?;

        let child_raw_fd = child_fd.as_raw_fd();
        let mut command = StdCommand::new(executor_program(program_override)?);
        command.arg("--internal-executor");
        command.arg("--control-fd");
        command.arg(CONTROL_FD.to_string());
        command.stdin(Stdio::null());
        command.stdout(Stdio::inherit());
        command.stderr(Stdio::inherit());

        unsafe {
            command.pre_exec(move || {
                if libc::dup2(child_raw_fd, CONTROL_FD) == -1 {
                    return Err(std::io::Error::last_os_error());
                }

                if child_raw_fd != CONTROL_FD {
                    libc::close(child_raw_fd);
                }

                Ok(())
            });
        }

        let child = command
            .spawn()
            .context("failed to spawn executor process")?;
        drop(child_fd);

        let read_fd =
            dup(&parent_fd).context("failed to duplicate executor control fd for parent reads")?;
        let write_fd =
            dup(&parent_fd).context("failed to duplicate executor control fd for parent writes")?;
        drop(parent_fd);

        let mut reader = ControlReader { fd: read_fd };
        let mut writer = ControlWriter { fd: write_fd };
        writer.send(
            &ExecutorRequest::Hello(ExecutorHello {
                home_dir,
                shell,
                exec_mode,
            }),
            None,
        )?;

        let hello = reader.recv::<ExecutorResponse>()?;
        if !matches!(hello.message, ExecutorResponse::HelloAck) {
            anyhow::bail!("executor did not acknowledge startup handshake");
        }

        let handle = tokio::runtime::Handle::try_current()
            .context("ExecutorClient::spawn requires a running Tokio runtime")?;
        let (event_tx, mut event_rx) = mpsc::unbounded_channel::<RemoteForwardEvent>();
        let inner = Arc::new(ExecutorClientInner {
            writer: Mutex::new(writer),
            pending: Mutex::new(HashMap::new()),
            remote_forwards: Mutex::new(HashMap::new()),
            next_request_id: AtomicU64::new(1),
            next_forward_token: AtomicU64::new(1),
            child: Mutex::new(Some(child)),
        });

        let thread_inner = Arc::clone(&inner);
        let (started_tx, started_rx) = std_mpsc::channel();
        thread::spawn(move || {
            // Signal only after the thread has fully started running user code.
            // This keeps the pre-auth seccomp sandbox from racing a half-started
            // control-reader thread into glibc's thread-registration syscalls.
            let _ = started_tx.send(());
            let mut reader = reader;

            loop {
                let packet = match reader.recv::<ExecutorResponse>() {
                    Ok(packet) => packet,
                    Err(err) => {
                        debug!("executor control channel closed: {err:#}");
                        break;
                    }
                };

                match packet.message {
                    ExecutorResponse::RequestOk { request_id, .. }
                    | ExecutorResponse::RequestErr { request_id, .. } => {
                        if let Some(tx) = thread_inner.pending.lock().unwrap().remove(&request_id) {
                            let _ = tx.send(packet.message);
                        }
                    }
                    ExecutorResponse::RemoteForwardIncoming {
                        token,
                        originator_address,
                        originator_port,
                    } => {
                        let Some(stream_fd) = packet.attached_fd else {
                            warn!(
                                "executor reported a forwarded connection for token {} without a socket fd",
                                token
                            );
                            continue;
                        };

                        if event_tx
                            .send(RemoteForwardEvent {
                                token,
                                originator_address,
                                originator_port,
                                stream_fd,
                            })
                            .is_err()
                        {
                            break;
                        }
                    }
                    ExecutorResponse::HelloAck => {
                        warn!("received unexpected executor hello acknowledgement");
                    }
                }
            }

            let mut pending = thread_inner.pending.lock().unwrap();
            for (_, tx) in pending.drain() {
                let _ = tx.send(ExecutorResponse::RequestErr {
                    request_id: 0,
                    message: "executor control channel closed".to_string(),
                });
            }
        });
        started_rx
            .recv()
            .context("executor control reader thread failed to start")?;

        let dispatch_inner = Arc::clone(&inner);
        handle.spawn(async move {
            while let Some(event) = event_rx.recv().await {
                if let Err(err) = dispatch_remote_forward_event(&dispatch_inner, event).await {
                    warn!("failed to handle executor remote-forward event: {err:#}");
                }
            }
        });

        Ok(Self { inner })
    }

    #[cfg(test)]
    pub fn inert_for_tests() -> Result<Self> {
        let (reader_fd, writer_fd) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::empty(),
        )
        .context("failed to create inert executor control socket")?;
        set_cloexec(&reader_fd)?;
        set_cloexec(&writer_fd)?;
        drop(reader_fd);
        Ok(Self {
            inner: Arc::new(ExecutorClientInner {
                writer: Mutex::new(ControlWriter { fd: writer_fd }),
                pending: Mutex::new(HashMap::new()),
                remote_forwards: Mutex::new(HashMap::new()),
                next_request_id: AtomicU64::new(1),
                next_forward_token: AtomicU64::new(1),
                child: Mutex::new(None),
            }),
        })
    }

    pub async fn start_process(&self, request: ProcessRequest) -> Result<ServiceStream> {
        let (parent_stream, child_fd) = unix_service_channel()?;
        let request_id = self.inner.next_request_id();
        let response = self
            .inner
            .request(
                ExecutorRequest::StartProcess {
                    request_id,
                    request,
                },
                Some(child_fd),
            )
            .await?;
        match response {
            ExecutorResponse::RequestOk { .. } => Ok(parent_stream),
            ExecutorResponse::RequestErr { message, .. } => Err(anyhow!(
                "executor failed to start process session: {message}"
            )),
            other => Err(anyhow!(
                "unexpected executor response to process request: {other:?}"
            )),
        }
    }

    pub async fn start_sftp(&self) -> Result<ServiceStream> {
        let (parent_stream, child_fd) = unix_service_channel()?;
        let request_id = self.inner.next_request_id();
        let response = self
            .inner
            .request(ExecutorRequest::StartSftp { request_id }, Some(child_fd))
            .await?;
        match response {
            ExecutorResponse::RequestOk { .. } => Ok(parent_stream),
            ExecutorResponse::RequestErr { message, .. } => {
                Err(anyhow!("executor failed to start SFTP session: {message}"))
            }
            other => Err(anyhow!(
                "unexpected executor response to SFTP request: {other:?}"
            )),
        }
    }

    pub async fn connect_tcp(&self, host: String, port: u16) -> Result<ServiceStream> {
        let (parent_stream, child_fd) = unix_service_channel()?;
        let request_id = self.inner.next_request_id();
        let response = self
            .inner
            .request(
                ExecutorRequest::ConnectTcp {
                    request_id,
                    host,
                    port,
                },
                Some(child_fd),
            )
            .await?;
        match response {
            ExecutorResponse::RequestOk { .. } => Ok(parent_stream),
            ExecutorResponse::RequestErr { message, .. } => Err(anyhow!(
                "executor failed to connect outbound TCP stream: {message}"
            )),
            other => Err(anyhow!(
                "unexpected executor response to direct-tcpip request: {other:?}"
            )),
        }
    }

    pub async fn start_remote_forward(
        &self,
        session_handle: server::Handle,
        connected_address: String,
        bind_address: String,
        bind_port: u16,
    ) -> Result<StartedRemoteForward> {
        let request_id = self.inner.next_request_id();
        let token = self.inner.next_forward_token();
        let response = self
            .inner
            .request(
                ExecutorRequest::StartRemoteForward {
                    request_id,
                    token,
                    bind_address,
                    bind_port,
                },
                None,
            )
            .await?;

        match response {
            ExecutorResponse::RequestOk {
                detail: ResponseDetail::BoundPort(bound_port),
                ..
            } => {
                let registration = RemoteForwardRegistration {
                    session_handle,
                    connected_address,
                    connected_port: u32::from(bound_port),
                };
                self.inner
                    .remote_forwards
                    .lock()
                    .unwrap()
                    .insert(token, registration);
                Ok(StartedRemoteForward {
                    token,
                    bound_port: u32::from(bound_port),
                })
            }
            ExecutorResponse::RequestErr { message, .. } => {
                Err(anyhow!("executor failed to bind remote forward: {message}"))
            }
            other => Err(anyhow!(
                "unexpected executor response to remote-forward request: {other:?}"
            )),
        }
    }

    pub async fn cancel_remote_forward(&self, token: u64) -> Result<()> {
        self.inner.remote_forwards.lock().unwrap().remove(&token);
        let request_id = self.inner.next_request_id();
        let response = self
            .inner
            .request(
                ExecutorRequest::CancelRemoteForward { request_id, token },
                None,
            )
            .await?;
        match response {
            ExecutorResponse::RequestOk { .. } => Ok(()),
            ExecutorResponse::RequestErr { message, .. } => Err(anyhow!(
                "executor failed to cancel remote forward: {message}"
            )),
            other => Err(anyhow!(
                "unexpected executor response to cancel-remote-forward request: {other:?}"
            )),
        }
    }
}

#[cfg(unix)]
impl ExecutorClientInner {
    fn next_request_id(&self) -> u64 {
        self.next_request_id.fetch_add(1, Ordering::Relaxed)
    }

    fn next_forward_token(&self) -> u64 {
        self.next_forward_token.fetch_add(1, Ordering::Relaxed)
    }

    async fn request(
        &self,
        request: ExecutorRequest,
        attached_fd: Option<OwnedFd>,
    ) -> Result<ExecutorResponse> {
        let request_id = request_id(&request)
            .ok_or_else(|| anyhow!("executor request does not carry a request id"))?;
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(request_id, tx);

        if let Err(err) = self.writer.lock().unwrap().send(&request, attached_fd) {
            self.pending.lock().unwrap().remove(&request_id);
            return Err(err);
        }

        rx.await
            .map_err(|_| anyhow!("executor control channel dropped the response"))
    }
}

#[cfg(unix)]
impl Drop for ExecutorClientInner {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.lock().unwrap().take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

// ─── Unix ExecutorState (runs inside the child executor process) ──────────────

#[cfg(unix)]
impl ExecutorState {
    fn hello(&self) -> Result<&ExecutorHello> {
        self.hello
            .as_ref()
            .ok_or_else(|| anyhow!("executor received a request before startup completed"))
    }

    fn send_response(
        &self,
        response: &ExecutorResponse,
        attached_fd: Option<OwnedFd>,
    ) -> Result<()> {
        self.writer.lock().unwrap().send(response, attached_fd)
    }

    fn send_request_result(&self, request_id: u64, result: Result<ResponseDetail>) -> Result<()> {
        match result {
            Ok(detail) => {
                self.send_response(&ExecutorResponse::RequestOk { request_id, detail }, None)
            }
            Err(err) => self.send_response(
                &ExecutorResponse::RequestErr {
                    request_id,
                    message: format!("{err:#}"),
                },
                None,
            ),
        }
    }

    async fn start_process(
        &self,
        request: ProcessRequest,
        attached_fd: Option<OwnedFd>,
    ) -> Result<()> {
        let hello = self.hello()?.clone();
        let Some(service_fd) = attached_fd else {
            anyhow::bail!("missing Unix service stream for process request");
        };
        let service_stream = unix_stream_from_fd(service_fd)?;

        if request.pty.is_some() {
            start_pty_process_service(hello, request, service_stream).await
        } else {
            start_piped_process_service(hello, request, service_stream).await
        }
    }

    async fn start_sftp(&self, attached_fd: Option<OwnedFd>) -> Result<()> {
        let hello = self.hello()?.clone();
        let Some(service_fd) = attached_fd else {
            anyhow::bail!("missing Unix service stream for SFTP request");
        };
        let stream = unix_stream_from_fd(service_fd)?;
        let sftp = LocalSftp::new(hello.home_dir);
        tokio::spawn(async move {
            russh_sftp::server::run(stream, sftp).await;
        });
        Ok(())
    }

    async fn connect_tcp(
        &self,
        host: String,
        port: u16,
        attached_fd: Option<OwnedFd>,
    ) -> Result<()> {
        let Some(service_fd) = attached_fd else {
            anyhow::bail!("missing Unix service stream for direct-tcpip request");
        };
        let stream = unix_stream_from_fd(service_fd)?;
        let target = TcpStream::connect((host.as_str(), port))
            .await
            .with_context(|| format!("failed to connect to {host}:{port}"))?;
        tokio::spawn(async move {
            if let Err(err) = proxy_byte_streams(stream, target).await {
                debug!("executor direct-tcpip proxy ended: {err:#}");
            }
        });
        Ok(())
    }

    async fn start_remote_forward(
        &mut self,
        token: u64,
        bind_address: String,
        bind_port: u16,
    ) -> Result<u16> {
        let listener = TcpListener::bind((bind_address.as_str(), bind_port))
            .await
            .with_context(|| format!("failed to bind remote forward {bind_address}:{bind_port}"))?;
        let bound_port = listener
            .local_addr()
            .context("failed to inspect remote-forward listener address")?
            .port();
        let writer = Arc::clone(&self.writer);

        let task = tokio::spawn(async move {
            loop {
                let (stream, origin) = match listener.accept().await {
                    Ok(accepted) => accepted,
                    Err(err) => {
                        debug!("executor remote-forward accept loop ended: {err}");
                        break;
                    }
                };

                let std_stream = match stream.into_std() {
                    Ok(stream) => stream,
                    Err(err) => {
                        debug!("failed to extract remote-forward socket fd: {err}");
                        continue;
                    }
                };
                let response = ExecutorResponse::RemoteForwardIncoming {
                    token,
                    originator_address: origin.ip().to_string(),
                    originator_port: u32::from(origin.port()),
                };
                let attached_fd: OwnedFd = std_stream.into();

                if let Err(err) = writer.lock().unwrap().send(&response, Some(attached_fd)) {
                    debug!("failed to report remote-forward connection to parent: {err:#}");
                    break;
                }
            }
        });

        if let Some(existing) = self.remote_forwards.insert(token, task) {
            existing.abort();
        }

        Ok(bound_port)
    }

    fn cancel_remote_forward(&mut self, token: u64) -> Result<()> {
        let Some(task) = self.remote_forwards.remove(&token) else {
            anyhow::bail!("unknown remote-forward token {token}");
        };
        task.abort();
        Ok(())
    }
}

// ─── Unix control channel recv/send ──────────────────────────────────────────

#[cfg(unix)]
impl ControlReader {
    fn recv<T>(&mut self) -> Result<TransportPacket<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        let mut buffer = vec![0_u8; MAX_CONTROL_MESSAGE_SIZE];
        let mut cmsg_space = cmsg_space!([RawFd; 8]);
        let mut iov = [IoSliceMut::new(&mut buffer)];
        let message = recvmsg::<()>(
            self.fd.as_raw_fd(),
            &mut iov,
            Some(&mut cmsg_space),
            MsgFlags::empty(),
        )
        .context("failed to receive executor control message")?;

        if message.bytes == 0 {
            anyhow::bail!("executor control channel reached EOF");
        }

        let mut attached_fd = None;
        let mut saw_extra_fd = false;
        let bytes_read = message.bytes;
        for cmsg in message
            .cmsgs()
            .context("failed to inspect executor control ancillary data")?
        {
            if let ControlMessageOwned::ScmRights(fds) = cmsg {
                for raw_fd in fds {
                    if attached_fd.is_none() {
                        attached_fd = Some(unsafe { OwnedFd::from_raw_fd(raw_fd) });
                    } else {
                        saw_extra_fd = true;
                        drop(unsafe { OwnedFd::from_raw_fd(raw_fd) });
                    }
                }
            }
        }
        let _ = message;

        if saw_extra_fd {
            anyhow::bail!("executor control message carried more than one attached fd");
        }

        let decoded = decode_message(
            &buffer[..bytes_read],
            "failed to decode executor control message",
        )?;

        Ok(TransportPacket {
            message: decoded,
            attached_fd,
        })
    }
}

#[cfg(unix)]
impl ControlWriter {
    fn send<T: Serialize>(&mut self, message: &T, attached_fd: Option<OwnedFd>) -> Result<()> {
        let payload = encode_message(message, "failed to encode executor control message")?;
        let iov = [IoSlice::new(&payload)];

        if let Some(fd) = attached_fd {
            let raw_fd = fd.as_raw_fd();
            let cmsgs = [ControlMessage::ScmRights(&[raw_fd])];
            sendmsg::<()>(self.fd.as_raw_fd(), &iov, &cmsgs, MsgFlags::empty(), None)
                .context("failed to send executor control message with fd")?;
        } else {
            sendmsg::<()>(self.fd.as_raw_fd(), &iov, &[], MsgFlags::empty(), None)
                .context("failed to send executor control message")?;
        }

        Ok(())
    }
}

// ─── Unix dispatch of incoming remote-forward connections ────────────────────

#[cfg(unix)]
async fn dispatch_remote_forward_event(
    inner: &ExecutorClientInner,
    event: RemoteForwardEvent,
) -> Result<()> {
    let registration = inner
        .remote_forwards
        .lock()
        .unwrap()
        .get(&event.token)
        .cloned()
        .ok_or_else(|| anyhow!("unknown remote-forward token {}", event.token))?;

    let stream = tcp_stream_from_fd(event.stream_fd)?;
    let channel = registration
        .session_handle
        .channel_open_forwarded_tcpip(
            registration.connected_address,
            registration.connected_port,
            event.originator_address,
            event.originator_port,
        )
        .await
        .context("failed to open forwarded-tcpip channel")?;

    tokio::spawn(async move {
        if let Err(err) = proxy_byte_streams(channel.into_stream(), stream).await {
            debug!("forwarded-tcpip proxy ended: {err:#}");
        }
    });

    Ok(())
}

// ─── Non-Unix (in-process) ExecutorClient ────────────────────────────────────
//
// On Windows (and any other non-Unix platform) there is no separate executor
// process.  Each service request spawns a Tokio task that runs the service
// function directly.  The "service stream" is an in-memory duplex channel.

#[cfg(not(unix))]
struct ExecutorClientInner {
    hello: ExecutorHello,
    next_forward_token: AtomicU64,
    remote_forward_regs: Mutex<HashMap<u64, RemoteForwardRegistration>>,
    remote_forwards: Mutex<HashMap<u64, tokio::task::JoinHandle<()>>>,
}

#[cfg(not(unix))]
#[derive(Clone)]
struct RemoteForwardRegistration {
    session_handle: server::Handle,
    connected_address: String,
    connected_port: u32,
}

#[cfg(not(unix))]
impl ExecutorClient {
    pub fn spawn(
        shell: PathBuf,
        exec_mode: ExecMode,
        home_dir: PathBuf,
        _program_override: Option<OsString>,
    ) -> Result<Self> {
        Ok(Self {
            inner: Arc::new(ExecutorClientInner {
                hello: ExecutorHello {
                    shell,
                    home_dir,
                    exec_mode,
                },
                next_forward_token: AtomicU64::new(1),
                remote_forward_regs: Mutex::new(HashMap::new()),
                remote_forwards: Mutex::new(HashMap::new()),
            }),
        })
    }

    #[cfg(test)]
    pub fn inert_for_tests() -> Result<Self> {
        Ok(Self {
            inner: Arc::new(ExecutorClientInner {
                hello: ExecutorHello {
                    home_dir: std::env::temp_dir(),
                    shell: PathBuf::from("cmd.exe"),
                    exec_mode: ExecMode::Cmd,
                },
                next_forward_token: AtomicU64::new(1),
                remote_forward_regs: Mutex::new(HashMap::new()),
                remote_forwards: Mutex::new(HashMap::new()),
            }),
        })
    }

    pub async fn start_process(&self, request: ProcessRequest) -> Result<ServiceStream> {
        let (parent, child) = tokio::io::duplex(MAX_SESSION_MESSAGE_SIZE);
        let hello = self.inner.hello.clone();
        tokio::spawn(async move {
            let result = if request.pty.is_some() {
                start_pty_process_service(hello, request, child).await
            } else {
                start_piped_process_service(hello, request, child).await
            };
            if let Err(err) = result {
                debug!("process service ended: {err:#}");
            }
        });
        Ok(parent)
    }

    pub async fn start_sftp(&self) -> Result<ServiceStream> {
        let (parent, child) = tokio::io::duplex(MAX_SESSION_MESSAGE_SIZE);
        let home_dir = self.inner.hello.home_dir.clone();
        tokio::spawn(async move {
            let sftp = LocalSftp::new(home_dir);
            russh_sftp::server::run(child, sftp).await;
        });
        Ok(parent)
    }

    pub async fn connect_tcp(&self, host: String, port: u16) -> Result<ServiceStream> {
        let target = TcpStream::connect((host.as_str(), port))
            .await
            .with_context(|| format!("failed to connect to {host}:{port}"))?;
        let (parent, child) = tokio::io::duplex(MAX_SESSION_MESSAGE_SIZE);
        tokio::spawn(async move {
            if let Err(err) = proxy_byte_streams(child, target).await {
                debug!("direct-tcpip proxy ended: {err:#}");
            }
        });
        Ok(parent)
    }

    pub async fn start_remote_forward(
        &self,
        session_handle: server::Handle,
        connected_address: String,
        bind_address: String,
        bind_port: u16,
    ) -> Result<StartedRemoteForward> {
        let token = self
            .inner
            .next_forward_token
            .fetch_add(1, Ordering::Relaxed);
        let listener = TcpListener::bind((bind_address.as_str(), bind_port))
            .await
            .with_context(|| format!("failed to bind remote forward {bind_address}:{bind_port}"))?;
        let bound_port = listener
            .local_addr()
            .context("failed to inspect remote-forward listener address")?
            .port();

        let reg = RemoteForwardRegistration {
            session_handle,
            connected_address,
            connected_port: u32::from(bound_port),
        };
        self.inner
            .remote_forward_regs
            .lock()
            .unwrap()
            .insert(token, reg);

        let inner = Arc::clone(&self.inner);
        let task = tokio::spawn(async move {
            loop {
                let (stream, origin) = match listener.accept().await {
                    Ok(a) => a,
                    Err(err) => {
                        debug!("remote-forward accept ended: {err}");
                        break;
                    }
                };
                let reg = match inner
                    .remote_forward_regs
                    .lock()
                    .unwrap()
                    .get(&token)
                    .cloned()
                {
                    Some(r) => r,
                    None => break,
                };
                tokio::spawn(async move {
                    let channel: russh::Channel<russh::server::Msg> = match reg
                        .session_handle
                        .channel_open_forwarded_tcpip(
                            reg.connected_address,
                            reg.connected_port,
                            origin.ip().to_string(),
                            u32::from(origin.port()),
                        )
                        .await
                    {
                        Ok(c) => c,
                        Err(err) => {
                            debug!("failed to open forwarded-tcpip channel: {err}");
                            return;
                        }
                    };
                    if let Err(err) = proxy_byte_streams(channel.into_stream(), stream).await {
                        debug!("forwarded-tcpip proxy ended: {err:#}");
                    }
                });
            }
        });

        self.inner
            .remote_forwards
            .lock()
            .unwrap()
            .insert(token, task);

        Ok(StartedRemoteForward {
            token,
            bound_port: u32::from(bound_port),
        })
    }

    pub async fn cancel_remote_forward(&self, token: u64) -> Result<()> {
        self.inner
            .remote_forward_regs
            .lock()
            .unwrap()
            .remove(&token);
        if let Some(task) = self.inner.remote_forwards.lock().unwrap().remove(&token) {
            task.abort();
        }
        Ok(())
    }
}

// ─── Service functions (shared between Unix executor process and Windows) ─────

async fn start_pty_process_service<S>(
    hello: ExecutorHello,
    request: ProcessRequest,
    stream: S,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let pty = request
        .pty
        .clone()
        .ok_or_else(|| anyhow!("PTY process request missing PTY settings"))?;
    let shell = hello.shell.clone();
    let cwd = hello.home_dir.clone();
    let env = request.env.clone();
    let command = request.command.clone();

    let mut launch = tokio::task::spawn_blocking(move || -> Result<PtyLaunch> {
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(pty.size.into())
            .context("failed to open PTY")?;

        let mut builder = CommandBuilder::new(&shell);
        builder.cwd(&cwd);
        for (key, value) in env {
            builder.env(key, value);
        }
        if let Some(command) = command {
            builder.arg(hello.exec_mode.command_flag());
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
        #[cfg(unix)]
        let process_group = pair.master.process_group_leader();
        #[cfg(not(unix))]
        let process_group: Option<i32> = None;

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

    let (mut stream_read, mut stream_write) = tokio::io::split(stream);
    let (output_tx, mut output_rx) = mpsc::unbounded_channel::<ProcessOutput>();
    let (exit_tx, mut exit_rx) = oneshot::channel::<u32>();
    let (control_tx, control_rx) = std_mpsc::channel::<PtyControl>();
    let control_close_tx = control_tx.clone();

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
        let mut input_task = Some(tokio::spawn(async move {
            let _ = handle_pty_service_input(&mut stream_read, control_tx).await;
        }));

        let mut child_exit = None;
        let mut output_closed = false;

        loop {
            #[cfg(windows)]
            if child_exit.is_some() {
                break;
            }

            #[cfg(not(windows))]
            if output_closed && child_exit.is_some() {
                break;
            }

            tokio::select! {
                maybe_output = output_rx.recv(), if !output_closed => {
                    match maybe_output {
                        Some(output) => {
                            if send_session_message(&mut stream_write, &output).await.is_err() {
                                break;
                            }
                        }
                        None => output_closed = true,
                    }
                }
                result = &mut exit_rx, if child_exit.is_none() => {
                    child_exit = Some(result.unwrap_or(255));
                    // Windows pseudocon output can stay open after the shell exits.
                    // Closing the PTY control side here lets the reader unwind so
                    // the SSH session can deliver exit-status/close promptly.
                    let _ = control_close_tx.send(PtyControl::Close);
                    if let Some(task) = input_task.take() {
                        task.abort();
                        let _ = task.await;
                    }
                }
            }
        }

        if let Some(code) = child_exit {
            let _ = send_session_message(&mut stream_write, &ProcessOutput::ExitStatus(code)).await;
        }
        let _ = stream_write.shutdown().await;
        if let Some(task) = input_task.take() {
            task.abort();
            let _ = task.await;
        }
    });

    Ok(())
}

async fn start_piped_process_service<S>(
    hello: ExecutorHello,
    request: ProcessRequest,
    stream: S,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut process = Command::new(&hello.shell);
    process.current_dir(&hello.home_dir);
    process.stdin(Stdio::piped());
    process.stdout(Stdio::piped());
    process.stderr(Stdio::piped());
    process.kill_on_drop(true);

    for (key, value) in request.env {
        process.env(key, value);
    }

    if let Some(command) = request.command {
        process.arg(hello.exec_mode.command_flag());
        process.arg(command);
    }

    let mut child = process.spawn().context("failed to spawn child process")?;
    let pid = child.id().context("child process has no pid")?;
    let stdin = child.stdin.take().context("missing child stdin")?;
    let stdout = child.stdout.take().context("missing child stdout")?;
    let stderr = child.stderr.take().context("missing child stderr")?;
    let (mut stream_read, mut stream_write) = tokio::io::split(stream);
    let (output_tx, mut output_rx) = mpsc::unbounded_channel::<ProcessOutput>();
    let (exit_tx, mut exit_rx) = oneshot::channel::<u32>();

    // On non-Unix we use a kill channel to signal the wait task because we
    // can't send POSIX signals directly.
    let (kill_tx, mut kill_rx) = mpsc::channel::<()>(1);
    let input_kill_tx = kill_tx.clone();
    let outer_kill_tx = kill_tx;

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
        tokio::select! {
            result = child.wait() => {
                let code = result.map(exit_status_code).unwrap_or(255);
                let _ = exit_tx.send(code);
            }
            _ = kill_rx.recv() => {
                let _ = child.start_kill();
                let code = child.wait().await.map(exit_status_code).unwrap_or(255);
                let _ = exit_tx.send(code);
            }
        }
    });

    tokio::spawn(async move {
        let input_task = tokio::spawn(async move {
            let _ = handle_piped_service_input(pid, input_kill_tx, &mut stream_read, stdin).await;
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
                        Some(output) => {
                            if send_session_message(&mut stream_write, &output).await.is_err() {
                                #[cfg(unix)]
                                let _ = send_signal_to_pid(pid, Signal::SIGKILL);
                                #[cfg(not(unix))]
                                let _ = outer_kill_tx.try_send(());
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
            let _ = send_session_message(&mut stream_write, &ProcessOutput::ExitStatus(code)).await;
        }
        let _ = stream_write.shutdown().await;
        input_task.abort();
        let _ = input_task.await;
    });

    Ok(())
}

async fn handle_pty_service_input<R>(
    reader: &mut R,
    control_tx: std_mpsc::Sender<PtyControl>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    while let Some(message) = read_session_message(reader).await? {
        match message {
            ProcessInput::Data(data) => {
                if control_tx.send(PtyControl::Write(data)).is_err() {
                    break;
                }
            }
            ProcessInput::Signal(signal) => {
                let _ = control_tx.send(PtyControl::Signal(signal));
            }
            ProcessInput::Resize(size) => {
                let _ = control_tx.send(PtyControl::Resize(size.into()));
            }
            ProcessInput::Eof => {
                let _ = control_tx.send(PtyControl::Eof);
            }
            ProcessInput::Close => {
                let _ = control_tx.send(PtyControl::Close);
                break;
            }
        }
    }

    let _ = control_tx.send(PtyControl::Close);
    Ok(())
}

async fn handle_piped_service_input<R>(
    pid: u32,
    kill_tx: mpsc::Sender<()>,
    reader: &mut R,
    mut stdin: ChildStdin,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    while let Some(message) = read_session_message(reader).await? {
        match message {
            ProcessInput::Data(data) => {
                if stdin.write_all(&data).await.is_err() {
                    break;
                }
            }
            ProcessInput::Signal(signal) => {
                #[cfg(unix)]
                let _ = send_signal_to_pid(pid, signal.into());
                #[cfg(not(unix))]
                let _ = (pid, signal); // signals are not supported on non-Unix
            }
            ProcessInput::Eof => {
                let _ = stdin.shutdown().await;
            }
            ProcessInput::Close => {
                #[cfg(unix)]
                let _ = send_signal_to_pid(pid, Signal::SIGKILL);
                #[cfg(not(unix))]
                let _ = kill_tx.try_send(());
                break;
            }
            ProcessInput::Resize(_) => {}
        }
    }

    let _ = stdin.shutdown().await;
    Ok(())
}

async fn read_session_message<R, T>(reader: &mut R) -> Result<Option<T>>
where
    R: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let length = match reader.read_u32().await {
        Ok(length) => length as usize,
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err).context("failed to read session message length"),
    };

    if length > MAX_SESSION_MESSAGE_SIZE {
        anyhow::bail!("session message length {length} exceeds the maximum supported size");
    }

    let mut buffer = vec![0_u8; length];
    reader
        .read_exact(&mut buffer)
        .await
        .context("failed to read session message body")?;
    let message = decode_message(&buffer, "failed to decode session message")?;
    Ok(Some(message))
}

async fn send_session_message<W, T>(writer: &mut W, message: &T) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let payload = encode_message(message, "failed to encode session message")?;
    let length = u32::try_from(payload.len()).context("session message too large")?;
    writer.write_u32(length).await?;
    writer.write_all(&payload).await?;
    Ok(())
}

fn read_process_stream<R>(
    mut stream: R,
    which: ProcessStream,
    output_tx: mpsc::UnboundedSender<ProcessOutput>,
) -> impl std::future::Future<Output = ()> + Send + 'static
where
    R: AsyncRead + Unpin + Send + 'static,
{
    async move {
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
}

fn run_pty_reader(
    mut reader: Box<dyn Read + Send>,
    output_tx: mpsc::UnboundedSender<ProcessOutput>,
) {
    let mut buffer = vec![0_u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                if output_tx
                    .send(ProcessOutput::Stdout(buffer[..read].to_vec()))
                    .is_err()
                {
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
                if let Some(writer) = writer.as_mut()
                    && (writer.write_all(&data).is_err() || writer.flush().is_err())
                {
                    break;
                }
            }
            PtyControl::Resize(size) => {
                let _ = master.resize(size);
            }
            PtyControl::Signal(signal) => {
                #[cfg(unix)]
                if let Some(group) = process_group {
                    let _ = send_signal_to_process_group(group, signal.into());
                }
                #[cfg(not(unix))]
                let _ = (process_group, signal); // POSIX signals not supported on non-Unix
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

async fn proxy_byte_streams<A, B>(mut left: A, mut right: B) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional(&mut left, &mut right)
        .await
        .map(|_| ())
        .map_err(Into::into)
}

// ─── Unix-only helper functions ───────────────────────────────────────────────

#[cfg(unix)]
fn unix_service_channel() -> Result<(UnixStream, OwnedFd)> {
    let (parent, child) = StdUnixStream::pair().context("failed to create Unix service stream")?;
    let parent = unix_stream_from_std(parent)?;
    Ok((parent, child.into()))
}

#[cfg(unix)]
fn set_cloexec(fd: &OwnedFd) -> Result<()> {
    let current_flags =
        fcntl(fd, FcntlArg::F_GETFD).context("failed to read socket close-on-exec flags")?;
    let updated_flags = FdFlag::from_bits_truncate(current_flags) | FdFlag::FD_CLOEXEC;
    fcntl(fd, FcntlArg::F_SETFD(updated_flags))
        .context("failed to set socket close-on-exec flag")?;
    Ok(())
}

#[cfg(unix)]
fn unix_stream_from_fd(fd: OwnedFd) -> Result<UnixStream> {
    let stream = StdUnixStream::from(fd);
    unix_stream_from_std(stream)
}

#[cfg(unix)]
fn unix_stream_from_std(stream: StdUnixStream) -> Result<UnixStream> {
    stream
        .set_nonblocking(true)
        .context("failed to mark Unix stream non-blocking")?;
    UnixStream::from_std(stream).context("failed to adopt Unix stream into Tokio")
}

#[cfg(unix)]
fn tcp_stream_from_fd(fd: OwnedFd) -> Result<TcpStream> {
    let stream = std::net::TcpStream::from(fd);
    stream
        .set_nonblocking(true)
        .context("failed to mark TCP stream non-blocking")?;
    TcpStream::from_std(stream).context("failed to adopt TCP stream into Tokio")
}

// ─── Signal mapping (Unix-only) ───────────────────────────────────────────────

#[cfg(unix)]
impl From<ExecutorSignal> for Signal {
    fn from(value: ExecutorSignal) -> Self {
        match value {
            ExecutorSignal::Abrt => Signal::SIGABRT,
            ExecutorSignal::Alrm => Signal::SIGALRM,
            ExecutorSignal::Fpe => Signal::SIGFPE,
            ExecutorSignal::Hup => Signal::SIGHUP,
            ExecutorSignal::Ill => Signal::SIGILL,
            ExecutorSignal::Int => Signal::SIGINT,
            ExecutorSignal::Kill => Signal::SIGKILL,
            ExecutorSignal::Pipe => Signal::SIGPIPE,
            ExecutorSignal::Quit => Signal::SIGQUIT,
            ExecutorSignal::Segv => Signal::SIGSEGV,
            ExecutorSignal::Term => Signal::SIGTERM,
            ExecutorSignal::Usr1 => Signal::SIGUSR1,
        }
    }
}

pub fn map_signal(signal: &Sig) -> Option<ExecutorSignal> {
    match signal {
        Sig::ABRT => Some(ExecutorSignal::Abrt),
        Sig::ALRM => Some(ExecutorSignal::Alrm),
        Sig::FPE => Some(ExecutorSignal::Fpe),
        Sig::HUP => Some(ExecutorSignal::Hup),
        Sig::ILL => Some(ExecutorSignal::Ill),
        Sig::INT => Some(ExecutorSignal::Int),
        Sig::KILL => Some(ExecutorSignal::Kill),
        Sig::PIPE => Some(ExecutorSignal::Pipe),
        Sig::QUIT => Some(ExecutorSignal::Quit),
        Sig::SEGV => Some(ExecutorSignal::Segv),
        Sig::TERM => Some(ExecutorSignal::Term),
        Sig::USR1 => Some(ExecutorSignal::Usr1),
        Sig::Custom(_) => None,
    }
}

#[cfg(unix)]
fn send_signal_to_pid(pid: u32, signal: Signal) -> Result<()> {
    let pid = i32::try_from(pid).context("child pid too large")?;
    kill(Pid::from_raw(pid), signal).context("failed to signal child")
}

#[cfg(unix)]
fn send_signal_to_process_group(group: i32, signal: Signal) -> Result<()> {
    killpg(Pid::from_raw(group), signal).context("failed to signal child process group")
}

// ─── Exit status helper ───────────────────────────────────────────────────────

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

// ─── Misc helpers ─────────────────────────────────────────────────────────────

#[cfg(unix)]
fn executor_program(program_override: Option<OsString>) -> Result<OsString> {
    if let Some(program) = program_override {
        return Ok(program);
    }

    std::env::current_exe()
        .map(|path| path.into_os_string())
        .context("failed to resolve current executable for executor spawn")
}

#[cfg(unix)]
fn request_id(request: &ExecutorRequest) -> Option<u64> {
    match request {
        ExecutorRequest::Hello(_) => None,
        ExecutorRequest::StartProcess { request_id, .. }
        | ExecutorRequest::StartSftp { request_id }
        | ExecutorRequest::ConnectTcp { request_id, .. }
        | ExecutorRequest::StartRemoteForward { request_id, .. }
        | ExecutorRequest::CancelRemoteForward { request_id, .. } => Some(*request_id),
    }
}

// ─── Internal types ───────────────────────────────────────────────────────────

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
    Signal(ExecutorSignal),
    Eof,
    Close,
}

enum ProcessStream {
    Stdout,
    Stderr,
}

impl From<SerializablePtySize> for PtySize {
    fn from(value: SerializablePtySize) -> Self {
        Self {
            rows: value.rows,
            cols: value.cols,
            pixel_width: value.pixel_width,
            pixel_height: value.pixel_height,
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[cfg(unix)]
    use std::fs::File;

    #[cfg(unix)]
    #[test]
    fn rejects_control_messages_with_multiple_attached_fds() {
        let (read_fd, write_fd) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::empty(),
        )
        .unwrap();
        let mut reader = ControlReader { fd: read_fd };

        let first = File::open("/dev/null").unwrap();
        let second = File::open("/dev/null").unwrap();
        let payload = encode_message(
            &ExecutorRequest::Hello(ExecutorHello {
                home_dir: PathBuf::from("/tmp"),
                shell: PathBuf::from("/bin/bash"),
                exec_mode: ExecMode::ShellLogin,
            }),
            "failed to encode executor control message",
        )
        .unwrap();
        let iov = [IoSlice::new(&payload)];
        let rights = [first.as_raw_fd(), second.as_raw_fd()];
        let cmsgs = [ControlMessage::ScmRights(&rights)];

        sendmsg::<()>(write_fd.as_raw_fd(), &iov, &cmsgs, MsgFlags::empty(), None).unwrap();

        match reader.recv::<ExecutorRequest>() {
            Ok(_) => panic!("control message with multiple attached fds unexpectedly succeeded"),
            Err(err) => assert!(err.to_string().contains("more than one attached fd")),
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_child_pids_that_do_not_fit_i32() {
        let err = send_signal_to_pid(i32::MAX as u32 + 1, Signal::SIGTERM).unwrap_err();
        assert!(err.to_string().contains("child pid too large"));
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use tokio::time::{Duration, timeout};

    fn windows_whoami_path() -> PathBuf {
        if let Ok(system_root) = std::env::var("SystemRoot") {
            let path = PathBuf::from(system_root).join("System32\\whoami.exe");
            if path.exists() {
                return path;
            }
        }

        PathBuf::from("whoami.exe")
    }

    fn windows_powershell_path() -> PathBuf {
        if let Ok(system_root) = std::env::var("SystemRoot") {
            let path = PathBuf::from(system_root)
                .join("System32\\WindowsPowerShell\\v1.0\\powershell.exe");
            if path.exists() {
                return path;
            }
        }

        PathBuf::from("powershell.exe")
    }

    #[tokio::test]
    async fn pty_process_exit_reports_status_and_closes_stream() {
        let (mut client_stream, service_stream) = tokio::io::duplex(MAX_SESSION_MESSAGE_SIZE);
        let hello = ExecutorHello {
            home_dir: dirs::home_dir().unwrap(),
            shell: windows_whoami_path(),
            exec_mode: ExecMode::ShellCommand,
        };
        let request = ProcessRequest {
            pty: Some(SerializablePtyRequest {
                term: "xterm-256color".to_string(),
                size: SerializablePtySize {
                    rows: 24,
                    cols: 80,
                    pixel_width: 0,
                    pixel_height: 0,
                },
            }),
            env: BTreeMap::new(),
            command: None,
        };

        start_pty_process_service(hello, request, service_stream)
            .await
            .unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        let mut outputs = Vec::new();
        let mut saw_eof = false;

        while tokio::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            match timeout(
                remaining.min(Duration::from_secs(2)),
                read_session_message::<_, ProcessOutput>(&mut client_stream),
            )
            .await
            {
                Ok(Ok(Some(message))) => {
                    if let ProcessOutput::Stdout(data) = &message
                        && data.windows(4).any(|window| window == b"\x1b[6n")
                    {
                        send_session_message(
                            &mut client_stream,
                            &ProcessInput::Data(b"\x1b[1;1R".to_vec()),
                        )
                        .await
                        .unwrap();
                    }
                    outputs.push(message);
                }
                Ok(Ok(None)) => {
                    saw_eof = true;
                    break;
                }
                Ok(Err(err)) => panic!("failed to read PTY process output: {err:#}"),
                Err(_) => continue,
            }
        }

        assert!(
            saw_eof,
            "PTY process did not close the service stream after exit; received outputs: {outputs:?}"
        );

        assert!(
            outputs
                .iter()
                .any(|message| matches!(message, ProcessOutput::ExitStatus(0))),
            "expected PTY process to report exit status 0, got {outputs:?}"
        );
    }

    #[tokio::test]
    async fn powershell_exec_mode_runs_exec_requests() {
        let (mut client_stream, service_stream) = tokio::io::duplex(MAX_SESSION_MESSAGE_SIZE);
        let hello = ExecutorHello {
            home_dir: dirs::home_dir().unwrap(),
            shell: windows_powershell_path(),
            exec_mode: ExecMode::PowerShell,
        };
        let request = ProcessRequest {
            pty: None,
            env: BTreeMap::new(),
            command: Some("cmd /c echo executor-ok".to_string()),
        };

        start_piped_process_service(hello, request, service_stream)
            .await
            .unwrap();

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_status = None;

        while let Some(message) = read_session_message::<_, ProcessOutput>(&mut client_stream)
            .await
            .unwrap()
        {
            match message {
                ProcessOutput::Stdout(data) => stdout.extend_from_slice(&data),
                ProcessOutput::Stderr(data) => stderr.extend_from_slice(&data),
                ProcessOutput::ExitStatus(code) => exit_status = Some(code),
            }
        }

        assert_eq!(exit_status, Some(0));
        assert_eq!(String::from_utf8(stdout).unwrap(), "executor-ok\r\n");
        assert!(stderr.is_empty(), "unexpected stderr: {stderr:?}");
    }
}
