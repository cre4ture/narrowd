use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::io::{IoSlice, IoSliceMut, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command as StdCommand, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc as std_mpsc};
use std::thread;

use anyhow::{Context, Result, anyhow};
use log::{debug, warn};
use nix::cmsg_space;
use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use nix::libc;
use nix::sys::signal::{Signal, kill, killpg};
use nix::sys::socket::{
    AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType, recvmsg,
    sendmsg, socketpair,
};
use nix::unistd::{Pid, dup};
use portable_pty::{
    Child as PtyChild, ChildKiller, CommandBuilder, MasterPty, PtySize, native_pty_system,
};
use russh::Sig;
use russh::server;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::process::{ChildStdin, Command};
use tokio::sync::{mpsc, oneshot};

use crate::sftp::LocalSftp;

const CONTROL_FD: RawFd = 3;
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

struct ExecutorClientInner {
    writer: Mutex<ControlWriter>,
    pending: Mutex<HashMap<u64, oneshot::Sender<ExecutorResponse>>>,
    remote_forwards: Mutex<HashMap<u64, RemoteForwardRegistration>>,
    next_request_id: AtomicU64,
    next_forward_token: AtomicU64,
    child: Mutex<Option<Child>>,
}

#[derive(Clone)]
struct RemoteForwardRegistration {
    session_handle: server::Handle,
    connected_address: String,
    connected_port: u32,
}

pub struct StartedRemoteForward {
    pub token: u64,
    pub bound_port: u32,
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

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
enum ResponseDetail {
    Empty,
    BoundPort(u16),
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
}

struct ControlReader {
    fd: OwnedFd,
}

struct ControlWriter {
    fd: OwnedFd,
}

struct TransportPacket<T> {
    message: T,
    attached_fd: Option<OwnedFd>,
}

struct RemoteForwardEvent {
    token: u64,
    originator_address: String,
    originator_port: u32,
    stream_fd: OwnedFd,
}

struct ExecutorState {
    writer: Arc<Mutex<ControlWriter>>,
    hello: Option<ExecutorHello>,
    remote_forwards: HashMap<u64, tokio::task::JoinHandle<()>>,
}

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

impl ExecutorClient {
    pub fn spawn(shell: PathBuf, home_dir: PathBuf) -> Result<Self> {
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
        let mut command = StdCommand::new(executor_program()?);
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
            &ExecutorRequest::Hello(ExecutorHello { home_dir, shell }),
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
        thread::spawn(move || {
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

    pub async fn start_process(&self, request: ProcessRequest) -> Result<UnixStream> {
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

    pub async fn start_sftp(&self) -> Result<UnixStream> {
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

    pub async fn connect_tcp(&self, host: String, port: u16) -> Result<UnixStream> {
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

impl Drop for ExecutorClientInner {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.lock().unwrap().take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

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

async fn start_pty_process_service(
    hello: ExecutorHello,
    request: ProcessRequest,
    stream: UnixStream,
) -> Result<()> {
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

    let (mut stream_read, mut stream_write) = tokio::io::split(stream);
    let (output_tx, mut output_rx) = mpsc::unbounded_channel::<ProcessOutput>();
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
            let _ = handle_pty_service_input(&mut stream_read, control_tx).await;
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

async fn start_piped_process_service(
    hello: ExecutorHello,
    request: ProcessRequest,
    stream: UnixStream,
) -> Result<()> {
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
        process.arg("-lc");
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
            let _ = handle_piped_service_input(pid, &mut stream_read, stdin).await;
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
                let _ = send_signal_to_pid(pid, signal.into());
            }
            ProcessInput::Eof => {
                let _ = stdin.shutdown().await;
            }
            ProcessInput::Close => {
                let _ = send_signal_to_pid(pid, Signal::SIGKILL);
                break;
            }
            ProcessInput::Resize(_) => {}
        }
    }

    let _ = stdin.shutdown().await;
    Ok(())
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
                if let Some(group) = process_group {
                    let _ = send_signal_to_process_group(group, signal.into());
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

fn unix_service_channel() -> Result<(UnixStream, OwnedFd)> {
    let (parent, child) = StdUnixStream::pair().context("failed to create Unix service stream")?;
    let parent = unix_stream_from_std(parent)?;
    Ok((parent, child.into()))
}

fn set_cloexec(fd: &OwnedFd) -> Result<()> {
    let current_flags =
        fcntl(fd, FcntlArg::F_GETFD).context("failed to read socket close-on-exec flags")?;
    let updated_flags = FdFlag::from_bits_truncate(current_flags) | FdFlag::FD_CLOEXEC;
    fcntl(fd, FcntlArg::F_SETFD(updated_flags))
        .context("failed to set socket close-on-exec flag")?;
    Ok(())
}

fn unix_stream_from_fd(fd: OwnedFd) -> Result<UnixStream> {
    let stream = StdUnixStream::from(fd);
    unix_stream_from_std(stream)
}

fn unix_stream_from_std(stream: StdUnixStream) -> Result<UnixStream> {
    stream
        .set_nonblocking(true)
        .context("failed to mark Unix stream non-blocking")?;
    UnixStream::from_std(stream).context("failed to adopt Unix stream into Tokio")
}

fn tcp_stream_from_fd(fd: OwnedFd) -> Result<TcpStream> {
    let stream = std::net::TcpStream::from(fd);
    stream
        .set_nonblocking(true)
        .context("failed to mark TCP stream non-blocking")?;
    TcpStream::from_std(stream).context("failed to adopt TCP stream into Tokio")
}

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

fn executor_program() -> Result<OsString> {
    if let Some(program) = std::env::var_os("NARROWD_EXECUTOR_PROGRAM") {
        return Ok(program);
    }

    if let Some(program) = std::env::var_os("CARGO_BIN_EXE_narrowd") {
        return Ok(program);
    }

    std::env::current_exe()
        .map(|path| path.into_os_string())
        .context("failed to resolve current executable for executor spawn")
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

fn send_signal_to_pid(pid: u32, signal: Signal) -> Result<()> {
    let pid = i32::try_from(pid).context("child pid too large")?;
    kill(Pid::from_raw(pid), signal).context("failed to signal child")
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;

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

    #[test]
    fn rejects_child_pids_that_do_not_fit_i32() {
        let err = send_signal_to_pid(i32::MAX as u32 + 1, Signal::SIGTERM).unwrap_err();
        assert!(err.to_string().contains("child pid too large"));
    }
}
