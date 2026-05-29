use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use getrandom::rand_core::UnwrapErr;
use narrowd::config::AppConfig;
use narrowd::sshd;
use nix::unistd::{User, getuid};
use russh::client;
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, ssh_key};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep, timeout};

struct AcceptAnyServerKey;

impl client::Handler for AcceptAnyServerKey {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[tokio::test]
async fn closes_silent_clients_after_banner_timeout() -> Result<()> {
    let tempdir = TempDir::new()?;
    let config = test_config(&tempdir, "", |config| {
        config.client_banner_timeout = Duration::from_millis(150);
        config.login_grace_time = Duration::from_millis(600);
    })?;
    let (addr, task) = spawn_server(config).await?;

    let mut stream = TcpStream::connect(addr).await?;
    let banner = read_banner(&mut stream).await?;
    assert!(banner.starts_with(b"SSH-2.0-"));

    sleep(Duration::from_millis(250)).await;
    wait_for_close(&mut stream, Duration::from_millis(400)).await?;

    task.abort();
    Ok(())
}

#[tokio::test]
async fn closes_banner_only_clients_after_login_grace_time() -> Result<()> {
    let tempdir = TempDir::new()?;
    let config = test_config(&tempdir, "", |config| {
        config.client_banner_timeout = Duration::from_millis(500);
        config.login_grace_time = Duration::from_millis(200);
    })?;
    let (addr, task) = spawn_server(config).await?;

    let mut stream = TcpStream::connect(addr).await?;
    let _banner = read_banner(&mut stream).await?;
    stream.write_all(b"SSH-2.0-test-client\r\n").await?;

    // Allow the server to advance into KEX before we wait for the hard pre-auth deadline.
    let _ = read_some(&mut stream, Duration::from_millis(100)).await;

    sleep(Duration::from_millis(250)).await;
    wait_for_close(&mut stream, Duration::from_millis(400)).await?;

    task.abort();
    Ok(())
}

#[tokio::test]
async fn authenticated_sessions_release_unauth_slots() -> Result<()> {
    let tempdir = TempDir::new()?;
    let client_key = Arc::new(generate_ed25519_key()?);
    let authorized_keys = format!("{}\n", client_key.public_key().to_openssh()?);
    let config = test_config(&tempdir, &authorized_keys, |config| {
        config.max_unauth_connections_global = 1;
        config.max_unauth_connections_per_ip = 1;
        config.max_unauth_connections_per_subnet = 4;
        config.new_connections_per_minute_per_ip = 60;
        config.new_connections_burst_per_ip = 8;
        config.client_banner_timeout = Duration::from_millis(500);
        config.login_grace_time = Duration::from_secs(1);
    })?;
    let (addr, task) = spawn_server(config).await?;

    let mut session = connect_client(addr).await?;
    let auth = session
        .authenticate_publickey(
            &daemon_username()?,
            PrivateKeyWithHashAlg::new(Arc::clone(&client_key), None),
        )
        .await?;
    assert!(
        auth.success(),
        "expected successful public-key authentication"
    );

    let mut second = TcpStream::connect(addr).await?;
    let banner = read_banner(&mut second).await?;
    assert!(banner.starts_with(b"SSH-2.0-"));

    session
        .disconnect(russh::Disconnect::ByApplication, "", "")
        .await?;

    task.abort();
    Ok(())
}

#[tokio::test]
async fn rejects_connections_over_global_unauth_limit_before_banner() -> Result<()> {
    let tempdir = TempDir::new()?;
    let config = test_config(&tempdir, "", |config| {
        config.max_unauth_connections_global = 1;
        config.max_unauth_connections_per_ip = 4;
        config.max_unauth_connections_per_subnet = 8;
        config.new_connections_per_minute_per_ip = 60;
        config.new_connections_burst_per_ip = 8;
        config.client_banner_timeout = Duration::from_secs(1);
        config.login_grace_time = Duration::from_secs(1);
    })?;
    let (addr, task) = spawn_server(config).await?;

    let mut first = TcpStream::connect(addr).await?;
    let banner = read_banner(&mut first).await?;
    assert!(banner.starts_with(b"SSH-2.0-"));

    let mut second = TcpStream::connect(addr).await?;
    expect_close_without_banner(&mut second, Duration::from_millis(300)).await?;

    task.abort();
    Ok(())
}

#[tokio::test]
async fn repeated_auth_failures_trigger_temporary_bans() -> Result<()> {
    let tempdir = TempDir::new()?;
    let good_key = generate_ed25519_key()?;
    let wrong_key = Arc::new(generate_ed25519_key()?);
    let authorized_keys = format!("{}\n", good_key.public_key().to_openssh()?);
    let config = test_config(&tempdir, &authorized_keys, |config| {
        config.max_unauth_connections_global = 4;
        config.max_unauth_connections_per_ip = 4;
        config.max_unauth_connections_per_subnet = 8;
        config.new_connections_per_minute_per_ip = 60;
        config.new_connections_burst_per_ip = 8;
        config.auth_failure_ban_threshold = 2;
        config.auth_failure_ban_window = Duration::from_secs(5);
        config.auth_failure_ban_duration = Duration::from_millis(500);
        config.auth_rejection_time = Duration::from_millis(20);
        config.client_banner_timeout = Duration::from_millis(500);
        config.login_grace_time = Duration::from_millis(500);
    })?;
    let (addr, task) = spawn_server(config).await?;

    for _ in 0..2 {
        let mut session = connect_client(addr).await?;
        let auth = session
            .authenticate_publickey(
                &daemon_username()?,
                PrivateKeyWithHashAlg::new(Arc::clone(&wrong_key), None),
            )
            .await?;
        assert!(!auth.success(), "wrong key should not authenticate");
        drop(session);
        sleep(Duration::from_millis(50)).await;
    }

    let mut banned = TcpStream::connect(addr).await?;
    expect_close_without_banner(&mut banned, Duration::from_millis(300)).await?;

    sleep(Duration::from_millis(650)).await;
    let mut recovered = TcpStream::connect(addr).await?;
    let banner = read_banner(&mut recovered).await?;
    assert!(banner.starts_with(b"SSH-2.0-"));

    task.abort();
    Ok(())
}

#[tokio::test]
async fn reloads_authorized_keys_after_file_change() -> Result<()> {
    let tempdir = TempDir::new()?;
    let first_key = Arc::new(generate_ed25519_key()?);
    let second_key = Arc::new(generate_ed25519_key()?);
    let authorized_keys_path = tempdir.path().join("authorized_keys");
    let authorized_keys = format!("{}\n", first_key.public_key().to_openssh()?);
    let config = test_config(&tempdir, &authorized_keys, |config| {
        config.authorized_keys_reload_interval = Duration::from_millis(30);
        config.client_banner_timeout = Duration::from_millis(500);
        config.login_grace_time = Duration::from_secs(1);
    })?;
    let (addr, task) = spawn_server(config).await?;

    assert!(authenticate_with_key(addr, Arc::clone(&first_key)).await?);
    assert!(!authenticate_with_key(addr, Arc::clone(&second_key)).await?);

    sleep(Duration::from_millis(60)).await;
    tokio::fs::write(
        &authorized_keys_path,
        format!("{}\n", second_key.public_key().to_openssh()?),
    )
    .await?;
    sleep(Duration::from_millis(80)).await;

    assert!(!authenticate_with_key(addr, Arc::clone(&first_key)).await?);
    assert!(authenticate_with_key(addr, Arc::clone(&second_key)).await?);

    task.abort();
    Ok(())
}

#[tokio::test]
async fn keeps_last_known_good_authorized_keys_after_failed_reload() -> Result<()> {
    let tempdir = TempDir::new()?;
    let first_key = Arc::new(generate_ed25519_key()?);
    let second_key = Arc::new(generate_ed25519_key()?);
    let authorized_keys_path = tempdir.path().join("authorized_keys");
    let authorized_keys = format!("{}\n", first_key.public_key().to_openssh()?);
    let config = test_config(&tempdir, &authorized_keys, |config| {
        config.authorized_keys_reload_interval = Duration::from_millis(30);
        config.client_banner_timeout = Duration::from_millis(500);
        config.login_grace_time = Duration::from_secs(1);
    })?;
    let (addr, task) = spawn_server(config).await?;

    assert!(authenticate_with_key(addr, Arc::clone(&first_key)).await?);

    sleep(Duration::from_millis(60)).await;
    tokio::fs::write(
        &authorized_keys_path,
        format!(
            "{}\n{}\n",
            first_key.public_key().to_openssh()?,
            first_key.public_key().to_openssh()?
        ),
    )
    .await?;
    sleep(Duration::from_millis(80)).await;

    assert!(authenticate_with_key(addr, Arc::clone(&first_key)).await?);
    assert!(!authenticate_with_key(addr, Arc::clone(&second_key)).await?);

    sleep(Duration::from_millis(60)).await;
    tokio::fs::write(
        &authorized_keys_path,
        format!("{}\n", second_key.public_key().to_openssh()?),
    )
    .await?;
    sleep(Duration::from_millis(80)).await;

    assert!(!authenticate_with_key(addr, Arc::clone(&first_key)).await?);
    assert!(authenticate_with_key(addr, Arc::clone(&second_key)).await?);

    task.abort();
    Ok(())
}

#[tokio::test]
async fn uses_warm_authorized_keys_cache_without_retouching_disk_each_auth() -> Result<()> {
    let tempdir = TempDir::new()?;
    let first_key = Arc::new(generate_ed25519_key()?);
    let authorized_keys_path = tempdir.path().join("authorized_keys");
    let authorized_keys = format!("{}\n", first_key.public_key().to_openssh()?);
    let config = test_config(&tempdir, &authorized_keys, |config| {
        config.authorized_keys_reload_interval = Duration::from_secs(60);
        config.client_banner_timeout = Duration::from_millis(500);
        config.login_grace_time = Duration::from_secs(1);
    })?;
    let (addr, task) = spawn_server(config).await?;

    assert!(authenticate_with_key(addr, Arc::clone(&first_key)).await?);
    tokio::fs::remove_file(&authorized_keys_path).await?;

    // This would fail immediately if auth re-read the file on every attempt.
    assert!(authenticate_with_key(addr, Arc::clone(&first_key)).await?);

    task.abort();
    Ok(())
}

fn test_config(
    tempdir: &TempDir,
    authorized_keys: &str,
    adjust: impl FnOnce(&mut AppConfig),
) -> Result<AppConfig> {
    let mut config = AppConfig::defaults()?;
    let host_key = tempdir.path().join("ssh_host_ed25519_key");
    let authorized_keys_file = tempdir.path().join("authorized_keys");

    generate_ed25519_key()?
        .write_openssh_file(&host_key, ssh_key::LineEnding::LF)
        .with_context(|| format!("failed to write host key {}", host_key.display()))?;
    std::fs::write(&authorized_keys_file, authorized_keys).with_context(|| {
        format!(
            "failed to write authorized_keys file {}",
            authorized_keys_file.display()
        )
    })?;

    config.listen_address = "127.0.0.1".to_string();
    config.port = 0;
    config.host_key = host_key;
    config.authorized_keys_file = authorized_keys_file;
    config.auth_rejection_time = Duration::from_millis(10);
    config.keepalive_interval = Duration::from_secs(1);
    config.keepalive_max = 2;
    adjust(&mut config);
    Ok(config)
}

async fn spawn_server(config: AppConfig) -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move { sshd::run_on_listener(config, listener).await });

    sleep(Duration::from_millis(50)).await;
    Ok((addr, task))
}

async fn connect_client(
    addr: SocketAddr,
) -> Result<client::Handle<AcceptAnyServerKey>, russh::Error> {
    let config = Arc::new(client::Config::default());
    client::connect(config, addr, AcceptAnyServerKey).await
}

async fn authenticate_with_key(addr: SocketAddr, key: Arc<PrivateKey>) -> Result<bool> {
    let mut session = connect_client(addr).await.map_err(anyhow::Error::from)?;
    let auth = session
        .authenticate_publickey(&daemon_username()?, PrivateKeyWithHashAlg::new(key, None))
        .await
        .map_err(anyhow::Error::from)?;

    Ok(auth.success())
}

fn generate_ed25519_key() -> Result<PrivateKey> {
    PrivateKey::random(
        &mut UnwrapErr(getrandom::SysRng),
        ssh_key::Algorithm::Ed25519,
    )
    .context("failed to generate ed25519 key")
}

fn daemon_username() -> Result<String> {
    let user = User::from_uid(getuid())
        .context("failed to resolve daemon user")?
        .context("current uid has no passwd entry")?;
    Ok(user.name)
}

async fn read_banner(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut banner = Vec::new();
    let mut byte = [0_u8; 1];

    loop {
        let read = timeout(Duration::from_millis(500), stream.read(&mut byte))
            .await
            .context("timed out waiting for SSH banner")??;
        if read == 0 {
            anyhow::bail!("connection closed before sending SSH banner");
        }

        banner.push(byte[0]);
        if byte[0] == b'\n' {
            return Ok(banner);
        }

        if banner.len() > 512 {
            anyhow::bail!("SSH banner exceeded 512 bytes");
        }
    }
}

async fn read_some(stream: &mut TcpStream, wait: Duration) -> Result<Vec<u8>> {
    let mut buffer = vec![0_u8; 4096];
    let read = timeout(wait, stream.read(&mut buffer))
        .await
        .context("timed out waiting for data")??;
    buffer.truncate(read);
    Ok(buffer)
}

async fn wait_for_close(stream: &mut TcpStream, within: Duration) -> Result<()> {
    let deadline = Instant::now() + within;
    let mut buffer = vec![0_u8; 4096];

    loop {
        let now = Instant::now();
        if now >= deadline {
            anyhow::bail!("connection did not close within {:?}", within);
        }

        match timeout(deadline - now, stream.read(&mut buffer)).await {
            Ok(Ok(0)) => return Ok(()),
            Ok(Ok(_)) => continue,
            Ok(Err(err))
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::UnexpectedEof
                ) =>
            {
                return Ok(());
            }
            Ok(Err(err)) => {
                return Err(err).context("unexpected read error while waiting for close");
            }
            Err(_) => anyhow::bail!("connection did not close within {:?}", within),
        }
    }
}

async fn expect_close_without_banner(stream: &mut TcpStream, within: Duration) -> Result<()> {
    let mut buffer = [0_u8; 512];

    match timeout(within, stream.read(&mut buffer)).await {
        Ok(Ok(0)) => Ok(()),
        Ok(Err(err))
            if matches!(
                err.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof
            ) =>
        {
            Ok(())
        }
        Ok(Ok(read)) => {
            anyhow::bail!("expected connection to close before banner, but received {read} bytes")
        }
        Ok(Err(err)) => Err(err).context("unexpected read error"),
        Err(_) => anyhow::bail!("connection stayed open for {:?}", within),
    }
}
