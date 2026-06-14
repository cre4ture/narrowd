use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use log::LevelFilter;

pub const SAMPLE_CONFIG: &str = "\
# narrowd sample config
# single-user SSH daemon
Port 2222
ListenAddress 0.0.0.0

HostKey ~/.config/narrowd/ssh_host_ed25519_key
AuthorizedKeysFile ~/.ssh/authorized_keys

Shell /bin/bash
PermitTTY yes
PermitExec yes

Subsystem sftp internal-sftp
AllowTcpForwarding yes
AllowRemoteForwarding yes
GatewayPorts yes

# Public exposure hardening defaults
MaxUnauthConnectionsGlobal 16
MaxUnauthConnectionsPerIp 3
MaxUnauthConnectionsPerSubnet 8
NewConnectionsPerMinutePerIp 12
NewConnectionsBurstPerIp 4
LoginGraceTime 15s
ClientBannerTimeout 5s
KexStartTimeout 5s
MaxAuthAttempts 4
AuthRejectionTime 2s
AuthFailureBanThreshold 8
AuthFailureBanWindow 10m
AuthFailureBanDuration 15m
InactivityTimeout 15m
KeepaliveInterval 30s
KeepaliveMax 3
ChannelBufferSize 32
EventBufferSize 16
WindowSize 1048576
MaximumPacketSize 32768
NoDelay yes
AuthorizedKeysMaxSize 256KiB
AuthorizedKeysMaxEntries 128
AuthorizedKeysReloadInterval 2s

LogLevel info
";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    pub fn parse(input: &str) -> Result<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "error" => Ok(Self::Error),
            "warn" | "warning" => Ok(Self::Warn),
            "info" => Ok(Self::Info),
            "debug" => Ok(Self::Debug),
            "trace" => Ok(Self::Trace),
            other => bail!("unsupported LogLevel value: {other}"),
        }
    }

    pub fn to_level_filter(self) -> LevelFilter {
        match self {
            Self::Error => LevelFilter::Error,
            Self::Warn => LevelFilter::Warn,
            Self::Info => LevelFilter::Info,
            Self::Debug => LevelFilter::Debug,
            Self::Trace => LevelFilter::Trace,
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        };
        write!(f, "{text}")
    }
}

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub listen_address: String,
    pub port: u16,
    pub host_key: PathBuf,
    pub authorized_keys_file: PathBuf,
    pub shell: PathBuf,
    pub permit_tty: bool,
    pub permit_exec: bool,
    pub sftp_enabled: bool,
    pub allow_tcp_forwarding: bool,
    pub allow_remote_forwarding: bool,
    pub gateway_ports: bool,
    pub max_unauth_connections_global: usize,
    pub max_unauth_connections_per_ip: usize,
    pub max_unauth_connections_per_subnet: usize,
    pub new_connections_per_minute_per_ip: usize,
    pub new_connections_burst_per_ip: usize,
    pub login_grace_time: Duration,
    pub client_banner_timeout: Duration,
    pub kex_start_timeout: Duration,
    pub max_auth_attempts: usize,
    pub auth_rejection_time: Duration,
    pub auth_failure_ban_threshold: usize,
    pub auth_failure_ban_window: Duration,
    pub auth_failure_ban_duration: Duration,
    pub inactivity_timeout: Duration,
    pub keepalive_interval: Duration,
    pub keepalive_max: usize,
    pub channel_buffer_size: usize,
    pub event_buffer_size: usize,
    pub window_size: u32,
    pub maximum_packet_size: u32,
    pub nodelay: bool,
    pub authorized_keys_max_size: usize,
    pub authorized_keys_max_entries: usize,
    pub authorized_keys_reload_interval: Duration,
    pub log_level: LogLevel,
}

impl AppConfig {
    pub fn load(requested_path: Option<PathBuf>) -> Result<Self> {
        let mut config = Self::defaults()?;
        let config_path = match requested_path {
            Some(path) => Some(expand_home(path)?),
            None => default_config_path()?.filter(|path| path.exists()),
        };

        if let Some(path) = config_path {
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("failed to read config file {}", path.display()))?;
            config.apply_text(&text, path.parent().unwrap_or(Path::new(".")))?;
        }

        Ok(config)
    }

    pub fn defaults() -> Result<Self> {
        let home = dirs::home_dir().context("unable to determine home directory")?;
        let config_root = dirs::config_dir().unwrap_or_else(|| home.join(".config"));

        Ok(Self {
            listen_address: "0.0.0.0".to_string(),
            port: 2222,
            host_key: config_root.join("narrowd/ssh_host_ed25519_key"),
            authorized_keys_file: home.join(".ssh/authorized_keys"),
            shell: PathBuf::from(if cfg!(windows) {
                "powershell.exe"
            } else {
                "/bin/bash"
            }),
            permit_tty: true,
            permit_exec: true,
            sftp_enabled: true,
            allow_tcp_forwarding: true,
            allow_remote_forwarding: true,
            gateway_ports: true,
            max_unauth_connections_global: 16,
            max_unauth_connections_per_ip: 3,
            max_unauth_connections_per_subnet: 8,
            new_connections_per_minute_per_ip: 12,
            new_connections_burst_per_ip: 4,
            login_grace_time: Duration::from_secs(15),
            client_banner_timeout: Duration::from_secs(5),
            kex_start_timeout: Duration::from_secs(5),
            max_auth_attempts: 4,
            auth_rejection_time: Duration::from_secs(2),
            auth_failure_ban_threshold: 8,
            auth_failure_ban_window: Duration::from_secs(10 * 60),
            auth_failure_ban_duration: Duration::from_secs(15 * 60),
            inactivity_timeout: Duration::from_secs(15 * 60),
            keepalive_interval: Duration::from_secs(30),
            keepalive_max: 3,
            channel_buffer_size: 32,
            event_buffer_size: 16,
            window_size: 1_048_576,
            maximum_packet_size: 32_768,
            nodelay: true,
            authorized_keys_max_size: 256 * 1024,
            authorized_keys_max_entries: 128,
            authorized_keys_reload_interval: Duration::from_secs(2),
            log_level: LogLevel::Info,
        })
    }

    fn apply_text(&mut self, text: &str, base_dir: &Path) -> Result<()> {
        for (idx, raw_line) in text.lines().enumerate() {
            let line_number = idx + 1;
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }

            let mut parts = line.split_whitespace();
            let key = parts.next().unwrap_or_default();
            let values = parts.collect::<Vec<_>>();
            if values.is_empty() {
                bail!("missing value for directive {key} on line {line_number}");
            }

            match key.to_ascii_lowercase().as_str() {
                "port" => {
                    self.port = values[0]
                        .parse::<u16>()
                        .with_context(|| format!("invalid Port on line {line_number}"))?;
                }
                "listenaddress" => {
                    self.listen_address = values.join(" ");
                }
                "hostkey" => {
                    self.host_key = resolve_config_path(&values.join(" "), base_dir)?;
                }
                "authorizedkeysfile" => {
                    self.authorized_keys_file = resolve_config_path(&values.join(" "), base_dir)?;
                }
                "shell" => {
                    self.shell = resolve_shell_command_or_path(&values.join(" "), base_dir)?;
                }
                "permittty" => {
                    self.permit_tty = parse_bool(values[0])
                        .with_context(|| format!("invalid PermitTTY on line {line_number}"))?;
                }
                "permitexec" => {
                    self.permit_exec = parse_bool(values[0])
                        .with_context(|| format!("invalid PermitExec on line {line_number}"))?;
                }
                "sftpenabled" => {
                    self.sftp_enabled = parse_bool(values[0])
                        .with_context(|| format!("invalid SftpEnabled on line {line_number}"))?;
                }
                "subsystem" => {
                    if values.first().copied() == Some("sftp") {
                        self.sftp_enabled = true;
                    }
                }
                "allowtcpforwarding" => {
                    self.allow_tcp_forwarding = parse_bool(values[0]).with_context(|| {
                        format!("invalid AllowTcpForwarding on line {line_number}")
                    })?;
                }
                "allowremoteforwarding" => {
                    self.allow_remote_forwarding = parse_bool(values[0]).with_context(|| {
                        format!("invalid AllowRemoteForwarding on line {line_number}")
                    })?;
                }
                "gatewayports" => {
                    self.gateway_ports = parse_bool(values[0])
                        .with_context(|| format!("invalid GatewayPorts on line {line_number}"))?;
                }
                "maxunauthconnectionsglobal" => {
                    self.max_unauth_connections_global =
                        values[0].parse::<usize>().with_context(|| {
                            format!("invalid MaxUnauthConnectionsGlobal on line {line_number}")
                        })?;
                }
                "maxunauthconnectionsperip" => {
                    self.max_unauth_connections_per_ip =
                        values[0].parse::<usize>().with_context(|| {
                            format!("invalid MaxUnauthConnectionsPerIp on line {line_number}")
                        })?;
                }
                "maxunauthconnectionspersubnet" => {
                    self.max_unauth_connections_per_subnet =
                        values[0].parse::<usize>().with_context(|| {
                            format!("invalid MaxUnauthConnectionsPerSubnet on line {line_number}")
                        })?;
                }
                "newconnectionsperminuteperip" => {
                    self.new_connections_per_minute_per_ip =
                        values[0].parse::<usize>().with_context(|| {
                            format!("invalid NewConnectionsPerMinutePerIp on line {line_number}")
                        })?;
                }
                "newconnectionsburstperip" => {
                    self.new_connections_burst_per_ip =
                        values[0].parse::<usize>().with_context(|| {
                            format!("invalid NewConnectionsBurstPerIp on line {line_number}")
                        })?;
                }
                "logingracetime" => {
                    self.login_grace_time = parse_duration(values[0])
                        .with_context(|| format!("invalid LoginGraceTime on line {line_number}"))?;
                }
                "clientbannertimeout" => {
                    self.client_banner_timeout = parse_duration(values[0]).with_context(|| {
                        format!("invalid ClientBannerTimeout on line {line_number}")
                    })?;
                }
                "kexstarttimeout" => {
                    self.kex_start_timeout = parse_duration(values[0]).with_context(|| {
                        format!("invalid KexStartTimeout on line {line_number}")
                    })?;
                }
                "maxauthattempts" => {
                    self.max_auth_attempts = values[0].parse::<usize>().with_context(|| {
                        format!("invalid MaxAuthAttempts on line {line_number}")
                    })?;
                }
                "authrejectiontime" => {
                    self.auth_rejection_time = parse_duration(values[0]).with_context(|| {
                        format!("invalid AuthRejectionTime on line {line_number}")
                    })?;
                }
                "authfailurebanthreshold" => {
                    self.auth_failure_ban_threshold =
                        values[0].parse::<usize>().with_context(|| {
                            format!("invalid AuthFailureBanThreshold on line {line_number}")
                        })?;
                }
                "authfailurebanwindow" => {
                    self.auth_failure_ban_window =
                        parse_duration(values[0]).with_context(|| {
                            format!("invalid AuthFailureBanWindow on line {line_number}")
                        })?;
                }
                "authfailurebanduration" => {
                    self.auth_failure_ban_duration =
                        parse_duration(values[0]).with_context(|| {
                            format!("invalid AuthFailureBanDuration on line {line_number}")
                        })?;
                }
                "inactivitytimeout" => {
                    self.inactivity_timeout = parse_duration(values[0]).with_context(|| {
                        format!("invalid InactivityTimeout on line {line_number}")
                    })?;
                }
                "keepaliveinterval" => {
                    self.keepalive_interval = parse_duration(values[0]).with_context(|| {
                        format!("invalid KeepaliveInterval on line {line_number}")
                    })?;
                }
                "keepalivemax" => {
                    self.keepalive_max = values[0]
                        .parse::<usize>()
                        .with_context(|| format!("invalid KeepaliveMax on line {line_number}"))?;
                }
                "channelbuffersize" => {
                    self.channel_buffer_size = values[0].parse::<usize>().with_context(|| {
                        format!("invalid ChannelBufferSize on line {line_number}")
                    })?;
                }
                "eventbuffersize" => {
                    self.event_buffer_size = values[0].parse::<usize>().with_context(|| {
                        format!("invalid EventBufferSize on line {line_number}")
                    })?;
                }
                "windowsize" => {
                    self.window_size = values[0]
                        .parse::<u32>()
                        .with_context(|| format!("invalid WindowSize on line {line_number}"))?;
                }
                "maximumpacketsize" => {
                    self.maximum_packet_size = values[0].parse::<u32>().with_context(|| {
                        format!("invalid MaximumPacketSize on line {line_number}")
                    })?;
                }
                "nodelay" => {
                    self.nodelay = parse_bool(values[0])
                        .with_context(|| format!("invalid NoDelay on line {line_number}"))?;
                }
                "authorizedkeysmaxsize" => {
                    self.authorized_keys_max_size =
                        parse_byte_size(values[0]).with_context(|| {
                            format!("invalid AuthorizedKeysMaxSize on line {line_number}")
                        })?;
                }
                "authorizedkeysmaxentries" => {
                    self.authorized_keys_max_entries =
                        values[0].parse::<usize>().with_context(|| {
                            format!("invalid AuthorizedKeysMaxEntries on line {line_number}")
                        })?;
                }
                "authorizedkeysreloadinterval" => {
                    self.authorized_keys_reload_interval =
                        parse_duration(values[0]).with_context(|| {
                            format!("invalid AuthorizedKeysReloadInterval on line {line_number}")
                        })?;
                }
                "pubkeyauthentication" => {
                    let enabled = parse_bool(values[0]).with_context(|| {
                        format!("invalid PubkeyAuthentication on line {line_number}")
                    })?;
                    if !enabled {
                        bail!("PubkeyAuthentication no is unsupported");
                    }
                }
                "passwordauthentication" => {
                    let enabled = parse_bool(values[0]).with_context(|| {
                        format!("invalid PasswordAuthentication on line {line_number}")
                    })?;
                    if enabled {
                        bail!("PasswordAuthentication yes is unsupported");
                    }
                }
                "permitopen" => {}
                "loglevel" => {
                    self.log_level = LogLevel::parse(values[0])
                        .with_context(|| format!("invalid LogLevel on line {line_number}"))?;
                }
                other => bail!("unsupported directive {other} on line {line_number}"),
            }
        }

        Ok(())
    }
}

fn parse_bool(input: &str) -> Result<bool> {
    match input.trim().to_ascii_lowercase().as_str() {
        "yes" | "true" | "on" | "1" => Ok(true),
        "no" | "false" | "off" | "0" => Ok(false),
        other => bail!("expected yes/no boolean, got {other}"),
    }
}

fn parse_duration(input: &str) -> Result<Duration> {
    let input = input.trim();
    if input.is_empty() {
        bail!("duration must not be empty");
    }

    let split_at = input
        .find(|ch: char| !ch.is_ascii_digit())
        .unwrap_or(input.len());
    let (digits, suffix) = input.split_at(split_at);
    if digits.is_empty() {
        bail!("duration must start with digits");
    }

    let value = digits.parse::<u64>()?;
    let duration = match suffix.to_ascii_lowercase().as_str() {
        "" | "s" => Duration::from_secs(value),
        "ms" => Duration::from_millis(value),
        "m" => Duration::from_secs(value.saturating_mul(60)),
        "h" => Duration::from_secs(value.saturating_mul(60 * 60)),
        other => bail!("unsupported duration suffix: {other}"),
    };

    Ok(duration)
}

fn parse_byte_size(input: &str) -> Result<usize> {
    let input = input.trim();
    if input.is_empty() {
        bail!("byte size must not be empty");
    }

    let split_at = input
        .find(|ch: char| !ch.is_ascii_digit())
        .unwrap_or(input.len());
    let (digits, suffix) = input.split_at(split_at);
    if digits.is_empty() {
        bail!("byte size must start with digits");
    }

    let value = digits.parse::<usize>()?;
    let multiplier = match suffix.to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" => 1_000,
        "ki" | "kib" => 1_024,
        "m" | "mb" => 1_000_000,
        "mi" | "mib" => 1_048_576,
        other => bail!("unsupported byte size suffix: {other}"),
    };

    value
        .checked_mul(multiplier)
        .context("byte size is too large")
}

fn default_config_path() -> Result<Option<PathBuf>> {
    let home = dirs::home_dir().context("unable to determine home directory")?;
    let config_root = dirs::config_dir().unwrap_or_else(|| home.join(".config"));
    Ok(Some(config_root.join("narrowd/narrowd.conf")))
}

fn resolve_config_path(input: &str, base_dir: &Path) -> Result<PathBuf> {
    let path = expand_home(PathBuf::from(input))?;
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(base_dir.join(path))
    }
}

fn resolve_shell_command_or_path(input: &str, base_dir: &Path) -> Result<PathBuf> {
    let path = expand_home(PathBuf::from(input))?;
    if path.is_absolute() {
        return Ok(path);
    }

    if path.components().nth(1).is_none() {
        return Ok(path);
    }

    Ok(base_dir.join(path))
}

fn expand_home(path: PathBuf) -> Result<PathBuf> {
    let text = path.to_string_lossy();
    if text == "~" || text.starts_with("~/") {
        let home = dirs::home_dir().context("unable to determine home directory")?;
        if text == "~" {
            Ok(home)
        } else {
            Ok(home.join(text.trim_start_matches("~/")))
        }
    } else {
        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_config() {
        let mut config = AppConfig::defaults().unwrap();
        config
            .apply_text(
                "Port 9922\nListenAddress 127.0.0.1\nPasswordAuthentication no\nLoginGraceTime 20s\nAuthorizedKeysMaxSize 64KiB\n",
                Path::new("/tmp"),
            )
            .unwrap();

        assert_eq!(config.port, 9922);
        assert_eq!(config.listen_address, "127.0.0.1");
        assert_eq!(config.login_grace_time, Duration::from_secs(20));
        assert_eq!(config.authorized_keys_max_size, 64 * 1024);
        assert_eq!(config.kex_start_timeout, Duration::from_secs(5));
    }

    #[test]
    fn parses_public_exposure_limits() {
        let mut config = AppConfig::defaults().unwrap();
        config
            .apply_text(
                "MaxUnauthConnectionsGlobal 10\nMaxUnauthConnectionsPerIp 2\nAuthFailureBanThreshold 5\nAuthFailureBanWindow 30s\nAuthorizedKeysReloadInterval 3s\nKexStartTimeout 7s\n",
                Path::new("/tmp"),
            )
            .unwrap();

        assert_eq!(config.max_unauth_connections_global, 10);
        assert_eq!(config.max_unauth_connections_per_ip, 2);
        assert_eq!(config.auth_failure_ban_threshold, 5);
        assert_eq!(config.auth_failure_ban_window, Duration::from_secs(30));
        assert_eq!(
            config.authorized_keys_reload_interval,
            Duration::from_secs(3)
        );
        assert_eq!(config.kex_start_timeout, Duration::from_secs(7));
    }

    #[test]
    fn rejects_password_auth_enable() {
        let mut config = AppConfig::defaults().unwrap();
        let err = config
            .apply_text("PasswordAuthentication yes\n", Path::new("/tmp"))
            .unwrap_err();

        assert!(err.to_string().contains("unsupported"));
    }

    #[test]
    fn parses_duration_suffixes() {
        assert_eq!(
            parse_duration("1500ms").unwrap(),
            Duration::from_millis(1500)
        );
        assert_eq!(parse_duration("15s").unwrap(), Duration::from_secs(15));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
    }

    #[test]
    fn parses_byte_sizes() {
        assert_eq!(parse_byte_size("256").unwrap(), 256);
        assert_eq!(parse_byte_size("64KiB").unwrap(), 64 * 1024);
        assert_eq!(parse_byte_size("1MiB").unwrap(), 1024 * 1024);
    }

    #[test]
    fn packaged_example_matches_sample_config() {
        let packaged_example = include_str!("../narrowd.conf.example");
        assert_eq!(packaged_example.replace("\r\n", "\n"), SAMPLE_CONFIG);
    }

    #[test]
    fn shell_directive_keeps_bare_command_name() {
        let mut config = AppConfig::defaults().unwrap();
        config
            .apply_text("Shell powershell.exe\n", Path::new("/tmp"))
            .unwrap();

        assert_eq!(config.shell, PathBuf::from("powershell.exe"));
    }

    #[test]
    fn shell_directive_resolves_relative_path_from_config_dir() {
        let mut config = AppConfig::defaults().unwrap();
        config
            .apply_text("Shell bin/custom-shell.exe\n", Path::new("/tmp"))
            .unwrap();

        assert_eq!(config.shell, Path::new("/tmp").join("bin/custom-shell.exe"));
    }
}
