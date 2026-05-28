use std::fmt;
use std::path::{Path, PathBuf};

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

# Parsed for compatibility, but X11 forwarding is not implemented yet.
X11Forwarding no
X11DisplayOffset 10
X11UseLocalhost yes

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
    pub x11_forwarding: bool,
    pub x11_display_offset: u16,
    pub x11_use_localhost: bool,
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

    fn defaults() -> Result<Self> {
        let home = dirs::home_dir().context("unable to determine home directory")?;
        let config_root = dirs::config_dir().unwrap_or_else(|| home.join(".config"));

        Ok(Self {
            listen_address: "0.0.0.0".to_string(),
            port: 2222,
            host_key: config_root.join("narrowd/ssh_host_ed25519_key"),
            authorized_keys_file: home.join(".ssh/authorized_keys"),
            shell: PathBuf::from("/bin/bash"),
            permit_tty: true,
            permit_exec: true,
            sftp_enabled: true,
            allow_tcp_forwarding: true,
            allow_remote_forwarding: true,
            gateway_ports: true,
            x11_forwarding: false,
            x11_display_offset: 10,
            x11_use_localhost: true,
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
                    self.shell = resolve_config_path(&values.join(" "), base_dir)?;
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
                "x11forwarding" => {
                    self.x11_forwarding = parse_bool(values[0])
                        .with_context(|| format!("invalid X11Forwarding on line {line_number}"))?;
                }
                "x11displayoffset" => {
                    self.x11_display_offset = values[0].parse::<u16>().with_context(|| {
                        format!("invalid X11DisplayOffset on line {line_number}")
                    })?;
                }
                "x11uselocalhost" => {
                    self.x11_use_localhost = parse_bool(values[0]).with_context(|| {
                        format!("invalid X11UseLocalhost on line {line_number}")
                    })?;
                }
                "forwardx11trusted" => {
                    let _ = parse_bool(values[0]).with_context(|| {
                        format!("invalid ForwardX11Trusted on line {line_number}")
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
                "Port 9922\nListenAddress 127.0.0.1\nPasswordAuthentication no\n",
                Path::new("/tmp"),
            )
            .unwrap();

        assert_eq!(config.port, 9922);
        assert_eq!(config.listen_address, "127.0.0.1");
    }

    #[test]
    fn rejects_password_auth_enable() {
        let mut config = AppConfig::defaults().unwrap();
        let err = config
            .apply_text("PasswordAuthentication yes\n", Path::new("/tmp"))
            .unwrap_err();

        assert!(err.to_string().contains("unsupported"));
    }
}
