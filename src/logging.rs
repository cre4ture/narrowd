use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::config;

const DEFAULT_LOG_ROTATE_BYTES: u64 = 10 * 1024 * 1024;

pub fn init(level: config::LogLevel, log_file: Option<PathBuf>) -> Result<()> {
    let mut builder = env_logger::Builder::new();
    builder.filter_level(level.to_level_filter());

    if let Some(path) = log_file {
        builder.target(env_logger::Target::Pipe(Box::new(RotatingLogFile::new(
            path,
            DEFAULT_LOG_ROTATE_BYTES,
        )?)));
        builder.write_style(env_logger::WriteStyle::Never);
    }

    if std::env::var_os("RUST_LOG").is_some() {
        builder.parse_default_env();
    }

    builder
        .try_init()
        .context("failed to initialize application logging")
}

pub fn append_bootstrap_error(path: Option<&Path>, message: &str) {
    let Some(path) = path else {
        return;
    };

    let _ = append_bootstrap_line(path, &format!("narrowd bootstrap error: {message}\n"));
}

fn append_bootstrap_line(path: &Path, message: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(message.as_bytes())?;
    file.flush()
}

struct RotatingLogFile {
    path: PathBuf,
    rotated_path: PathBuf,
    max_bytes: u64,
    current_len: u64,
    file: Option<File>,
}

impl RotatingLogFile {
    fn new(path: PathBuf, max_bytes: u64) -> Result<Self> {
        let rotated_path = rotated_log_path(&path);
        let (file, current_len) = open_log_file(&path)?;

        Ok(Self {
            path,
            rotated_path,
            max_bytes,
            current_len,
            file: Some(file),
        })
    }

    fn rotate_if_needed(&mut self, incoming_len: usize) -> io::Result<()> {
        if incoming_len == 0
            || self.current_len == 0
            || self.current_len.saturating_add(incoming_len as u64) <= self.max_bytes
        {
            return Ok(());
        }

        if let Some(mut file) = self.file.take() {
            file.flush()?;
        }

        if self.rotated_path.exists() {
            std::fs::remove_file(&self.rotated_path)?;
        }

        std::fs::rename(&self.path, &self.rotated_path)?;
        let (file, current_len) = open_log_file(&self.path)?;
        self.file = Some(file);
        self.current_len = current_len;
        Ok(())
    }
}

impl Write for RotatingLogFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.rotate_if_needed(buf.len())?;
        let written = self
            .file
            .as_mut()
            .expect("log file handle must be open")
            .write(buf)?;
        self.current_len = self.current_len.saturating_add(written as u64);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file
            .as_mut()
            .expect("log file handle must be open")
            .flush()
    }
}

fn open_log_file(path: &Path) -> io::Result<(File, u64)> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let file = OpenOptions::new().create(true).append(true).open(path)?;
    let current_len = file.metadata()?.len();
    Ok((file, current_len))
}

fn rotated_log_path(path: &Path) -> PathBuf {
    let mut rotated_name = path
        .file_name()
        .map(OsString::from)
        .unwrap_or_else(|| OsString::from("narrowd.log"));
    rotated_name.push(".1");

    match path.parent() {
        Some(parent) => parent.join(rotated_name),
        None => PathBuf::from(rotated_name),
    }
}
