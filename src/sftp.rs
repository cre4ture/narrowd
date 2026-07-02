use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version,
};
use russh_sftp::server::StatusReply;
use tokio::fs::{self, File as TokioFile, ReadDir};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom};

const MAX_SFTP_READ_LEN: u32 = 1 << 20;

enum HandleState {
    File {
        file: TokioFile,
    },
    Dir {
        path: PathBuf,
        entries: Box<ReadDir>,
    },
}

pub struct LocalSftp {
    root_dir: PathBuf,
    handles: HashMap<String, HandleState>,
    next_handle_id: u64,
}

impl LocalSftp {
    pub fn new(root_dir: PathBuf) -> Self {
        Self {
            root_dir,
            handles: HashMap::new(),
            next_handle_id: 0,
        }
    }

    fn make_handle(&mut self) -> String {
        self.next_handle_id += 1;
        format!("h{}", self.next_handle_id)
    }

    fn resolve_path(&self, path: &str) -> PathBuf {
        let input = Path::new(path);
        if input.is_absolute() {
            normalize_path(PathBuf::from("/"), input)
        } else {
            normalize_path(self.root_dir.clone(), input)
        }
    }

    fn ok_status(id: u32) -> Status {
        Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".to_string(),
            language_tag: "en-US".to_string(),
        }
    }
}

impl russh_sftp::server::Handler for LocalSftp {
    type Error = StatusReply;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported.into()
    }

    async fn init(
        &mut self,
        _version: u32,
        _extensions: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        Ok(Version::new())
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        let path = self.resolve_path(&filename);
        let std_options: std::fs::OpenOptions = pflags.into();
        let std_file = std_options.open(&path).map_err(io_error_to_status)?;
        let file = TokioFile::from_std(std_file);

        let handle = self.make_handle();
        self.handles
            .insert(handle.clone(), HandleState::File { file });

        Ok(Handle { id, handle })
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        self.handles
            .remove(&handle)
            .ok_or_else(|| StatusCode::NoSuchFile.with_message("unknown SFTP handle"))?;
        Ok(Self::ok_status(id))
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let HandleState::File { file } = self
            .handles
            .get_mut(&handle)
            .ok_or_else(|| StatusCode::NoSuchFile.with_message("unknown SFTP handle"))?
        else {
            return Err(StatusCode::Failure.with_message("handle is not a file"));
        };

        file.seek(SeekFrom::Start(offset))
            .await
            .map_err(io_error_to_status)?;
        let effective_len = len.min(MAX_SFTP_READ_LEN);
        let mut buffer = vec![0_u8; effective_len as usize];
        let read = file.read(&mut buffer).await.map_err(io_error_to_status)?;
        if read == 0 {
            return Err(StatusCode::Eof.into());
        }
        buffer.truncate(read);

        Ok(Data { id, data: buffer })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let HandleState::File { file } = self
            .handles
            .get_mut(&handle)
            .ok_or_else(|| StatusCode::NoSuchFile.with_message("unknown SFTP handle"))?
        else {
            return Err(StatusCode::Failure.with_message("handle is not a file"));
        };

        file.seek(SeekFrom::Start(offset))
            .await
            .map_err(io_error_to_status)?;
        file.write_all(&data).await.map_err(io_error_to_status)?;
        file.flush().await.map_err(io_error_to_status)?;

        Ok(Self::ok_status(id))
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let path = self.resolve_path(&path);
        let metadata = fs::symlink_metadata(path)
            .await
            .map_err(io_error_to_status)?;
        Ok(Attrs {
            id,
            attrs: FileAttributes::from(&metadata),
        })
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let attrs = match self
            .handles
            .get_mut(&handle)
            .ok_or_else(|| StatusCode::NoSuchFile.with_message("unknown SFTP handle"))?
        {
            HandleState::File { file } => {
                let metadata = file.metadata().await.map_err(io_error_to_status)?;
                FileAttributes::from(&metadata)
            }
            HandleState::Dir { path, .. } => {
                let metadata = fs::metadata(path).await.map_err(io_error_to_status)?;
                FileAttributes::from(&metadata)
            }
        };

        Ok(Attrs { id, attrs })
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let path = self.resolve_path(&path);
        let entries = Box::new(fs::read_dir(&path).await.map_err(io_error_to_status)?);
        let handle = self.make_handle();
        self.handles
            .insert(handle.clone(), HandleState::Dir { path, entries });
        Ok(Handle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        let HandleState::Dir { entries, .. } = self
            .handles
            .get_mut(&handle)
            .ok_or_else(|| StatusCode::NoSuchFile.with_message("unknown SFTP handle"))?
        else {
            return Err(StatusCode::Failure.with_message("handle is not a directory"));
        };

        match entries.next_entry().await.map_err(io_error_to_status)? {
            Some(entry) => {
                let metadata = entry.metadata().await.map_err(io_error_to_status)?;
                let filename = entry.file_name().to_string_lossy().into_owned();
                Ok(Name {
                    id,
                    files: vec![File::new(filename, FileAttributes::from(&metadata))],
                })
            }
            None => Err(StatusCode::Eof.into()),
        }
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        let path = self.resolve_path(&filename);
        fs::remove_file(path).await.map_err(io_error_to_status)?;
        Ok(Self::ok_status(id))
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let path = self.resolve_path(&path);
        fs::create_dir(path).await.map_err(io_error_to_status)?;
        Ok(Self::ok_status(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        let path = self.resolve_path(&path);
        fs::remove_dir(path).await.map_err(io_error_to_status)?;
        Ok(Self::ok_status(id))
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let path = self.resolve_path(&path);
        let display = match fs::canonicalize(&path).await {
            Ok(canonical) => canonical,
            Err(_) => path,
        };

        Ok(Name {
            id,
            files: vec![File::dummy(display.to_string_lossy().into_owned())],
        })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let path = self.resolve_path(&path);
        let metadata = fs::metadata(path).await.map_err(io_error_to_status)?;
        Ok(Attrs {
            id,
            attrs: FileAttributes::from(&metadata),
        })
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        let oldpath = self.resolve_path(&oldpath);
        let newpath = self.resolve_path(&newpath);
        fs::rename(oldpath, newpath)
            .await
            .map_err(io_error_to_status)?;
        Ok(Self::ok_status(id))
    }

    async fn readlink(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let path = self.resolve_path(&path);
        let target = fs::read_link(path).await.map_err(io_error_to_status)?;
        Ok(Name {
            id,
            files: vec![File::dummy(target.to_string_lossy().into_owned())],
        })
    }

    async fn symlink(
        &mut self,
        _id: u32,
        linkpath: String,
        targetpath: String,
    ) -> Result<Status, Self::Error> {
        let linkpath = self.resolve_path(&linkpath);
        let targetpath = self.resolve_path(&targetpath);

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(targetpath, linkpath).map_err(io_error_to_status)?;
            Ok(Self::ok_status(_id))
        }

        #[cfg(not(unix))]
        {
            let _ = (linkpath, targetpath);
            Err(StatusCode::OpUnsupported.into())
        }
    }
}

fn normalize_path(base: PathBuf, input: &Path) -> PathBuf {
    let mut out = base;

    for component in input.components() {
        match component {
            Component::Prefix(prefix) => out.push(prefix.as_os_str()),
            Component::RootDir => out = PathBuf::from("/"),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(part) => out.push(part),
        }
    }

    if out.as_os_str().is_empty() {
        PathBuf::from("/")
    } else {
        out
    }
}

fn io_error_to_status(error: std::io::Error) -> StatusReply {
    match error.kind() {
        std::io::ErrorKind::NotFound => StatusCode::NoSuchFile.with_message(error.to_string()),
        std::io::ErrorKind::PermissionDenied => {
            StatusCode::PermissionDenied.with_message(error.to_string())
        }
        std::io::ErrorKind::AlreadyExists => StatusCode::Failure.with_message(error.to_string()),
        std::io::ErrorKind::UnexpectedEof => StatusCode::Eof.with_message(error.to_string()),
        _ => StatusCode::Failure.with_message(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use russh_sftp::server::Handler;
    use tempfile::TempDir;

    #[tokio::test]
    async fn read_caps_large_client_lengths() {
        let tempdir = TempDir::new().unwrap();
        let file_path = tempdir.path().join("large.bin");
        let content_len = MAX_SFTP_READ_LEN as usize + 4096;
        let content = vec![b'x'; content_len];
        std::fs::write(&file_path, &content).unwrap();

        let mut sftp = LocalSftp::new(tempdir.path().to_path_buf());
        let handle = sftp
            .open(
                1,
                "large.bin".to_string(),
                OpenFlags::READ,
                FileAttributes::default(),
            )
            .await
            .unwrap()
            .handle;

        let data = sftp.read(2, handle, 0, u32::MAX).await.unwrap();

        assert_eq!(data.data.len(), MAX_SFTP_READ_LEN as usize);
        assert!(data.data.iter().all(|byte| *byte == b'x'));
    }
}
