/// https://github.com/BourgondAries/file-rotate](https://github.com/BourgondAries/file-rotate
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

/// Condition on which a file is rotated.
pub enum RotationMode {
    /// Cut the log at the exact size in bytes.
    Bytes(usize),
    /// Cut the log file at line breaks.
    Lines(usize),
    /// Cut the log file after surpassing size in bytes (but having written a complete buffer from a write call.)
    BytesSurpassed(usize),
}

/// The main writer used for rotating logs.
pub struct FileRotate {
    basename: PathBuf,
    count: usize,
    file: Option<File>,
    file_number: usize,
    max_file_number: usize,
    mode: RotationMode,
}

impl FileRotate {
    /// Create a new [FileRotate].
    ///
    /// The basename of the `path` is used to create new log files by appending an extension of the
    /// form `.N`, where N is `0..=max_file_number`.
    ///
    /// `rotation_mode` specifies the limits for rotating a file.
    ///
    /// # Panics
    ///
    /// Panics if `bytes == 0` or `lines == 0`.
    pub fn open<P: AsRef<Path>>(
        path: P,
        rotation_mode: RotationMode,
        max_file_number: usize,
    ) -> anyhow::Result<Self> {
        match rotation_mode {
            RotationMode::Bytes(bytes) => {
                assert!(bytes > 0);
            }
            RotationMode::Lines(lines) => {
                assert!(lines > 0);
            }
            RotationMode::BytesSurpassed(bytes) => {
                assert!(bytes > 0);
            }
        };

        let path = path.as_ref();

        let file = OpenOptions::new().create(true).append(true).open(path)?;

        let file_size = file.metadata().map(|it| it.len()).unwrap_or_default();

        let file_number = current_file_number(path)
            .ok()
            .unwrap_or_default()
            .map(|it| it + 1)
            .unwrap_or_default();

        let count = match &rotation_mode {
            RotationMode::Bytes(_) | RotationMode::BytesSurpassed(_) => file_size as usize,
            RotationMode::Lines(_) => 0usize,
        };

        Ok(Self {
            basename: path.to_path_buf(),
            count,
            file: Some(file),
            file_number,
            max_file_number,
            mode: rotation_mode,
        })
    }

    fn rotate(&mut self) -> io::Result<()> {
        let mut path = self.basename.clone();
        let new_file_name = format!(
            "{}.{}",
            path.file_name().unwrap().to_str().unwrap(),
            self.file_number
        );

        let deleted = if self.file_number >= self.max_file_number {
            Some(format!(
                "{}.{}",
                path.file_name().unwrap().to_str().unwrap(),
                self.file_number - self.max_file_number
            ))
        } else {
            None
        };

        path.set_file_name(new_file_name);

        let _ = self.file.take();

        let _ = fs::rename(&self.basename, path);

        self.file = Some(File::create(&self.basename)?);

        // 删除旧日志
        if let Some(d) = deleted {
            let mut to_be_deleted = self.basename.clone();
            to_be_deleted.set_file_name(d);
            fs::remove_file(to_be_deleted).ok();
        }

        self.file_number += 1;
        self.count = 0;

        Ok(())
    }
}

impl Write for FileRotate {
    fn write(&mut self, mut buf: &[u8]) -> io::Result<usize> {
        let written = buf.len();
        match self.mode {
            RotationMode::Bytes(bytes) => {
                while self.count + buf.len() > bytes {
                    let bytes_left = bytes - self.count;
                    if let Some(Err(err)) = self
                        .file
                        .as_mut()
                        .map(|file| file.write(&buf[..bytes_left]))
                    {
                        return Err(err);
                    }
                    self.rotate()?;
                    buf = &buf[bytes_left..];
                }
                self.count += buf.len();
                if let Some(Err(err)) = self.file.as_mut().map(|file| file.write(buf)) {
                    return Err(err);
                }
            }
            RotationMode::Lines(lines) => {
                while let Some((idx, _)) = buf.iter().enumerate().find(|(_, byte)| *byte == &b'\n')
                {
                    if let Some(Err(err)) =
                        self.file.as_mut().map(|file| file.write(&buf[..idx + 1]))
                    {
                        return Err(err);
                    }
                    self.count += 1;
                    buf = &buf[idx + 1..];
                    if self.count >= lines {
                        self.rotate()?;
                    }
                }
                if let Some(Err(err)) = self.file.as_mut().map(|file| file.write(buf)) {
                    return Err(err);
                }
            }
            RotationMode::BytesSurpassed(bytes) => {
                if let Some(Err(err)) = self.file.as_mut().map(|file| file.write(buf)) {
                    return Err(err);
                }
                self.count += buf.len();
                if self.count > bytes {
                    self.rotate()?
                }
            }
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(Err(err)) = self.file.as_mut().map(|file| file.flush()) {
            Err(err)
        } else {
            Ok(())
        }
    }
}

fn current_file_number(path: &Path) -> anyhow::Result<Option<usize>> {
    let filename = path.file_name().unwrap().to_str().unwrap();
    let mut n = -1i64;
    for it in fs::read_dir(path.parent().unwrap())? {
        let ent = it?;
        let p = ent.path();
        if !p.is_file() {
            continue;
        }
        if let Some(f) = p.file_name() {
            if let Some(s) = f.to_str() {
                if s.starts_with(filename) && s.ne(filename) {
                    let suffix = &s[filename.len()..];
                    if suffix.starts_with('.') && suffix.len() > 1 {
                        let numstr = &suffix[1..];
                        if let Ok(v) = numstr.parse::<i64>() {
                            if v > n {
                                n = v;
                            }
                        }
                    }
                }
            }
        }
    }
    if n >= 0 {
        Ok(Some(n as usize))
    } else {
        Ok(None)
    }
}
