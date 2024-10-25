use std::io::{self, Write};
use std::path::Path;

use bytesize::ByteSize;
use chrono::Local;
use garde::Validate;
use log::LevelFilter;
use serde::{Deserialize, Serialize};
use slog::{Drain, Logger};

use super::rotate::{FileRotate, RotationMode};

const DEFAULT_CHAN_SIZE: usize = 8192;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Overflow {
    Drop,
    Block,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Off,
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl Default for Level {
    fn default() -> Self {
        Self::Info
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Hash, Validate)]
#[garde(allow_unvalidated)]
pub struct FileConfig {
    #[garde(length(min = 1))]
    pub path: String,
    #[garde(range(min = 1))]
    pub rotate_num: Option<usize>,
    pub rotate_size: Option<ByteSize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[garde(allow_unvalidated)]
pub struct Config {
    #[serde(default)]
    pub level: Level,
    #[serde(default)]
    pub line_num: bool,

    // no header
    #[serde(default)]
    pub noh: bool,

    // async ctrl
    #[garde(range(min = 1))]
    pub chan_size: Option<usize>,
    pub overflow: Option<Overflow>,

    #[serde(default)]
    pub stdout: bool,
    #[garde(dive)]
    pub file: Option<FileConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            level: Default::default(),
            stdout: true,
            file: None,
            line_num: false,
            noh: false,
            chan_size: None,
            overflow: None,
        }
    }
}

pub fn init_global(c: &Config) -> anyhow::Result<()> {
    if let Some(l) = new_logger(c)? {
        slog_scope::set_global_logger(l).cancel_reset();
        slog_stdlog::init().ok();
        match c.level {
            Level::Off => log::set_max_level(LevelFilter::Off),
            Level::Trace => log::set_max_level(LevelFilter::Trace),
            Level::Debug => log::set_max_level(LevelFilter::Debug),
            Level::Info => log::set_max_level(LevelFilter::Info),
            Level::Warn => log::set_max_level(LevelFilter::Warn),
            Level::Error => log::set_max_level(LevelFilter::Error),
        }
    }
    Ok(())
}

fn custom_timestamp(w: &mut dyn Write) -> io::Result<()> {
    write!(w, "{}", Local::now().format("%Y-%m-%dT%H:%M:%S.%3f%z"))
}

fn custom_header(
    fn_timestamp: &dyn slog_term::ThreadSafeTimestampFn<Output = io::Result<()>>,
    mut rd: &mut dyn slog_term::RecordDecorator,
    record: &slog::Record,
    use_file_location: bool,
) -> io::Result<bool> {
    rd.start_timestamp()?;
    fn_timestamp(&mut rd)?;

    rd.start_whitespace()?;
    write!(rd, " ")?;

    rd.start_level()?;
    write!(rd, "{}", record.level().as_short_str())?;

    rd.start_whitespace()?;

    if use_file_location {
        rd.start_location()?;
        write!(
            rd,
            " [{}:{}]",
            record.location().file,
            record.location().line,
        )?;
    } else {
        write!(rd, " [{}]", record.module())?;
    }

    rd.start_whitespace()?;
    write!(rd, " ")?;

    rd.start_msg()?;
    let mut count_rd = slog_term::CountingWriter::new(&mut rd);
    write!(count_rd, "{}", record.msg())?;
    Ok(count_rd.count() != 0)
}

fn no_header(
    fn_timestamp: &dyn slog_term::ThreadSafeTimestampFn<Output = io::Result<()>>,
    mut rd: &mut dyn slog_term::RecordDecorator,
    record: &slog::Record,
    use_file_location: bool,
) -> io::Result<bool> {
    rd.start_msg()?;
    let mut count_rd = slog_term::CountingWriter::new(&mut rd);
    write!(count_rd, "{}", record.msg())?;
    Ok(count_rd.count() != 0)
}

fn new_logger(c: &Config) -> anyhow::Result<Option<Logger>> {
    if !c.stdout && c.file.is_none() {
        return Ok(None);
    }

    let lvl = match c.level {
        Level::Trace => Some(slog::Level::Trace),
        Level::Debug => Some(slog::Level::Debug),
        Level::Info => Some(slog::Level::Info),
        Level::Warn => Some(slog::Level::Warning),
        Level::Error => Some(slog::Level::Error),
        Level::Off => None,
    };

    let l = match lvl {
        Some(lvl) => {
            let filter = move |it: &slog::Record| it.level().is_at_least(lvl);

            let create_stdout_logger = || {
                let decorator = slog_term::TermDecorator::new().build();
                let mut bu = slog_term::FullFormat::new(decorator);
                bu = bu.use_custom_timestamp(custom_timestamp);
                bu = bu.use_custom_header_print(if c.noh { no_header } else { custom_header });
                if c.line_num {
                    bu = bu.use_file_location();
                }

                let drain = bu.build().fuse();
                slog_async::Async::new(drain)
                    .chan_size(c.chan_size.unwrap_or(DEFAULT_CHAN_SIZE))
                    .overflow_strategy(match c.overflow {
                        Some(Overflow::Block) | None => slog_async::OverflowStrategy::Block,
                        Some(Overflow::Drop) => slog_async::OverflowStrategy::DropAndReport,
                    })
                    .build()
                    .fuse()
            };

            match &c.file {
                Some(fc) => {
                    let path = Path::new(&fc.path);

                    if let Some(dir) = path.parent() {
                        std::fs::create_dir_all(dir)?;
                    }

                    let size = fc.rotate_size.unwrap_or(ByteSize::mb(128)).as_u64();
                    let rotate_bytes = u64::max(ByteSize::mb(16).as_u64(), size) as usize;

                    // 创建滚动日志
                    let file = FileRotate::open(
                        path,
                        RotationMode::BytesSurpassed(rotate_bytes),
                        usize::max(1, fc.rotate_num.unwrap_or(3)),
                    )?;

                    // 64KB缓冲, 加速日志写入
                    let file = io::BufWriter::with_capacity(64 * 1024, file);

                    let decorator = slog_term::PlainDecorator::new(file);

                    let mut bu = slog_term::FullFormat::new(decorator);
                    bu = bu.use_custom_timestamp(custom_timestamp);
                    bu = bu.use_custom_header_print(if c.noh { no_header } else { custom_header });
                    if c.line_num {
                        bu = bu.use_file_location();
                    }

                    let drain = bu.build().fuse();
                    let drain = slog_async::Async::new(drain)
                        .chan_size(c.chan_size.unwrap_or(DEFAULT_CHAN_SIZE))
                        .overflow_strategy(match c.overflow {
                            Some(Overflow::Block) | None => slog_async::OverflowStrategy::Block,
                            Some(Overflow::Drop) => slog_async::OverflowStrategy::DropAndReport,
                        })
                        .build()
                        .fuse();

                    if c.stdout {
                        let stdout = create_stdout_logger();
                        let drain = slog::Duplicate(stdout, drain).fuse();
                        let drain = slog::Filter::new(drain, filter).fuse();
                        Some(Logger::root(drain, slog::o!()))
                    } else {
                        let drain = slog::Filter::new(drain, filter).fuse();
                        Some(Logger::root(drain, slog::o!()))
                    }
                }
                None => {
                    let drain = create_stdout_logger();
                    let drain = slog::Filter::new(drain, filter).fuse();
                    Some(Logger::root(drain, slog::o!()))
                }
            }
        }
        None => None,
    };
    Ok(l)
}
