#![forbid(unsafe_code)]

use std::fmt;
use std::io;

/// All errors produced by the ext4fs library.
#[derive(Debug)]
pub enum Ext4Error {
    /// I/O error from the underlying reader.
    Io(io::Error),
    /// The superblock magic number was not 0xEF53.
    InvalidMagic { found: u16 },
    /// A superblock field is invalid or out of range.
    InvalidSuperblock(String),
    /// The filesystem uses an incompatible feature we cannot handle.
    UnsupportedFeature(String),
    /// The requested inode number is out of range.
    InodeOutOfRange { ino: u64, max: u64 },
    /// The requested block number is out of range.
    BlockOutOfRange { block: u64, max: u64 },
    /// A metadata structure is corrupt.
    CorruptMetadata { structure: &'static str, detail: String },
    /// CRC32C checksum mismatch.
    ChecksumMismatch { structure: &'static str, expected: u32, computed: u32 },
    /// Path does not exist.
    PathNotFound(String),
    /// Expected a directory, found something else.
    NotADirectory(String),
    /// Expected a symlink, found something else.
    NotASymlink(String),
    /// Too many levels of symbolic links.
    SymlinkLoop { path: String, depth: u32 },
    /// Filesystem has no journal.
    NoJournal,
    /// Journal data is corrupt.
    JournalCorrupt(String),
    /// Could not recover file data.
    RecoveryFailed { ino: u64, reason: String },
    /// Insufficient data to parse a structure.
    TooShort { structure: &'static str, expected: usize, found: usize },
}

impl fmt::Display for Ext4Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::InvalidMagic { found } => write!(f, "invalid superblock magic: 0x{found:04X} (expected 0xEF53)"),
            Self::InvalidSuperblock(msg) => write!(f, "invalid superblock: {msg}"),
            Self::UnsupportedFeature(feat) => write!(f, "unsupported feature: {feat}"),
            Self::InodeOutOfRange { ino, max } => write!(f, "inode {ino} out of range (max {max})"),
            Self::BlockOutOfRange { block, max } => write!(f, "block {block} out of range (max {max})"),
            Self::CorruptMetadata { structure, detail } => write!(f, "corrupt {structure}: {detail}"),
            Self::ChecksumMismatch { structure, expected, computed } => {
                write!(f, "checksum mismatch in {structure}: expected 0x{expected:08X}, computed 0x{computed:08X}")
            }
            Self::PathNotFound(p) => write!(f, "path not found: {p}"),
            Self::NotADirectory(p) => write!(f, "not a directory: {p}"),
            Self::NotASymlink(p) => write!(f, "not a symlink: {p}"),
            Self::SymlinkLoop { path, depth } => write!(f, "symlink loop at {path} (depth {depth})"),
            Self::NoJournal => write!(f, "filesystem has no journal"),
            Self::JournalCorrupt(msg) => write!(f, "journal corrupt: {msg}"),
            Self::RecoveryFailed { ino, reason } => write!(f, "recovery failed for inode {ino}: {reason}"),
            Self::TooShort { structure, expected, found } => {
                write!(f, "{structure}: need {expected} bytes, got {found}")
            }
        }
    }
}

impl std::error::Error for Ext4Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Ext4Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, Ext4Error>;
