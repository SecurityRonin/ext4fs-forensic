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

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn display_io() {
        let err = Ext4Error::Io(io::Error::new(io::ErrorKind::NotFound, "gone"));
        let msg = err.to_string();
        assert!(msg.contains("I/O error"), "got: {msg}");
        assert!(msg.contains("gone"), "got: {msg}");
    }

    #[test]
    fn display_invalid_magic() {
        let err = Ext4Error::InvalidMagic { found: 0xBEEF };
        let msg = err.to_string();
        assert!(msg.contains("BEEF"), "got: {msg}");
        assert!(msg.contains("0xEF53"), "got: {msg}");
    }

    #[test]
    fn display_invalid_superblock() {
        let err = Ext4Error::InvalidSuperblock("bad field".into());
        let msg = err.to_string();
        assert!(msg.contains("invalid superblock"), "got: {msg}");
        assert!(msg.contains("bad field"), "got: {msg}");
    }

    #[test]
    fn display_unsupported_feature() {
        let err = Ext4Error::UnsupportedFeature("inline_data".into());
        let msg = err.to_string();
        assert!(msg.contains("unsupported feature"), "got: {msg}");
        assert!(msg.contains("inline_data"), "got: {msg}");
    }

    #[test]
    fn display_inode_out_of_range() {
        let err = Ext4Error::InodeOutOfRange { ino: 999, max: 100 };
        let msg = err.to_string();
        assert!(msg.contains("999"), "got: {msg}");
        assert!(msg.contains("100"), "got: {msg}");
    }

    #[test]
    fn display_block_out_of_range() {
        let err = Ext4Error::BlockOutOfRange { block: 50, max: 10 };
        let msg = err.to_string();
        assert!(msg.contains("50"), "got: {msg}");
        assert!(msg.contains("10"), "got: {msg}");
    }

    #[test]
    fn display_corrupt_metadata() {
        let err = Ext4Error::CorruptMetadata {
            structure: "group_desc",
            detail: "bad checksum".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("corrupt group_desc"), "got: {msg}");
        assert!(msg.contains("bad checksum"), "got: {msg}");
    }

    #[test]
    fn display_checksum_mismatch() {
        let err = Ext4Error::ChecksumMismatch {
            structure: "inode",
            expected: 0xDEADBEEF,
            computed: 0xCAFEBABE,
        };
        let msg = err.to_string();
        assert!(msg.contains("inode"), "got: {msg}");
        assert!(msg.contains("DEADBEEF"), "got: {msg}");
        assert!(msg.contains("CAFEBABE"), "got: {msg}");
    }

    #[test]
    fn display_path_not_found() {
        let err = Ext4Error::PathNotFound("/missing".into());
        let msg = err.to_string();
        assert!(msg.contains("path not found"), "got: {msg}");
        assert!(msg.contains("/missing"), "got: {msg}");
    }

    #[test]
    fn display_not_a_directory() {
        let err = Ext4Error::NotADirectory("/file".into());
        let msg = err.to_string();
        assert!(msg.contains("not a directory"), "got: {msg}");
    }

    #[test]
    fn display_not_a_symlink() {
        let err = Ext4Error::NotASymlink("/regular".into());
        let msg = err.to_string();
        assert!(msg.contains("not a symlink"), "got: {msg}");
    }

    #[test]
    fn display_symlink_loop() {
        let err = Ext4Error::SymlinkLoop {
            path: "/a".into(),
            depth: 40,
        };
        let msg = err.to_string();
        assert!(msg.contains("symlink loop"), "got: {msg}");
        assert!(msg.contains("40"), "got: {msg}");
    }

    #[test]
    fn display_no_journal() {
        let err = Ext4Error::NoJournal;
        let msg = err.to_string();
        assert!(msg.contains("no journal"), "got: {msg}");
    }

    #[test]
    fn display_journal_corrupt() {
        let err = Ext4Error::JournalCorrupt("truncated".into());
        let msg = err.to_string();
        assert!(msg.contains("journal corrupt"), "got: {msg}");
        assert!(msg.contains("truncated"), "got: {msg}");
    }

    #[test]
    fn display_recovery_failed() {
        let err = Ext4Error::RecoveryFailed {
            ino: 42,
            reason: "zeroed".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("42"), "got: {msg}");
        assert!(msg.contains("zeroed"), "got: {msg}");
    }

    #[test]
    fn display_too_short() {
        let err = Ext4Error::TooShort {
            structure: "extent_header",
            expected: 12,
            found: 4,
        };
        let msg = err.to_string();
        assert!(msg.contains("extent_header"), "got: {msg}");
        assert!(msg.contains("12"), "got: {msg}");
        assert!(msg.contains("4"), "got: {msg}");
    }

    #[test]
    fn source_io_returns_some() {
        let err = Ext4Error::Io(io::Error::new(io::ErrorKind::BrokenPipe, "pipe"));
        assert!(err.source().is_some());
    }

    #[test]
    fn source_non_io_returns_none() {
        let err = Ext4Error::NoJournal;
        assert!(err.source().is_none());

        let err = Ext4Error::InvalidMagic { found: 0 };
        assert!(err.source().is_none());

        let err = Ext4Error::PathNotFound("x".into());
        assert!(err.source().is_none());
    }

    #[test]
    fn from_io_error() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        let ext4_err: Ext4Error = io_err.into();
        match ext4_err {
            Ext4Error::Io(_) => {}
            other => panic!("expected Io variant, got: {other:?}"),
        }
    }
}
