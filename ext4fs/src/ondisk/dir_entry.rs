#![forbid(unsafe_code)]
use crate::error::{Ext4Error, Result};

/// File type stored in the dir_entry file_type byte (ext2 dir_entry_2 format).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirEntryType {
    Unknown,
    RegularFile,
    Directory,
    CharDevice,
    BlockDevice,
    Fifo,
    Socket,
    Symlink,
}

impl From<u8> for DirEntryType {
    fn from(v: u8) -> Self {
        match v {
            1 => Self::RegularFile,
            2 => Self::Directory,
            3 => Self::CharDevice,
            4 => Self::BlockDevice,
            5 => Self::Fifo,
            6 => Self::Socket,
            7 => Self::Symlink,
            _ => Self::Unknown,
        }
    }
}

/// A single directory entry parsed from an ext4 directory data block.
///
/// Layout (all little-endian):
///   0..4  inode    u32
///   4..6  rec_len  u16
///   6     name_len u8
///   7     file_type u8
///   8..8+name_len  name bytes
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub inode: u32,
    pub rec_len: u16,
    pub name: Vec<u8>,
    pub file_type: DirEntryType,
}

const HEADER_LEN: usize = 8;

impl DirEntry {
    /// Parse a single directory entry from the start of `buf`.
    ///
    /// Returns `Err(TooShort)` if the buffer is shorter than the 8-byte header
    /// or shorter than the full entry (header + name).
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_LEN {
            return Err(Ext4Error::TooShort {
                structure: "DirEntry",
                expected: HEADER_LEN,
                found: buf.len(),
            });
        }

        let inode = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let rec_len = u16::from_le_bytes(buf[4..6].try_into().unwrap());
        let name_len = buf[6] as usize;
        let file_type = DirEntryType::from(buf[7]);

        let needed = HEADER_LEN + name_len;
        if buf.len() < needed {
            return Err(Ext4Error::TooShort {
                structure: "DirEntry name",
                expected: needed,
                found: buf.len(),
            });
        }

        let name = buf[HEADER_LEN..HEADER_LEN + name_len].to_vec();

        Ok(Self { inode, rec_len, name, file_type })
    }

    /// Return the entry name as a lossy UTF-8 string.
    pub fn name_str(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }

    /// An entry with inode == 0 has been deleted (the space is reused by rec_len).
    pub fn is_deleted(&self) -> bool {
        self.inode == 0
    }
}

/// Iterate through every directory entry in a directory data block.
///
/// Stops at the end of the block or if `rec_len` is zero (would loop forever).
/// Entries with `inode == 0` are included — callers decide whether to skip them.
pub fn parse_dir_block(block: &[u8]) -> Vec<DirEntry> {
    let mut entries = Vec::new();
    let mut offset = 0usize;

    while offset < block.len() {
        let remaining = &block[offset..];
        match DirEntry::parse(remaining) {
            Ok(entry) => {
                let rec_len = entry.rec_len as usize;
                entries.push(entry);
                if rec_len == 0 {
                    break; // guard against infinite loop on corrupt data
                }
                offset += rec_len;
            }
            Err(_) => break,
        }
    }

    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dir_entry() {
        let mut buf = vec![0u8; 20];
        buf[0] = 12; // inode
        buf[4] = 20; // rec_len
        buf[6] = 5;  // name_len
        buf[7] = 1;  // file_type (regular)
        buf[8..13].copy_from_slice(b"hello");
        let entry = DirEntry::parse(&buf).unwrap();
        assert_eq!(entry.inode, 12);
        assert_eq!(entry.rec_len, 20);
        assert_eq!(entry.name, b"hello");
        assert_eq!(entry.file_type, DirEntryType::RegularFile);
    }

    #[test]
    fn parse_dot_entries() {
        let mut buf = vec![0u8; 12];
        buf[0] = 2; buf[4] = 12; buf[6] = 1; buf[7] = 2; buf[8] = b'.';
        let entry = DirEntry::parse(&buf).unwrap();
        assert_eq!(entry.name, b".");
        assert_eq!(entry.file_type, DirEntryType::Directory);
    }

    #[test]
    fn skip_deleted_entry() {
        let mut buf = vec![0u8; 12];
        buf[0] = 0; buf[4] = 12; buf[6] = 3; buf[7] = 1;
        buf[8..11].copy_from_slice(b"foo");
        let entry = DirEntry::parse(&buf).unwrap();
        assert_eq!(entry.inode, 0);
    }

    #[test]
    fn reject_too_short() {
        let buf = vec![0u8; 4];
        let err = DirEntry::parse(&buf).unwrap_err();
        assert!(matches!(err, crate::error::Ext4Error::TooShort { .. }));
    }

    #[test]
    fn is_deleted_flag() {
        let mut buf = vec![0u8; 12];
        buf[0] = 0; buf[4] = 12; buf[6] = 3; buf[7] = 1;
        buf[8..11].copy_from_slice(b"del");
        let entry = DirEntry::parse(&buf).unwrap();
        assert!(entry.is_deleted());
    }

    #[test]
    fn name_str_utf8() {
        let mut buf = vec![0u8; 13];
        buf[0] = 5; buf[4] = 13; buf[6] = 5; buf[7] = 1;
        buf[8..13].copy_from_slice(b"world");
        let entry = DirEntry::parse(&buf).unwrap();
        assert_eq!(entry.name_str(), "world");
    }

    #[test]
    fn parse_dir_block_multiple_entries() {
        // Two back-to-back 12-byte entries.
        let mut block = vec![0u8; 24];
        // Entry 1: inode=1, rec_len=12, name_len=1, type=2 (dir), name="."
        block[0] = 1; block[4] = 12; block[6] = 1; block[7] = 2; block[8] = b'.';
        // Entry 2: inode=2, rec_len=12, name_len=2, type=2 (dir), name=".."
        block[12] = 2; block[16] = 12; block[18] = 2; block[19] = 2;
        block[20] = b'.'; block[21] = b'.';
        let entries = parse_dir_block(&block);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, b".");
        assert_eq!(entries[1].name, b"..");
    }

    #[test]
    fn dir_entry_type_from_u8() {
        assert_eq!(DirEntryType::from(0), DirEntryType::Unknown);
        assert_eq!(DirEntryType::from(1), DirEntryType::RegularFile);
        assert_eq!(DirEntryType::from(2), DirEntryType::Directory);
        assert_eq!(DirEntryType::from(3), DirEntryType::CharDevice);
        assert_eq!(DirEntryType::from(4), DirEntryType::BlockDevice);
        assert_eq!(DirEntryType::from(5), DirEntryType::Fifo);
        assert_eq!(DirEntryType::from(6), DirEntryType::Socket);
        assert_eq!(DirEntryType::from(7), DirEntryType::Symlink);
        assert_eq!(DirEntryType::from(255), DirEntryType::Unknown);
    }
}
