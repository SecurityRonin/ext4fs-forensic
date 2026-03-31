#![forbid(unsafe_code)]
use crate::error::{Ext4Error, Result};

pub const XATTR_MAGIC: u32 = 0xEA020000;

// ---------------------------------------------------------------------------
// Little-endian read helpers
// ---------------------------------------------------------------------------

fn le16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn le32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

// ---------------------------------------------------------------------------
// XattrNamespace
// ---------------------------------------------------------------------------

/// The namespace prefix index stored in each xattr entry header.
///
/// Values follow the kernel ext4 definitions:
///   1 = user, 2 = posix_acl_access (security), 3 = posix_acl_default,
///   4 = trusted, 6 = security (LSM), 7 = system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XattrNamespace {
    User,
    Security,
    Trusted,
    System,
    Unknown(u8),
}

impl From<u8> for XattrNamespace {
    fn from(v: u8) -> Self {
        match v {
            1 => XattrNamespace::User,
            2 | 3 => XattrNamespace::Security,
            4 => XattrNamespace::Trusted,
            6 | 7 => XattrNamespace::System,
            other => XattrNamespace::Unknown(other),
        }
    }
}

// ---------------------------------------------------------------------------
// XattrBlockHeader
// ---------------------------------------------------------------------------

/// On-disk header of an external xattr block (first 32 bytes).
///
/// Layout (all little-endian):
///   0..4   magic      (must be 0xEA020000)
///   4..8   refcount
///   8..12  blocks
///   12..16 hash
///   16..20 checksum   (metadata checksum when has_metadata_csum feature set)
///   20..32 reserved
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XattrBlockHeader {
    pub magic: u32,
    pub refcount: u32,
    pub blocks: u32,
    pub hash: u32,
    pub checksum: u32,
}

impl XattrBlockHeader {
    /// Minimum size of the header in bytes.
    pub const MIN_SIZE: usize = 32;

    /// Parse an xattr block header from `buf`.
    ///
    /// Returns `Err(CorruptMetadata)` if the buffer is too short or the magic
    /// number does not match `XATTR_MAGIC`.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::MIN_SIZE {
            return Err(Ext4Error::TooShort {
                structure: "XattrBlockHeader",
                expected: Self::MIN_SIZE,
                found: buf.len(),
            });
        }

        let magic = le32(buf, 0);
        if magic != XATTR_MAGIC {
            return Err(Ext4Error::CorruptMetadata {
                structure: "XattrBlockHeader",
                detail: format!("bad magic: 0x{magic:08X} (expected 0x{XATTR_MAGIC:08X})"),
            });
        }

        Ok(XattrBlockHeader {
            magic,
            refcount: le32(buf, 4),
            blocks: le32(buf, 8),
            hash: le32(buf, 12),
            checksum: le32(buf, 16),
        })
    }
}

// ---------------------------------------------------------------------------
// XattrEntry
// ---------------------------------------------------------------------------

/// One parsed xattr entry.
///
/// On-disk entry layout (all little-endian):
///   0      name_len   (u8)
///   1      name_index (u8) → XattrNamespace
///   2..4   value_offs (u16) — offset from start of value region
///   4..8   value_inum (u32) — inode for ea_inode feature (0 otherwise)
///   8..12  value_size (u32)
///   12..16 hash       (u32)
///   16..   name       (name_len bytes, NOT NUL-terminated)
///
/// `entry_size` is the total byte length of the entry, rounded up to a
/// 4-byte boundary:  (16 + name_len + 3) & !3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XattrEntry {
    pub name_index: XattrNamespace,
    pub name: Vec<u8>,
    pub value_offset: u16,
    pub value_inum: u32,
    pub value_size: u32,
    pub hash: u32,
    /// Total byte size of this entry (4-byte aligned), useful for advancing
    /// through a packed list of entries.
    pub entry_size: usize,
}

impl XattrEntry {
    /// Minimum fixed-header size (before the variable-length name).
    const HEADER_SIZE: usize = 16;

    /// Parse one xattr entry from the beginning of `buf`.
    ///
    /// Returns `Err(TooShort)` if `buf` is too small to contain the fixed
    /// header or the declared name.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::HEADER_SIZE {
            return Err(Ext4Error::TooShort {
                structure: "XattrEntry",
                expected: Self::HEADER_SIZE,
                found: buf.len(),
            });
        }

        let name_len = buf[0] as usize;
        let name_index = XattrNamespace::from(buf[1]);
        let value_offset = le16(buf, 2);
        let value_inum = le32(buf, 4);
        let value_size = le32(buf, 8);
        let hash = le32(buf, 12);

        let name_end = Self::HEADER_SIZE + name_len;
        if buf.len() < name_end {
            return Err(Ext4Error::TooShort {
                structure: "XattrEntry name",
                expected: name_end,
                found: buf.len(),
            });
        }

        let name = buf[Self::HEADER_SIZE..name_end].to_vec();

        // 4-byte aligned total size
        let entry_size = (Self::HEADER_SIZE + name_len + 3) & !3;

        Ok(XattrEntry {
            name_index,
            name,
            value_offset,
            value_inum,
            value_size,
            hash,
            entry_size,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_xattr_header() {
        let mut buf = vec![0u8; 32];
        buf[0..4].copy_from_slice(&0xEA020000u32.to_le_bytes());
        buf[4..8].copy_from_slice(&1u32.to_le_bytes()); // refcount
        buf[8..12].copy_from_slice(&1u32.to_le_bytes()); // blocks
        let hdr = XattrBlockHeader::parse(&buf).unwrap();
        assert_eq!(hdr.magic, XATTR_MAGIC);
        assert_eq!(hdr.refcount, 1);
        assert_eq!(hdr.blocks, 1);
    }

    #[test]
    fn reject_bad_xattr_magic() {
        let buf = vec![0u8; 32];
        let err = XattrBlockHeader::parse(&buf).unwrap_err();
        assert!(matches!(err, crate::error::Ext4Error::CorruptMetadata { .. }));
    }

    #[test]
    fn parse_xattr_entry() {
        let mut buf = vec![0u8; 20];
        buf[0] = 4; // name_len
        buf[1] = 1; // name_index (user)
        buf[2..4].copy_from_slice(&100u16.to_le_bytes()); // value_offs
        buf[8..12].copy_from_slice(&5u32.to_le_bytes()); // value_size
        buf[16..20].copy_from_slice(b"test"); // name
        let entry = XattrEntry::parse(&buf).unwrap();
        assert_eq!(entry.name_index, XattrNamespace::User);
        assert_eq!(entry.name, b"test");
        assert_eq!(entry.value_offset, 100);
        assert_eq!(entry.value_size, 5);
    }
}
