#![forbid(unsafe_code)]
use crate::error::{Ext4Error, Result};

pub const JOURNAL_MAGIC: u32 = 0xC03B3998;

// JBD2 feature incompat flags
pub const JBD2_FEATURE_INCOMPAT_64BIT: u32 = 0x00000002;
pub const JBD2_FEATURE_INCOMPAT_CSUM_V2: u32 = 0x00000008;
pub const JBD2_FEATURE_INCOMPAT_CSUM_V3: u32 = 0x00000010;

// ── helpers ──────────────────────────────────────────────────────────────────

#[inline]
fn be32(buf: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(buf[off..off + 4].try_into().unwrap())
}

#[inline]
fn be64(buf: &[u8], off: usize) -> u64 {
    u64::from_be_bytes(buf[off..off + 8].try_into().unwrap())
}

fn check_len(buf: &[u8], need: usize, structure: &'static str) -> Result<()> {
    if buf.len() < need {
        Err(Ext4Error::TooShort { structure, expected: need, found: buf.len() })
    } else {
        Ok(())
    }
}

// ── JournalBlockType ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalBlockType {
    Descriptor,
    Commit,
    SuperblockV1,
    SuperblockV2,
    Revoke,
    Unknown(u32),
}

impl From<u32> for JournalBlockType {
    fn from(v: u32) -> Self {
        match v {
            1 => Self::Descriptor,
            2 => Self::Commit,
            3 => Self::SuperblockV1,
            4 => Self::SuperblockV2,
            5 => Self::Revoke,
            other => Self::Unknown(other),
        }
    }
}

// ── JournalHeader ─────────────────────────────────────────────────────────────

/// Common 12-byte header present at the start of every JBD2 block.
#[derive(Debug, Clone)]
pub struct JournalHeader {
    pub magic: u32,
    pub block_type: JournalBlockType,
    pub sequence: u32,
}

impl JournalHeader {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        check_len(buf, 12, "JournalHeader")?;
        let magic = be32(buf, 0);
        if magic != JOURNAL_MAGIC {
            return Err(Ext4Error::JournalCorrupt(format!(
                "bad journal magic: 0x{magic:08X}"
            )));
        }
        Ok(Self {
            magic,
            block_type: JournalBlockType::from(be32(buf, 4)),
            sequence: be32(buf, 8),
        })
    }
}

// ── JournalSuperblock ─────────────────────────────────────────────────────────

/// JBD2 superblock (journal block 0).
///
/// Offsets (all big-endian):
///   0x00 header (12 bytes)
///   0x0C block_size
///   0x10 max_len
///   0x14 first
///   0x18 sequence
///   0x1C start
///   0x20 errno
///   0x24 feature_compat
///   0x28 feature_incompat
///   0x2C feature_ro_compat
///   0x30 uuid (16 bytes)
///   0x40 nr_users
///   0x44 dynsuper
///   0x48 max_transaction
///   0x4C max_trans_data
///   0x50 checksum_type (1 byte)
///   0xFC checksum (u32)
#[derive(Debug, Clone)]
pub struct JournalSuperblock {
    pub header: JournalHeader,
    pub block_size: u32,
    pub max_len: u32,
    pub first: u32,
    pub sequence: u32,
    pub start: u32,
    pub errno: u32,
    pub feature_compat: u32,
    pub feature_incompat: u32,
    pub feature_ro_compat: u32,
    pub uuid: [u8; 16],
    pub nr_users: u32,
    pub checksum_type: u8,
    pub checksum: u32,
}

impl JournalSuperblock {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        check_len(buf, 0x100, "JournalSuperblock")?;
        let header = JournalHeader::parse(buf)?;
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&buf[0x30..0x40]);
        Ok(Self {
            header,
            block_size: be32(buf, 0x0C),
            max_len: be32(buf, 0x10),
            first: be32(buf, 0x14),
            sequence: be32(buf, 0x18),
            start: be32(buf, 0x1C),
            errno: be32(buf, 0x20),
            feature_compat: be32(buf, 0x24),
            feature_incompat: be32(buf, 0x28),
            feature_ro_compat: be32(buf, 0x2C),
            uuid,
            nr_users: be32(buf, 0x40),
            checksum_type: buf[0x50],
            checksum: be32(buf, 0xFC),
        })
    }

    pub fn is_64bit(&self) -> bool {
        self.feature_incompat & JBD2_FEATURE_INCOMPAT_64BIT != 0
    }

    pub fn has_csum_v3(&self) -> bool {
        self.feature_incompat & JBD2_FEATURE_INCOMPAT_CSUM_V3 != 0
    }

    pub fn has_csum_v2(&self) -> bool {
        self.feature_incompat & JBD2_FEATURE_INCOMPAT_CSUM_V2 != 0
    }
}

// ── JournalBlockTag ───────────────────────────────────────────────────────────

/// A block tag inside a descriptor block.
///
/// v3 layout (16 bytes, same_uuid=true) or 32 bytes (same_uuid=false):
///   0x00  blocknr_lo (u32)
///   0x04  flags (u32)  bit0=escaped, bit1=same_uuid, bit3=last_tag
///   0x08  blocknr_hi (u32, only meaningful when is_64bit)
///   0x0C  checksum (u32)
///   0x10  uuid (16 bytes, present only when same_uuid=false)
#[derive(Debug, Clone)]
pub struct JournalBlockTag {
    pub blocknr: u64,
    pub checksum: u32,
    pub escaped: bool,
    pub same_uuid: bool,
    pub last_tag: bool,
    /// Byte size consumed by this tag in the descriptor block.
    pub tag_size: usize,
}

impl JournalBlockTag {
    pub fn parse_v3(buf: &[u8], is_64bit: bool) -> Self {
        let blocknr_lo = be32(buf, 0x00) as u64;
        let flags = be32(buf, 0x04);
        let escaped = flags & 0x01 != 0;
        let same_uuid = flags & 0x02 != 0;
        let last_tag = flags & 0x08 != 0;
        let blocknr_hi = if is_64bit { be32(buf, 0x08) as u64 } else { 0 };
        let blocknr = (blocknr_hi << 32) | blocknr_lo;
        let checksum = be32(buf, 0x0C);
        // 16-byte base + 16-byte UUID when uuid is not shared
        let tag_size = if same_uuid { 16 } else { 32 };
        Self { blocknr, checksum, escaped, same_uuid, last_tag, tag_size }
    }
}

// ── JournalCommit ─────────────────────────────────────────────────────────────

/// Commit block — marks end of a complete transaction.
///
/// Offsets (beyond the 12-byte header):
///   0x0C  checksum_type (u8)
///   0x0D  checksum_size (u8)
///   0x30  commit_seconds (i64 BE)
///   0x38  commit_nanoseconds (u32 BE)
#[derive(Debug, Clone)]
pub struct JournalCommit {
    pub sequence: u32,
    pub commit_seconds: i64,
    pub commit_nanoseconds: u32,
}

impl JournalCommit {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        check_len(buf, 0x3C, "JournalCommit")?;
        let header = JournalHeader::parse(buf)?;
        Ok(Self {
            sequence: header.sequence,
            commit_seconds: be64(buf, 0x30) as i64,
            commit_nanoseconds: be32(buf, 0x38),
        })
    }
}

// ── JournalRevoke ─────────────────────────────────────────────────────────────

/// Revoke block — lists blocks whose old versions must not be replayed.
///
/// Layout:
///   0x00  header (12 bytes)
///   0x0C  count (u32) — total byte length of revoke data (including header)
///   0x10  revoked block numbers (u32 or u64 each, depending on 64bit flag)
#[derive(Debug, Clone)]
pub struct JournalRevoke {
    pub sequence: u32,
    pub revoked_blocks: Vec<u64>,
}

impl JournalRevoke {
    pub fn parse(buf: &[u8], is_64bit: bool) -> Result<Self> {
        check_len(buf, 16, "JournalRevoke")?;
        let header = JournalHeader::parse(buf)?;
        let byte_count = be32(buf, 12) as usize;
        check_len(buf, byte_count, "JournalRevoke data")?;
        let entry_size = if is_64bit { 8usize } else { 4 };
        let data = &buf[16..byte_count];
        let mut revoked_blocks = Vec::with_capacity(data.len() / entry_size);
        let mut off = 0;
        while off + entry_size <= data.len() {
            let blk = if is_64bit {
                be64(data, off)
            } else {
                be32(data, off) as u64
            };
            revoked_blocks.push(blk);
            off += entry_size;
        }
        Ok(Self { sequence: header.sequence, revoked_blocks })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_journal_header() {
        let mut buf = vec![0u8; 12];
        buf[0..4].copy_from_slice(&0xC03B3998u32.to_be_bytes());
        buf[4..8].copy_from_slice(&1u32.to_be_bytes()); // descriptor
        buf[8..12].copy_from_slice(&42u32.to_be_bytes());
        let hdr = JournalHeader::parse(&buf).unwrap();
        assert_eq!(hdr.magic, JOURNAL_MAGIC);
        assert_eq!(hdr.block_type, JournalBlockType::Descriptor);
        assert_eq!(hdr.sequence, 42);
    }

    #[test]
    fn reject_bad_journal_magic() {
        let buf = vec![0u8; 12];
        let err = JournalHeader::parse(&buf).unwrap_err();
        assert!(matches!(err, crate::error::Ext4Error::JournalCorrupt(_)));
    }

    #[test]
    fn parse_journal_superblock() {
        let mut buf = vec![0u8; 1024];
        buf[0..4].copy_from_slice(&JOURNAL_MAGIC.to_be_bytes());
        buf[4..8].copy_from_slice(&4u32.to_be_bytes()); // sb_v2
        buf[8..12].copy_from_slice(&1u32.to_be_bytes());
        buf[0x0C..0x10].copy_from_slice(&4096u32.to_be_bytes()); // block_size
        buf[0x10..0x14].copy_from_slice(&1024u32.to_be_bytes()); // max_len
        buf[0x14..0x18].copy_from_slice(&1u32.to_be_bytes()); // first
        let jsb = JournalSuperblock::parse(&buf).unwrap();
        assert_eq!(jsb.block_size, 4096);
        assert_eq!(jsb.max_len, 1024);
        assert_eq!(jsb.first, 1);
    }

    #[test]
    fn parse_block_tag_v3() {
        let mut buf = vec![0u8; 16];
        buf[0..4].copy_from_slice(&500u32.to_be_bytes()); // blocknr
        buf[4..8].copy_from_slice(&0x08u32.to_be_bytes()); // flags: LAST_TAG
        buf[12..16].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
        let tag = JournalBlockTag::parse_v3(&buf, false);
        assert_eq!(tag.blocknr, 500);
        assert!(tag.last_tag);
        assert!(!tag.escaped);
    }

    #[test]
    fn parse_commit_block() {
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(&JOURNAL_MAGIC.to_be_bytes());
        buf[4..8].copy_from_slice(&2u32.to_be_bytes()); // commit
        buf[8..12].copy_from_slice(&99u32.to_be_bytes());
        buf[0x30..0x38].copy_from_slice(&1_700_000_000u64.to_be_bytes());
        buf[0x38..0x3C].copy_from_slice(&500_000_000u32.to_be_bytes());
        let commit = JournalCommit::parse(&buf).unwrap();
        assert_eq!(commit.sequence, 99);
        assert_eq!(commit.commit_seconds, 1_700_000_000);
        assert_eq!(commit.commit_nanoseconds, 500_000_000);
    }
}
