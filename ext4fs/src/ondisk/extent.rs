#![forbid(unsafe_code)]
use crate::error::{Ext4Error, Result};

pub const EXTENT_MAGIC: u16 = 0xF30A;

// ---------------------------------------------------------------------------
// Local LE helpers
// ---------------------------------------------------------------------------

#[inline]
fn le16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

#[inline]
fn le32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

// ---------------------------------------------------------------------------
// ExtentHeader  (12 bytes, on-disk: ext4_extent_header)
//   0  magic       u16 LE
//   2  entries     u16 LE
//   4  max         u16 LE
//   6  depth       u16 LE
//   8  generation  u32 LE
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtentHeader {
    pub magic:      u16,
    pub entries:    u16,
    pub max:        u16,
    pub depth:      u16,
    pub generation: u32,
}

impl ExtentHeader {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 12 {
            return Err(Ext4Error::TooShort {
                structure: "ExtentHeader",
                expected:  12,
                found:     buf.len(),
            });
        }
        let magic = le16(buf, 0);
        if magic != EXTENT_MAGIC {
            return Err(Ext4Error::CorruptMetadata {
                structure: "ExtentHeader",
                detail:    format!("bad magic: 0x{magic:04X}"),
            });
        }
        Ok(Self {
            magic,
            entries:    le16(buf, 2),
            max:        le16(buf, 4),
            depth:      le16(buf, 6),
            generation: le32(buf, 8),
        })
    }
}

// ---------------------------------------------------------------------------
// ExtentLeaf  (12 bytes, on-disk: ext4_extent)
//   0  ee_block     u32 LE  — first logical block
//   4  ee_len       u16 LE  — bit 15: unwritten; bits 14-0: length
//   6  ee_start_hi  u16 LE  — high 16 bits of physical block
//   8  ee_start_lo  u32 LE  — low 32 bits of physical block
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtentLeaf {
    pub logical_block:  u32,
    pub length:         u16,
    pub physical_block: u64,
    pub unwritten:      bool,
}

impl ExtentLeaf {
    pub fn parse(buf: &[u8]) -> Self {
        let logical_block = le32(buf, 0);
        let ee_len        = le16(buf, 4);
        let start_hi      = le16(buf, 6) as u64;
        let start_lo      = le32(buf, 8) as u64;

        let unwritten     = (ee_len & 0x8000) != 0;
        let length        = ee_len & 0x7FFF;
        let physical_block = (start_hi << 32) | start_lo;

        Self { logical_block, length, physical_block, unwritten }
    }
}

// ---------------------------------------------------------------------------
// ExtentIndex  (12 bytes, on-disk: ext4_extent_idx)
//   0  ei_block    u32 LE  — first logical block covered by this subtree
//   4  ei_leaf_lo  u32 LE  — low 32 bits of child block
//   8  ei_leaf_hi  u16 LE  — high 16 bits of child block
//  10  (unused)    u16
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtentIndex {
    pub logical_block: u32,
    pub child_block:   u64,
}

impl ExtentIndex {
    pub fn parse(buf: &[u8]) -> Self {
        let logical_block = le32(buf, 0);
        let leaf_lo       = le32(buf, 4) as u64;
        let leaf_hi       = le16(buf, 8) as u64;
        let child_block   = (leaf_hi << 32) | leaf_lo;
        Self { logical_block, child_block }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_extent_header() {
        let mut buf = vec![0u8; 12];
        buf[0] = 0x0A; buf[1] = 0xF3; // magic 0xF30A
        buf[2] = 3;                    // entries
        buf[4] = 4;                    // max
        buf[6] = 0;                    // depth (leaf)
        let hdr = ExtentHeader::parse(&buf).unwrap();
        assert_eq!(hdr.magic,   EXTENT_MAGIC);
        assert_eq!(hdr.entries, 3);
        assert_eq!(hdr.max,     4);
        assert_eq!(hdr.depth,   0);
    }

    #[test]
    fn reject_bad_magic() {
        let buf = vec![0u8; 12];
        let err = ExtentHeader::parse(&buf).unwrap_err();
        assert!(matches!(err, crate::error::Ext4Error::CorruptMetadata { .. }));
    }

    #[test]
    fn parse_extent_leaf() {
        let mut buf = vec![0u8; 12];
        buf[4] = 10;                   // ee_len = 10
        buf[8] = 0xF4; buf[9] = 0x01; // ee_start_lo = 500 (0x01F4)
        let leaf = ExtentLeaf::parse(&buf);
        assert_eq!(leaf.logical_block,  0);
        assert_eq!(leaf.length,         10);
        assert_eq!(leaf.physical_block, 500);
        assert!(!leaf.unwritten);
    }

    #[test]
    fn extent_leaf_unwritten_flag() {
        let mut buf = vec![0u8; 12];
        buf[4] = 0x05; buf[5] = 0x80; // ee_len with bit 15 set
        let leaf = ExtentLeaf::parse(&buf);
        assert_eq!(leaf.length, 5);
        assert!(leaf.unwritten);
    }

    #[test]
    fn parse_extent_index() {
        let mut buf = vec![0u8; 12];
        buf[0] = 0xE8; buf[1] = 0x03; // ei_block = 1000
        buf[4] = 0xD0; buf[5] = 0x07; // ei_leaf_lo = 2000
        buf[8] = 1;                    // ei_leaf_hi = 1
        let idx = ExtentIndex::parse(&buf);
        assert_eq!(idx.logical_block, 1000);
        assert_eq!(idx.child_block,   (1u64 << 32) | 2000);
    }
}
