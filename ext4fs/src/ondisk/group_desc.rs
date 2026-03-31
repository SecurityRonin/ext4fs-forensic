#![forbid(unsafe_code)]

use crate::error::{Ext4Error, Result};
use bitflags::bitflags;

// ---------------------------------------------------------------------------
// Helper functions for little-endian reads
// ---------------------------------------------------------------------------

fn le16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn le32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

// ---------------------------------------------------------------------------
// Group descriptor flags
// ---------------------------------------------------------------------------

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct GroupDescFlags: u16 {
        const INODE_UNINIT  = 0x0001;
        const BLOCK_UNINIT  = 0x0002;
        const INODE_ZEROED  = 0x0004;
    }
}

// ---------------------------------------------------------------------------
// GroupDescriptor — normalized 32-bit + optional 64-bit hi fields
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct GroupDescriptor {
    pub block_bitmap:      u64,
    pub inode_bitmap:      u64,
    pub inode_table:       u64,
    pub free_blocks_count: u32,
    pub free_inodes_count: u32,
    pub used_dirs_count:   u32,
    pub flags:             GroupDescFlags,
    pub itable_unused:     u32,
    pub checksum:          u16,
}

impl GroupDescriptor {
    pub fn parse(buf: &[u8], desc_size: u16) -> Result<Self> {
        let min_len = desc_size as usize;
        if buf.len() < min_len {
            return Err(Ext4Error::TooShort {
                structure: "GroupDescriptor",
                expected: min_len,
                found: buf.len(),
            });
        }

        // Low 32-bit halves (always present for desc_size >= 32)
        let block_bitmap_lo = le32(buf, 0x00) as u64;
        let inode_bitmap_lo = le32(buf, 0x04) as u64;
        let inode_table_lo  = le32(buf, 0x08) as u64;
        let free_blocks_lo  = le16(buf, 0x0C) as u32;
        let free_inodes_lo  = le16(buf, 0x0E) as u32;
        let used_dirs_lo    = le16(buf, 0x10) as u32;
        let flags_raw       = le16(buf, 0x12);
        let itable_unused_lo = le16(buf, 0x1C) as u32;
        let checksum        = le16(buf, 0x1E);

        // High 32-bit halves (present only for desc_size >= 64)
        let (block_bitmap, inode_bitmap, inode_table,
             free_blocks_count, free_inodes_count, used_dirs_count, itable_unused) =
            if desc_size >= 64 {
                let bb_hi = (le32(buf, 0x20) as u64) << 32;
                let ib_hi = (le32(buf, 0x24) as u64) << 32;
                let it_hi = (le32(buf, 0x28) as u64) << 32;
                let fb_hi = (le16(buf, 0x2C) as u32) << 16;
                let fi_hi = (le16(buf, 0x2E) as u32) << 16;
                let ud_hi = (le16(buf, 0x30) as u32) << 16;
                let iu_hi = (le16(buf, 0x32) as u32) << 16;
                (
                    bb_hi | block_bitmap_lo,
                    ib_hi | inode_bitmap_lo,
                    it_hi | inode_table_lo,
                    fb_hi | free_blocks_lo,
                    fi_hi | free_inodes_lo,
                    ud_hi | used_dirs_lo,
                    iu_hi | itable_unused_lo,
                )
            } else {
                (
                    block_bitmap_lo,
                    inode_bitmap_lo,
                    inode_table_lo,
                    free_blocks_lo,
                    free_inodes_lo,
                    used_dirs_lo,
                    itable_unused_lo,
                )
            };

        let flags = GroupDescFlags::from_bits_truncate(flags_raw);

        Ok(Self {
            block_bitmap,
            inode_bitmap,
            inode_table,
            free_blocks_count,
            free_inodes_count,
            used_dirs_count,
            flags,
            itable_unused,
            checksum,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_32byte_descriptor() {
        let mut buf = vec![0u8; 32];
        buf[0x00] = 100; // bg_block_bitmap_lo
        buf[0x04] = 101; // bg_inode_bitmap_lo
        buf[0x08] = 102; // bg_inode_table_lo
        buf[0x0C] = 50;  // bg_free_blocks_count_lo
        buf[0x0E] = 30;  // bg_free_inodes_count_lo
        buf[0x12] = 0x04; // bg_flags (INODE_ZEROED)

        let gd = GroupDescriptor::parse(&buf, 32).unwrap();
        assert_eq!(gd.block_bitmap, 100);
        assert_eq!(gd.inode_bitmap, 101);
        assert_eq!(gd.inode_table, 102);
        assert_eq!(gd.free_blocks_count, 50);
        assert_eq!(gd.free_inodes_count, 30);
        assert!(gd.flags.contains(GroupDescFlags::INODE_ZEROED));
    }

    #[test]
    fn parse_64byte_descriptor() {
        let mut buf = vec![0u8; 64];
        buf[0x00] = 100;
        buf[0x04] = 101;
        buf[0x08] = 102;
        buf[0x20] = 1; // bg_block_bitmap_hi
        buf[0x24] = 2; // bg_inode_bitmap_hi
        buf[0x28] = 3; // bg_inode_table_hi

        let gd = GroupDescriptor::parse(&buf, 64).unwrap();
        assert_eq!(gd.block_bitmap, (1u64 << 32) | 100);
        assert_eq!(gd.inode_bitmap, (2u64 << 32) | 101);
        assert_eq!(gd.inode_table, (3u64 << 32) | 102);
    }

    #[test]
    fn reject_too_short() {
        let buf = vec![0u8; 10];
        let err = GroupDescriptor::parse(&buf, 32).unwrap_err();
        assert!(matches!(err, crate::error::Ext4Error::TooShort { .. }));
    }
}
