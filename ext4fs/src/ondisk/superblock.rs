#![forbid(unsafe_code)]

use crate::error::{Ext4Error, Result};
use bitflags::bitflags;
use crc::{Algorithm, Crc};

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
// Feature-flag bitflags
// ---------------------------------------------------------------------------

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CompatFeatures: u32 {
        const HAS_JOURNAL   = 0x0004;
        const EXT_ATTR      = 0x0008;
        const RESIZE_INODE  = 0x0010;
        const DIR_INDEX     = 0x0020;
        const SPARSE_SUPER2 = 0x0200;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct IncompatFeatures: u32 {
        const FILETYPE     = 0x0002;
        const RECOVER      = 0x0004;
        const JOURNAL_DEV  = 0x0008;
        const META_BG      = 0x0010;
        const EXTENTS      = 0x0040;
        const IS_64BIT     = 0x0080;
        const MMP          = 0x0100;
        const FLEX_BG      = 0x0200;
        const EA_INODE     = 0x0400;
        const DIRDATA      = 0x1000;
        const CSUM_SEED    = 0x2000;
        const LARGEDIR     = 0x4000;
        const INLINE_DATA  = 0x8000;
        const ENCRYPT      = 0x1_0000;
        const CASEFOLD     = 0x2_0000;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct RoCompatFeatures: u32 {
        const SPARSE_SUPER  = 0x0001;
        const LARGE_FILE    = 0x0002;
        const BTREE_DIR     = 0x0004;
        const HUGE_FILE     = 0x0008;
        const GDT_CSUM      = 0x0010;
        const DIR_NLINK     = 0x0020;
        const EXTRA_ISIZE   = 0x0040;
        const HAS_SNAPSHOT  = 0x0080;
        const QUOTA          = 0x0100;
        const BIGALLOC       = 0x0200;
        const METADATA_CSUM  = 0x0400;
        const ORPHAN_PRESENT = 0x8000;
    }
}

// ---------------------------------------------------------------------------
// CRC32C algorithm matching Linux kernel's crc32c_le()
// ---------------------------------------------------------------------------

/// CRC-32C (Castagnoli) matching the Linux kernel's `crc32c_le()` function.
///
/// The standard CRC-32/ISCSI algorithm has `xorout = 0xFFFFFFFF`, meaning
/// the finalized result is XORed with all-ones.  The Linux kernel's CRC32C
/// implementation does **not** apply this final XOR — it returns the raw CRC
/// register state.  We define a custom algorithm with `xorout = 0` to match.
pub(crate) const EXT4_CRC32C: Algorithm<u32> = Algorithm {
    width: 32,
    poly: 0x1EDC_6F41,
    init: 0xFFFF_FFFF,
    refin: true,
    refout: true,
    xorout: 0x0000_0000, // kernel does NOT apply final XOR
    check: 0x0, // not used
    residue: 0x0, // not used
};

// ---------------------------------------------------------------------------
// Superblock
// ---------------------------------------------------------------------------

/// Minimum buffer length required to parse through `s_inode_size` at offset 0x5A.
const MIN_SUPERBLOCK_LEN: usize = 0x5A;

/// Parsed ext4 superblock.  All multi-byte fields are converted from
/// little-endian on disk to native endianness.
#[derive(Debug)]
pub struct Superblock {
    pub inodes_count: u32,
    /// Combined lo + hi (64-bit mode).
    pub blocks_count: u64,
    pub reserved_blocks: u64,
    pub free_blocks: u64,
    pub free_inodes: u32,
    pub first_data_block: u32,
    /// Computed: `2^(10 + s_log_block_size)`.
    pub block_size: u32,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub magic: u16,
    pub state: u16,
    pub rev_level: u32,
    pub inode_size: u16,
    pub desc_size: u16,
    pub feature_compat: CompatFeatures,
    pub feature_incompat: IncompatFeatures,
    pub feature_ro_compat: RoCompatFeatures,
    pub uuid: [u8; 16],
    pub volume_name: [u8; 16],
    pub last_mounted: [u8; 64],
    pub mkfs_time: u32,
    pub mount_time: u32,
    pub write_time: u32,
    pub lastcheck_time: u32,
    pub journal_inum: u32,
    pub hash_seed: [u32; 4],
    pub def_hash_version: u8,
    pub checksum_type: u8,
    pub checksum_seed: u32,
    pub checksum: u32,
    pub is_64bit: bool,
    pub log_groups_per_flex: u32,
    pub last_orphan: u32,
    pub first_error_time: u32,
    pub last_error_time: u32,
}

impl Superblock {
    /// Parse an ext4 superblock from the given byte slice.
    ///
    /// The slice should begin at the start of the superblock (i.e. byte 1024
    /// of the filesystem image has already been skipped by the caller).
    /// A minimum of [`MIN_SUPERBLOCK_LEN`] bytes is required; a full 1024-byte
    /// superblock is needed to access all extended fields.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < MIN_SUPERBLOCK_LEN {
            return Err(Ext4Error::TooShort {
                structure: "superblock",
                expected: MIN_SUPERBLOCK_LEN,
                found: buf.len(),
            });
        }

        let magic = le16(buf, 0x38);
        if magic != 0xEF53 {
            return Err(Ext4Error::InvalidMagic { found: magic });
        }

        let rev_level = le32(buf, 0x4C);
        let inode_size = if rev_level >= 1 { le16(buf, 0x58) } else { 128 };

        let log_block_size = le32(buf, 0x18);
        let block_size = 1u32 << (10 + log_block_size);

        let feature_incompat_raw = if buf.len() > 0x64 { le32(buf, 0x60) } else { 0 };
        let feature_incompat =
            IncompatFeatures::from_bits_truncate(feature_incompat_raw);
        let is_64bit = feature_incompat.contains(IncompatFeatures::IS_64BIT);

        let blocks_count_lo = le32(buf, 0x04) as u64;
        let blocks_count_hi = if is_64bit && buf.len() > 0x154 {
            le32(buf, 0x150) as u64
        } else {
            0
        };
        let blocks_count = blocks_count_lo | (blocks_count_hi << 32);

        let r_blocks_lo = le32(buf, 0x08) as u64;
        let r_blocks_hi = if is_64bit && buf.len() > 0x158 {
            le32(buf, 0x154) as u64
        } else {
            0
        };
        let reserved_blocks = r_blocks_lo | (r_blocks_hi << 32);

        let free_blocks_lo = le32(buf, 0x0C) as u64;
        let free_blocks_hi = if is_64bit && buf.len() > 0x15C {
            le32(buf, 0x158) as u64
        } else {
            0
        };
        let free_blocks = free_blocks_lo | (free_blocks_hi << 32);

        let feature_compat_raw = if buf.len() > 0x60 { le32(buf, 0x5C) } else { 0 };
        let feature_ro_raw = if buf.len() > 0x68 { le32(buf, 0x64) } else { 0 };

        let mut uuid = [0u8; 16];
        if buf.len() >= 0x78 {
            uuid.copy_from_slice(&buf[0x68..0x78]);
        }

        let mut volume_name = [0u8; 16];
        if buf.len() >= 0x88 {
            volume_name.copy_from_slice(&buf[0x78..0x88]);
        }

        let mut last_mounted = [0u8; 64];
        if buf.len() >= 0xC8 {
            last_mounted.copy_from_slice(&buf[0x88..0xC8]);
        }

        let desc_size = if buf.len() > 0x100 { le16(buf, 0xFE) } else { 32 };

        let journal_inum = if buf.len() > 0xE4 { le32(buf, 0xE0) } else { 0 };
        let last_orphan = if buf.len() > 0xEC { le32(buf, 0xE8) } else { 0 };

        let hash_seed = if buf.len() >= 0xFC {
            [
                le32(buf, 0xEC),
                le32(buf, 0xF0),
                le32(buf, 0xF4),
                le32(buf, 0xF8),
            ]
        } else {
            [0u32; 4]
        };

        let def_hash_version = if buf.len() > 0xFC { buf[0xFC] } else { 0 };

        let mkfs_time = if buf.len() > 0x10C { le32(buf, 0x108) } else { 0 };

        let log_groups_per_flex = if buf.len() > 0x16C { le32(buf, 0x168) } else { 0 };
        let checksum_type = if buf.len() > 0x16D { buf[0x16C] } else { 0 };

        let first_error_time = if buf.len() > 0x194 { le32(buf, 0x190) } else { 0 };
        let last_error_time = if buf.len() > 0x1B4 { le32(buf, 0x1B0) } else { 0 };

        let checksum_seed = if buf.len() > 0x260 { le32(buf, 0x25C) } else { 0 };
        let checksum = if buf.len() >= 0x400 { le32(buf, 0x3FC) } else { 0 };

        Ok(Superblock {
            inodes_count: le32(buf, 0x00),
            blocks_count,
            reserved_blocks,
            free_blocks,
            free_inodes: le32(buf, 0x10),
            first_data_block: le32(buf, 0x14),
            block_size,
            blocks_per_group: le32(buf, 0x20),
            inodes_per_group: le32(buf, 0x28),
            magic,
            state: le16(buf, 0x3A),
            rev_level,
            inode_size,
            desc_size,
            feature_compat: CompatFeatures::from_bits_truncate(feature_compat_raw),
            feature_incompat,
            feature_ro_compat: RoCompatFeatures::from_bits_truncate(feature_ro_raw),
            uuid,
            volume_name,
            last_mounted,
            mkfs_time,
            mount_time: le32(buf, 0x2C),
            write_time: le32(buf, 0x30),
            lastcheck_time: if buf.len() > 0x44 { le32(buf, 0x40) } else { 0 },
            journal_inum,
            hash_seed,
            def_hash_version,
            checksum_type,
            checksum_seed,
            checksum,
            is_64bit,
            log_groups_per_flex,
            last_orphan,
            first_error_time,
            last_error_time,
        })
    }

    /// Volume label as a UTF-8 string, trimmed of trailing null bytes.
    pub fn label(&self) -> &str {
        let end = self
            .volume_name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.volume_name.len());
        std::str::from_utf8(&self.volume_name[..end]).unwrap_or("")
    }

    /// UUID formatted as a standard hyphenated string.
    pub fn uuid_string(&self) -> String {
        let u = &self.uuid;
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            u[0], u[1], u[2], u[3],
            u[4], u[5],
            u[6], u[7],
            u[8], u[9],
            u[10], u[11], u[12], u[13], u[14], u[15],
        )
    }

    /// Whether the filesystem has metadata checksumming enabled.
    pub fn has_metadata_csum(&self) -> bool {
        self.feature_ro_compat
            .contains(RoCompatFeatures::METADATA_CSUM)
    }

    /// Whether the filesystem uses extents (vs. block maps).
    pub fn has_extents(&self) -> bool {
        self.feature_incompat
            .contains(IncompatFeatures::EXTENTS)
    }

    /// Verify the superblock CRC32C checksum.
    ///
    /// The checksum covers bytes 0..0x3FC (everything except the 4-byte
    /// checksum field itself at offset 0x3FC).
    ///
    /// The superblock checksum is special: unlike other ext4 metadata, it is
    /// computed with the default CRC32C initial value (~0 / 0xFFFFFFFF) rather
    /// than the UUID-derived or stored seed.  This is because the superblock
    /// itself contains the UUID used to derive seeds for other structures.
    ///
    /// The Linux kernel's `crc32c_le()` does NOT apply the final XOR that the
    /// standard CRC-32/ISCSI algorithm specifies (xorout=0xFFFFFFFF).  We use
    /// a custom algorithm definition with `xorout=0` to match kernel behavior.
    pub fn verify_checksum(&self, raw_buf: &[u8]) -> bool {
        if !self.has_metadata_csum() {
            return true; // feature not enabled, nothing to verify
        }
        if raw_buf.len() < 0x400 {
            return false; // buffer too short to contain checksum field
        }

        let crc32c = Crc::<u32>::new(&EXT4_CRC32C);

        // Superblock uses default initial value (~0), not the UUID/seed.
        let mut digest = crc32c.digest();
        digest.update(&raw_buf[..0x3FC]);
        let computed = digest.finalize();

        computed == self.checksum
    }

    /// Whether inline data is supported.
    pub fn has_inline_data(&self) -> bool {
        self.feature_incompat
            .contains(IncompatFeatures::INLINE_DATA)
    }

    /// Whether the filesystem has a journal.
    pub fn has_journal(&self) -> bool {
        self.feature_compat
            .contains(CompatFeatures::HAS_JOURNAL)
    }

    /// Number of block groups (rounded up).
    pub fn group_count(&self) -> u32 {
        if self.blocks_per_group == 0 {
            return 0;
        }
        let total = self.blocks_count;
        let per = self.blocks_per_group as u64;
        total.div_ceil(per) as u32
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_superblock_bytes() -> Vec<u8> {
        let mut buf = vec![0u8; 1024];
        buf[0x38] = 0x53;
        buf[0x39] = 0xEF; // magic = 0xEF53
        buf[0x18] = 2; // log_block_size = 2 -> 4096
        buf[0x00] = 64; // inodes_count = 64
        buf[0x04] = 0x00;
        buf[0x05] = 0x04; // blocks_count_lo = 1024
        buf[0x28] = 64; // inodes_per_group = 64
        buf[0x20] = 0x00;
        buf[0x21] = 0x04; // blocks_per_group = 1024
        buf[0x58] = 0x00;
        buf[0x59] = 0x01; // inode_size = 256
        buf[0x4C] = 1; // rev_level = 1
        buf[0xFE] = 32; // desc_size = 32
        buf
    }

    #[test]
    fn parse_valid_superblock() {
        let buf = minimal_superblock_bytes();
        let sb = Superblock::parse(&buf).unwrap();
        assert_eq!(sb.magic, 0xEF53);
        assert_eq!(sb.block_size, 4096);
        assert_eq!(sb.inodes_count, 64);
        assert_eq!(sb.blocks_count, 1024);
        assert_eq!(sb.inodes_per_group, 64);
        assert_eq!(sb.inode_size, 256);
    }

    #[test]
    fn reject_invalid_magic() {
        let mut buf = minimal_superblock_bytes();
        buf[0x38] = 0x00;
        buf[0x39] = 0x00;
        let err = Superblock::parse(&buf).unwrap_err();
        assert!(matches!(err, crate::error::Ext4Error::InvalidMagic { found: 0 }));
    }

    #[test]
    fn reject_too_short_buffer() {
        let buf = vec![0u8; 50];
        let err = Superblock::parse(&buf).unwrap_err();
        assert!(matches!(err, crate::error::Ext4Error::TooShort { .. }));
    }

    #[test]
    fn parse_from_minimal_image() {
        let img_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/minimal.img");
        if !std::path::Path::new(img_path).exists() {
            eprintln!("Skipping: minimal.img not found");
            return;
        }
        let data = std::fs::read(img_path).unwrap();
        let sb = Superblock::parse(&data[1024..2048]).unwrap();
        assert_eq!(sb.magic, 0xEF53);
        assert_eq!(sb.block_size, 4096);
        assert_eq!(sb.label(), "test-ext4");
        assert!(sb.has_extents());
        assert!(sb.has_metadata_csum());
        assert!(sb.is_64bit);
        assert!(sb.inodes_count > 0);
        assert!(sb.blocks_count > 0);
    }

    #[test]
    fn group_count_calculation() {
        let buf = minimal_superblock_bytes();
        let sb = Superblock::parse(&buf).unwrap();
        // blocks_count=1024, blocks_per_group=1024 => 1 group
        assert_eq!(sb.group_count(), 1);
    }

    #[test]
    fn inode_size_default_for_rev0() {
        let mut buf = minimal_superblock_bytes();
        // Set rev_level = 0
        buf[0x4C] = 0;
        buf[0x4D] = 0;
        buf[0x4E] = 0;
        buf[0x4F] = 0;
        let sb = Superblock::parse(&buf).unwrap();
        assert_eq!(sb.inode_size, 128);
    }

    #[test]
    fn uuid_string_format() {
        let mut buf = minimal_superblock_bytes();
        // Write a known UUID at offset 0x68
        let uuid_bytes: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        ];
        buf[0x68..0x78].copy_from_slice(&uuid_bytes);
        let sb = Superblock::parse(&buf).unwrap();
        assert_eq!(
            sb.uuid_string(),
            "01234567-89ab-cdef-fedc-ba9876543210"
        );
    }

    #[test]
    fn label_with_nulls() {
        let mut buf = minimal_superblock_bytes();
        // Write "hello" followed by nulls at offset 0x78
        buf[0x78] = b'h';
        buf[0x79] = b'e';
        buf[0x7A] = b'l';
        buf[0x7B] = b'l';
        buf[0x7C] = b'o';
        // rest is already zeros
        let sb = Superblock::parse(&buf).unwrap();
        assert_eq!(sb.label(), "hello");
    }

    #[test]
    fn feature_flags_roundtrip() {
        let mut buf = minimal_superblock_bytes();
        // Set feature_compat = HAS_JOURNAL | DIR_INDEX
        let compat = CompatFeatures::HAS_JOURNAL | CompatFeatures::DIR_INDEX;
        let compat_bytes = compat.bits().to_le_bytes();
        buf[0x5C..0x60].copy_from_slice(&compat_bytes);

        // Set feature_incompat = EXTENTS | IS_64BIT | FLEX_BG
        let incompat =
            IncompatFeatures::EXTENTS | IncompatFeatures::IS_64BIT | IncompatFeatures::FLEX_BG;
        let incompat_bytes = incompat.bits().to_le_bytes();
        buf[0x60..0x64].copy_from_slice(&incompat_bytes);

        // Set feature_ro_compat = METADATA_CSUM | HUGE_FILE
        let ro = RoCompatFeatures::METADATA_CSUM | RoCompatFeatures::HUGE_FILE;
        let ro_bytes = ro.bits().to_le_bytes();
        buf[0x64..0x68].copy_from_slice(&ro_bytes);

        let sb = Superblock::parse(&buf).unwrap();
        assert!(sb.has_journal());
        assert!(sb.has_extents());
        assert!(sb.has_metadata_csum());
        assert!(sb.is_64bit);
        assert_eq!(sb.feature_compat, compat);
        assert_eq!(sb.feature_incompat, incompat);
        assert_eq!(sb.feature_ro_compat, ro);
    }

    #[test]
    fn verify_superblock_checksum() {
        let img_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/minimal.img");
        if !std::path::Path::new(img_path).exists() {
            eprintln!("skip: minimal.img not found");
            return;
        }
        let data = std::fs::read(img_path).unwrap();
        let sb = Superblock::parse(&data[1024..2048]).unwrap();
        if sb.has_metadata_csum() {
            assert!(sb.verify_checksum(&data[1024..2048]));
        }
    }

    #[test]
    fn has_inline_data_feature() {
        let mut buf = minimal_superblock_bytes();
        // Set incompat feature with INLINE_DATA (0x8000)
        buf[0x60..0x64].copy_from_slice(&0x8000u32.to_le_bytes());
        let sb = Superblock::parse(&buf).unwrap();
        assert!(sb.has_inline_data());
    }

    #[test]
    fn blocks_count_64bit() {
        let mut buf = minimal_superblock_bytes();
        // Enable 64bit feature
        let incompat = IncompatFeatures::IS_64BIT;
        let incompat_bytes = incompat.bits().to_le_bytes();
        buf[0x60..0x64].copy_from_slice(&incompat_bytes);

        // blocks_count_lo = 0x1000
        buf[0x04] = 0x00;
        buf[0x05] = 0x10;
        buf[0x06] = 0x00;
        buf[0x07] = 0x00;

        // blocks_count_hi = 0x02
        buf[0x150] = 0x02;
        buf[0x151] = 0x00;
        buf[0x152] = 0x00;
        buf[0x153] = 0x00;

        let sb = Superblock::parse(&buf).unwrap();
        // Expected: 0x02_0000_1000
        assert_eq!(sb.blocks_count, 0x02_0000_1000);
    }
}
