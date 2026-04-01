#![forbid(unsafe_code)]
use crate::error::{Ext4Error, Result};
use crate::ondisk::superblock::EXT4_CRC32C;
use bitflags::bitflags;
use crc::Crc;

// ---------------------------------------------------------------------------
// Timestamp
// ---------------------------------------------------------------------------

/// A nanosecond-precision timestamp as used in ext4 inodes.
///
/// The `seconds` field is the full 34-bit signed epoch extended via the two
/// low bits of the "extra" word. `nanoseconds` is always in [0, 999_999_999].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Timestamp {
    pub seconds: i64,
    pub nanoseconds: u32,
}

impl PartialOrd for Timestamp {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Timestamp {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.seconds
            .cmp(&other.seconds)
            .then(self.nanoseconds.cmp(&other.nanoseconds))
    }
}

/// Decode a 32-bit inode timestamp, optionally extended by a 32-bit "extra"
/// word that carries epoch bits [1:0] and nanoseconds in bits [31:2].
///
/// Without an extra word the 32-bit value is sign-extended to i64 (covering
/// dates up to 2038). With the extra word the epoch extension shifts the
/// range to cover dates up to ~2446.
fn decode_timestamp(secs_raw: u32, extra: Option<u32>) -> Timestamp {
    match extra {
        None => Timestamp {
            seconds: secs_raw as i32 as i64,
            nanoseconds: 0,
        },
        Some(ex) => {
            let epoch_bits = (ex & 0x3) as i64;
            let nanoseconds = ex >> 2;
            // The 34-bit seconds: upper 2 bits come from the extra word, the
            // lower 32 bits are the raw seconds field treated as unsigned.
            let seconds = ((epoch_bits) << 32) | (secs_raw as i64);
            Timestamp { seconds, nanoseconds }
        }
    }
}

// ---------------------------------------------------------------------------
// InodeFlags
// ---------------------------------------------------------------------------

bitflags! {
    /// Inode flags (i_flags field at offset 0x20).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct InodeFlags: u32 {
        const SYNC         = 0x0000_0010;
        const IMMUTABLE    = 0x0000_0020;
        const APPEND       = 0x0000_0040;
        const NODUMP       = 0x0000_0080;
        const NOATIME      = 0x0000_0100;
        const ENCRYPT      = 0x0000_0800;
        const INDEX        = 0x0000_1000;
        const HUGE_FILE    = 0x0004_0000;
        const EXTENTS      = 0x0008_0000;
        const EA_INODE     = 0x0020_0000;
        const INLINE_DATA  = 0x1000_0000;
        const CASEFOLD     = 0x2000_0000;
        const VERITY       = 0x8000_0000;
    }
}

// ---------------------------------------------------------------------------
// FileType
// ---------------------------------------------------------------------------

/// File type derived from the high 4 bits of `i_mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Unknown,
    Fifo,
    CharDevice,
    Directory,
    BlockDevice,
    RegularFile,
    Symlink,
    Socket,
}

impl FileType {
    fn from_mode(mode: u16) -> Self {
        match mode >> 12 {
            0x1 => FileType::Fifo,
            0x2 => FileType::CharDevice,
            0x4 => FileType::Directory,
            0x6 => FileType::BlockDevice,
            0x8 => FileType::RegularFile,
            0xA => FileType::Symlink,
            0xC => FileType::Socket,
            _ => FileType::Unknown,
        }
    }
}

// ---------------------------------------------------------------------------
// Inode
// ---------------------------------------------------------------------------

/// Parsed on-disk ext4 inode (128-byte base + optional extended fields).
#[derive(Debug, Clone)]
pub struct Inode {
    // --- mode / ownership ---
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,

    // --- size ---
    /// Full 64-bit file size (i_size_lo | i_size_hi << 32).
    pub size: u64,

    // --- timestamps ---
    pub atime: Timestamp,
    pub ctime: Timestamp,
    pub mtime: Timestamp,
    /// Deletion time (raw 32-bit seconds; 0 = not deleted).
    pub dtime: u32,
    /// Creation time — only valid when `extra_isize` >= 28.
    pub crtime: Timestamp,

    // --- link / block counts ---
    pub links_count: u16,
    /// Full 48-bit block count in 512-byte units (i_blocks_lo | i_blocks_hi << 32).
    pub blocks_count: u64,

    // --- flags ---
    pub flags: InodeFlags,

    // --- raw block map / extent tree ---
    pub i_block: [u8; 60],

    // --- misc ---
    pub generation: u32,
    pub file_acl: u64,
    pub extra_isize: u16,
    /// Combined 32-bit checksum (lo 16 at 0x7C, hi 16 at 0x82).
    pub checksum: u32,
    pub projid: u32,
}

// Minimum size of the fixed 128-byte inode base structure.
const INODE_BASE_SIZE: usize = 128;

impl Inode {
    /// Parse an inode from `buf`.
    ///
    /// `inode_size` is the value from the superblock (`s_inode_size`); it
    /// determines how many bytes are available for extended fields.
    pub fn parse(buf: &[u8], inode_size: u16) -> Result<Self> {
        let inode_size = inode_size as usize;
        let required = INODE_BASE_SIZE.min(inode_size);
        if buf.len() < required || buf.len() < INODE_BASE_SIZE {
            return Err(Ext4Error::TooShort {
                structure: "inode",
                expected: INODE_BASE_SIZE,
                found: buf.len(),
            });
        }

        // --- helpers ---
        let u16_at = |off: usize| -> u16 {
            u16::from_le_bytes([buf[off], buf[off + 1]])
        };
        let u32_at = |off: usize| -> u32 {
            u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
        };

        // --- base fields ---
        let mode = u16_at(0x00);
        let uid_lo = u16_at(0x02) as u32;
        let size_lo = u32_at(0x04) as u64;
        let atime_raw = u32_at(0x08);
        let ctime_raw = u32_at(0x0C);
        let mtime_raw = u32_at(0x10);
        let dtime = u32_at(0x14);
        let gid_lo = u16_at(0x18) as u32;
        let links_count = u16_at(0x1A);
        let blocks_lo = u32_at(0x1C) as u64;
        let flags_raw = u32_at(0x20);

        let mut i_block = [0u8; 60];
        i_block.copy_from_slice(&buf[0x28..0x64]);

        let generation = u32_at(0x64);
        let file_acl_lo = u32_at(0x68) as u64;
        let size_hi = u32_at(0x6C) as u64;
        let blocks_hi = u16_at(0x74) as u64;
        let file_acl_hi = u16_at(0x76) as u64;
        let uid_hi = u16_at(0x78) as u32;
        let gid_hi = u16_at(0x7A) as u32;
        let checksum_lo = u16_at(0x7C) as u32;

        // --- extended fields (present when inode_size > 128 and buf is large enough) ---
        let (extra_isize, checksum_hi, ctime_extra, mtime_extra, atime_extra,
             crtime_raw, crtime_extra, projid) = if buf.len() > INODE_BASE_SIZE {
            let extra_isize = u16_at(0x80);
            let checksum_hi = u16_at(0x82) as u32;
            // Extended timestamps are present when extra_isize >= 28 (covers up to 0x94+4 = 0x98).
            // extra_isize field is at 0x80; extended ts start at 0x84.
            // We need buf to contain at least 0x80 + extra_isize bytes.
            let ext_end = 0x80 + (extra_isize as usize);
            let (ctime_extra, mtime_extra, atime_extra, crtime_raw, crtime_extra) =
                if extra_isize >= 28 && buf.len() >= ext_end {
                    (
                        Some(u32_at(0x84)),
                        Some(u32_at(0x88)),
                        Some(u32_at(0x8C)),
                        Some(u32_at(0x90)),
                        Some(u32_at(0x94)),
                    )
                } else {
                    (None, None, None, None, None)
                };
            // projid at 0x9C (extra_isize >= 32 means 0x80+32=0xA0, but projid is at 0x9C = offset 28 from 0x80+4)
            let projid = if extra_isize >= 32 && buf.len() >= 0xA0 {
                u32_at(0x9C)
            } else {
                0
            };
            (extra_isize, checksum_hi, ctime_extra, mtime_extra, atime_extra, crtime_raw, crtime_extra, projid)
        } else {
            (0, 0, None, None, None, None, None, 0)
        };

        // --- compose multi-word fields ---
        let uid = uid_lo | (uid_hi << 16);
        let gid = gid_lo | (gid_hi << 16);
        let size = size_lo | (size_hi << 32);
        let blocks_count = blocks_lo | (blocks_hi << 32);
        let file_acl = file_acl_lo | (file_acl_hi << 32);
        let checksum = checksum_lo | (checksum_hi << 16);
        let flags = InodeFlags::from_bits_truncate(flags_raw);

        // --- timestamps ---
        let atime = decode_timestamp(atime_raw, atime_extra);
        let ctime = decode_timestamp(ctime_raw, ctime_extra);
        let mtime = decode_timestamp(mtime_raw, mtime_extra);
        let crtime = match (crtime_raw, crtime_extra) {
            (Some(secs), extra) => decode_timestamp(secs, extra),
            _ => Timestamp::default(),
        };

        Ok(Inode {
            mode,
            uid,
            gid,
            size,
            atime,
            ctime,
            mtime,
            dtime,
            crtime,
            links_count,
            blocks_count,
            flags,
            i_block,
            generation,
            file_acl,
            extra_isize,
            checksum,
            projid,
        })
    }

    /// Extract the file type from the high nibble of `i_mode`.
    pub fn file_type(&self) -> FileType {
        FileType::from_mode(self.mode)
    }

    /// Extract the permission bits (low 12 bits of `i_mode`).
    pub fn mode_permissions(&self) -> u16 {
        self.mode & 0x0FFF
    }

    /// True if this inode uses the extent tree (EXTENTS flag set).
    pub fn uses_extents(&self) -> bool {
        self.flags.contains(InodeFlags::EXTENTS)
    }

    /// True if this inode stores data inline in `i_block`.
    pub fn has_inline_data(&self) -> bool {
        self.flags.contains(InodeFlags::INLINE_DATA)
    }

    /// True if this directory uses an HTree (htree/INDEX flag set).
    pub fn has_htree(&self) -> bool {
        self.flags.contains(InodeFlags::INDEX)
    }

    /// True if the inode has been deleted (`dtime` != 0).
    ///
    /// This is the authoritative deletion marker in ext4. When the kernel
    /// deletes a file, it sets `dtime` to the current time. An inode with
    /// `links_count == 0` but `dtime == 0` is an **orphan** (unlinked while
    /// still open, or system crashed mid-deletion) — a forensically distinct
    /// state. Use [`is_orphan`] to detect those.
    pub fn is_deleted(&self) -> bool {
        self.dtime != 0
    }

    /// Verify the inode's CRC32C checksum (METADATA_CSUM feature).
    ///
    /// The algorithm:
    /// 1. Seed from `csum_seed` (or `crc32c(0xFFFFFFFF, uuid)` if zero)
    /// 2. Feed `le32(ino)` then `le32(generation)`
    /// 3. Feed the full raw inode bytes with both checksum fields zeroed
    /// 4. Compare the 32-bit result against `self.checksum`
    pub fn verify_checksum(
        &self,
        raw_buf: &[u8],
        uuid: &[u8; 16],
        ino: u32,
        generation: u32,
        csum_seed: u32,
    ) -> bool {
        let crc32c = Crc::<u32>::new(&EXT4_CRC32C);

        let seed = if csum_seed != 0 {
            csum_seed
        } else {
            let mut d = crc32c.digest();
            d.update(uuid);
            d.finalize()
        };

        let mut digest = crc32c.digest_with_initial(seed.reverse_bits());
        digest.update(&ino.to_le_bytes());
        digest.update(&generation.to_le_bytes());

        // Zero out the checksum fields before computing
        let mut buf = raw_buf.to_vec();
        // lo16 at 0x7C
        if buf.len() > 0x7E {
            buf[0x7C] = 0;
            buf[0x7D] = 0;
        }
        // hi16 at 0x82 (only if extended inode)
        if buf.len() > 0x84 {
            buf[0x82] = 0;
            buf[0x83] = 0;
        }
        digest.update(&buf);

        let computed = digest.finalize();
        computed == self.checksum
    }

    /// True if the inode is an orphan: unlinked (`links_count == 0`) but
    /// never fully deleted (`dtime == 0`) and still has content (`mode != 0`).
    ///
    /// Orphans typically result from:
    /// - A file unlinked while still held open by a process (common temp file pattern)
    /// - A system crash during file deletion before `dtime` was written
    /// - An unclean shutdown leaving inodes in the orphan list
    ///
    /// Forensically distinct from deleted inodes — orphans were not
    /// intentionally removed by the user/process at the time of imaging.
    pub fn is_orphan(&self) -> bool {
        self.links_count == 0 && self.dtime == 0 && self.mode != 0
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_inode_bytes(mode: u16, size: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 256];
        buf[0x00] = (mode & 0xFF) as u8;
        buf[0x01] = (mode >> 8) as u8;
        buf[0x04] = (size & 0xFF) as u8;
        buf[0x05] = ((size >> 8) & 0xFF) as u8;
        buf[0x06] = ((size >> 16) & 0xFF) as u8;
        buf[0x07] = ((size >> 24) & 0xFF) as u8;
        let atime: u32 = 1_700_000_000;
        buf[0x08..0x0C].copy_from_slice(&atime.to_le_bytes());
        buf[0x1A] = 1; // links_count
        buf[0x20] = 0x00; buf[0x21] = 0x00; buf[0x22] = 0x08; buf[0x23] = 0x00; // EXTENTS flag
        buf[0x80] = 32; // extra_isize
        let crtime: u32 = 1_699_000_000;
        buf[0x90..0x94].copy_from_slice(&crtime.to_le_bytes());
        buf
    }

    #[test]
    fn parse_regular_file_inode() {
        let buf = make_inode_bytes(0x8180, 12);
        let inode = Inode::parse(&buf, 256).unwrap();
        assert_eq!(inode.file_type(), FileType::RegularFile);
        assert_eq!(inode.mode_permissions(), 0o600);
        assert_eq!(inode.size, 12);
        assert_eq!(inode.links_count, 1);
        assert!(inode.flags.contains(InodeFlags::EXTENTS));
        assert_eq!(inode.atime.seconds, 1_700_000_000);
        assert_eq!(inode.crtime.seconds, 1_699_000_000);
    }

    #[test]
    fn parse_directory_inode() {
        let buf = make_inode_bytes(0x4180, 4096);
        let inode = Inode::parse(&buf, 256).unwrap();
        assert_eq!(inode.file_type(), FileType::Directory);
    }

    #[test]
    fn timestamp_nanoseconds() {
        let mut buf = make_inode_bytes(0x8180, 100);
        let extra = 500_000_000u32 << 2;
        buf[0x8C..0x90].copy_from_slice(&extra.to_le_bytes());
        let inode = Inode::parse(&buf, 256).unwrap();
        assert_eq!(inode.atime.nanoseconds, 500_000_000);
    }

    #[test]
    fn dtime_set_means_deleted() {
        let mut buf = make_inode_bytes(0x8180, 100);
        let dtime: u32 = 1_700_001_000;
        buf[0x14..0x18].copy_from_slice(&dtime.to_le_bytes());
        buf[0x1A] = 0;
        let inode = Inode::parse(&buf, 256).unwrap();
        assert_eq!(inode.dtime, 1_700_001_000);
        assert_eq!(inode.links_count, 0);
    }

    #[test]
    fn i_block_60_bytes() {
        let mut buf = make_inode_bytes(0x8180, 100);
        for i in 0..60 { buf[0x28 + i] = i as u8; }
        let inode = Inode::parse(&buf, 256).unwrap();
        assert_eq!(inode.i_block.len(), 60);
        assert_eq!(inode.i_block[0], 0);
        assert_eq!(inode.i_block[59], 59);
    }

    #[test]
    fn verify_inode_checksum_on_forensic_img() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/forensic.img");
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => { eprintln!("skip: forensic.img not found"); return; }
        };
        use crate::ondisk::superblock::Superblock;
        let sb = Superblock::parse(&data[1024..]).unwrap();
        assert!(sb.has_metadata_csum(), "forensic.img should have metadata_csum");

        let inode_size = sb.inode_size;
        let inodes_per_group = sb.inodes_per_group;

        // Read group descriptor to find inode table
        let desc_size = sb.desc_size;
        let gdt_offset = sb.block_size as usize;
        use crate::ondisk::group_desc::GroupDescriptor;
        let gd = GroupDescriptor::parse(
            &data[gdt_offset..gdt_offset + desc_size as usize],
            desc_size,
        ).unwrap();

        // Read inode 12 (hello.txt) raw bytes from inode table
        let ino: u32 = 12;
        let index = (ino - 1) % inodes_per_group;
        let byte_offset = gd.inode_table * sb.block_size as u64 + index as u64 * inode_size as u64;
        let raw = &data[byte_offset as usize..(byte_offset + inode_size as u64) as usize];
        let inode = Inode::parse(raw, inode_size).unwrap();

        assert!(
            inode.verify_checksum(raw, &sb.uuid, ino, inode.generation, sb.checksum_seed),
            "inode 12 checksum should verify"
        );
    }

    #[test]
    fn reject_too_short() {
        let buf = vec![0u8; 50];
        let err = Inode::parse(&buf, 256).unwrap_err();
        assert!(matches!(err, crate::error::Ext4Error::TooShort { .. }));
    }
}
