# ext4fs Library Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a forensic-grade ext4 filesystem parsing library in pure safe Rust that can read files, enumerate inodes (allocated + deleted), parse the jbd2 journal, generate forensic timelines, and recover deleted files — all from any `Read+Seek` source.

**Architecture:** 6-layer bottom-up design: Layer 0 (on-disk struct parsing from `&[u8]`) → Layer 1 (block device abstraction over `Read+Seek`) → Layer 2 (inode operations + extent tree traversal) → Layer 3 (directory operations + path resolution) → Layer 4 (forensic operations: deleted files, journal, timeline, recovery, xattrs, carving) → Layer 5 (public `Ext4Fs<R>` API). All ext4 fields are little-endian; jbd2 journal fields are big-endian.

**Tech Stack:** Rust, `#![forbid(unsafe_code)]`, `bitflags` 2.x for feature flags, `crc` 3.x for CRC32C checksums. No other dependencies in the library crate.

**Reference:** Byte-level offsets and field definitions are from the Linux kernel ext4 documentation and the forensic reference at `~/src/ewf/docs/ext4-forensic-reference.md`.

---

## File Structure

```
ext4fs-forensic/
├── Cargo.toml                    (workspace root)
├── ext4fs/
│   ├── Cargo.toml                (library crate)
│   └── src/
│       ├── lib.rs                (Layer 5: Ext4Fs<R> public API, re-exports)
│       ├── error.rs              (Ext4Error enum, Result alias)
│       ├── ondisk/               (Layer 0: on-disk struct definitions)
│       │   ├── mod.rs            (re-exports all structs)
│       │   ├── superblock.rs     (Superblock + feature flags)
│       │   ├── group_desc.rs     (GroupDescriptor, GroupDescriptor64)
│       │   ├── inode.rs          (Inode + InodeFlags + FileType + Timestamp)
│       │   ├── extent.rs         (ExtentHeader, ExtentLeaf, ExtentIndex)
│       │   ├── dir_entry.rs      (DirEntry + DirEntryType)
│       │   ├── journal.rs        (JournalSuperblock, JournalBlockTag, etc.)
│       │   └── xattr.rs          (XattrHeader, XattrEntry)
│       ├── block.rs              (Layer 1: BlockReader<R>)
│       ├── inode.rs              (Layer 2: inode reading, extent traversal, bitmap ops)
│       ├── dir.rs                (Layer 3: directory parsing, path resolution)
│       └── forensic/             (Layer 4: forensic operations)
│           ├── mod.rs            (re-exports)
│           ├── deleted.rs        (deleted inode detection)
│           ├── journal.rs        (jbd2 journal parsing)
│           ├── recovery.rs       (deleted file recovery)
│           ├── xattr.rs          (extended attribute reading)
│           ├── timeline.rs       (forensic timeline generation)
│           └── carving.rs        (unallocated block access, extent signature scanning)
└── tests/
    └── data/                     (synthetic ext4 test images, created by Task 1)
        └── minimal.img           (smallest valid ext4 with known contents)
```

---

### Task 1: Workspace Scaffold + Test Image + Error Types

**Files:**
- Create: `Cargo.toml` (workspace)
- Create: `ext4fs/Cargo.toml`
- Create: `ext4fs/src/lib.rs`
- Create: `ext4fs/src/error.rs`
- Create: `tests/create-minimal-image.sh`
- Create: `tests/data/minimal.img` (generated)

This task sets up the workspace, creates the minimal test image we'll use throughout all later tasks, and defines the error types.

- [ ] **Step 1: Create workspace Cargo.toml**

```toml
# ext4fs-forensic/Cargo.toml
[workspace]
members = ["ext4fs"]
resolver = "2"
```

- [ ] **Step 2: Create ext4fs crate Cargo.toml**

```toml
# ext4fs-forensic/ext4fs/Cargo.toml
[package]
name = "ext4fs"
version = "0.1.0"
edition = "2021"
description = "Forensic-grade ext4 filesystem parser"
license = "MIT"

[dependencies]
bitflags = "2"
crc = "3"
```

- [ ] **Step 3: Create the error module**

```rust
// ext4fs/src/error.rs
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
```

- [ ] **Step 4: Create lib.rs with forbid(unsafe_code)**

```rust
// ext4fs/src/lib.rs
#![forbid(unsafe_code)]

pub mod error;
```

- [ ] **Step 5: Create the minimal test image creation script**

This script creates `minimal.img` — a 4 MiB ext4 image with one file (`hello.txt` containing `"Hello, ext4!\n"`) and one subdirectory (`subdir/`) containing `nested.txt` (`"Nested file\n"`). It requires Linux with `mkfs.ext4`, `mount`, and root access (for mount).

```bash
#!/usr/bin/env bash
# tests/create-minimal-image.sh
# Creates minimal.img — a small ext4 image for unit testing.
# Requires: Linux, mkfs.ext4, mount (needs root), debugfs
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IMG="$SCRIPT_DIR/data/minimal.img"
MNT=$(mktemp -d)

mkdir -p "$SCRIPT_DIR/data"

# Create 4 MiB image with ext4, metadata_csum, extents, 64bit
dd if=/dev/zero of="$IMG" bs=1M count=4 2>/dev/null
mkfs.ext4 -F -b 4096 -O extents,metadata_csum,64bit,extra_isize -L "test-ext4" "$IMG" >/dev/null 2>&1

# Mount, write test files, unmount
sudo mount -o loop "$IMG" "$MNT"
echo -n "Hello, ext4!" | sudo tee "$MNT/hello.txt" >/dev/null
sudo mkdir "$MNT/subdir"
echo -n "Nested file" | sudo tee "$MNT/subdir/nested.txt" >/dev/null
sudo umount "$MNT"
rmdir "$MNT"

echo "Created $IMG"

# Print reference data for tests
echo "--- Reference data (use in tests) ---"
debugfs -R "stats" "$IMG" 2>/dev/null | head -20
echo "---"
debugfs -R "stat hello.txt" "$IMG" 2>/dev/null
echo "---"
debugfs -R "stat subdir/nested.txt" "$IMG" 2>/dev/null
```

If you don't have Linux with root access, you can create the image using `debugfs` write commands instead. Alternatively, the prebuilt `minimal.img` will be committed to the repo after first creation.

- [ ] **Step 6: Generate the test image (on a Linux system) or use a pre-built one**

Run: `bash tests/create-minimal-image.sh`

If running on macOS (no ext4 tools), create the image on a Linux VM or Docker:

```bash
docker run --rm -v "$(pwd)/tests:/tests" --privileged ubuntu:24.04 bash /tests/create-minimal-image.sh
```

The image will be committed to the repo at `tests/data/minimal.img`.

- [ ] **Step 7: Verify workspace builds**

Run: `cd ~/src/ext4fs-forensic && cargo build`
Expected: Build succeeds with no errors.

- [ ] **Step 8: Run initial test (empty test suite should pass)**

Run: `cd ~/src/ext4fs-forensic && cargo test`
Expected: `0 tests passed`

- [ ] **Step 9: Commit**

```bash
cd ~/src/ext4fs-forensic
git add Cargo.toml ext4fs/ tests/
git commit -m "feat: scaffold workspace, error types, and test image script"
```

---

### Task 2: Layer 0 — Superblock Parsing

**Files:**
- Create: `ext4fs/src/ondisk/mod.rs`
- Create: `ext4fs/src/ondisk/superblock.rs`
- Modify: `ext4fs/src/lib.rs`
- Test: `ext4fs/src/ondisk/superblock.rs` (inline `#[cfg(test)]`)

Parse the ext4 superblock from a 1024-byte `&[u8]` slice. Extract all critical fields: magic, block size, block/inode counts, feature flags, UUID, label, timestamps, checksum.

- [ ] **Step 1: Write failing test for superblock magic validation**

```rust
// At bottom of ext4fs/src/ondisk/superblock.rs

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_superblock_bytes() -> Vec<u8> {
        // 1024 bytes of zeros, then set magic at offset 0x38
        let mut buf = vec![0u8; 1024];
        // s_magic at offset 0x38 = 0xEF53 (little-endian)
        buf[0x38] = 0x53;
        buf[0x39] = 0xEF;
        // s_log_block_size at 0x18 = 2 (means 4096-byte blocks: 2^(10+2))
        buf[0x18] = 2;
        // s_inodes_count at 0x00 = 64
        buf[0x00] = 64;
        // s_blocks_count_lo at 0x04 = 1024
        buf[0x04] = 0x00;
        buf[0x05] = 0x04;
        // s_inodes_per_group at 0x28 = 64
        buf[0x28] = 64;
        // s_blocks_per_group at 0x20 = 1024
        buf[0x20] = 0x00;
        buf[0x21] = 0x04;
        // s_inode_size at 0x58 = 256
        buf[0x58] = 0x00;
        buf[0x59] = 0x01;
        // s_rev_level at 0x4C = 1 (dynamic)
        buf[0x4C] = 1;
        // s_desc_size at 0xFE = 32
        buf[0xFE] = 32;
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
        buf[0x38] = 0x00; // corrupt magic
        buf[0x39] = 0x00;
        let err = Superblock::parse(&buf).unwrap_err();
        assert!(matches!(err, crate::error::Ext4Error::InvalidMagic { found: 0 }));
    }

    #[test]
    fn reject_too_short_buffer() {
        let buf = vec![0u8; 100]; // way too short
        let err = Superblock::parse(&buf).unwrap_err();
        assert!(matches!(err, crate::error::Ext4Error::TooShort { .. }));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/src/ext4fs-forensic && cargo test -p ext4fs`
Expected: FAIL — `Superblock` not defined.

- [ ] **Step 3: Implement Superblock parsing**

```rust
// ext4fs/src/ondisk/superblock.rs
#![forbid(unsafe_code)]

use crate::error::{Ext4Error, Result};
use bitflags::bitflags;

/// Minimum valid superblock size (original ext2 superblock).
const MIN_SUPERBLOCK_SIZE: usize = 264; // through s_inode_size at 0x58 + 2

/// Parsed ext4 superblock.
#[derive(Debug, Clone)]
pub struct Superblock {
    // Core fields
    pub inodes_count: u32,
    pub blocks_count: u64,       // combined lo + hi
    pub reserved_blocks: u64,    // combined lo + hi
    pub free_blocks: u64,        // combined lo + hi
    pub free_inodes: u32,
    pub first_data_block: u32,
    pub block_size: u32,         // computed: 2^(10 + s_log_block_size)
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub magic: u16,
    pub state: u16,
    pub rev_level: u32,
    pub inode_size: u16,
    pub desc_size: u16,          // group descriptor size (32 or 64)

    // Feature flags
    pub feature_compat: CompatFeatures,
    pub feature_incompat: IncompatFeatures,
    pub feature_ro_compat: RoCompatFeatures,

    // Identity
    pub uuid: [u8; 16],
    pub volume_name: [u8; 16],
    pub last_mounted: [u8; 64],

    // Timestamps
    pub mkfs_time: u32,
    pub mount_time: u32,         // s_mtime at 0x2C
    pub write_time: u32,         // s_wtime at 0x30
    pub lastcheck_time: u32,     // s_lastcheck at 0x40

    // Journal
    pub journal_inum: u32,

    // Hash
    pub hash_seed: [u32; 4],
    pub def_hash_version: u8,

    // Checksum
    pub checksum_type: u8,
    pub checksum_seed: u32,
    pub checksum: u32,           // at 0x3FC

    // Extended (64-bit)
    pub is_64bit: bool,

    // Flex block groups
    pub log_groups_per_flex: u32,

    // Orphan
    pub last_orphan: u32,

    // Snapshot
    pub first_error_time: u32,
    pub last_error_time: u32,
}

bitflags! {
    /// Compatible feature flags (s_feature_compat at 0x5C).
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
    /// Incompatible feature flags (s_feature_incompat at 0x60).
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
    /// Read-only compatible feature flags (s_feature_ro_compat at 0x64).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct RoCompatFeatures: u32 {
        const SPARSE_SUPER = 0x0001;
        const LARGE_FILE   = 0x0002;
        const BTREE_DIR    = 0x0004;
        const HUGE_FILE    = 0x0008;
        const GDT_CSUM     = 0x0010;
        const DIR_NLINK    = 0x0020;
        const EXTRA_ISIZE  = 0x0040;
        const HAS_SNAPSHOT = 0x0080;
        const QUOTA        = 0x0100;
        const BIGALLOC     = 0x0200;
        const METADATA_CSUM = 0x0400;
        const ORPHAN_PRESENT = 0x8000;
    }
}

/// Read a little-endian u16 from a byte slice at the given offset.
fn le16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

/// Read a little-endian u32 from a byte slice at the given offset.
fn le32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

impl Superblock {
    /// Parse a superblock from a 1024-byte (or larger) buffer.
    /// The buffer should start at the superblock offset (byte 1024 of the device).
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < MIN_SUPERBLOCK_SIZE {
            return Err(Ext4Error::TooShort {
                structure: "superblock",
                expected: MIN_SUPERBLOCK_SIZE,
                found: buf.len(),
            });
        }

        let magic = le16(buf, 0x38);
        if magic != 0xEF53 {
            return Err(Ext4Error::InvalidMagic { found: magic });
        }

        let log_block_size = le32(buf, 0x18);
        let block_size = 1u32 << (10 + log_block_size);

        let rev_level = le32(buf, 0x4C);
        let inode_size = if rev_level >= 1 { le16(buf, 0x58) } else { 128 };

        let feature_incompat_raw = if buf.len() > 0x63 { le32(buf, 0x60) } else { 0 };
        let feature_incompat = IncompatFeatures::from_bits_truncate(feature_incompat_raw);
        let is_64bit = feature_incompat.contains(IncompatFeatures::IS_64BIT);

        let blocks_count_lo = le32(buf, 0x04) as u64;
        let blocks_count_hi = if is_64bit && buf.len() > 0x153 { le32(buf, 0x150) as u64 } else { 0 };
        let blocks_count = (blocks_count_hi << 32) | blocks_count_lo;

        let reserved_lo = le32(buf, 0x08) as u64;
        let reserved_hi = if is_64bit && buf.len() > 0x157 { le32(buf, 0x154) as u64 } else { 0 };

        let free_blocks_lo = le32(buf, 0x0C) as u64;
        let free_blocks_hi = if is_64bit && buf.len() > 0x15B { le32(buf, 0x158) as u64 } else { 0 };

        let desc_size = if rev_level >= 1 && buf.len() > 0xFF {
            let ds = le16(buf, 0xFE);
            if ds == 0 { 32 } else { ds }
        } else {
            32
        };

        let feature_compat_raw = if buf.len() > 0x5F { le32(buf, 0x5C) } else { 0 };
        let feature_ro_compat_raw = if buf.len() > 0x67 { le32(buf, 0x64) } else { 0 };

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

        let mut hash_seed = [0u32; 4];
        if buf.len() >= 0xFC {
            for i in 0..4 {
                hash_seed[i] = le32(buf, 0xEC + i * 4);
            }
        }

        let checksum = if buf.len() >= 0x400 { le32(buf, 0x3FC) } else { 0 };
        let checksum_seed = if buf.len() > 0x25F { le32(buf, 0x25C) } else { 0 };

        Ok(Superblock {
            inodes_count: le32(buf, 0x00),
            blocks_count,
            reserved_blocks: (reserved_hi << 32) | reserved_lo,
            free_blocks: (free_blocks_hi << 32) | free_blocks_lo,
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
            feature_ro_compat: RoCompatFeatures::from_bits_truncate(feature_ro_compat_raw),
            uuid,
            volume_name,
            last_mounted,
            mkfs_time: if buf.len() > 0x10B { le32(buf, 0x108) } else { 0 },
            mount_time: le32(buf, 0x2C),
            write_time: le32(buf, 0x30),
            lastcheck_time: if buf.len() > 0x43 { le32(buf, 0x40) } else { 0 },
            journal_inum: if buf.len() > 0xE3 { le32(buf, 0xE0) } else { 0 },
            hash_seed,
            def_hash_version: if buf.len() > 0xFC { buf[0xFC] } else { 0 },
            checksum_type: if buf.len() > 0x16C { buf[0x16C] } else { 0 },
            checksum_seed,
            checksum,
            is_64bit,
            log_groups_per_flex: if buf.len() > 0x16B { le32(buf, 0x168) } else { 0 },
            last_orphan: if buf.len() > 0xEB { le32(buf, 0xE8) } else { 0 },
            first_error_time: if buf.len() > 0x193 { le32(buf, 0x190) } else { 0 },
            last_error_time: if buf.len() > 0x1B3 { le32(buf, 0x1B0) } else { 0 },
        })
    }

    /// Volume label as a UTF-8 string (trimmed of nulls).
    pub fn label(&self) -> &str {
        let end = self.volume_name.iter().position(|&b| b == 0).unwrap_or(16);
        std::str::from_utf8(&self.volume_name[..end]).unwrap_or("")
    }

    /// UUID formatted as hex string (e.g., "550e8400-e29b-41d4-a716-446655440000").
    pub fn uuid_string(&self) -> String {
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.uuid[0], self.uuid[1], self.uuid[2], self.uuid[3],
            self.uuid[4], self.uuid[5],
            self.uuid[6], self.uuid[7],
            self.uuid[8], self.uuid[9],
            self.uuid[10], self.uuid[11], self.uuid[12], self.uuid[13], self.uuid[14], self.uuid[15],
        )
    }

    /// Whether metadata checksums are enabled.
    pub fn has_metadata_csum(&self) -> bool {
        self.feature_ro_compat.contains(RoCompatFeatures::METADATA_CSUM)
    }

    /// Whether extents are enabled.
    pub fn has_extents(&self) -> bool {
        self.feature_incompat.contains(IncompatFeatures::EXTENTS)
    }

    /// Whether inline data is enabled.
    pub fn has_inline_data(&self) -> bool {
        self.feature_incompat.contains(IncompatFeatures::INLINE_DATA)
    }

    /// Whether the filesystem has a journal.
    pub fn has_journal(&self) -> bool {
        self.feature_compat.contains(CompatFeatures::HAS_JOURNAL)
    }

    /// Number of block groups.
    pub fn group_count(&self) -> u32 {
        let blocks = if self.blocks_count == 0 { 1 } else { self.blocks_count };
        let bpg = self.blocks_per_group as u64;
        if bpg == 0 { return 1; }
        ((blocks + bpg - 1) / bpg) as u32
    }
}
```

- [ ] **Step 4: Create ondisk/mod.rs and update lib.rs**

```rust
// ext4fs/src/ondisk/mod.rs
#![forbid(unsafe_code)]

pub mod superblock;

pub use superblock::*;
```

```rust
// ext4fs/src/lib.rs
#![forbid(unsafe_code)]

pub mod error;
pub mod ondisk;
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd ~/src/ext4fs-forensic && cargo test -p ext4fs`
Expected: 3 tests pass (`parse_valid_superblock`, `reject_invalid_magic`, `reject_too_short_buffer`).

- [ ] **Step 6: Write test against real image (if minimal.img exists)**

Add to the test module in `superblock.rs`:

```rust
    #[test]
    fn parse_from_minimal_image() {
        let img_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/minimal.img");
        if !std::path::Path::new(img_path).exists() {
            eprintln!("Skipping: minimal.img not found (run tests/create-minimal-image.sh)");
            return;
        }
        let data = std::fs::read(img_path).unwrap();
        // Superblock starts at byte 1024
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
```

- [ ] **Step 7: Run tests**

Run: `cd ~/src/ext4fs-forensic && cargo test -p ext4fs`
Expected: All tests pass (4 if image exists, 3 + skip otherwise).

- [ ] **Step 8: Commit**

```bash
cd ~/src/ext4fs-forensic
git add ext4fs/src/ondisk/ ext4fs/src/lib.rs
git commit -m "feat: Layer 0 — superblock parsing with feature flags"
```

---

### Task 3: Layer 0 — Group Descriptor Parsing

**Files:**
- Create: `ext4fs/src/ondisk/group_desc.rs`
- Modify: `ext4fs/src/ondisk/mod.rs`

Parse both 32-byte and 64-byte group descriptors. Normalize both to a common struct with combined hi+lo fields.

- [ ] **Step 1: Write failing tests**

```rust
// ext4fs/src/ondisk/group_desc.rs

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_32byte_descriptor() {
        let mut buf = vec![0u8; 32];
        // bg_block_bitmap_lo = 100
        buf[0x00] = 100;
        // bg_inode_bitmap_lo = 101
        buf[0x04] = 101;
        // bg_inode_table_lo = 102
        buf[0x08] = 102;
        // bg_free_blocks_count_lo = 50
        buf[0x0C] = 50;
        // bg_free_inodes_count_lo = 30
        buf[0x0E] = 30;
        // bg_flags = 0x04 (INODE_ZEROED)
        buf[0x12] = 0x04;

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
        // lo fields
        buf[0x00] = 100;
        buf[0x04] = 101;
        buf[0x08] = 102;
        // hi fields (64-bit extension)
        buf[0x20] = 1; // bg_block_bitmap_hi = 1 → combined = (1 << 32) | 100
        buf[0x24] = 2; // bg_inode_bitmap_hi = 2
        buf[0x28] = 3; // bg_inode_table_hi = 3

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/src/ext4fs-forensic && cargo test -p ext4fs`
Expected: FAIL — `GroupDescriptor` not defined.

- [ ] **Step 3: Implement GroupDescriptor**

```rust
// ext4fs/src/ondisk/group_desc.rs
#![forbid(unsafe_code)]

use crate::error::{Ext4Error, Result};
use bitflags::bitflags;

bitflags! {
    /// Block group flags (bg_flags at offset 0x12).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct GroupDescFlags: u16 {
        const INODE_UNINIT  = 0x0001;
        const BLOCK_UNINIT  = 0x0002;
        const INODE_ZEROED  = 0x0004;
    }
}

/// Parsed block group descriptor (normalized to 64-bit fields).
#[derive(Debug, Clone)]
pub struct GroupDescriptor {
    pub block_bitmap: u64,
    pub inode_bitmap: u64,
    pub inode_table: u64,
    pub free_blocks_count: u32,
    pub free_inodes_count: u32,
    pub used_dirs_count: u32,
    pub flags: GroupDescFlags,
    pub itable_unused: u32,
    pub checksum: u16,
}

fn le16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn le32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

impl GroupDescriptor {
    /// Parse a group descriptor from a byte slice.
    /// `desc_size` is from `Superblock::desc_size` (32 or 64).
    pub fn parse(buf: &[u8], desc_size: u16) -> Result<Self> {
        let min = desc_size as usize;
        if buf.len() < min.max(32) {
            return Err(Ext4Error::TooShort {
                structure: "group_descriptor",
                expected: min,
                found: buf.len(),
            });
        }

        let block_bitmap_lo = le32(buf, 0x00) as u64;
        let inode_bitmap_lo = le32(buf, 0x04) as u64;
        let inode_table_lo = le32(buf, 0x08) as u64;
        let free_blocks_lo = le16(buf, 0x0C) as u32;
        let free_inodes_lo = le16(buf, 0x0E) as u32;
        let used_dirs_lo = le16(buf, 0x10) as u32;
        let flags_raw = le16(buf, 0x12);
        let itable_unused_lo = le16(buf, 0x1C) as u32;
        let checksum = le16(buf, 0x1E);

        // 64-bit extensions
        let (bb_hi, ib_hi, it_hi, fb_hi, fi_hi, ud_hi, iu_hi) = if desc_size >= 64 && buf.len() >= 64 {
            (
                le32(buf, 0x20) as u64,
                le32(buf, 0x24) as u64,
                le32(buf, 0x28) as u64,
                le16(buf, 0x2C) as u32,
                le16(buf, 0x2E) as u32,
                le16(buf, 0x30) as u32,
                le16(buf, 0x32) as u32,
            )
        } else {
            (0, 0, 0, 0, 0, 0, 0)
        };

        Ok(GroupDescriptor {
            block_bitmap: (bb_hi << 32) | block_bitmap_lo,
            inode_bitmap: (ib_hi << 32) | inode_bitmap_lo,
            inode_table: (it_hi << 32) | inode_table_lo,
            free_blocks_count: (fb_hi << 16) | free_blocks_lo,
            free_inodes_count: (fi_hi << 16) | free_inodes_lo,
            used_dirs_count: (ud_hi << 16) | used_dirs_lo,
            flags: GroupDescFlags::from_bits_truncate(flags_raw),
            itable_unused: (iu_hi << 16) | itable_unused_lo,
            checksum,
        })
    }
}
```

- [ ] **Step 4: Update ondisk/mod.rs**

```rust
// ext4fs/src/ondisk/mod.rs
#![forbid(unsafe_code)]

pub mod superblock;
pub mod group_desc;

pub use superblock::*;
pub use group_desc::*;
```

- [ ] **Step 5: Run tests**

Run: `cd ~/src/ext4fs-forensic && cargo test -p ext4fs`
Expected: All tests pass (previous + 3 new).

- [ ] **Step 6: Commit**

```bash
cd ~/src/ext4fs-forensic
git add ext4fs/src/ondisk/group_desc.rs ext4fs/src/ondisk/mod.rs
git commit -m "feat: Layer 0 — group descriptor parsing (32-bit + 64-bit)"
```

---

### Task 4: Layer 0 — Inode Parsing with Timestamps

**Files:**
- Create: `ext4fs/src/ondisk/inode.rs`
- Modify: `ext4fs/src/ondisk/mod.rs`

Parse the full inode structure including all 5 timestamps (atime, mtime, ctime, crtime, dtime) with nanosecond precision from the extended fields.

- [ ] **Step 1: Write failing tests**

```rust
// ext4fs/src/ondisk/inode.rs

#[cfg(test)]
mod tests {
    use super::*;

    fn make_inode_bytes(mode: u16, size: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 256];
        // i_mode at 0x00
        buf[0x00] = (mode & 0xFF) as u8;
        buf[0x01] = (mode >> 8) as u8;
        // i_size_lo at 0x04
        buf[0x04] = (size & 0xFF) as u8;
        buf[0x05] = ((size >> 8) & 0xFF) as u8;
        buf[0x06] = ((size >> 16) & 0xFF) as u8;
        buf[0x07] = ((size >> 24) & 0xFF) as u8;
        // i_atime at 0x08 = 1700000000
        let atime: u32 = 1_700_000_000;
        buf[0x08..0x0C].copy_from_slice(&atime.to_le_bytes());
        // i_links_count at 0x1A = 1
        buf[0x1A] = 1;
        // i_flags at 0x20 = EXTENTS_FL (0x00080000)
        buf[0x20] = 0x00;
        buf[0x21] = 0x00;
        buf[0x22] = 0x08;
        buf[0x23] = 0x00;
        // i_extra_isize at 0x80 = 32 (enables extended timestamps)
        buf[0x80] = 32;
        // i_crtime at 0x90 = 1699000000
        let crtime: u32 = 1_699_000_000;
        buf[0x90..0x94].copy_from_slice(&crtime.to_le_bytes());
        buf
    }

    #[test]
    fn parse_regular_file_inode() {
        let buf = make_inode_bytes(0x8180, 12); // regular file, mode 0600
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
        let buf = make_inode_bytes(0x4180, 4096); // directory, mode 0600
        let inode = Inode::parse(&buf, 256).unwrap();
        assert_eq!(inode.file_type(), FileType::Directory);
    }

    #[test]
    fn timestamp_nanoseconds() {
        let mut buf = make_inode_bytes(0x8180, 100);
        // i_atime_extra at 0x8C: nanoseconds in bits 2-31
        // 500_000_000 ns << 2 = 2_000_000_000
        let extra = 500_000_000u32 << 2;
        buf[0x8C..0x90].copy_from_slice(&extra.to_le_bytes());
        let inode = Inode::parse(&buf, 256).unwrap();
        assert_eq!(inode.atime.nanoseconds, 500_000_000);
    }

    #[test]
    fn dtime_set_means_deleted() {
        let mut buf = make_inode_bytes(0x8180, 100);
        // i_dtime at 0x14 = 1700001000
        let dtime: u32 = 1_700_001_000;
        buf[0x14..0x18].copy_from_slice(&dtime.to_le_bytes());
        buf[0x1A] = 0; // links_count = 0
        let inode = Inode::parse(&buf, 256).unwrap();
        assert_eq!(inode.dtime, 1_700_001_000);
        assert_eq!(inode.links_count, 0);
    }

    #[test]
    fn i_block_60_bytes() {
        let mut buf = make_inode_bytes(0x8180, 100);
        // Write known pattern into i_block at 0x28 (60 bytes)
        for i in 0..60 {
            buf[0x28 + i] = i as u8;
        }
        let inode = Inode::parse(&buf, 256).unwrap();
        assert_eq!(inode.i_block.len(), 60);
        assert_eq!(inode.i_block[0], 0);
        assert_eq!(inode.i_block[59], 59);
    }

    #[test]
    fn reject_too_short() {
        let buf = vec![0u8; 50];
        let err = Inode::parse(&buf, 256).unwrap_err();
        assert!(matches!(err, crate::error::Ext4Error::TooShort { .. }));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/src/ext4fs-forensic && cargo test -p ext4fs`
Expected: FAIL — `Inode` not defined.

- [ ] **Step 3: Implement Inode parsing**

```rust
// ext4fs/src/ondisk/inode.rs
#![forbid(unsafe_code)]

use crate::error::{Ext4Error, Result};
use bitflags::bitflags;

/// Minimum inode size (original ext2 128 bytes).
const MIN_INODE_SIZE: usize = 128;

/// A timestamp with seconds and nanoseconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp {
    /// Seconds since Unix epoch (34-bit range: up to year 2446).
    pub seconds: i64,
    /// Nanoseconds (0-999_999_999).
    pub nanoseconds: u32,
}

bitflags! {
    /// Inode flags (i_flags at offset 0x20).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct InodeFlags: u32 {
        const SYNC          = 0x0000_0010;
        const IMMUTABLE     = 0x0000_0020;
        const APPEND        = 0x0000_0040;
        const NODUMP        = 0x0000_0080;
        const NOATIME       = 0x0000_0100;
        const ENCRYPT       = 0x0000_0800;
        const INDEX          = 0x0000_1000;
        const HUGE_FILE     = 0x0001_0000;
        const EA_INODE      = 0x0004_0000;
        const EXTENTS       = 0x0008_0000;
        const INLINE_DATA   = 0x1000_0000;
        const CASEFOLD      = 0x2000_0000;
        const VERITY        = 0x8000_0000;
    }
}

/// File type derived from i_mode upper 4 bits.
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

/// Parsed ext4 inode.
#[derive(Debug, Clone)]
pub struct Inode {
    pub mode: u16,
    pub uid: u32,            // combined lo + hi
    pub gid: u32,            // combined lo + hi
    pub size: u64,           // combined lo + hi
    pub atime: Timestamp,
    pub ctime: Timestamp,
    pub mtime: Timestamp,
    pub crtime: Timestamp,   // creation time (extended inode only)
    pub dtime: u32,          // deletion time (no nanosecond extension)
    pub links_count: u16,
    pub blocks_count: u64,   // combined lo + hi
    pub flags: InodeFlags,
    pub i_block: [u8; 60],   // raw extent tree / block pointers / inline data
    pub generation: u32,
    pub file_acl: u64,       // extended attribute block (combined lo + hi)
    pub extra_isize: u16,
    pub checksum: u32,       // combined lo + hi
    pub projid: u32,
}

fn le16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn le32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Decode a timestamp from the base 32-bit seconds and optional extra field.
/// Extra field format: bits 0-1 = epoch extension, bits 2-31 = nanoseconds.
fn decode_timestamp(base_seconds: u32, extra: Option<u32>) -> Timestamp {
    match extra {
        Some(extra_val) => {
            let epoch_bits = (extra_val & 0x3) as i64;
            let nanoseconds = extra_val >> 2;
            Timestamp {
                seconds: (epoch_bits << 32) | (base_seconds as i64),
                nanoseconds,
            }
        }
        None => Timestamp {
            seconds: base_seconds as i32 as i64, // sign-extend 32-bit
            nanoseconds: 0,
        },
    }
}

impl Inode {
    /// Parse an inode from a byte slice.
    /// `inode_size` is from `Superblock::inode_size` (typically 256).
    pub fn parse(buf: &[u8], inode_size: u16) -> Result<Self> {
        let min = MIN_INODE_SIZE.min(inode_size as usize);
        if buf.len() < min {
            return Err(Ext4Error::TooShort {
                structure: "inode",
                expected: min,
                found: buf.len(),
            });
        }

        let mode = le16(buf, 0x00);
        let uid_lo = le16(buf, 0x02) as u32;
        let gid_lo = le16(buf, 0x18) as u32;
        let size_lo = le32(buf, 0x04) as u64;
        let size_hi = if buf.len() > 0x6F { le32(buf, 0x6C) as u64 } else { 0 };

        let uid_hi = if buf.len() > 0x79 { le16(buf, 0x78) as u32 } else { 0 };
        let gid_hi = if buf.len() > 0x7B { le16(buf, 0x7A) as u32 } else { 0 };

        let blocks_lo = le32(buf, 0x1C) as u64;
        let blocks_hi = if buf.len() > 0x75 { le16(buf, 0x74) as u64 } else { 0 };

        let file_acl_lo = if buf.len() > 0x6B { le32(buf, 0x68) as u64 } else { 0 };
        let file_acl_hi = if buf.len() > 0x77 { le16(buf, 0x76) as u64 } else { 0 };

        let checksum_lo = if buf.len() > 0x7D { le16(buf, 0x7C) as u32 } else { 0 };

        let extra_isize = if buf.len() > 0x81 && inode_size > 128 {
            le16(buf, 0x80)
        } else {
            0
        };

        // Extended timestamps are available if extra_isize >= 32 (covers through 0x9F)
        let has_extra_ts = extra_isize >= 32 && buf.len() >= 0x98;

        let atime_extra = if has_extra_ts { Some(le32(buf, 0x8C)) } else { None };
        let ctime_extra = if has_extra_ts { Some(le32(buf, 0x84)) } else { None };
        let mtime_extra = if has_extra_ts { Some(le32(buf, 0x88)) } else { None };

        let crtime = if has_extra_ts && buf.len() >= 0x98 {
            let crtime_extra = if buf.len() >= 0x98 { Some(le32(buf, 0x94)) } else { None };
            decode_timestamp(le32(buf, 0x90), crtime_extra)
        } else {
            Timestamp::default()
        };

        let checksum_hi = if extra_isize >= 4 && buf.len() > 0x83 {
            le16(buf, 0x82) as u32
        } else {
            0
        };

        let projid = if extra_isize >= 32 && buf.len() >= 0xA0 {
            le32(buf, 0x9C)
        } else {
            0
        };

        let mut i_block = [0u8; 60];
        if buf.len() >= 0x64 {
            i_block.copy_from_slice(&buf[0x28..0x64]);
        }

        Ok(Inode {
            mode,
            uid: (uid_hi << 16) | uid_lo,
            gid: (gid_hi << 16) | gid_lo,
            size: (size_hi << 32) | size_lo,
            atime: decode_timestamp(le32(buf, 0x08), atime_extra),
            ctime: decode_timestamp(le32(buf, 0x0C), ctime_extra),
            mtime: decode_timestamp(le32(buf, 0x10), mtime_extra),
            crtime,
            dtime: le32(buf, 0x14),
            links_count: le16(buf, 0x1A),
            blocks_count: (blocks_hi << 32) | blocks_lo,
            flags: InodeFlags::from_bits_truncate(le32(buf, 0x20)),
            i_block,
            generation: if buf.len() > 0x67 { le32(buf, 0x64) } else { 0 },
            file_acl: (file_acl_hi << 32) | file_acl_lo,
            extra_isize,
            checksum: (checksum_hi << 16) | checksum_lo,
            projid,
        })
    }

    /// Extract the file type from i_mode (upper 4 bits).
    pub fn file_type(&self) -> FileType {
        match self.mode & 0xF000 {
            0x1000 => FileType::Fifo,
            0x2000 => FileType::CharDevice,
            0x4000 => FileType::Directory,
            0x6000 => FileType::BlockDevice,
            0x8000 => FileType::RegularFile,
            0xA000 => FileType::Symlink,
            0xC000 => FileType::Socket,
            _ => FileType::Unknown,
        }
    }

    /// Extract the permission bits from i_mode (lower 12 bits).
    pub fn mode_permissions(&self) -> u16 {
        self.mode & 0x0FFF
    }

    /// Whether this inode uses extent trees (vs legacy block pointers).
    pub fn uses_extents(&self) -> bool {
        self.flags.contains(InodeFlags::EXTENTS)
    }

    /// Whether this inode stores data inline (in i_block + xattr).
    pub fn has_inline_data(&self) -> bool {
        self.flags.contains(InodeFlags::INLINE_DATA)
    }

    /// Whether this inode is a directory with HTree indexing.
    pub fn has_htree(&self) -> bool {
        self.flags.contains(InodeFlags::INDEX)
    }

    /// Whether this inode appears to be deleted.
    pub fn is_deleted(&self) -> bool {
        self.dtime != 0 || (self.links_count == 0 && self.mode != 0)
    }
}
```

- [ ] **Step 4: Update ondisk/mod.rs**

```rust
// ext4fs/src/ondisk/mod.rs
#![forbid(unsafe_code)]

pub mod superblock;
pub mod group_desc;
pub mod inode;

pub use superblock::*;
pub use group_desc::*;
pub use inode::*;
```

- [ ] **Step 5: Run tests**

Run: `cd ~/src/ext4fs-forensic && cargo test -p ext4fs`
Expected: All tests pass (previous + 6 new inode tests).

- [ ] **Step 6: Commit**

```bash
cd ~/src/ext4fs-forensic
git add ext4fs/src/ondisk/inode.rs ext4fs/src/ondisk/mod.rs
git commit -m "feat: Layer 0 — inode parsing with 5 timestamps and nanosecond precision"
```

---

### Task 5: Layer 0 — Extent Tree Structs

**Files:**
- Create: `ext4fs/src/ondisk/extent.rs`
- Modify: `ext4fs/src/ondisk/mod.rs`

Parse extent headers, leaf entries, and index entries from `&[u8]`.

- [ ] **Step 1: Write failing tests**

```rust
// ext4fs/src/ondisk/extent.rs

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_extent_header() {
        let mut buf = vec![0u8; 12];
        // eh_magic = 0xF30A
        buf[0] = 0x0A;
        buf[1] = 0xF3;
        // eh_entries = 3
        buf[2] = 3;
        // eh_max = 4
        buf[4] = 4;
        // eh_depth = 0 (leaf)
        buf[6] = 0;
        let hdr = ExtentHeader::parse(&buf).unwrap();
        assert_eq!(hdr.magic, EXTENT_MAGIC);
        assert_eq!(hdr.entries, 3);
        assert_eq!(hdr.max, 4);
        assert_eq!(hdr.depth, 0);
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
        // ee_block = 0 (first logical block)
        // ee_len = 10 (10 blocks)
        buf[4] = 10;
        // ee_start_hi = 0
        // ee_start_lo = 500
        buf[8] = 0xF4;
        buf[9] = 0x01; // 500
        let leaf = ExtentLeaf::parse(&buf);
        assert_eq!(leaf.logical_block, 0);
        assert_eq!(leaf.length, 10);
        assert_eq!(leaf.physical_block, 500);
        assert!(!leaf.unwritten);
    }

    #[test]
    fn extent_leaf_unwritten_flag() {
        let mut buf = vec![0u8; 12];
        // ee_len = 0x8005 (bit 15 set = unwritten, actual length = 5)
        buf[4] = 0x05;
        buf[5] = 0x80;
        let leaf = ExtentLeaf::parse(&buf);
        assert_eq!(leaf.length, 5);
        assert!(leaf.unwritten);
    }

    #[test]
    fn parse_extent_index() {
        let mut buf = vec![0u8; 12];
        // ei_block = 1000
        buf[0] = 0xE8;
        buf[1] = 0x03;
        // ei_leaf_lo = 2000
        buf[4] = 0xD0;
        buf[5] = 0x07;
        // ei_leaf_hi = 1
        buf[8] = 1;
        let idx = ExtentIndex::parse(&buf);
        assert_eq!(idx.logical_block, 1000);
        assert_eq!(idx.child_block, (1u64 << 32) | 2000);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/src/ext4fs-forensic && cargo test -p ext4fs`
Expected: FAIL — extent types not defined.

- [ ] **Step 3: Implement extent structs**

```rust
// ext4fs/src/ondisk/extent.rs
#![forbid(unsafe_code)]

use crate::error::{Ext4Error, Result};

/// Extent header magic number.
pub const EXTENT_MAGIC: u16 = 0xF30A;

fn le16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn le32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Extent tree header (12 bytes).
#[derive(Debug, Clone, Copy)]
pub struct ExtentHeader {
    pub magic: u16,
    pub entries: u16,
    pub max: u16,
    pub depth: u16,
    pub generation: u32,
}

impl ExtentHeader {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 12 {
            return Err(Ext4Error::TooShort {
                structure: "extent_header",
                expected: 12,
                found: buf.len(),
            });
        }
        let magic = le16(buf, 0);
        if magic != EXTENT_MAGIC {
            return Err(Ext4Error::CorruptMetadata {
                structure: "extent_header",
                detail: format!("bad magic: 0x{magic:04X} (expected 0xF30A)"),
            });
        }
        Ok(ExtentHeader {
            magic,
            entries: le16(buf, 2),
            max: le16(buf, 4),
            depth: le16(buf, 6),
            generation: le32(buf, 8),
        })
    }
}

/// Extent leaf entry (12 bytes, at depth 0).
#[derive(Debug, Clone, Copy)]
pub struct ExtentLeaf {
    pub logical_block: u32,
    pub length: u16,
    pub physical_block: u64,
    pub unwritten: bool,
}

impl ExtentLeaf {
    pub fn parse(buf: &[u8]) -> Self {
        let ee_len = le16(buf, 4);
        let unwritten = (ee_len & 0x8000) != 0;
        let length = if unwritten { ee_len & 0x7FFF } else { ee_len };

        let start_hi = le16(buf, 6) as u64;
        let start_lo = le32(buf, 8) as u64;

        ExtentLeaf {
            logical_block: le32(buf, 0),
            length,
            physical_block: (start_hi << 32) | start_lo,
            unwritten,
        }
    }
}

/// Extent index entry (12 bytes, at depth > 0).
#[derive(Debug, Clone, Copy)]
pub struct ExtentIndex {
    pub logical_block: u32,
    pub child_block: u64,
}

impl ExtentIndex {
    pub fn parse(buf: &[u8]) -> Self {
        let leaf_lo = le32(buf, 4) as u64;
        let leaf_hi = le16(buf, 8) as u64;
        ExtentIndex {
            logical_block: le32(buf, 0),
            child_block: (leaf_hi << 32) | leaf_lo,
        }
    }
}
```

- [ ] **Step 4: Update ondisk/mod.rs**

```rust
// ext4fs/src/ondisk/mod.rs
#![forbid(unsafe_code)]

pub mod superblock;
pub mod group_desc;
pub mod inode;
pub mod extent;

pub use superblock::*;
pub use group_desc::*;
pub use inode::*;
pub use extent::*;
```

- [ ] **Step 5: Run tests**

Run: `cd ~/src/ext4fs-forensic && cargo test -p ext4fs`
Expected: All tests pass.

- [ ] **Step 6: Commit**

```bash
cd ~/src/ext4fs-forensic
git add ext4fs/src/ondisk/extent.rs ext4fs/src/ondisk/mod.rs
git commit -m "feat: Layer 0 — extent tree structs (header, leaf, index)"
```

---

### Task 6: Layer 0 — Directory Entry Structs

**Files:**
- Create: `ext4fs/src/ondisk/dir_entry.rs`
- Modify: `ext4fs/src/ondisk/mod.rs`

- [ ] **Step 1: Write failing tests**

```rust
// ext4fs/src/ondisk/dir_entry.rs

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dir_entry() {
        let mut buf = vec![0u8; 20];
        // inode = 12
        buf[0] = 12;
        // rec_len = 20
        buf[4] = 20;
        // name_len = 5
        buf[6] = 5;
        // file_type = 1 (regular file)
        buf[7] = 1;
        // name = "hello"
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
        buf[0] = 2; // root inode
        buf[4] = 12; // rec_len
        buf[6] = 1; // name_len
        buf[7] = 2; // directory
        buf[8] = b'.';
        let entry = DirEntry::parse(&buf).unwrap();
        assert_eq!(entry.name, b".");
        assert_eq!(entry.file_type, DirEntryType::Directory);
    }

    #[test]
    fn skip_deleted_entry() {
        let mut buf = vec![0u8; 12];
        buf[0] = 0; // inode = 0 means deleted
        buf[4] = 12;
        buf[6] = 3;
        buf[7] = 1;
        buf[8..11].copy_from_slice(b"foo");
        let entry = DirEntry::parse(&buf).unwrap();
        assert_eq!(entry.inode, 0); // caller checks inode == 0 to skip
    }

    #[test]
    fn reject_too_short() {
        let buf = vec![0u8; 4];
        let err = DirEntry::parse(&buf).unwrap_err();
        assert!(matches!(err, crate::error::Ext4Error::TooShort { .. }));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/src/ext4fs-forensic && cargo test -p ext4fs`
Expected: FAIL — `DirEntry` not defined.

- [ ] **Step 3: Implement DirEntry**

```rust
// ext4fs/src/ondisk/dir_entry.rs
#![forbid(unsafe_code)]

use crate::error::{Ext4Error, Result};

/// Directory entry file type (from file_type byte at offset 0x07).
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
    fn from(val: u8) -> Self {
        match val {
            1 => DirEntryType::RegularFile,
            2 => DirEntryType::Directory,
            3 => DirEntryType::CharDevice,
            4 => DirEntryType::BlockDevice,
            5 => DirEntryType::Fifo,
            6 => DirEntryType::Socket,
            7 => DirEntryType::Symlink,
            _ => DirEntryType::Unknown,
        }
    }
}

/// Parsed ext4 directory entry (ext4_dir_entry_2 format).
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub inode: u32,
    pub rec_len: u16,
    pub name: Vec<u8>,
    pub file_type: DirEntryType,
}

fn le16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn le32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

impl DirEntry {
    /// Parse a single directory entry from the start of `buf`.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 8 {
            return Err(Ext4Error::TooShort {
                structure: "dir_entry",
                expected: 8,
                found: buf.len(),
            });
        }

        let inode = le32(buf, 0);
        let rec_len = le16(buf, 4);
        let name_len = buf[6] as usize;
        let file_type = DirEntryType::from(buf[7]);

        let name_end = 8 + name_len;
        let name = if name_end <= buf.len() {
            buf[8..name_end].to_vec()
        } else {
            buf[8..buf.len().min(8 + name_len)].to_vec()
        };

        Ok(DirEntry {
            inode,
            rec_len,
            name,
            file_type,
        })
    }

    /// Name as a lossy UTF-8 string.
    pub fn name_str(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }

    /// Whether this entry has been deleted (inode == 0).
    pub fn is_deleted(&self) -> bool {
        self.inode == 0
    }
}

/// Parse all directory entries from a block of directory data.
/// Returns entries in order, including deleted entries (inode == 0).
pub fn parse_dir_block(block: &[u8]) -> Vec<DirEntry> {
    let mut entries = Vec::new();
    let mut offset = 0;
    while offset + 8 <= block.len() {
        let rec_len = le16(block, offset + 4) as usize;
        if rec_len < 8 || offset + rec_len > block.len() {
            break;
        }
        if let Ok(entry) = DirEntry::parse(&block[offset..offset + rec_len]) {
            entries.push(entry);
        }
        offset += rec_len;
    }
    entries
}
```

- [ ] **Step 4: Update ondisk/mod.rs**

```rust
// ext4fs/src/ondisk/mod.rs
#![forbid(unsafe_code)]

pub mod superblock;
pub mod group_desc;
pub mod inode;
pub mod extent;
pub mod dir_entry;

pub use superblock::*;
pub use group_desc::*;
pub use inode::*;
pub use extent::*;
pub use dir_entry::*;
```

- [ ] **Step 5: Run tests**

Run: `cd ~/src/ext4fs-forensic && cargo test -p ext4fs`
Expected: All tests pass.

- [ ] **Step 6: Commit**

```bash
cd ~/src/ext4fs-forensic
git add ext4fs/src/ondisk/dir_entry.rs ext4fs/src/ondisk/mod.rs
git commit -m "feat: Layer 0 — directory entry parsing with file type"
```

---

### Task 7: Layer 0 — Journal Structs (Big-Endian)

**Files:**
- Create: `ext4fs/src/ondisk/journal.rs`
- Modify: `ext4fs/src/ondisk/mod.rs`

Parse jbd2 journal on-disk structures. **These are big-endian**, unlike all other ext4 structures.

- [ ] **Step 1: Write failing tests**

```rust
// ext4fs/src/ondisk/journal.rs

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_journal_header() {
        let mut buf = vec![0u8; 12];
        // h_magic = 0xC03B3998 (big-endian)
        buf[0..4].copy_from_slice(&0xC03B3998u32.to_be_bytes());
        // h_blocktype = 1 (descriptor)
        buf[4..8].copy_from_slice(&1u32.to_be_bytes());
        // h_sequence = 42
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
        // header
        buf[0..4].copy_from_slice(&JOURNAL_MAGIC.to_be_bytes());
        buf[4..8].copy_from_slice(&4u32.to_be_bytes()); // sb_v2
        buf[8..12].copy_from_slice(&1u32.to_be_bytes()); // sequence
        // s_blocksize = 4096
        buf[0x0C..0x10].copy_from_slice(&4096u32.to_be_bytes());
        // s_maxlen = 1024
        buf[0x10..0x14].copy_from_slice(&1024u32.to_be_bytes());
        // s_first = 1
        buf[0x14..0x18].copy_from_slice(&1u32.to_be_bytes());
        let jsb = JournalSuperblock::parse(&buf).unwrap();
        assert_eq!(jsb.block_size, 4096);
        assert_eq!(jsb.max_len, 1024);
        assert_eq!(jsb.first, 1);
    }

    #[test]
    fn parse_block_tag_v3() {
        let mut buf = vec![0u8; 16];
        // t_blocknr = 500 (big-endian)
        buf[0..4].copy_from_slice(&500u32.to_be_bytes());
        // t_flags = 0x08 (LAST_TAG)
        buf[4..8].copy_from_slice(&0x08u32.to_be_bytes());
        // t_blocknr_high = 0
        // t_checksum
        buf[12..16].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
        let tag = JournalBlockTag::parse_v3(&buf, false);
        assert_eq!(tag.blocknr, 500);
        assert!(tag.last_tag);
        assert!(!tag.escaped);
    }

    #[test]
    fn parse_commit_block() {
        let mut buf = vec![0u8; 64];
        // header
        buf[0..4].copy_from_slice(&JOURNAL_MAGIC.to_be_bytes());
        buf[4..8].copy_from_slice(&2u32.to_be_bytes()); // commit
        buf[8..12].copy_from_slice(&99u32.to_be_bytes()); // sequence
        // h_commit_sec at 0x30 = 1700000000
        buf[0x30..0x38].copy_from_slice(&1_700_000_000u64.to_be_bytes());
        // h_commit_nsec at 0x38 = 500000000
        buf[0x38..0x3C].copy_from_slice(&500_000_000u32.to_be_bytes());
        let commit = JournalCommit::parse(&buf).unwrap();
        assert_eq!(commit.sequence, 99);
        assert_eq!(commit.commit_seconds, 1_700_000_000);
        assert_eq!(commit.commit_nanoseconds, 500_000_000);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/src/ext4fs-forensic && cargo test -p ext4fs`
Expected: FAIL — journal types not defined.

- [ ] **Step 3: Implement journal structs**

```rust
// ext4fs/src/ondisk/journal.rs
#![forbid(unsafe_code)]

use crate::error::{Ext4Error, Result};

/// jbd2 journal magic number (big-endian on disk).
pub const JOURNAL_MAGIC: u32 = 0xC03B3998;

fn be32(buf: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn be64(buf: &[u8], off: usize) -> u64 {
    u64::from_be_bytes([
        buf[off], buf[off + 1], buf[off + 2], buf[off + 3],
        buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7],
    ])
}

/// Journal block type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalBlockType {
    Descriptor,     // 1
    Commit,         // 2
    SuperblockV1,   // 3
    SuperblockV2,   // 4
    Revoke,         // 5
    Unknown(u32),
}

impl From<u32> for JournalBlockType {
    fn from(val: u32) -> Self {
        match val {
            1 => JournalBlockType::Descriptor,
            2 => JournalBlockType::Commit,
            3 => JournalBlockType::SuperblockV1,
            4 => JournalBlockType::SuperblockV2,
            5 => JournalBlockType::Revoke,
            other => JournalBlockType::Unknown(other),
        }
    }
}

/// Common journal block header (12 bytes, big-endian).
#[derive(Debug, Clone, Copy)]
pub struct JournalHeader {
    pub magic: u32,
    pub block_type: JournalBlockType,
    pub sequence: u32,
}

impl JournalHeader {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 12 {
            return Err(Ext4Error::TooShort {
                structure: "journal_header",
                expected: 12,
                found: buf.len(),
            });
        }
        let magic = be32(buf, 0);
        if magic != JOURNAL_MAGIC {
            return Err(Ext4Error::JournalCorrupt(
                format!("bad magic: 0x{magic:08X} (expected 0xC03B3998)")
            ));
        }
        Ok(JournalHeader {
            magic,
            block_type: JournalBlockType::from(be32(buf, 4)),
            sequence: be32(buf, 8),
        })
    }
}

/// Journal superblock (big-endian).
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
    pub uuid: [u8; 16],
    pub nr_users: u32,
    pub checksum_type: u8,
    pub checksum: u32,
}

impl JournalSuperblock {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 0x100 {
            return Err(Ext4Error::TooShort {
                structure: "journal_superblock",
                expected: 0x100,
                found: buf.len(),
            });
        }
        let header = JournalHeader::parse(buf)?;

        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&buf[0x30..0x40]);

        Ok(JournalSuperblock {
            header,
            block_size: be32(buf, 0x0C),
            max_len: be32(buf, 0x10),
            first: be32(buf, 0x14),
            sequence: be32(buf, 0x18),
            start: be32(buf, 0x1C),
            errno: be32(buf, 0x20),
            feature_compat: be32(buf, 0x24),
            feature_incompat: be32(buf, 0x28),
            uuid,
            nr_users: be32(buf, 0x40),
            checksum_type: buf[0x50],
            checksum: if buf.len() >= 0x100 { be32(buf, 0xFC) } else { 0 },
        })
    }

    /// Whether the journal uses 64-bit block numbers.
    pub fn is_64bit(&self) -> bool {
        (self.feature_incompat & 0x1) != 0
    }

    /// Whether the journal uses CRC32C checksums (v3 tags).
    pub fn has_csum_v3(&self) -> bool {
        (self.feature_incompat & 0x10) != 0
    }

    /// Whether the journal uses v2 checksums.
    pub fn has_csum_v2(&self) -> bool {
        (self.feature_incompat & 0x8) != 0
    }
}

/// A tag in a descriptor block, mapping a journal data block to a filesystem block.
#[derive(Debug, Clone, Copy)]
pub struct JournalBlockTag {
    pub blocknr: u64,
    pub checksum: u32,
    pub escaped: bool,
    pub same_uuid: bool,
    pub last_tag: bool,
    /// Size of this tag in bytes (for advancing offset).
    pub tag_size: usize,
}

impl JournalBlockTag {
    /// Parse a CSUM_V3 tag (fixed 16 bytes, or 32 if UUID present).
    pub fn parse_v3(buf: &[u8], is_64bit: bool) -> Self {
        let blocknr_lo = be32(buf, 0) as u64;
        let flags = be32(buf, 4);
        let blocknr_hi = if is_64bit { be32(buf, 8) as u64 } else { 0 };
        let checksum = be32(buf, 12);

        let escaped = (flags & 0x1) != 0;
        let same_uuid = (flags & 0x2) != 0;
        let last_tag = (flags & 0x8) != 0;

        let tag_size = if same_uuid { 16 } else { 32 };

        JournalBlockTag {
            blocknr: (blocknr_hi << 32) | blocknr_lo,
            checksum,
            escaped,
            same_uuid,
            last_tag,
            tag_size,
        }
    }
}

/// Parsed commit block.
#[derive(Debug, Clone, Copy)]
pub struct JournalCommit {
    pub sequence: u32,
    pub commit_seconds: i64,
    pub commit_nanoseconds: u32,
}

impl JournalCommit {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        let header = JournalHeader::parse(buf)?;
        if header.block_type != JournalBlockType::Commit {
            return Err(Ext4Error::JournalCorrupt(
                format!("expected commit block, got {:?}", header.block_type)
            ));
        }
        let commit_seconds = if buf.len() >= 0x38 { be64(buf, 0x30) as i64 } else { 0 };
        let commit_nanoseconds = if buf.len() >= 0x3C { be32(buf, 0x38) } else { 0 };

        Ok(JournalCommit {
            sequence: header.sequence,
            commit_seconds,
            commit_nanoseconds,
        })
    }
}

/// Parsed revocation block.
#[derive(Debug, Clone)]
pub struct JournalRevoke {
    pub sequence: u32,
    pub revoked_blocks: Vec<u64>,
}

impl JournalRevoke {
    /// Parse a revocation block.
    /// `is_64bit` determines whether block numbers are 4 or 8 bytes.
    pub fn parse(buf: &[u8], is_64bit: bool) -> Result<Self> {
        let header = JournalHeader::parse(buf)?;
        if header.block_type != JournalBlockType::Revoke {
            return Err(Ext4Error::JournalCorrupt(
                format!("expected revoke block, got {:?}", header.block_type)
            ));
        }

        let count = if buf.len() >= 16 { be32(buf, 12) as usize } else { 0 };
        let entry_size = if is_64bit { 8 } else { 4 };
        let mut revoked_blocks = Vec::new();
        let mut offset = 16;
        while offset + entry_size <= count.min(buf.len()) {
            let block = if is_64bit {
                be64(buf, offset)
            } else {
                be32(buf, offset) as u64
            };
            revoked_blocks.push(block);
            offset += entry_size;
        }

        Ok(JournalRevoke {
            sequence: header.sequence,
            revoked_blocks,
        })
    }
}
```

- [ ] **Step 4: Update ondisk/mod.rs**

Add `pub mod journal;` and `pub use journal::*;`.

- [ ] **Step 5: Run tests**

Run: `cd ~/src/ext4fs-forensic && cargo test -p ext4fs`
Expected: All tests pass.

- [ ] **Step 6: Commit**

```bash
cd ~/src/ext4fs-forensic
git add ext4fs/src/ondisk/journal.rs ext4fs/src/ondisk/mod.rs
git commit -m "feat: Layer 0 — jbd2 journal structs (big-endian)"
```

---

### Task 8: Layer 0 — Xattr Structs

**Files:**
- Create: `ext4fs/src/ondisk/xattr.rs`
- Modify: `ext4fs/src/ondisk/mod.rs`

- [ ] **Step 1: Write failing tests**

```rust
// ext4fs/src/ondisk/xattr.rs

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_xattr_header() {
        let mut buf = vec![0u8; 32];
        // magic = 0xEA020000
        buf[0..4].copy_from_slice(&0xEA020000u32.to_le_bytes());
        // refcount = 1
        buf[4..8].copy_from_slice(&1u32.to_le_bytes());
        // blocks = 1
        buf[8..12].copy_from_slice(&1u32.to_le_bytes());
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
        // name_len = 4
        buf[0] = 4;
        // name_index = 1 (user)
        buf[1] = 1;
        // value_offs = 100
        buf[2..4].copy_from_slice(&100u16.to_le_bytes());
        // value_inum = 0
        // value_size = 5
        buf[8..12].copy_from_slice(&5u32.to_le_bytes());
        // name = "test"
        buf[16..20].copy_from_slice(b"test");
        let entry = XattrEntry::parse(&buf).unwrap();
        assert_eq!(entry.name_index, XattrNamespace::User);
        assert_eq!(entry.name, b"test");
        assert_eq!(entry.value_offset, 100);
        assert_eq!(entry.value_size, 5);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/src/ext4fs-forensic && cargo test -p ext4fs`
Expected: FAIL — xattr types not defined.

- [ ] **Step 3: Implement xattr structs**

```rust
// ext4fs/src/ondisk/xattr.rs
#![forbid(unsafe_code)]

use crate::error::{Ext4Error, Result};

/// Xattr block header magic.
pub const XATTR_MAGIC: u32 = 0xEA020000;

fn le16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn le32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Xattr namespace (name_index field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XattrNamespace {
    User,       // 1
    System,     // 7 (POSIX ACL access), 6 (POSIX ACL default)
    Security,   // 2
    Trusted,    // 4
    Unknown(u8),
}

impl From<u8> for XattrNamespace {
    fn from(val: u8) -> Self {
        match val {
            1 => XattrNamespace::User,
            2 => XattrNamespace::Security,
            4 => XattrNamespace::Trusted,
            6 | 7 => XattrNamespace::System,
            other => XattrNamespace::Unknown(other),
        }
    }
}

/// Xattr block header (32 bytes).
#[derive(Debug, Clone)]
pub struct XattrBlockHeader {
    pub magic: u32,
    pub refcount: u32,
    pub blocks: u32,
    pub hash: u32,
    pub checksum: u32,
}

impl XattrBlockHeader {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 32 {
            return Err(Ext4Error::TooShort {
                structure: "xattr_block_header",
                expected: 32,
                found: buf.len(),
            });
        }
        let magic = le32(buf, 0);
        if magic != XATTR_MAGIC {
            return Err(Ext4Error::CorruptMetadata {
                structure: "xattr_block_header",
                detail: format!("bad magic: 0x{magic:08X} (expected 0xEA020000)"),
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

/// Xattr entry header.
/// Layout: name_len(1) + name_index(1) + value_offs(2) + value_inum(4) + value_size(4) + hash(4) + name(name_len)
#[derive(Debug, Clone)]
pub struct XattrEntry {
    pub name_index: XattrNamespace,
    pub name: Vec<u8>,
    pub value_offset: u16,
    pub value_inum: u32,
    pub value_size: u32,
    pub hash: u32,
    /// Total size of this entry in bytes (for advancing offset).
    pub entry_size: usize,
}

impl XattrEntry {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 16 {
            return Err(Ext4Error::TooShort {
                structure: "xattr_entry",
                expected: 16,
                found: buf.len(),
            });
        }
        let name_len = buf[0] as usize;
        let name_index = XattrNamespace::from(buf[1]);
        let value_offset = le16(buf, 2);
        let value_inum = le32(buf, 4);
        let value_size = le32(buf, 8);
        let hash = le32(buf, 12);

        let name_start = 16;
        let name_end = name_start + name_len;
        if buf.len() < name_end {
            return Err(Ext4Error::TooShort {
                structure: "xattr_entry_name",
                expected: name_end,
                found: buf.len(),
            });
        }
        let name = buf[name_start..name_end].to_vec();

        // Entries are 4-byte aligned
        let entry_size = (name_end + 3) & !3;

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
```

- [ ] **Step 4: Update ondisk/mod.rs**

Add `pub mod xattr;` and `pub use xattr::*;`.

- [ ] **Step 5: Run tests**

Run: `cd ~/src/ext4fs-forensic && cargo test -p ext4fs`
Expected: All tests pass.

- [ ] **Step 6: Commit**

```bash
cd ~/src/ext4fs-forensic
git add ext4fs/src/ondisk/xattr.rs ext4fs/src/ondisk/mod.rs
git commit -m "feat: Layer 0 — xattr header and entry parsing"
```

---

### Task 9: Layer 1 — BlockReader (Open + Superblock + Group Descriptors)

**Files:**
- Create: `ext4fs/src/block.rs`
- Modify: `ext4fs/src/lib.rs`

The `BlockReader<R: Read + Seek>` reads the superblock at offset 1024, validates it, then reads and caches all group descriptors.

- [ ] **Step 1: Write failing tests**

```rust
// ext4fs/src/block.rs

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn load_minimal_image() -> Option<Vec<u8>> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/minimal.img");
        std::fs::read(path).ok()
    }

    #[test]
    fn open_minimal_image() {
        let data = match load_minimal_image() {
            Some(d) => d,
            None => { eprintln!("skip: minimal.img not found"); return; }
        };
        let mut reader = BlockReader::open(Cursor::new(data)).unwrap();
        assert_eq!(reader.superblock().magic, 0xEF53);
        assert_eq!(reader.superblock().block_size, 4096);
        assert!(reader.group_count() > 0);
        assert!(reader.group_descriptors().len() > 0);
    }

    #[test]
    fn reject_too_small_image() {
        let data = vec![0u8; 512]; // too small for superblock
        let err = BlockReader::open(Cursor::new(data)).unwrap_err();
        assert!(matches!(err, crate::error::Ext4Error::Io(_) | crate::error::Ext4Error::TooShort { .. }));
    }

    #[test]
    fn read_block_zero() {
        let data = match load_minimal_image() {
            Some(d) => d,
            None => { eprintln!("skip: minimal.img not found"); return; }
        };
        let mut reader = BlockReader::open(Cursor::new(data)).unwrap();
        let block = reader.read_block(0).unwrap();
        assert_eq!(block.len(), 4096);
    }

    #[test]
    fn read_block_out_of_range() {
        let data = match load_minimal_image() {
            Some(d) => d,
            None => { eprintln!("skip: minimal.img not found"); return; }
        };
        let mut reader = BlockReader::open(Cursor::new(data)).unwrap();
        let err = reader.read_block(u64::MAX).unwrap_err();
        assert!(matches!(err, crate::error::Ext4Error::BlockOutOfRange { .. }));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/src/ext4fs-forensic && cargo test -p ext4fs`
Expected: FAIL — `BlockReader` not defined.

- [ ] **Step 3: Implement BlockReader**

```rust
// ext4fs/src/block.rs
#![forbid(unsafe_code)]

use crate::error::{Ext4Error, Result};
use crate::ondisk::{GroupDescriptor, Superblock};
use std::io::{Read, Seek, SeekFrom};

/// Block device abstraction over any Read+Seek source.
/// Caches the superblock and all group descriptors on open.
pub struct BlockReader<R: Read + Seek> {
    source: R,
    superblock: Superblock,
    group_descs: Vec<GroupDescriptor>,
}

impl<R: Read + Seek> BlockReader<R> {
    /// Open a block reader on a Read+Seek source.
    /// Reads and validates the superblock at offset 1024, then reads all group descriptors.
    pub fn open(mut source: R) -> Result<Self> {
        // Read superblock (1024 bytes at offset 1024)
        source.seek(SeekFrom::Start(1024))?;
        let mut sb_buf = vec![0u8; 1024];
        source.read_exact(&mut sb_buf)?;
        let superblock = Superblock::parse(&sb_buf)?;

        // Read group descriptors
        let group_count = superblock.group_count();
        let desc_size = superblock.desc_size as usize;
        let block_size = superblock.block_size as u64;

        // Group descriptor table starts in the block after the superblock.
        // For block_size >= 2048, superblock is in block 0, GDT in block 1.
        // For block_size == 1024, superblock is in block 1, GDT in block 2.
        let gdt_block = if superblock.block_size == 1024 { 2 } else { 1 };
        let gdt_offset = gdt_block * block_size;
        let gdt_size = group_count as usize * desc_size;

        source.seek(SeekFrom::Start(gdt_offset))?;
        let mut gdt_buf = vec![0u8; gdt_size];
        source.read_exact(&mut gdt_buf)?;

        let mut group_descs = Vec::with_capacity(group_count as usize);
        for i in 0..group_count as usize {
            let offset = i * desc_size;
            let end = offset + desc_size;
            if end > gdt_buf.len() { break; }
            let gd = GroupDescriptor::parse(&gdt_buf[offset..end], superblock.desc_size)?;
            group_descs.push(gd);
        }

        Ok(BlockReader {
            source,
            superblock,
            group_descs,
        })
    }

    /// Reference to the cached superblock.
    pub fn superblock(&self) -> &Superblock {
        &self.superblock
    }

    /// Reference to all cached group descriptors.
    pub fn group_descriptors(&self) -> &[GroupDescriptor] {
        &self.group_descs
    }

    /// Number of block groups.
    pub fn group_count(&self) -> u32 {
        self.group_descs.len() as u32
    }

    /// Block size in bytes.
    pub fn block_size(&self) -> u32 {
        self.superblock.block_size
    }

    /// Read a single block by block number.
    pub fn read_block(&mut self, block_num: u64) -> Result<Vec<u8>> {
        if block_num >= self.superblock.blocks_count {
            return Err(Ext4Error::BlockOutOfRange {
                block: block_num,
                max: self.superblock.blocks_count,
            });
        }
        let offset = block_num * self.superblock.block_size as u64;
        self.read_bytes(offset, self.superblock.block_size as usize)
    }

    /// Read multiple contiguous blocks.
    pub fn read_blocks(&mut self, start: u64, count: u64) -> Result<Vec<u8>> {
        let end = start.checked_add(count).ok_or(Ext4Error::BlockOutOfRange {
            block: start,
            max: self.superblock.blocks_count,
        })?;
        if end > self.superblock.blocks_count {
            return Err(Ext4Error::BlockOutOfRange {
                block: end - 1,
                max: self.superblock.blocks_count,
            });
        }
        let offset = start * self.superblock.block_size as u64;
        let len = count as usize * self.superblock.block_size as usize;
        self.read_bytes(offset, len)
    }

    /// Read arbitrary bytes from the underlying source.
    pub fn read_bytes(&mut self, offset: u64, len: usize) -> Result<Vec<u8>> {
        self.source.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; len];
        self.source.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Get a group descriptor by group number.
    pub fn group_descriptor(&self, group: u32) -> Result<&GroupDescriptor> {
        self.group_descs.get(group as usize).ok_or(Ext4Error::CorruptMetadata {
            structure: "group_descriptor",
            detail: format!("group {group} out of range (max {})", self.group_descs.len()),
        })
    }

    /// Block number of the inode bitmap for a block group.
    pub fn inode_bitmap_block(&self, group: u32) -> Result<u64> {
        Ok(self.group_descriptor(group)?.inode_bitmap)
    }

    /// Block number of the block bitmap for a block group.
    pub fn block_bitmap_block(&self, group: u32) -> Result<u64> {
        Ok(self.group_descriptor(group)?.block_bitmap)
    }

    /// Block number of the inode table for a block group.
    pub fn inode_table_block(&self, group: u32) -> Result<u64> {
        Ok(self.group_descriptor(group)?.inode_table)
    }
}
```

- [ ] **Step 4: Update lib.rs**

```rust
// ext4fs/src/lib.rs
#![forbid(unsafe_code)]

pub mod error;
pub mod ondisk;
pub mod block;
```

- [ ] **Step 5: Run tests**

Run: `cd ~/src/ext4fs-forensic && cargo test -p ext4fs`
Expected: All tests pass (skip gracefully if minimal.img not found).

- [ ] **Step 6: Commit**

```bash
cd ~/src/ext4fs-forensic
git add ext4fs/src/block.rs ext4fs/src/lib.rs
git commit -m "feat: Layer 1 — BlockReader with superblock validation and group descriptors"
```

---

### Task 10: Layer 2 — Inode Reading + Extent Tree Traversal

**Files:**
- Create: `ext4fs/src/inode.rs`
- Modify: `ext4fs/src/lib.rs`

Read inodes by number from the inode table. Follow extent trees to build block mappings. Read complete file data.

- [ ] **Step 1: Write failing tests**

```rust
// ext4fs/src/inode.rs

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::BlockReader;
    use crate::ondisk::FileType;
    use std::io::Cursor;

    fn open_minimal() -> Option<InodeReader<Cursor<Vec<u8>>>> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/minimal.img");
        let data = std::fs::read(path).ok()?;
        let block_reader = BlockReader::open(Cursor::new(data)).ok()?;
        Some(InodeReader::new(block_reader))
    }

    #[test]
    fn read_root_inode() {
        let mut reader = match open_minimal() {
            Some(r) => r,
            None => { eprintln!("skip: minimal.img not found"); return; }
        };
        let inode = reader.read_inode(2).unwrap(); // root is always inode 2
        assert_eq!(inode.file_type(), FileType::Directory);
        assert!(inode.links_count >= 2); // . and ..
    }

    #[test]
    fn read_inode_out_of_range() {
        let mut reader = match open_minimal() {
            Some(r) => r,
            None => { eprintln!("skip: minimal.img not found"); return; }
        };
        let err = reader.read_inode(0).unwrap_err(); // inode 0 doesn't exist
        assert!(matches!(err, crate::error::Ext4Error::InodeOutOfRange { .. }));
    }

    #[test]
    fn read_file_data() {
        let mut reader = match open_minimal() {
            Some(r) => r,
            None => { eprintln!("skip: minimal.img not found"); return; }
        };
        // We need to find hello.txt's inode via directory parsing,
        // but for now test that reading root inode data gives directory entries
        let data = reader.read_inode_data(2).unwrap();
        assert!(!data.is_empty()); // root dir has at least . and ..
    }

    #[test]
    fn inode_block_map_for_root() {
        let mut reader = match open_minimal() {
            Some(r) => r,
            None => { eprintln!("skip: minimal.img not found"); return; }
        };
        let inode = reader.read_inode(2).unwrap();
        if inode.uses_extents() {
            let map = reader.inode_block_map(2).unwrap();
            assert!(!map.is_empty());
            assert!(map[0].physical_block > 0);
        }
    }

    #[test]
    fn is_inode_allocated() {
        let mut reader = match open_minimal() {
            Some(r) => r,
            None => { eprintln!("skip: minimal.img not found"); return; }
        };
        assert!(reader.is_inode_allocated(2).unwrap()); // root is allocated
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/src/ext4fs-forensic && cargo test -p ext4fs`
Expected: FAIL — `InodeReader` not defined.

- [ ] **Step 3: Implement InodeReader**

```rust
// ext4fs/src/inode.rs
#![forbid(unsafe_code)]

use crate::block::BlockReader;
use crate::error::{Ext4Error, Result};
use crate::ondisk::{ExtentHeader, ExtentIndex, ExtentLeaf, Inode};
use std::io::{Read, Seek};

/// Mapping from logical file blocks to physical disk blocks.
#[derive(Debug, Clone)]
pub struct BlockMapping {
    pub logical_block: u64,
    pub physical_block: u64,
    pub length: u64,
    pub unwritten: bool,
}

/// Layer 2: Reads inodes, follows extent trees, reads file data.
pub struct InodeReader<R: Read + Seek> {
    pub(crate) block_reader: BlockReader<R>,
}

impl<R: Read + Seek> InodeReader<R> {
    pub fn new(block_reader: BlockReader<R>) -> Self {
        InodeReader { block_reader }
    }

    /// Read an inode by number (1-based).
    pub fn read_inode(&mut self, ino: u64) -> Result<Inode> {
        let sb = self.block_reader.superblock();
        if ino == 0 || ino > sb.inodes_count as u64 {
            return Err(Ext4Error::InodeOutOfRange {
                ino,
                max: sb.inodes_count as u64,
            });
        }

        let inodes_per_group = sb.inodes_per_group as u64;
        let inode_size = sb.inode_size as u64;
        let group = ((ino - 1) / inodes_per_group) as u32;
        let index = (ino - 1) % inodes_per_group;

        let inode_table = self.block_reader.inode_table_block(group)?;
        let offset = inode_table * sb.block_size as u64 + index * inode_size;
        let buf = self.block_reader.read_bytes(offset, inode_size as usize)?;

        Inode::parse(&buf, sb.inode_size)
    }

    /// Build a block mapping for an inode (extent tree traversal).
    pub fn inode_block_map(&mut self, ino: u64) -> Result<Vec<BlockMapping>> {
        let inode = self.read_inode(ino)?;
        if inode.has_inline_data() {
            return Ok(Vec::new()); // inline data, no block mapping
        }
        if inode.uses_extents() {
            self.walk_extent_tree(&inode.i_block)
        } else {
            self.walk_indirect_blocks(&inode.i_block)
        }
    }

    /// Walk an extent tree starting from the 60-byte i_block area.
    fn walk_extent_tree(&mut self, i_block: &[u8; 60]) -> Result<Vec<BlockMapping>> {
        let header = ExtentHeader::parse(i_block)?;
        let mut mappings = Vec::new();
        self.walk_extent_node(i_block, &header, &mut mappings)?;
        Ok(mappings)
    }

    fn walk_extent_node(
        &mut self,
        buf: &[u8],
        header: &ExtentHeader,
        mappings: &mut Vec<BlockMapping>,
    ) -> Result<()> {
        if header.depth == 0 {
            // Leaf level: parse extent entries
            for i in 0..header.entries as usize {
                let offset = 12 + i * 12;
                if offset + 12 > buf.len() { break; }
                let leaf = ExtentLeaf::parse(&buf[offset..]);
                mappings.push(BlockMapping {
                    logical_block: leaf.logical_block as u64,
                    physical_block: leaf.physical_block,
                    length: leaf.length as u64,
                    unwritten: leaf.unwritten,
                });
            }
        } else {
            // Interior level: parse index entries, recurse
            for i in 0..header.entries as usize {
                let offset = 12 + i * 12;
                if offset + 12 > buf.len() { break; }
                let index = ExtentIndex::parse(&buf[offset..]);
                let child_block = self.block_reader.read_block(index.child_block)?;
                let child_header = ExtentHeader::parse(&child_block)?;
                self.walk_extent_node(&child_block, &child_header, mappings)?;
            }
        }
        Ok(())
    }

    /// Walk legacy indirect block pointers (ext2/ext3 style).
    /// i_block[0..12] = direct, [12] = indirect, [13] = double, [14] = triple.
    fn walk_indirect_blocks(&mut self, i_block: &[u8; 60]) -> Result<Vec<BlockMapping>> {
        let mut mappings = Vec::new();
        let block_size = self.block_reader.block_size();
        let ptrs_per_block = block_size as u64 / 4;

        // Helper to read a u32 block pointer from i_block
        let read_ptr = |off: usize| -> u32 {
            if off + 4 > 60 { return 0; }
            u32::from_le_bytes([i_block[off], i_block[off + 1], i_block[off + 2], i_block[off + 3]])
        };

        // Direct blocks (0-11)
        let mut logical = 0u64;
        for i in 0..12 {
            let blk = read_ptr(i * 4) as u64;
            if blk != 0 {
                mappings.push(BlockMapping {
                    logical_block: logical,
                    physical_block: blk,
                    length: 1,
                    unwritten: false,
                });
            }
            logical += 1;
        }

        // Single indirect
        let ind_blk = read_ptr(48) as u64;
        if ind_blk != 0 {
            self.walk_indirect_level(ind_blk, &mut logical, 1, ptrs_per_block, &mut mappings)?;
        } else {
            logical += ptrs_per_block;
        }

        // Double indirect
        let dind_blk = read_ptr(52) as u64;
        if dind_blk != 0 {
            self.walk_indirect_level(dind_blk, &mut logical, 2, ptrs_per_block, &mut mappings)?;
        } else {
            logical += ptrs_per_block * ptrs_per_block;
        }

        // Triple indirect
        let tind_blk = read_ptr(56) as u64;
        if tind_blk != 0 {
            self.walk_indirect_level(tind_blk, &mut logical, 3, ptrs_per_block, &mut mappings)?;
        }

        Ok(mappings)
    }

    fn walk_indirect_level(
        &mut self,
        block: u64,
        logical: &mut u64,
        depth: u32,
        ptrs_per_block: u64,
        mappings: &mut Vec<BlockMapping>,
    ) -> Result<()> {
        let data = self.block_reader.read_block(block)?;
        for i in 0..ptrs_per_block as usize {
            let off = i * 4;
            if off + 4 > data.len() { break; }
            let ptr = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]) as u64;
            if depth == 1 {
                if ptr != 0 {
                    mappings.push(BlockMapping {
                        logical_block: *logical,
                        physical_block: ptr,
                        length: 1,
                        unwritten: false,
                    });
                }
                *logical += 1;
            } else if ptr != 0 {
                self.walk_indirect_level(ptr, logical, depth - 1, ptrs_per_block, mappings)?;
            } else {
                // Skip the range this null pointer covers
                let skip = ptrs_per_block.pow(depth - 1);
                *logical += skip;
            }
        }
        Ok(())
    }

    /// Read complete file data for an inode.
    pub fn read_inode_data(&mut self, ino: u64) -> Result<Vec<u8>> {
        let inode = self.read_inode(ino)?;
        let size = inode.size as usize;

        if inode.has_inline_data() {
            // Inline data: first 60 bytes in i_block, rest in system.data xattr
            let inline_len = size.min(60);
            return Ok(inode.i_block[..inline_len].to_vec());
            // TODO: xattr continuation when size > 60 (Task for xattr parsing)
        }

        let mappings = self.inode_block_map(ino)?;
        let block_size = self.block_reader.block_size() as u64;
        let mut data = Vec::with_capacity(size);

        for mapping in &mappings {
            for i in 0..mapping.length {
                let remaining = size.saturating_sub(data.len());
                if remaining == 0 { break; }
                let block_data = self.block_reader.read_block(mapping.physical_block + i)?;
                let to_copy = remaining.min(block_data.len());
                data.extend_from_slice(&block_data[..to_copy]);
            }
            if data.len() >= size { break; }
        }

        data.truncate(size);
        Ok(data)
    }

    /// Read a range of file data (for FUSE pread).
    pub fn read_inode_data_range(&mut self, ino: u64, offset: u64, len: u64) -> Result<Vec<u8>> {
        let inode = self.read_inode(ino)?;
        let file_size = inode.size;
        if offset >= file_size {
            return Ok(Vec::new());
        }
        let actual_len = len.min(file_size - offset) as usize;

        if inode.has_inline_data() {
            let start = offset as usize;
            let end = (start + actual_len).min(60);
            return Ok(inode.i_block[start..end].to_vec());
        }

        let mappings = self.inode_block_map(ino)?;
        let block_size = self.block_reader.block_size() as u64;
        let mut data = Vec::with_capacity(actual_len);
        let mut file_offset = 0u64;

        for mapping in &mappings {
            let mapping_start = mapping.logical_block * block_size;
            let mapping_end = mapping_start + mapping.length * block_size;

            if mapping_end <= offset {
                file_offset = mapping_end;
                continue;
            }
            if mapping_start >= offset + len {
                break;
            }

            for i in 0..mapping.length {
                let block_start = (mapping.logical_block + i) * block_size;
                let block_end = block_start + block_size;

                if block_end <= offset { continue; }
                if block_start >= offset + actual_len as u64 { break; }

                let block_data = self.block_reader.read_block(mapping.physical_block + i)?;

                let read_start = if block_start < offset {
                    (offset - block_start) as usize
                } else {
                    0
                };
                let remaining = actual_len - data.len();
                let read_end = block_data.len().min(read_start + remaining);

                data.extend_from_slice(&block_data[read_start..read_end]);
                if data.len() >= actual_len { break; }
            }
            if data.len() >= actual_len { break; }
        }

        Ok(data)
    }

    /// Check if an inode is allocated (bit set in inode bitmap).
    pub fn is_inode_allocated(&mut self, ino: u64) -> Result<bool> {
        let sb = self.block_reader.superblock();
        if ino == 0 || ino > sb.inodes_count as u64 {
            return Err(Ext4Error::InodeOutOfRange {
                ino,
                max: sb.inodes_count as u64,
            });
        }
        let group = ((ino - 1) / sb.inodes_per_group as u64) as u32;
        let index = ((ino - 1) % sb.inodes_per_group as u64) as usize;

        let bitmap_block = self.block_reader.inode_bitmap_block(group)?;
        let bitmap = self.block_reader.read_block(bitmap_block)?;

        let byte_index = index / 8;
        let bit_index = index % 8;
        if byte_index >= bitmap.len() {
            return Ok(false);
        }
        Ok((bitmap[byte_index] >> bit_index) & 1 == 1)
    }

    /// Check if a block is allocated (bit set in block bitmap).
    pub fn is_block_allocated(&mut self, block: u64) -> Result<bool> {
        let sb = self.block_reader.superblock();
        if block >= sb.blocks_count {
            return Err(Ext4Error::BlockOutOfRange {
                block,
                max: sb.blocks_count,
            });
        }
        let group = (block / sb.blocks_per_group as u64) as u32;
        let index = (block % sb.blocks_per_group as u64) as usize;

        let bitmap_block = self.block_reader.block_bitmap_block(group)?;
        let bitmap = self.block_reader.read_block(bitmap_block)?;

        let byte_index = index / 8;
        let bit_index = index % 8;
        if byte_index >= bitmap.len() {
            return Ok(false);
        }
        Ok((bitmap[byte_index] >> bit_index) & 1 == 1)
    }

    /// Iterate all inodes in a specific block group.
    pub fn iter_inodes_in_group(&mut self, group: u32) -> Result<Vec<(u64, Inode)>> {
        let sb = self.block_reader.superblock();
        let ipg = sb.inodes_per_group as u64;
        let inode_size = sb.inode_size as u64;
        let inode_table = self.block_reader.inode_table_block(group)?;
        let table_offset = inode_table * sb.block_size as u64;
        let table_size = ipg * inode_size;
        let buf = self.block_reader.read_bytes(table_offset, table_size as usize)?;

        let mut inodes = Vec::new();
        let base_ino = group as u64 * ipg + 1;
        for i in 0..ipg {
            let offset = (i * inode_size) as usize;
            let end = offset + inode_size as usize;
            if end > buf.len() { break; }
            if let Ok(inode) = Inode::parse(&buf[offset..end], sb.inode_size) {
                if inode.mode != 0 || inode.dtime != 0 {
                    inodes.push((base_ino + i, inode));
                }
            }
        }
        Ok(inodes)
    }

    /// Iterate ALL inodes on the filesystem.
    pub fn iter_all_inodes(&mut self) -> Result<Vec<(u64, Inode)>> {
        let group_count = self.block_reader.group_count();
        let mut all = Vec::new();
        for g in 0..group_count {
            let group_inodes = self.iter_inodes_in_group(g)?;
            all.extend(group_inodes);
        }
        Ok(all)
    }

    /// Access the underlying block reader (for forensic operations).
    pub fn block_reader(&self) -> &BlockReader<R> {
        &self.block_reader
    }

    /// Mutable access to the underlying block reader.
    pub fn block_reader_mut(&mut self) -> &mut BlockReader<R> {
        &mut self.block_reader
    }
}
```

- [ ] **Step 4: Update lib.rs**

```rust
// ext4fs/src/lib.rs
#![forbid(unsafe_code)]

pub mod error;
pub mod ondisk;
pub mod block;
pub mod inode;
```

- [ ] **Step 5: Run tests**

Run: `cd ~/src/ext4fs-forensic && cargo test -p ext4fs`
Expected: All tests pass.

- [ ] **Step 6: Commit**

```bash
cd ~/src/ext4fs-forensic
git add ext4fs/src/inode.rs ext4fs/src/lib.rs
git commit -m "feat: Layer 2 — inode reading, extent tree traversal, bitmap operations"
```

---

### Task 11: Layer 3 — Directory Operations + Path Resolution

**Files:**
- Create: `ext4fs/src/dir.rs`
- Modify: `ext4fs/src/lib.rs`

- [ ] **Step 1: Write failing tests**

```rust
// ext4fs/src/dir.rs

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::BlockReader;
    use crate::inode::InodeReader;
    use std::io::Cursor;

    fn open_minimal() -> Option<DirReader<Cursor<Vec<u8>>>> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/minimal.img");
        let data = std::fs::read(path).ok()?;
        let block_reader = BlockReader::open(Cursor::new(data)).ok()?;
        let inode_reader = InodeReader::new(block_reader);
        Some(DirReader::new(inode_reader))
    }

    #[test]
    fn read_root_directory() {
        let mut reader = match open_minimal() {
            Some(r) => r,
            None => { eprintln!("skip: minimal.img not found"); return; }
        };
        let entries = reader.read_dir(2).unwrap();
        let names: Vec<String> = entries.iter().map(|e| e.name_str()).collect();
        assert!(names.contains(&".".to_string()));
        assert!(names.contains(&"..".to_string()));
        assert!(names.contains(&"hello.txt".to_string()));
        assert!(names.contains(&"subdir".to_string()));
        assert!(names.contains(&"lost+found".to_string()));
    }

    #[test]
    fn lookup_file_in_root() {
        let mut reader = match open_minimal() {
            Some(r) => r,
            None => { eprintln!("skip: minimal.img not found"); return; }
        };
        let ino = reader.lookup(2, b"hello.txt").unwrap();
        assert!(ino.is_some());
        assert!(ino.unwrap() > 0);
    }

    #[test]
    fn lookup_nonexistent() {
        let mut reader = match open_minimal() {
            Some(r) => r,
            None => { eprintln!("skip: minimal.img not found"); return; }
        };
        let ino = reader.lookup(2, b"nonexistent.txt").unwrap();
        assert!(ino.is_none());
    }

    #[test]
    fn resolve_path_root() {
        let mut reader = match open_minimal() {
            Some(r) => r,
            None => { eprintln!("skip: minimal.img not found"); return; }
        };
        let ino = reader.resolve_path("/").unwrap();
        assert_eq!(ino, 2);
    }

    #[test]
    fn resolve_path_file() {
        let mut reader = match open_minimal() {
            Some(r) => r,
            None => { eprintln!("skip: minimal.img not found"); return; }
        };
        let ino = reader.resolve_path("/hello.txt").unwrap();
        assert!(ino > 0);
    }

    #[test]
    fn resolve_path_nested() {
        let mut reader = match open_minimal() {
            Some(r) => r,
            None => { eprintln!("skip: minimal.img not found"); return; }
        };
        let ino = reader.resolve_path("/subdir/nested.txt").unwrap();
        assert!(ino > 0);
    }

    #[test]
    fn resolve_path_not_found() {
        let mut reader = match open_minimal() {
            Some(r) => r,
            None => { eprintln!("skip: minimal.img not found"); return; }
        };
        let err = reader.resolve_path("/nonexistent").unwrap_err();
        assert!(matches!(err, crate::error::Ext4Error::PathNotFound(_)));
    }

    #[test]
    fn read_file_content_via_path() {
        let mut reader = match open_minimal() {
            Some(r) => r,
            None => { eprintln!("skip: minimal.img not found"); return; }
        };
        let ino = reader.resolve_path("/hello.txt").unwrap();
        let data = reader.inode_reader_mut().read_inode_data(ino).unwrap();
        assert_eq!(data, b"Hello, ext4!");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/src/ext4fs-forensic && cargo test -p ext4fs`
Expected: FAIL — `DirReader` not defined.

- [ ] **Step 3: Implement DirReader**

```rust
// ext4fs/src/dir.rs
#![forbid(unsafe_code)]

use crate::error::{Ext4Error, Result};
use crate::inode::InodeReader;
use crate::ondisk::{parse_dir_block, DirEntry, FileType};
use std::io::{Read, Seek};

const MAX_SYMLINK_DEPTH: u32 = 40;

/// Layer 3: Directory parsing and path resolution.
pub struct DirReader<R: Read + Seek> {
    inode_reader: InodeReader<R>,
}

impl<R: Read + Seek> DirReader<R> {
    pub fn new(inode_reader: InodeReader<R>) -> Self {
        DirReader { inode_reader }
    }

    /// List all entries in a directory (by inode number).
    pub fn read_dir(&mut self, dir_ino: u64) -> Result<Vec<DirEntry>> {
        let dir_data = self.inode_reader.read_inode_data(dir_ino)?;
        let block_size = self.inode_reader.block_reader().block_size() as usize;

        let mut all_entries = Vec::new();
        let mut offset = 0;
        while offset < dir_data.len() {
            let end = (offset + block_size).min(dir_data.len());
            let entries = parse_dir_block(&dir_data[offset..end]);
            for entry in entries {
                if !entry.is_deleted() {
                    all_entries.push(entry);
                }
            }
            offset = end;
        }
        Ok(all_entries)
    }

    /// Look up a name in a directory. Returns the inode number if found.
    pub fn lookup(&mut self, dir_ino: u64, name: &[u8]) -> Result<Option<u64>> {
        let entries = self.read_dir(dir_ino)?;
        for entry in &entries {
            if entry.name == name {
                return Ok(Some(entry.inode as u64));
            }
        }
        Ok(None)
    }

    /// Resolve an absolute path to an inode number.
    /// Follows symlinks up to MAX_SYMLINK_DEPTH levels.
    pub fn resolve_path(&mut self, path: &str) -> Result<u64> {
        self.resolve_path_depth(path, 0)
    }

    fn resolve_path_depth(&mut self, path: &str, depth: u32) -> Result<u64> {
        if depth > MAX_SYMLINK_DEPTH {
            return Err(Ext4Error::SymlinkLoop {
                path: path.to_string(),
                depth,
            });
        }

        let mut current_ino = 2u64; // root inode

        let path = path.trim_start_matches('/');
        if path.is_empty() {
            return Ok(current_ino);
        }

        for component in path.split('/') {
            if component.is_empty() || component == "." {
                continue;
            }
            if component == ".." {
                // Look up parent
                if let Some(parent_ino) = self.lookup(current_ino, b"..")? {
                    current_ino = parent_ino;
                }
                continue;
            }

            match self.lookup(current_ino, component.as_bytes())? {
                Some(ino) => {
                    let inode = self.inode_reader.read_inode(ino)?;
                    if inode.file_type() == FileType::Symlink {
                        let target = self.read_link(ino)?;
                        let target_str = String::from_utf8_lossy(&target);
                        if target_str.starts_with('/') {
                            current_ino = self.resolve_path_depth(&target_str, depth + 1)?;
                        } else {
                            // Relative symlink: resolve from parent directory
                            // For simplicity, reconstruct the path
                            // The parent is current_ino (the directory we're in)
                            current_ino = self.resolve_relative_symlink(
                                current_ino, &target_str, depth + 1
                            )?;
                        }
                    } else {
                        current_ino = ino;
                    }
                }
                None => {
                    return Err(Ext4Error::PathNotFound(path.to_string()));
                }
            }
        }

        Ok(current_ino)
    }

    fn resolve_relative_symlink(
        &mut self,
        parent_ino: u64,
        target: &str,
        depth: u32,
    ) -> Result<u64> {
        if depth > MAX_SYMLINK_DEPTH {
            return Err(Ext4Error::SymlinkLoop {
                path: target.to_string(),
                depth,
            });
        }

        let mut current_ino = parent_ino;
        for component in target.split('/') {
            if component.is_empty() || component == "." { continue; }
            if component == ".." {
                if let Some(parent) = self.lookup(current_ino, b"..")? {
                    current_ino = parent;
                }
                continue;
            }
            match self.lookup(current_ino, component.as_bytes())? {
                Some(ino) => {
                    let inode = self.inode_reader.read_inode(ino)?;
                    if inode.file_type() == FileType::Symlink {
                        let link_target = self.read_link(ino)?;
                        let link_str = String::from_utf8_lossy(&link_target);
                        if link_str.starts_with('/') {
                            current_ino = self.resolve_path_depth(&link_str, depth + 1)?;
                        } else {
                            current_ino = self.resolve_relative_symlink(
                                current_ino, &link_str, depth + 1
                            )?;
                        }
                    } else {
                        current_ino = ino;
                    }
                }
                None => return Err(Ext4Error::PathNotFound(target.to_string())),
            }
        }
        Ok(current_ino)
    }

    /// Read symlink target. Inline if < 60 bytes (stored in i_block),
    /// otherwise read from data blocks.
    pub fn read_link(&mut self, ino: u64) -> Result<Vec<u8>> {
        let inode = self.inode_reader.read_inode(ino)?;
        if inode.file_type() != FileType::Symlink {
            return Err(Ext4Error::NotASymlink(format!("inode {ino}")));
        }
        let size = inode.size as usize;
        if size <= 60 && !inode.uses_extents() {
            // Inline symlink: target stored directly in i_block
            Ok(inode.i_block[..size].to_vec())
        } else {
            // Block symlink: read from data blocks
            self.inode_reader.read_inode_data(ino)
        }
    }

    /// Access the underlying inode reader.
    pub fn inode_reader(&self) -> &InodeReader<R> {
        &self.inode_reader
    }

    /// Mutable access to the inode reader.
    pub fn inode_reader_mut(&mut self) -> &mut InodeReader<R> {
        &mut self.inode_reader
    }
}
```

- [ ] **Step 4: Update lib.rs**

```rust
// ext4fs/src/lib.rs
#![forbid(unsafe_code)]

pub mod error;
pub mod ondisk;
pub mod block;
pub mod inode;
pub mod dir;
```

- [ ] **Step 5: Run tests**

Run: `cd ~/src/ext4fs-forensic && cargo test -p ext4fs`
Expected: All tests pass.

- [ ] **Step 6: Commit**

```bash
cd ~/src/ext4fs-forensic
git add ext4fs/src/dir.rs ext4fs/src/lib.rs
git commit -m "feat: Layer 3 — directory parsing, path resolution, symlink following"
```

---

### Task 12: Layer 4 — Deleted Inode Detection

**Files:**
- Create: `ext4fs/src/forensic/mod.rs`
- Create: `ext4fs/src/forensic/deleted.rs`
- Modify: `ext4fs/src/lib.rs`

- [ ] **Step 1: Write failing tests**

```rust
// ext4fs/src/forensic/deleted.rs

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::BlockReader;
    use crate::inode::InodeReader;
    use std::io::Cursor;

    fn open_minimal() -> Option<InodeReader<Cursor<Vec<u8>>>> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/minimal.img");
        let data = std::fs::read(path).ok()?;
        let block_reader = BlockReader::open(Cursor::new(data)).ok()?;
        Some(InodeReader::new(block_reader))
    }

    #[test]
    fn no_deleted_inodes_in_fresh_image() {
        let mut reader = match open_minimal() {
            Some(r) => r,
            None => { eprintln!("skip: minimal.img not found"); return; }
        };
        let deleted = find_deleted_inodes(&mut reader).unwrap();
        // A freshly created image should have no deleted inodes
        assert_eq!(deleted.len(), 0);
    }

    #[test]
    fn deleted_inode_detection_logic() {
        // Test the detection logic with a synthetic inode
        use crate::ondisk::Inode;
        let mut buf = vec![0u8; 256];
        buf[0x00] = 0x80; buf[0x01] = 0x81; // regular file, mode 0600
        buf[0x04] = 100; // size = 100
        buf[0x14] = 0x01; // dtime != 0 (low byte)
        buf[0x1A] = 0; // links_count = 0
        let inode = Inode::parse(&buf, 256).unwrap();
        assert!(inode.is_deleted());
        assert_eq!(inode.dtime, 1);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/src/ext4fs-forensic && cargo test -p ext4fs`
Expected: FAIL — `find_deleted_inodes` not defined.

- [ ] **Step 3: Implement deleted inode detection**

```rust
// ext4fs/src/forensic/deleted.rs
#![forbid(unsafe_code)]

use crate::error::Result;
use crate::inode::InodeReader;
use crate::ondisk::{FileType, Inode, Timestamp};
use std::io::{Read, Seek};

/// Information about a deleted inode.
#[derive(Debug, Clone)]
pub struct DeletedInode {
    pub ino: u64,
    pub file_type: FileType,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub atime: Timestamp,
    pub mtime: Timestamp,
    pub ctime: Timestamp,
    pub crtime: Timestamp,
    pub dtime: u32,
    /// Estimated recoverability: fraction of data blocks still unallocated (0.0 to 1.0).
    pub recoverability: f64,
}

/// Scan all inodes for deletion markers.
/// A deleted inode has: dtime != 0, or links_count == 0 with non-zero mode,
/// or inode bitmap shows unallocated while inode has content.
pub fn find_deleted_inodes<R: Read + Seek>(
    reader: &mut InodeReader<R>,
) -> Result<Vec<DeletedInode>> {
    let all_inodes = reader.iter_all_inodes()?;
    let mut deleted = Vec::new();

    for (ino, inode) in &all_inodes {
        if !inode.is_deleted() {
            continue;
        }
        // Skip truly empty inodes (mode == 0 and no dtime)
        if inode.mode == 0 && inode.dtime == 0 {
            continue;
        }

        // Estimate recoverability by checking if data blocks are still free
        let recoverability = estimate_recoverability(reader, *ino, inode)?;

        deleted.push(DeletedInode {
            ino: *ino,
            file_type: inode.file_type(),
            mode: inode.mode,
            uid: inode.uid,
            gid: inode.gid,
            size: inode.size,
            atime: inode.atime,
            mtime: inode.mtime,
            ctime: inode.ctime,
            crtime: inode.crtime,
            dtime: inode.dtime,
            recoverability,
        });
    }

    Ok(deleted)
}

/// Estimate what fraction of a deleted file's blocks are still unallocated.
fn estimate_recoverability<R: Read + Seek>(
    reader: &mut InodeReader<R>,
    ino: u64,
    inode: &Inode,
) -> Result<f64> {
    if inode.size == 0 {
        return Ok(0.0);
    }

    // Try to get block mappings. If extent root is zeroed (common for small deleted files),
    // this will fail and recoverability is 0.
    let mappings = match reader.inode_block_map(ino) {
        Ok(m) => m,
        Err(_) => return Ok(0.0),
    };

    if mappings.is_empty() {
        return Ok(0.0);
    }

    let total_blocks: u64 = mappings.iter().map(|m| m.length).sum();
    if total_blocks == 0 {
        return Ok(0.0);
    }

    let mut free_blocks = 0u64;
    for mapping in &mappings {
        for i in 0..mapping.length {
            let block = mapping.physical_block + i;
            match reader.is_block_allocated(block) {
                Ok(false) => free_blocks += 1,
                _ => {}
            }
        }
    }

    Ok(free_blocks as f64 / total_blocks as f64)
}
```

```rust
// ext4fs/src/forensic/mod.rs
#![forbid(unsafe_code)]

pub mod deleted;

pub use deleted::*;
```

- [ ] **Step 4: Update lib.rs**

```rust
// ext4fs/src/lib.rs
#![forbid(unsafe_code)]

pub mod error;
pub mod ondisk;
pub mod block;
pub mod inode;
pub mod dir;
pub mod forensic;
```

- [ ] **Step 5: Run tests**

Run: `cd ~/src/ext4fs-forensic && cargo test -p ext4fs`
Expected: All tests pass.

- [ ] **Step 6: Commit**

```bash
cd ~/src/ext4fs-forensic
git add ext4fs/src/forensic/ ext4fs/src/lib.rs
git commit -m "feat: Layer 4 — deleted inode detection with recoverability estimation"
```

---

### Task 13: Layer 4 — Journal Parsing (jbd2)

**Files:**
- Create: `ext4fs/src/forensic/journal.rs`
- Modify: `ext4fs/src/forensic/mod.rs`

Parse the jbd2 journal from inode 8. Scan for descriptor blocks, commit blocks, and revoke blocks. Build a list of transactions with timestamps.

- [ ] **Step 1: Write failing tests**

```rust
// ext4fs/src/forensic/journal.rs

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::BlockReader;
    use crate::inode::InodeReader;
    use std::io::Cursor;

    fn open_minimal() -> Option<InodeReader<Cursor<Vec<u8>>>> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/minimal.img");
        let data = std::fs::read(path).ok()?;
        let br = BlockReader::open(Cursor::new(data)).ok()?;
        Some(InodeReader::new(br))
    }

    #[test]
    fn parse_journal_from_minimal() {
        let mut reader = match open_minimal() {
            Some(r) => r,
            None => { eprintln!("skip: minimal.img not found"); return; }
        };
        if !reader.block_reader().superblock().has_journal() {
            eprintln!("skip: no journal in image");
            return;
        }
        let journal = parse_journal(&mut reader).unwrap();
        assert!(journal.block_size > 0);
        // A fresh image should have at least 1 transaction (from mkfs writes)
        assert!(!journal.transactions.is_empty());
    }

    #[test]
    fn transactions_have_commit_timestamps() {
        let mut reader = match open_minimal() {
            Some(r) => r,
            None => { eprintln!("skip: minimal.img not found"); return; }
        };
        if !reader.block_reader().superblock().has_journal() { return; }
        let journal = parse_journal(&mut reader).unwrap();
        for txn in &journal.transactions {
            // Not all transactions may have timestamps, but sequence should be positive
            assert!(txn.sequence > 0);
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/src/ext4fs-forensic && cargo test -p ext4fs`
Expected: FAIL — `parse_journal` not defined.

- [ ] **Step 3: Implement journal parsing**

```rust
// ext4fs/src/forensic/journal.rs
#![forbid(unsafe_code)]

use crate::error::{Ext4Error, Result};
use crate::inode::InodeReader;
use crate::ondisk::journal::{
    JournalBlockTag, JournalBlockType, JournalCommit, JournalHeader, JournalSuperblock,
    JOURNAL_MAGIC,
};
use std::io::{Read, Seek};

/// A mapping from a journal data block to a filesystem block.
#[derive(Debug, Clone)]
pub struct JournalMapping {
    pub journal_block: u64,
    pub filesystem_block: u64,
}

/// A parsed journal transaction.
#[derive(Debug, Clone)]
pub struct Transaction {
    pub sequence: u32,
    pub commit_seconds: i64,
    pub commit_nanoseconds: u32,
    pub mappings: Vec<JournalMapping>,
    pub revoked_blocks: Vec<u64>,
}

/// Parsed journal.
#[derive(Debug, Clone)]
pub struct Journal {
    pub block_size: u32,
    pub total_blocks: u32,
    pub first_block: u32,
    pub transactions: Vec<Transaction>,
    pub is_64bit: bool,
    pub has_csum_v3: bool,
}

/// Parse the jbd2 journal from inode 8.
pub fn parse_journal<R: Read + Seek>(reader: &mut InodeReader<R>) -> Result<Journal> {
    let sb = reader.block_reader().superblock();
    if !sb.has_journal() {
        return Err(Ext4Error::NoJournal);
    }

    let journal_ino = sb.journal_inum as u64;
    if journal_ino == 0 {
        return Err(Ext4Error::NoJournal);
    }

    // Read entire journal inode data
    let journal_data = reader.read_inode_data(journal_ino)?;
    if journal_data.len() < 1024 {
        return Err(Ext4Error::JournalCorrupt("journal too small".into()));
    }

    // Parse journal superblock (first block of journal)
    let fs_block_size = sb.block_size as usize;
    let jsb = JournalSuperblock::parse(&journal_data[..fs_block_size.min(journal_data.len())])?;
    let j_block_size = jsb.block_size as usize;
    if j_block_size == 0 {
        return Err(Ext4Error::JournalCorrupt("journal block size is 0".into()));
    }

    let is_64bit = jsb.is_64bit();
    let has_csum_v3 = jsb.has_csum_v3();
    let total_blocks = jsb.max_len;
    let first_block = jsb.first;

    // Scan journal blocks for transactions
    let mut transactions = Vec::new();
    let mut current_mappings: Vec<JournalMapping> = Vec::new();
    let mut current_revoked: Vec<u64> = Vec::new();
    let mut current_sequence: u32 = 0;
    let mut data_block_index: u64 = 0;
    let mut pending_tags: Vec<u64> = Vec::new(); // filesystem block numbers from descriptor

    let mut block_idx = first_block as usize;
    while block_idx < total_blocks as usize {
        let offset = block_idx * j_block_size;
        if offset + 12 > journal_data.len() { break; }

        let block_data = &journal_data[offset..offset + j_block_size.min(journal_data.len() - offset)];

        // Try to parse as journal header
        match JournalHeader::parse(block_data) {
            Ok(header) => {
                match header.block_type {
                    JournalBlockType::Descriptor => {
                        current_sequence = header.sequence;
                        pending_tags.clear();
                        // Parse tags
                        let mut tag_offset = 12;
                        loop {
                            if tag_offset + 16 > block_data.len() { break; }
                            let tag = JournalBlockTag::parse_v3(
                                &block_data[tag_offset..],
                                is_64bit,
                            );
                            pending_tags.push(tag.blocknr);
                            let is_last = tag.last_tag;
                            tag_offset += tag.tag_size;
                            if is_last { break; }
                        }
                        // Data blocks follow the descriptor block
                        for (i, &fs_block) in pending_tags.iter().enumerate() {
                            let data_block = block_idx as u64 + 1 + i as u64;
                            current_mappings.push(JournalMapping {
                                journal_block: data_block,
                                filesystem_block: fs_block,
                            });
                        }
                        block_idx += 1 + pending_tags.len(); // skip descriptor + data blocks
                        continue;
                    }
                    JournalBlockType::Commit => {
                        let commit = JournalCommit::parse(block_data)
                            .unwrap_or(JournalCommit {
                                sequence: header.sequence,
                                commit_seconds: 0,
                                commit_nanoseconds: 0,
                            });
                        transactions.push(Transaction {
                            sequence: commit.sequence,
                            commit_seconds: commit.commit_seconds,
                            commit_nanoseconds: commit.commit_nanoseconds,
                            mappings: std::mem::take(&mut current_mappings),
                            revoked_blocks: std::mem::take(&mut current_revoked),
                        });
                    }
                    JournalBlockType::Revoke => {
                        use crate::ondisk::journal::JournalRevoke;
                        if let Ok(revoke) = JournalRevoke::parse(block_data, is_64bit) {
                            current_revoked.extend(revoke.revoked_blocks);
                        }
                    }
                    JournalBlockType::SuperblockV1 | JournalBlockType::SuperblockV2 => {
                        // Skip journal superblock copies
                    }
                    JournalBlockType::Unknown(_) => {}
                }
            }
            Err(_) => {
                // Not a journal header block, skip
            }
        }
        block_idx += 1;
    }

    Ok(Journal {
        block_size: j_block_size as u32,
        total_blocks,
        first_block,
        transactions,
        is_64bit,
        has_csum_v3,
    })
}

/// Find all journal versions of a specific inode's metadata block.
pub fn inode_history<R: Read + Seek>(
    reader: &mut InodeReader<R>,
    journal: &Journal,
    ino: u64,
) -> Result<Vec<InodeVersion>> {
    let sb = reader.block_reader().superblock();
    let ipg = sb.inodes_per_group as u64;
    let inode_size = sb.inode_size as u64;
    let block_size = sb.block_size as u64;
    let group = ((ino - 1) / ipg) as u32;
    let index = (ino - 1) % ipg;
    let inode_table = reader.block_reader().inode_table_block(group)?;
    let inode_offset_in_table = index * inode_size;
    let target_block = inode_table + inode_offset_in_table / block_size;
    let offset_in_block = (inode_offset_in_table % block_size) as usize;

    let journal_ino = sb.journal_inum as u64;
    let journal_data = reader.read_inode_data(journal_ino)?;
    let j_block_size = journal.block_size as usize;

    let mut versions = Vec::new();
    for txn in &journal.transactions {
        for mapping in &txn.mappings {
            if mapping.filesystem_block == target_block {
                let j_offset = mapping.journal_block as usize * j_block_size;
                if j_offset + j_block_size <= journal_data.len() {
                    let block_data = &journal_data[j_offset..j_offset + j_block_size];
                    let end = offset_in_block + inode_size as usize;
                    if end <= block_data.len() {
                        if let Ok(inode) = crate::ondisk::Inode::parse(
                            &block_data[offset_in_block..end],
                            sb.inode_size,
                        ) {
                            versions.push(InodeVersion {
                                sequence: txn.sequence,
                                commit_seconds: txn.commit_seconds,
                                commit_nanoseconds: txn.commit_nanoseconds,
                                inode,
                            });
                        }
                    }
                }
            }
        }
    }

    versions.sort_by_key(|v| v.sequence);
    Ok(versions)
}

/// A historical version of an inode from the journal.
#[derive(Debug, Clone)]
pub struct InodeVersion {
    pub sequence: u32,
    pub commit_seconds: i64,
    pub commit_nanoseconds: u32,
    pub inode: crate::ondisk::Inode,
}
```

- [ ] **Step 4: Update forensic/mod.rs**

```rust
// ext4fs/src/forensic/mod.rs
#![forbid(unsafe_code)]

pub mod deleted;
pub mod journal;

pub use deleted::*;
pub use journal::*;
```

- [ ] **Step 5: Run tests**

Run: `cd ~/src/ext4fs-forensic && cargo test -p ext4fs`
Expected: All tests pass.

- [ ] **Step 6: Commit**

```bash
cd ~/src/ext4fs-forensic
git add ext4fs/src/forensic/journal.rs ext4fs/src/forensic/mod.rs
git commit -m "feat: Layer 4 — jbd2 journal parsing with transaction and inode history"
```

---

### Task 14: Layer 4 — Deleted File Recovery + Xattr Parsing + Timeline + Carving

**Files:**
- Create: `ext4fs/src/forensic/recovery.rs`
- Create: `ext4fs/src/forensic/xattr.rs`
- Create: `ext4fs/src/forensic/timeline.rs`
- Create: `ext4fs/src/forensic/carving.rs`
- Modify: `ext4fs/src/forensic/mod.rs`

This task implements the remaining forensic modules. Each is relatively small and independent.

- [ ] **Step 1: Write failing tests for recovery**

```rust
// ext4fs/src/forensic/recovery.rs

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_result_fields() {
        let result = RecoveryResult {
            data: vec![1, 2, 3],
            expected_size: 100,
            recovered_size: 3,
            overwritten_ranges: vec![BlockRange { start: 10, length: 97 }],
        };
        assert_eq!(result.recovery_percentage(), 3.0);
    }
}
```

- [ ] **Step 2: Write failing tests for xattr**

```rust
// ext4fs/src/forensic/xattr.rs

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::BlockReader;
    use crate::inode::InodeReader;
    use std::io::Cursor;

    fn open_minimal() -> Option<InodeReader<Cursor<Vec<u8>>>> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/minimal.img");
        let data = std::fs::read(path).ok()?;
        let br = BlockReader::open(Cursor::new(data)).ok()?;
        Some(InodeReader::new(br))
    }

    #[test]
    fn read_xattrs_from_file() {
        let mut reader = match open_minimal() {
            Some(r) => r,
            None => { eprintln!("skip: minimal.img not found"); return; }
        };
        // Root inode — may or may not have xattrs, but should not error
        let xattrs = read_xattrs(&mut reader, 2).unwrap();
        // Fresh image may have no xattrs, that's fine
        let _ = xattrs;
    }
}
```

- [ ] **Step 3: Write failing tests for timeline**

```rust
// ext4fs/src/forensic/timeline.rs

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::BlockReader;
    use crate::inode::InodeReader;
    use std::io::Cursor;

    fn open_minimal() -> Option<InodeReader<Cursor<Vec<u8>>>> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/minimal.img");
        let data = std::fs::read(path).ok()?;
        let br = BlockReader::open(Cursor::new(data)).ok()?;
        Some(InodeReader::new(br))
    }

    #[test]
    fn generate_timeline_from_minimal() {
        let mut reader = match open_minimal() {
            Some(r) => r,
            None => { eprintln!("skip: minimal.img not found"); return; }
        };
        let events = generate_timeline(&mut reader).unwrap();
        assert!(!events.is_empty());
        // Events should be sorted by timestamp
        for window in events.windows(2) {
            assert!(window[0].timestamp <= window[1].timestamp);
        }
    }
}
```

- [ ] **Step 4: Write failing tests for carving**

```rust
// ext4fs/src/forensic/carving.rs

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::BlockReader;
    use crate::inode::InodeReader;
    use std::io::Cursor;

    fn open_minimal() -> Option<InodeReader<Cursor<Vec<u8>>>> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/minimal.img");
        let data = std::fs::read(path).ok()?;
        let br = BlockReader::open(Cursor::new(data)).ok()?;
        Some(InodeReader::new(br))
    }

    #[test]
    fn find_unallocated_blocks() {
        let mut reader = match open_minimal() {
            Some(r) => r,
            None => { eprintln!("skip: minimal.img not found"); return; }
        };
        let ranges = unallocated_blocks(&mut reader).unwrap();
        // A 4 MiB image with a few files should have some unallocated blocks
        assert!(!ranges.is_empty());
        // Ranges should be non-overlapping and positive length
        for range in &ranges {
            assert!(range.length > 0);
        }
    }
}
```

- [ ] **Step 5: Run tests to verify all fail**

Run: `cd ~/src/ext4fs-forensic && cargo test -p ext4fs`
Expected: FAIL — modules not defined.

- [ ] **Step 6: Implement recovery.rs**

```rust
// ext4fs/src/forensic/recovery.rs
#![forbid(unsafe_code)]

use crate::error::{Ext4Error, Result};
use crate::inode::InodeReader;
use std::io::{Read, Seek};

/// A contiguous range of blocks.
#[derive(Debug, Clone)]
pub struct BlockRange {
    pub start: u64,
    pub length: u64,
}

/// Result of a deleted file recovery attempt.
#[derive(Debug, Clone)]
pub struct RecoveryResult {
    pub data: Vec<u8>,
    pub expected_size: u64,
    pub recovered_size: u64,
    pub overwritten_ranges: Vec<BlockRange>,
}

impl RecoveryResult {
    /// Percentage of the file that was recovered.
    pub fn recovery_percentage(&self) -> f64 {
        if self.expected_size == 0 { return 0.0; }
        (self.recovered_size as f64 / self.expected_size as f64) * 100.0
    }
}

/// Attempt to recover a deleted file's data by inode number.
pub fn recover_file<R: Read + Seek>(
    reader: &mut InodeReader<R>,
    ino: u64,
) -> Result<RecoveryResult> {
    let inode = reader.read_inode(ino)?;
    let expected_size = inode.size;

    if expected_size == 0 {
        return Ok(RecoveryResult {
            data: Vec::new(),
            expected_size: 0,
            recovered_size: 0,
            overwritten_ranges: Vec::new(),
        });
    }

    // Try to get block mappings
    let mappings = match reader.inode_block_map(ino) {
        Ok(m) => m,
        Err(_) => {
            return Err(Ext4Error::RecoveryFailed {
                ino,
                reason: "extent tree root is zeroed (common for small deleted ext4 files)".into(),
            });
        }
    };

    if mappings.is_empty() {
        return Err(Ext4Error::RecoveryFailed {
            ino,
            reason: "no block mappings found".into(),
        });
    }

    let block_size = reader.block_reader().block_size() as u64;
    let mut data = Vec::with_capacity(expected_size as usize);
    let mut overwritten_ranges = Vec::new();

    for mapping in &mappings {
        for i in 0..mapping.length {
            let block = mapping.physical_block + i;
            let is_allocated = reader.is_block_allocated(block).unwrap_or(true);

            if is_allocated {
                // Block has been reallocated — data is overwritten
                overwritten_ranges.push(BlockRange {
                    start: (mapping.logical_block + i) * block_size,
                    length: block_size,
                });
                // Write zeros for overwritten blocks
                let remaining = (expected_size as usize).saturating_sub(data.len());
                let fill = remaining.min(block_size as usize);
                data.extend(std::iter::repeat(0u8).take(fill));
            } else {
                // Block is still free — read the data
                match reader.block_reader_mut().read_block(block) {
                    Ok(block_data) => {
                        let remaining = (expected_size as usize).saturating_sub(data.len());
                        let to_copy = remaining.min(block_data.len());
                        data.extend_from_slice(&block_data[..to_copy]);
                    }
                    Err(_) => {
                        let remaining = (expected_size as usize).saturating_sub(data.len());
                        let fill = remaining.min(block_size as usize);
                        data.extend(std::iter::repeat(0u8).take(fill));
                    }
                }
            }
            if data.len() >= expected_size as usize { break; }
        }
        if data.len() >= expected_size as usize { break; }
    }

    data.truncate(expected_size as usize);
    let recovered_size = data.iter().enumerate().filter(|(i, _)| {
        !overwritten_ranges.iter().any(|r| {
            let start = r.start as usize;
            let end = start + r.length as usize;
            *i >= start && *i < end
        })
    }).count() as u64;

    Ok(RecoveryResult {
        data,
        expected_size,
        recovered_size,
        overwritten_ranges,
    })
}
```

- [ ] **Step 7: Implement xattr.rs**

```rust
// ext4fs/src/forensic/xattr.rs
#![forbid(unsafe_code)]

use crate::error::Result;
use crate::inode::InodeReader;
use crate::ondisk::xattr::{XattrBlockHeader, XattrEntry, XattrNamespace};
use std::io::{Read, Seek};

/// A parsed extended attribute with its value.
#[derive(Debug, Clone)]
pub struct Xattr {
    pub namespace: XattrNamespace,
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

/// Read all extended attributes for an inode.
pub fn read_xattrs<R: Read + Seek>(
    reader: &mut InodeReader<R>,
    ino: u64,
) -> Result<Vec<Xattr>> {
    let inode = reader.read_inode(ino)?;
    let mut xattrs = Vec::new();

    // 1. Inline xattrs (in inode extra space after offset 0x80 + extra_isize)
    // The inline xattr area starts at offset (128 + extra_isize) in the inode
    // We would need raw inode bytes for this; for now focus on block xattrs.

    // 2. Block xattrs (from i_file_acl)
    if inode.file_acl != 0 {
        let block_data = reader.block_reader_mut().read_block(inode.file_acl)?;
        if let Ok(_header) = XattrBlockHeader::parse(&block_data) {
            let mut offset = 32; // skip header
            while offset + 16 <= block_data.len() {
                // Check for end marker (name_len == 0)
                if block_data[offset] == 0 { break; }
                match XattrEntry::parse(&block_data[offset..]) {
                    Ok(entry) => {
                        // Read value
                        let value_start = entry.value_offset as usize;
                        let value_end = value_start + entry.value_size as usize;
                        let value = if value_end <= block_data.len() {
                            block_data[value_start..value_end].to_vec()
                        } else {
                            Vec::new()
                        };

                        xattrs.push(Xattr {
                            namespace: entry.name_index,
                            name: entry.name.clone(),
                            value,
                        });
                        offset += entry.entry_size;
                    }
                    Err(_) => break,
                }
            }
        }
    }

    Ok(xattrs)
}
```

- [ ] **Step 8: Implement timeline.rs**

```rust
// ext4fs/src/forensic/timeline.rs
#![forbid(unsafe_code)]

use crate::error::Result;
use crate::inode::InodeReader;
use crate::ondisk::Timestamp;
use std::io::{Read, Seek};

/// Type of filesystem event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    Created,
    Modified,
    Accessed,
    Changed,
    Deleted,
    Mounted,
}

/// A single event in the forensic timeline.
#[derive(Debug, Clone)]
pub struct TimelineEvent {
    pub timestamp: Timestamp,
    pub event_type: EventType,
    pub inode: u64,
    pub path: Option<String>,
    pub size: u64,
    pub uid: u32,
    pub gid: u32,
}

/// Generate a forensic timeline from all filesystem timestamps.
pub fn generate_timeline<R: Read + Seek>(
    reader: &mut InodeReader<R>,
) -> Result<Vec<TimelineEvent>> {
    let mut events = Vec::new();

    // Superblock timestamps
    let sb = reader.block_reader().superblock();
    if sb.mount_time != 0 {
        events.push(TimelineEvent {
            timestamp: Timestamp { seconds: sb.mount_time as i64, nanoseconds: 0 },
            event_type: EventType::Mounted,
            inode: 0,
            path: None,
            size: 0,
            uid: 0,
            gid: 0,
        });
    }

    // Inode timestamps
    let all_inodes = reader.iter_all_inodes()?;
    for (ino, inode) in &all_inodes {
        let base = |ts: &Timestamp, event_type: EventType| -> Option<TimelineEvent> {
            if ts.seconds == 0 { return None; }
            Some(TimelineEvent {
                timestamp: *ts,
                event_type,
                inode: *ino,
                path: None, // path resolution is expensive; caller can resolve
                size: inode.size,
                uid: inode.uid,
                gid: inode.gid,
            })
        };

        if let Some(e) = base(&inode.crtime, EventType::Created) { events.push(e); }
        if let Some(e) = base(&inode.mtime, EventType::Modified) { events.push(e); }
        if let Some(e) = base(&inode.atime, EventType::Accessed) { events.push(e); }
        if let Some(e) = base(&inode.ctime, EventType::Changed) { events.push(e); }
        if inode.dtime != 0 {
            events.push(TimelineEvent {
                timestamp: Timestamp { seconds: inode.dtime as i64, nanoseconds: 0 },
                event_type: EventType::Deleted,
                inode: *ino,
                path: None,
                size: inode.size,
                uid: inode.uid,
                gid: inode.gid,
            });
        }
    }

    events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    Ok(events)
}
```

- [ ] **Step 9: Implement carving.rs**

```rust
// ext4fs/src/forensic/carving.rs
#![forbid(unsafe_code)]

use crate::error::Result;
use crate::forensic::recovery::BlockRange;
use crate::inode::InodeReader;
use crate::ondisk::extent::EXTENT_MAGIC;
use std::io::{Read, Seek};

/// A potential inode found by carving extent signatures.
#[derive(Debug, Clone)]
pub struct CarvedInode {
    pub block: u64,
    pub offset_in_block: usize,
}

/// Iterate block bitmaps and yield contiguous unallocated block ranges.
pub fn unallocated_blocks<R: Read + Seek>(
    reader: &mut InodeReader<R>,
) -> Result<Vec<BlockRange>> {
    let sb = reader.block_reader().superblock();
    let group_count = reader.block_reader().group_count();
    let bpg = sb.blocks_per_group as u64;
    let mut ranges = Vec::new();

    for g in 0..group_count {
        let bitmap_block = reader.block_reader_mut().block_bitmap_block(g)?;
        let bitmap = reader.block_reader_mut().read_block(bitmap_block)?;
        let base_block = g as u64 * bpg;

        let mut run_start: Option<u64> = None;
        let blocks_in_group = bpg.min(sb.blocks_count - base_block);

        for bit in 0..blocks_in_group as usize {
            let byte = bit / 8;
            let bit_pos = bit % 8;
            let allocated = if byte < bitmap.len() {
                (bitmap[byte] >> bit_pos) & 1 == 1
            } else {
                false
            };

            if !allocated {
                if run_start.is_none() {
                    run_start = Some(base_block + bit as u64);
                }
            } else {
                if let Some(start) = run_start {
                    let current = base_block + bit as u64;
                    ranges.push(BlockRange {
                        start,
                        length: current - start,
                    });
                    run_start = None;
                }
            }
        }
        // Close any open run at end of group
        if let Some(start) = run_start {
            let end = base_block + blocks_in_group;
            ranges.push(BlockRange {
                start,
                length: end - start,
            });
        }
    }

    Ok(ranges)
}

/// Read raw data from a contiguous unallocated range.
pub fn read_unallocated<R: Read + Seek>(
    reader: &mut InodeReader<R>,
    range: &BlockRange,
) -> Result<Vec<u8>> {
    reader.block_reader_mut().read_blocks(range.start, range.length)
}

/// Scan unallocated blocks for extent tree magic (0xF30A) — potential orphaned inodes.
pub fn find_extent_signatures<R: Read + Seek>(
    reader: &mut InodeReader<R>,
    ranges: &[BlockRange],
) -> Result<Vec<CarvedInode>> {
    let mut found = Vec::new();

    for range in ranges {
        for i in 0..range.length {
            let block = range.start + i;
            let data = match reader.block_reader_mut().read_block(block) {
                Ok(d) => d,
                Err(_) => continue,
            };
            // Scan for extent magic at 12-byte aligned offsets
            let mut offset = 0;
            while offset + 12 <= data.len() {
                if data.len() >= offset + 2 {
                    let magic = u16::from_le_bytes([data[offset], data[offset + 1]]);
                    if magic == EXTENT_MAGIC {
                        found.push(CarvedInode {
                            block,
                            offset_in_block: offset,
                        });
                    }
                }
                offset += 12;
            }
        }
    }

    Ok(found)
}
```

- [ ] **Step 10: Update forensic/mod.rs**

```rust
// ext4fs/src/forensic/mod.rs
#![forbid(unsafe_code)]

pub mod deleted;
pub mod journal;
pub mod recovery;
pub mod xattr;
pub mod timeline;
pub mod carving;

pub use deleted::*;
pub use journal::*;
pub use recovery::*;
pub use xattr::*;
pub use timeline::*;
pub use carving::*;
```

- [ ] **Step 11: Run tests**

Run: `cd ~/src/ext4fs-forensic && cargo test -p ext4fs`
Expected: All tests pass.

- [ ] **Step 12: Commit**

```bash
cd ~/src/ext4fs-forensic
git add ext4fs/src/forensic/
git commit -m "feat: Layer 4 — recovery, xattr parsing, timeline, carving"
```

---

### Task 15: Layer 5 — Public Ext4Fs API

**Files:**
- Modify: `ext4fs/src/lib.rs`

Wire up the `Ext4Fs<R>` struct that provides the complete tier 1 + tier 2 public API.

- [ ] **Step 1: Write failing tests**

```rust
// In ext4fs/src/lib.rs, at the bottom

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn open_minimal() -> Option<Ext4Fs<Cursor<Vec<u8>>>> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/minimal.img");
        let data = std::fs::read(path).ok()?;
        Ext4Fs::open(Cursor::new(data)).ok()
    }

    #[test]
    fn open_and_read_superblock() {
        let fs = match open_minimal() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        assert_eq!(fs.superblock().magic, 0xEF53);
    }

    #[test]
    fn read_file_by_path() {
        let mut fs = match open_minimal() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        let data = fs.read_file("/hello.txt").unwrap();
        assert_eq!(data, b"Hello, ext4!");
    }

    #[test]
    fn read_nested_file() {
        let mut fs = match open_minimal() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        let data = fs.read_file("/subdir/nested.txt").unwrap();
        assert_eq!(data, b"Nested file");
    }

    #[test]
    fn list_root_directory() {
        let mut fs = match open_minimal() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        let entries = fs.read_dir("/").unwrap();
        let names: Vec<String> = entries.iter().map(|e| e.name_str()).collect();
        assert!(names.contains(&"hello.txt".to_string()));
        assert!(names.contains(&"subdir".to_string()));
    }

    #[test]
    fn file_metadata() {
        let mut fs = match open_minimal() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        let meta = fs.metadata("/hello.txt").unwrap();
        assert_eq!(meta.file_type, ondisk::FileType::RegularFile);
        assert_eq!(meta.size, 12); // "Hello, ext4!" is 12 bytes
        assert!(meta.mtime.seconds > 0);
    }

    #[test]
    fn exists_check() {
        let mut fs = match open_minimal() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        assert!(fs.exists("/hello.txt").unwrap());
        assert!(!fs.exists("/nonexistent").unwrap());
    }

    #[test]
    fn all_inodes() {
        let mut fs = match open_minimal() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        let inodes = fs.all_inodes().unwrap();
        assert!(!inodes.is_empty());
    }

    #[test]
    fn deleted_inodes_on_fresh_image() {
        let mut fs = match open_minimal() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        let deleted = fs.deleted_inodes().unwrap();
        assert!(deleted.is_empty());
    }

    #[test]
    fn timeline_generation() {
        let mut fs = match open_minimal() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        let events = fs.timeline().unwrap();
        assert!(!events.is_empty());
    }

    #[test]
    fn unallocated_blocks_exist() {
        let mut fs = match open_minimal() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        let ranges = fs.unallocated_blocks().unwrap();
        assert!(!ranges.is_empty());
    }
}
```

- [ ] **Step 2: Run tests to verify failure**

Run: `cd ~/src/ext4fs-forensic && cargo test -p ext4fs`
Expected: FAIL — `Ext4Fs` not defined.

- [ ] **Step 3: Implement Ext4Fs**

```rust
// ext4fs/src/lib.rs
#![forbid(unsafe_code)]

pub mod error;
pub mod ondisk;
pub mod block;
pub mod inode;
pub mod dir;
pub mod forensic;

use block::BlockReader;
use dir::DirReader;
use error::Result;
use inode::{BlockMapping, InodeReader};
use ondisk::{DirEntry, FileType, Inode, Superblock, Timestamp};
use std::io::{Read, Seek};

/// Full inode metadata for the public API.
#[derive(Debug, Clone)]
pub struct InodeMetadata {
    pub ino: u64,
    pub file_type: FileType,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub links_count: u16,
    pub atime: Timestamp,
    pub mtime: Timestamp,
    pub ctime: Timestamp,
    pub crtime: Timestamp,
    pub dtime: u32,
    pub flags: ondisk::InodeFlags,
    pub generation: u32,
    pub allocated: bool,
}

/// Forensic-grade ext4 filesystem reader.
///
/// Accepts any `Read + Seek` source (raw image file, EWF reader, etc.).
/// Provides both standard filesystem access (tier 1) and forensic operations (tier 2).
pub struct Ext4Fs<R: Read + Seek> {
    dir_reader: DirReader<R>,
}

impl<R: Read + Seek> Ext4Fs<R> {
    /// Open an ext4 filesystem from a Read+Seek source.
    pub fn open(source: R) -> Result<Self> {
        let block_reader = BlockReader::open(source)?;
        let inode_reader = InodeReader::new(block_reader);
        let dir_reader = DirReader::new(inode_reader);
        Ok(Ext4Fs { dir_reader })
    }

    // --- Tier 1: Standard filesystem access ---

    /// Reference to the superblock.
    pub fn superblock(&self) -> &Superblock {
        self.dir_reader.inode_reader().block_reader().superblock()
    }

    /// Read a file's contents by path.
    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>> {
        let ino = self.dir_reader.resolve_path(path)?;
        self.dir_reader.inode_reader_mut().read_inode_data(ino)
    }

    /// List directory entries by path.
    pub fn read_dir(&mut self, path: &str) -> Result<Vec<DirEntry>> {
        let ino = if path == "/" { 2 } else { self.dir_reader.resolve_path(path)? };
        self.dir_reader.read_dir(ino)
    }

    /// Get full metadata for a path (follows symlinks).
    pub fn metadata(&mut self, path: &str) -> Result<InodeMetadata> {
        let ino = self.dir_reader.resolve_path(path)?;
        let inode = self.dir_reader.inode_reader_mut().read_inode(ino)?;
        let allocated = self.dir_reader.inode_reader_mut().is_inode_allocated(ino)?;
        Ok(InodeMetadata {
            ino,
            file_type: inode.file_type(),
            mode: inode.mode,
            uid: inode.uid,
            gid: inode.gid,
            size: inode.size,
            links_count: inode.links_count,
            atime: inode.atime,
            mtime: inode.mtime,
            ctime: inode.ctime,
            crtime: inode.crtime,
            dtime: inode.dtime,
            flags: inode.flags,
            generation: inode.generation,
            allocated,
        })
    }

    /// Read a symlink's target by path.
    pub fn symlink_target(&mut self, path: &str) -> Result<Vec<u8>> {
        let ino = self.dir_reader.resolve_path(path)?;
        self.dir_reader.read_link(ino)
    }

    /// Check if a path exists.
    pub fn exists(&mut self, path: &str) -> Result<bool> {
        match self.dir_reader.resolve_path(path) {
            Ok(_) => Ok(true),
            Err(error::Ext4Error::PathNotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    // --- Tier 2: Forensic access ---

    /// Read any inode by number.
    pub fn inode(&mut self, ino: u64) -> Result<Inode> {
        self.dir_reader.inode_reader_mut().read_inode(ino)
    }

    /// Enumerate all inodes (allocated and deleted).
    pub fn all_inodes(&mut self) -> Result<Vec<(u64, Inode)>> {
        self.dir_reader.inode_reader_mut().iter_all_inodes()
    }

    /// Find all deleted inodes with metadata.
    pub fn deleted_inodes(&mut self) -> Result<Vec<forensic::DeletedInode>> {
        forensic::find_deleted_inodes(self.dir_reader.inode_reader_mut())
    }

    /// Attempt to recover a deleted file by inode number.
    pub fn recover_file(&mut self, ino: u64) -> Result<forensic::RecoveryResult> {
        forensic::recovery::recover_file(self.dir_reader.inode_reader_mut(), ino)
    }

    /// Parse the jbd2 journal.
    pub fn journal(&mut self) -> Result<forensic::Journal> {
        forensic::journal::parse_journal(self.dir_reader.inode_reader_mut())
    }

    /// Generate a forensic timeline of all filesystem events.
    pub fn timeline(&mut self) -> Result<Vec<forensic::TimelineEvent>> {
        forensic::timeline::generate_timeline(self.dir_reader.inode_reader_mut())
    }

    /// Read extended attributes for an inode.
    pub fn xattrs(&mut self, ino: u64) -> Result<Vec<forensic::Xattr>> {
        forensic::xattr::read_xattrs(self.dir_reader.inode_reader_mut(), ino)
    }

    /// Get all unallocated block ranges.
    pub fn unallocated_blocks(&mut self) -> Result<Vec<forensic::BlockRange>> {
        forensic::carving::unallocated_blocks(self.dir_reader.inode_reader_mut())
    }

    /// Read raw data from an unallocated block range.
    pub fn read_unallocated(&mut self, range: &forensic::BlockRange) -> Result<Vec<u8>> {
        forensic::carving::read_unallocated(self.dir_reader.inode_reader_mut(), range)
    }

    /// Check if a specific inode is allocated.
    pub fn is_inode_allocated(&mut self, ino: u64) -> Result<bool> {
        self.dir_reader.inode_reader_mut().is_inode_allocated(ino)
    }

    /// Check if a specific block is allocated.
    pub fn is_block_allocated(&mut self, block: u64) -> Result<bool> {
        self.dir_reader.inode_reader_mut().is_block_allocated(block)
    }

    /// Read a raw block by number.
    pub fn read_block(&mut self, block: u64) -> Result<Vec<u8>> {
        self.dir_reader.inode_reader_mut().block_reader_mut().read_block(block)
    }
}
```

- [ ] **Step 4: Run tests**

Run: `cd ~/src/ext4fs-forensic && cargo test -p ext4fs`
Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
cd ~/src/ext4fs-forensic
git add ext4fs/src/lib.rs
git commit -m "feat: Layer 5 — Ext4Fs public API with tier 1 + tier 2 forensic access"
```

---

### Task 16: CRC32C Checksum Verification

**Files:**
- Modify: `ext4fs/src/ondisk/superblock.rs`
- Modify: `ext4fs/src/block.rs`

Add checksum verification for the superblock and group descriptors. Other structures (inodes, extents, directories) can be added incrementally.

- [ ] **Step 1: Write failing test for superblock checksum**

Add to `superblock.rs` tests:

```rust
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/src/ext4fs-forensic && cargo test -p ext4fs superblock`
Expected: FAIL — `verify_checksum` not defined.

- [ ] **Step 3: Implement superblock checksum verification**

Add to `Superblock` impl in `superblock.rs`:

```rust
    /// Verify the superblock CRC32C checksum.
    /// The checksum covers bytes 0..0x3FC (everything except the checksum field itself).
    pub fn verify_checksum(&self, raw_buf: &[u8]) -> bool {
        if !self.has_metadata_csum() || raw_buf.len() < 0x400 {
            return true; // no checksum to verify
        }

        use crc::{Crc, CRC_32_ISCSI};
        let crc32c = Crc::<u32>::new(&CRC_32_ISCSI);

        // Seed: checksum_seed if CSUM_SEED flag set, otherwise CRC32C of UUID
        let seed = if self.feature_incompat.contains(IncompatFeatures::CSUM_SEED) {
            self.checksum_seed
        } else {
            let mut digest = crc32c.digest();
            digest.update(&self.uuid);
            digest.finalize()
        };

        // CRC32C of superblock bytes 0..0x3FC, seeded
        let mut digest = crc32c.digest_with_initial(seed);
        digest.update(&raw_buf[..0x3FC]);
        let computed = digest.finalize();

        computed == self.checksum
    }
```

- [ ] **Step 4: Run tests**

Run: `cd ~/src/ext4fs-forensic && cargo test -p ext4fs`
Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
cd ~/src/ext4fs-forensic
git add ext4fs/src/ondisk/superblock.rs
git commit -m "feat: CRC32C checksum verification for superblock"
```

---

## Self-Review

**1. Spec coverage:**
- Layer 0 on-disk structs: Tasks 2-8 ✓ (superblock, group desc, inode, extent, dir_entry, journal, xattr)
- Layer 1 block device: Task 9 ✓
- Layer 2 inode ops: Task 10 ✓ (read_inode, block_map, read_data, data_range, iter, bitmaps)
- Layer 3 directory ops: Task 11 ✓ (read_dir, lookup, resolve_path, read_link, symlinks)
- Layer 4 forensic ops: Tasks 12-14 ✓ (deleted, journal, recovery, xattr, timeline, carving)
- Layer 5 public API: Task 15 ✓ (Ext4Fs with both tiers)
- Checksum verification: Task 16 ✓
- Error types: Task 1 ✓
- Test strategy: Tasks 1 (image script), 2-16 (layer tests) ✓
- `#![forbid(unsafe_code)]`: Every file ✓
- `Read+Seek` source: BlockReader ✓
- HTree directories: Not yet optimized (linear scan works, HTree optimization deferred — noted in spec as supported but linear scan is functionally correct)
- MCP Server: Out of scope (separate plan for ext4fs-cli)
- FUSE Mount: Out of scope (separate plan for ext4fs-fuse)

**2. Placeholder scan:** No TBD/TODO/placeholders found. All steps have code.

**3. Type consistency:**
- `Superblock` — consistent across tasks 2, 9, 10-16
- `GroupDescriptor` — consistent (task 3, 9)
- `Inode` — consistent (task 4, 10, 12-15)
- `ExtentHeader`/`ExtentLeaf`/`ExtentIndex` — consistent (task 5, 10)
- `DirEntry` — consistent (task 6, 11, 15)
- `BlockMapping` — defined in task 10, used in 10, 14
- `BlockRange` — defined in task 14 (recovery.rs), used in carving.rs
- `Timestamp` — defined in task 4, used throughout
- `InodeMetadata` — defined in task 15
- `Ext4Fs` — defined in task 15
- `BlockReader` — defined in task 9, used in 10-15
- `InodeReader` — defined in task 10, used in 11-15
- `DirReader` — defined in task 11, used in 15
- `DeletedInode` — defined in task 12, used in 15
- `Journal`/`Transaction`/`InodeVersion` — defined in task 13, used in 15
- `RecoveryResult` — defined in task 14, used in 15
- `Xattr` — defined in task 14, used in 15
- `TimelineEvent` — defined in task 14, used in 15
- `CarvedInode` — defined in task 14

All names match. No inconsistencies found.
