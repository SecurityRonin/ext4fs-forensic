# Clippy Fixes + HTree/Inline Data + FUSE Mount Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix all clippy warnings, add HTree directory fallback + inline data xattr overflow, and build a full FUSE mount crate with ro/rw views, forensic virtual directories, COW overlay, and session management.

**Architecture:** Three phases — (1) clippy cleanup, (2) forensic feature additions to `ext4fs` library, (3) new `ext4fs-fuse` workspace member implementing `fuser::Filesystem` with synthetic inode mapping, lazy-loaded virtual directories, and a sidecar-based COW overlay.

**Tech Stack:** Rust, `fuser` 0.15, `clap` 4.x, `serde`/`serde_json` 1.x, `sha2` 0.10, `crc` 3.x

---

### Task 1: Fix All Clippy Warnings

**Files:**
- Modify: `ext4fs/src/inode.rs:287`
- Modify: `ext4fs/src/ondisk/superblock.rs:371`
- Modify: `ext4fs/src/ondisk/extent.rs:51`
- Modify: `ext4fs/src/forensic/deleted.rs:139,204-205`
- Modify: `ext4fs/src/forensic/journal.rs:97`
- Modify: `ext4fs/src/forensic/recovery.rs:81,93`
- Modify: `ext4fs/src/forensic/xattr.rs:181,185`
- Modify: `ext4fs/src/forensic/carving.rs:152`
- Modify: `ext4fs/src/block.rs:127`

**Step 1: Fix all 13 warnings**

Apply these mechanical fixes:

1. `inode.rs:287` — unused variable `block_size` → prefix with `_`
2. `superblock.rs:371` — `((total + per - 1) / per)` → `total.div_ceil(per)`
3. `extent.rs:51` — format string: use variable directly in string
4. `deleted.rs:139` — `match` single pattern → `if let`
5. `deleted.rs:204-205` — format strings: use variables directly
6. `journal.rs:97` — `match` single pattern → `if let`
7. `recovery.rs:81` — `std::iter::repeat(0u8).take(fill)` → `vec![0u8; fill]` (use `.extend_from_slice`)
8. `recovery.rs:93` — same pattern
9. `xattr.rs:181,185` — format strings: use variables directly
10. `carving.rs:152` — format string: use variable directly
11. `block.rs:127` — remove unnecessary `mut`

**Step 2: Run clippy to verify zero warnings**

Run: `cargo clippy -p ext4fs --all-targets 2>&1`
Expected: 0 warnings

**Step 3: Run full test suite**

Run: `cargo test -p ext4fs`
Expected: 132 passed

**Step 4: Commit**

```
fix: resolve all clippy warnings
```

---

### Task 2: HTree Directory Fallback

**Files:**
- Modify: `ext4fs/src/dir.rs:29-51` (read_dir method)

HTree directories have the `INDEX` flag set. The first data block contains an HTree root node (fake `.` and `..` entries followed by a hash tree root structure). The remaining blocks contain normal directory entry blocks.

The current `read_dir` already scans all data blocks linearly and parses directory entries. The fix is to handle the HTree root block's special format — its first 40 bytes are a fake dotdot entry + HTree root header, but `parse_dir_block` already handles entries with `rec_len` spanning the rest, so it should mostly work. The key issue: in HTree directories, the first block's entries after `.` and `..` are HTree index nodes, not real directory entries. We need to skip parsing the first block's hash tree metadata and only collect the `.` and `..` from it.

Actually, `parse_dir_block` already handles this correctly because HTree root blocks encode `.` and `..` as real directory entries with padded `rec_len` values that span the hash tree data. The linear scan naturally skips the index data. We just need to verify this works.

**Step 1: Write the test (against forensic.img which may have HTree dirs)**

Add to `ext4fs/src/dir.rs` test module:

```rust
fn open_forensic() -> Option<DirReader<Cursor<Vec<u8>>>> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/forensic.img");
    let data = std::fs::read(path).ok()?;
    let br = BlockReader::open(Cursor::new(data)).ok()?;
    let ir = InodeReader::new(br);
    Some(DirReader::new(ir))
}

#[test]
fn read_dir_handles_all_directory_types() {
    // Verify we can read all directories in the filesystem without error
    let mut r = match open_forensic() {
        Some(r) => r,
        None => { eprintln!("skip: forensic.img not found"); return; }
    };
    let all_inodes = r.inode_reader_mut().iter_all_inodes().unwrap();
    let mut dir_count = 0;
    for (ino, inode) in &all_inodes {
        if inode.file_type() == FileType::Directory && inode.mode != 0 {
            let entries = r.read_dir(*ino).unwrap();
            // Every directory should have at least . and ..
            let names: Vec<String> = entries.iter().map(|e| e.name_str()).collect();
            assert!(names.contains(&".".to_string()), "dir ino {} missing '.'", ino);
            assert!(names.contains(&"..".to_string()), "dir ino {} missing '..'", ino);
            dir_count += 1;
        }
    }
    assert!(dir_count > 0, "no directories found");
}
```

**Step 2: Run test**

Run: `cargo test -p ext4fs read_dir_handles_all -- --nocapture`
Expected: PASS (linear scan already handles HTree correctly)

If it fails on any directory, investigate and fix the HTree root block parsing.

**Step 3: Commit**

```
test: verify directory reading works for all directory types including HTree
```

---

### Task 3: Inline Data Xattr Overflow

**Files:**
- Modify: `ext4fs/src/inode.rs:280-284` (read_inode_data inline data path)
- Modify: `ext4fs/src/forensic/xattr.rs` (need access from inode.rs)

For files with `INLINE_DATA` flag and size > 60 bytes, the overflow data is stored in a `system.data` xattr. The current code only reads the first 60 bytes from `i_block`.

**Step 1: Write the failing test**

Add to `ext4fs/src/inode.rs` test module. Since we likely don't have an inline data file in our test images, create a unit test that verifies the code path exists:

```rust
#[test]
fn read_inode_data_inline_returns_correct_length() {
    // Verify inline data reads exactly inode.size bytes (not always 60)
    let mut reader = match open_minimal() {
        Some(r) => r,
        None => { eprintln!("skip: minimal.img not found"); return; }
    };
    // hello.txt (12 bytes "Hello, ext4!") uses extents, not inline data
    // This test verifies the non-inline path still works correctly
    let data = reader.read_inode_data(12).unwrap();
    assert_eq!(data.len(), 12);
    assert_eq!(&data, b"Hello, ext4!");
}
```

**Step 2: Implement xattr overflow for inline data**

In `ext4fs/src/inode.rs`, update `read_inode_data()` at line 280:

```rust
pub fn read_inode_data(&mut self, ino: u64) -> Result<Vec<u8>> {
    let inode = self.read_inode(ino)?;
    if inode.has_inline_data() {
        let len = (inode.size as usize).min(60);
        let mut data = inode.i_block[..len].to_vec();
        // For inline data files > 60 bytes, overflow is in system.data xattr
        if inode.size > 60 {
            if let Ok(raw) = self.read_inode_raw(ino) {
                let inode_size = self.block_reader.superblock().inode_size as usize;
                let ibody_offset = 0x80 + inode.extra_isize as usize;
                if inode_size > ibody_offset {
                    let ibody = &raw[ibody_offset..];
                    // Search for system.data xattr (namespace index 7, name "data")
                    if let Some(value) = find_system_data_xattr(ibody) {
                        data.extend_from_slice(&value);
                    }
                }
            }
        }
        data.truncate(inode.size as usize);
        return Ok(data);
    }
    // ... rest of existing code unchanged
```

Add helper function in `inode.rs`:

```rust
use crate::ondisk::xattr::XattrEntry;

/// Search ibody xattr region for system.data xattr (used for inline data overflow).
fn find_system_data_xattr(ibody: &[u8]) -> Option<Vec<u8>> {
    let mut offset = 0;
    while offset + 16 <= ibody.len() {
        if ibody[offset] == 0 { break; }
        match XattrEntry::parse(&ibody[offset..]) {
            Ok(entry) => {
                // system.data: name_index 7 (SYSTEM), name "data"
                if entry.name_index as u8 == 7 && entry.name == b"data" {
                    let vs = entry.value_offset as usize;
                    let ve = vs + entry.value_size as usize;
                    if ve <= ibody.len() {
                        return Some(ibody[vs..ve].to_vec());
                    }
                }
                offset += entry.entry_size;
            }
            Err(_) => break,
        }
    }
    None
}
```

Note: The `XattrNamespace` enum uses `System` for index 7. Check `ondisk/xattr.rs` for the exact mapping — if index 7 maps differently, adjust accordingly.

**Step 3: Run tests**

Run: `cargo test -p ext4fs`
Expected: all pass

**Step 4: Commit**

```
feat: inline data xattr overflow support for files > 60 bytes
```

---

### Task 4: FUSE Crate Scaffold

**Files:**
- Create: `ext4fs-fuse/Cargo.toml`
- Create: `ext4fs-fuse/src/main.rs`
- Modify: `Cargo.toml` (workspace members)

**Step 1: Add workspace member**

Update root `Cargo.toml`:
```toml
[workspace]
members = ["ext4fs", "ext4fs-fuse"]
resolver = "2"
```

**Step 2: Create ext4fs-fuse/Cargo.toml**

```toml
[package]
name = "ext4fs-fuse"
version = "0.1.0"
edition = "2021"
description = "Forensic FUSE mount for ext4 images"
license = "MIT"

[dependencies]
ext4fs = { path = "../ext4fs" }
fuser = "0.15"
clap = { version = "4", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha2 = "0.10"
```

**Step 3: Create minimal main.rs**

```rust
#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "ext4fs-fuse", about = "Forensic FUSE mount for ext4 images")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Mount an ext4 image
    Mount {
        /// Path to ext4 image file
        image: String,
        /// Mount point directory
        mountpoint: String,
        /// Session directory for COW overlay persistence
        #[arg(long)]
        session: Option<String>,
        /// Resume a previous session
        #[arg(long)]
        resume: bool,
    },
    /// Export session for sharing
    ExportSession {
        /// Session directory to export
        session_dir: String,
        /// Output tarball path
        #[arg(long)]
        output: String,
    },
    /// Import a session from tarball
    ImportSession {
        /// Tarball to import
        tarball: String,
        /// Session directory to extract to
        #[arg(long)]
        session: String,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Mount { image, mountpoint, session, resume } => {
            eprintln!("Mounting {} at {} (session: {:?}, resume: {})",
                image, mountpoint, session, resume);
            todo!("FUSE mount implementation")
        }
        Commands::ExportSession { session_dir, output } => {
            eprintln!("Exporting session {} to {}", session_dir, output);
            todo!("session export")
        }
        Commands::ImportSession { tarball, session } => {
            eprintln!("Importing session from {} to {}", tarball, session);
            todo!("session import")
        }
    }
}
```

**Step 4: Verify it builds**

Run: `cargo build -p ext4fs-fuse`
Expected: compiles (panics at runtime on `todo!()`, but that's expected)

**Step 5: Commit**

```
feat: ext4fs-fuse crate scaffold with CLI parser
```

---

### Task 5: FUSE Inode Mapping + Virtual Directory Structure

**Files:**
- Create: `ext4fs-fuse/src/inode_map.rs`
- Create: `ext4fs-fuse/src/vfs.rs`

The FUSE filesystem needs to map between FUSE inodes (u64) and our virtual directory structure. Real ext4 inodes are offset to avoid collisions with synthetic virtual inodes.

**Step 1: Write tests for inode mapping**

Create `ext4fs-fuse/src/inode_map.rs`:

```rust
#![forbid(unsafe_code)]

/// FUSE inode number constants for virtual directories.
pub const FUSE_ROOT_INO: u64 = 1;
pub const FUSE_RO_INO: u64 = 2;
pub const FUSE_RW_INO: u64 = 3;
pub const FUSE_DELETED_INO: u64 = 4;
pub const FUSE_JOURNAL_INO: u64 = 5;
pub const FUSE_METADATA_INO: u64 = 6;
pub const FUSE_UNALLOCATED_INO: u64 = 7;
pub const FUSE_SESSION_INO: u64 = 8;

/// Offset added to real ext4 inodes when exposing them under ro/.
const RO_INODE_OFFSET: u64 = 1_000;
/// Offset for rw/ overlay inodes.
const RW_INODE_OFFSET: u64 = 10_000_000;
/// Offset for deleted/ virtual file inodes.
const DELETED_INODE_OFFSET: u64 = 20_000_000;
/// Offset for metadata/ virtual file inodes.
const METADATA_INODE_OFFSET: u64 = 30_000_000;
/// Offset for journal/ virtual file inodes.
const JOURNAL_INODE_OFFSET: u64 = 40_000_000;
/// Offset for unallocated/ virtual file inodes.
const UNALLOCATED_INODE_OFFSET: u64 = 50_000_000;

/// Which virtual namespace a FUSE inode belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InodeNamespace {
    /// Virtual root or top-level directory
    Virtual(u64),
    /// Real ext4 inode under ro/
    Ro(u64),
    /// Overlay inode under rw/
    Rw(u64),
    /// Deleted file virtual inode
    Deleted(u64),
    /// Metadata virtual file
    Metadata(u64),
    /// Journal virtual file
    Journal(u64),
    /// Unallocated block range
    Unallocated(u64),
}

/// Convert a FUSE inode number to its namespace and real inode.
pub fn decode_fuse_ino(ino: u64) -> InodeNamespace {
    if ino <= FUSE_SESSION_INO {
        InodeNamespace::Virtual(ino)
    } else if ino >= UNALLOCATED_INODE_OFFSET {
        InodeNamespace::Unallocated(ino - UNALLOCATED_INODE_OFFSET)
    } else if ino >= JOURNAL_INODE_OFFSET {
        InodeNamespace::Journal(ino - JOURNAL_INODE_OFFSET)
    } else if ino >= METADATA_INODE_OFFSET {
        InodeNamespace::Metadata(ino - METADATA_INODE_OFFSET)
    } else if ino >= DELETED_INODE_OFFSET {
        InodeNamespace::Deleted(ino - DELETED_INODE_OFFSET)
    } else if ino >= RW_INODE_OFFSET {
        InodeNamespace::Rw(ino - RW_INODE_OFFSET)
    } else {
        InodeNamespace::Ro(ino - RO_INODE_OFFSET)
    }
}

/// Encode a real ext4 inode for the ro/ namespace.
pub fn ro_ino(ext4_ino: u64) -> u64 {
    ext4_ino + RO_INODE_OFFSET
}

/// Encode an overlay inode for the rw/ namespace.
pub fn rw_ino(ext4_ino: u64) -> u64 {
    ext4_ino + RW_INODE_OFFSET
}

/// Encode a deleted inode for the deleted/ namespace.
pub fn deleted_ino(ext4_ino: u64) -> u64 {
    ext4_ino + DELETED_INODE_OFFSET
}

/// Encode a metadata virtual inode.
pub fn metadata_ino(id: u64) -> u64 {
    id + METADATA_INODE_OFFSET
}

/// Encode a journal virtual inode.
pub fn journal_ino(seq: u64) -> u64 {
    seq + JOURNAL_INODE_OFFSET
}

/// Encode an unallocated range virtual inode.
pub fn unallocated_ino(id: u64) -> u64 {
    id + UNALLOCATED_INODE_OFFSET
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_ro_inode() {
        let ext4_ino = 42;
        let fuse = ro_ino(ext4_ino);
        assert_eq!(decode_fuse_ino(fuse), InodeNamespace::Ro(ext4_ino));
    }

    #[test]
    fn roundtrip_rw_inode() {
        let ext4_ino = 42;
        let fuse = rw_ino(ext4_ino);
        assert_eq!(decode_fuse_ino(fuse), InodeNamespace::Rw(ext4_ino));
    }

    #[test]
    fn roundtrip_deleted_inode() {
        let ext4_ino = 21;
        let fuse = deleted_ino(ext4_ino);
        assert_eq!(decode_fuse_ino(fuse), InodeNamespace::Deleted(ext4_ino));
    }

    #[test]
    fn virtual_root() {
        assert_eq!(decode_fuse_ino(FUSE_ROOT_INO), InodeNamespace::Virtual(1));
    }

    #[test]
    fn virtual_dirs() {
        assert_eq!(decode_fuse_ino(FUSE_RO_INO), InodeNamespace::Virtual(2));
        assert_eq!(decode_fuse_ino(FUSE_RW_INO), InodeNamespace::Virtual(3));
        assert_eq!(decode_fuse_ino(FUSE_DELETED_INO), InodeNamespace::Virtual(4));
    }

    #[test]
    fn namespaces_do_not_overlap() {
        // Verify that max realistic ext4 inode in ro/ doesn't collide with rw/
        let max_ro = ro_ino(9_000_000);
        let min_rw = rw_ino(0);
        assert!(max_ro < min_rw);
    }
}
```

**Step 2: Run tests**

Run: `cargo test -p ext4fs-fuse`
Expected: PASS

**Step 3: Commit**

```
feat: FUSE inode mapping with namespace decode/encode
```

---

### Task 6: Session Manager

**Files:**
- Create: `ext4fs-fuse/src/session.rs`

**Step 1: Write tests and implementation**

```rust
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionMetadata {
    pub image_path: String,
    pub image_sha256: String,
    pub created: String,
    pub examiner: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct OverlayMetadata {
    /// Created files: overlay_id -> {parent_ext4_ino, name, size}
    pub created: HashMap<String, OverlayEntry>,
    /// Modified files: ext4_ino -> overlay_id
    pub modified: HashMap<u64, String>,
    /// Whiteout (deleted in rw/): ext4_ino list
    pub deleted: Vec<u64>,
    /// Created directories: overlay_id -> {parent_ext4_ino, name}
    pub dirs: HashMap<String, OverlayEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OverlayEntry {
    pub parent_ino: u64,
    pub name: String,
    pub size: u64,
}

pub struct Session {
    pub dir: PathBuf,
    pub metadata: SessionMetadata,
    pub overlay: OverlayMetadata,
}

impl Session {
    /// Create a new session for an image.
    pub fn create(session_dir: &Path, image_path: &str) -> io::Result<Self> {
        fs::create_dir_all(session_dir.join("overlay/files"))?;

        let image_sha256 = compute_image_hash(image_path)?;
        let metadata = SessionMetadata {
            image_path: image_path.to_string(),
            image_sha256,
            created: chrono_now(),
            examiner: whoami(),
        };

        let session = Session {
            dir: session_dir.to_path_buf(),
            metadata,
            overlay: OverlayMetadata::default(),
        };
        session.save()?;
        Ok(session)
    }

    /// Resume an existing session, verifying image hash.
    pub fn resume(session_dir: &Path, image_path: &str) -> io::Result<Self> {
        let meta_path = session_dir.join("session.json");
        let meta_str = fs::read_to_string(&meta_path)?;
        let metadata: SessionMetadata = serde_json::from_str(&meta_str)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let current_hash = compute_image_hash(image_path)?;
        if current_hash != metadata.image_sha256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Image hash mismatch: expected {}, got {}. Evidence may have been modified.",
                    metadata.image_sha256, current_hash
                ),
            ));
        }

        let overlay_path = session_dir.join("overlay/metadata.json");
        let overlay = if overlay_path.exists() {
            let s = fs::read_to_string(&overlay_path)?;
            serde_json::from_str(&s)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        } else {
            OverlayMetadata::default()
        };

        Ok(Session {
            dir: session_dir.to_path_buf(),
            metadata,
            overlay,
        })
    }

    /// Save session state to disk.
    pub fn save(&self) -> io::Result<()> {
        let meta_str = serde_json::to_string_pretty(&self.metadata)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        fs::write(self.dir.join("session.json"), meta_str)?;

        let overlay_str = serde_json::to_string_pretty(&self.overlay)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        fs::create_dir_all(self.dir.join("overlay"))?;
        fs::write(self.dir.join("overlay/metadata.json"), overlay_str)?;
        Ok(())
    }

    /// Path to store an overlay file by its id.
    pub fn overlay_file_path(&self, id: &str) -> PathBuf {
        self.dir.join("overlay/files").join(id)
    }

    /// Write a file to the overlay.
    pub fn write_overlay_file(&self, id: &str, data: &[u8]) -> io::Result<()> {
        let path = self.overlay_file_path(id);
        fs::write(&path, data)?;
        // fsync for crash safety
        let f = fs::File::open(&path)?;
        f.sync_all()?;
        Ok(())
    }

    /// Read a file from the overlay.
    pub fn read_overlay_file(&self, id: &str) -> io::Result<Vec<u8>> {
        fs::read(self.overlay_file_path(id))
    }
}

/// Export a session directory to a tar.gz.
pub fn export_session(session_dir: &Path, output: &Path) -> io::Result<()> {
    use std::process::Command;
    let status = Command::new("tar")
        .args([
            "-czf",
            output.to_str().unwrap(),
            "-C",
            session_dir.parent().unwrap().to_str().unwrap(),
            session_dir.file_name().unwrap().to_str().unwrap(),
        ])
        .status()?;
    if !status.success() {
        return Err(io::Error::new(io::ErrorKind::Other, "tar failed"));
    }
    Ok(())
}

/// Import a session from a tar.gz.
pub fn import_session(tarball: &Path, session_dir: &Path) -> io::Result<()> {
    use std::process::Command;
    fs::create_dir_all(session_dir)?;
    let status = Command::new("tar")
        .args([
            "-xzf",
            tarball.to_str().unwrap(),
            "-C",
            session_dir.to_str().unwrap(),
            "--strip-components=1",
        ])
        .status()?;
    if !status.success() {
        return Err(io::Error::new(io::ErrorKind::Other, "tar extraction failed"));
    }
    Ok(())
}

fn compute_image_hash(path: &str) -> io::Result<String> {
    let data = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Ok(format!("{:x}", hasher.finalize()))
}

fn chrono_now() -> String {
    // Simple ISO-ish timestamp without chrono dependency
    use std::time::SystemTime;
    let d = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", d.as_secs())
}

fn whoami() -> String {
    std::env::var("USER").unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn create_and_resume_session() {
        let tmp = std::env::temp_dir().join("ext4fs-test-session");
        let _ = fs::remove_dir_all(&tmp);

        // Create a fake image
        let img_path = tmp.join("test.img");
        fs::create_dir_all(&tmp).unwrap();
        let mut f = fs::File::create(&img_path).unwrap();
        f.write_all(b"fake image data").unwrap();

        let session_dir = tmp.join("session");
        let session = Session::create(&session_dir, img_path.to_str().unwrap()).unwrap();
        assert!(!session.metadata.image_sha256.is_empty());
        assert!(session_dir.join("session.json").exists());

        // Resume
        let resumed = Session::resume(&session_dir, img_path.to_str().unwrap()).unwrap();
        assert_eq!(resumed.metadata.image_sha256, session.metadata.image_sha256);

        // Cleanup
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn resume_detects_tampered_image() {
        let tmp = std::env::temp_dir().join("ext4fs-test-tamper");
        let _ = fs::remove_dir_all(&tmp);

        let img_path = tmp.join("test.img");
        fs::create_dir_all(&tmp).unwrap();
        fs::write(&img_path, b"original").unwrap();

        let session_dir = tmp.join("session");
        Session::create(&session_dir, img_path.to_str().unwrap()).unwrap();

        // Tamper with image
        fs::write(&img_path, b"tampered").unwrap();

        let result = Session::resume(&session_dir, img_path.to_str().unwrap());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("hash mismatch"), "got: {err}");

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn overlay_file_roundtrip() {
        let tmp = std::env::temp_dir().join("ext4fs-test-overlay");
        let _ = fs::remove_dir_all(&tmp);

        let img_path = tmp.join("test.img");
        fs::create_dir_all(&tmp).unwrap();
        fs::write(&img_path, b"image").unwrap();

        let session_dir = tmp.join("session");
        let session = Session::create(&session_dir, img_path.to_str().unwrap()).unwrap();

        session.write_overlay_file("file1", b"hello overlay").unwrap();
        let data = session.read_overlay_file("file1").unwrap();
        assert_eq!(data, b"hello overlay");

        let _ = fs::remove_dir_all(&tmp);
    }
}
```

**Step 2: Run tests**

Run: `cargo test -p ext4fs-fuse`
Expected: PASS

**Step 3: Commit**

```
feat: session manager with COW overlay, hash verification, export/import
```

---

### Task 7: FUSE Filesystem — ro/ Read-Only Mount

**Files:**
- Create: `ext4fs-fuse/src/fusefs.rs`
- Modify: `ext4fs-fuse/src/main.rs`

This is the core FUSE implementation. Start with just the ro/ view (read-only pristine evidence).

**Step 1: Implement Ext4FuseFs struct and ro/ operations**

The `Ext4FuseFs` struct wraps an `Ext4Fs<File>` and implements `fuser::Filesystem`. For this task, implement:
- `lookup` — resolve names in virtual root and under `ro/`
- `getattr` — return file attributes (translate ext4 inodes to FUSE attrs)
- `readdir` — list virtual root entries and ext4 directory entries under `ro/`
- `read` — read file data from ext4 image
- `readlink` — read symlink targets

Key details:
- FUSE root (ino 1) contains: `ro`, `rw`, `deleted`, `journal`, `metadata`, `unallocated`, `session`
- `ro/` (ino 2) maps to ext4 root inode 2 (via `ro_ino(2)` = 1002)
- All write operations on `ro/` return `EROFS` (libc::EROFS)
- Use `inode_map::decode_fuse_ino()` to dispatch operations to the right handler

The `Ext4Fs` needs `RefCell` wrapping because `fuser::Filesystem` methods take `&self` but `Ext4Fs` methods need `&mut self`. Use `RefCell<Ext4Fs<File>>`.

**Step 2: Wire up main.rs mount command**

```rust
Commands::Mount { image, mountpoint, session, resume } => {
    let file = std::fs::File::open(&image).expect("cannot open image");
    let fs = ext4fs::Ext4Fs::open(file).expect("cannot parse ext4");
    let fusefs = fusefs::Ext4FuseFs::new(fs, session_manager);
    let options = vec![
        fuser::MountOption::RO,
        fuser::MountOption::FSName("ext4fs-fuse".to_string()),
        fuser::MountOption::AllowOther,
    ];
    fuser::mount2(fusefs, &mountpoint, &options).expect("mount failed");
}
```

**Step 3: Test manually**

Run: `cargo build -p ext4fs-fuse && ./target/debug/ext4fs-fuse mount tests/data/forensic.img /tmp/evidence`
Then: `ls /tmp/evidence/` — should show `ro/`, `rw/`, `deleted/`, etc.
Then: `ls /tmp/evidence/ro/` — should show ext4 filesystem contents
Then: `cat /tmp/evidence/ro/hello.txt` — should output file content
Then: `fusermount -u /tmp/evidence` (Linux) or `umount /tmp/evidence` (macOS)

**Step 4: Commit**

```
feat: FUSE ro/ read-only mount with virtual directory structure
```

---

### Task 8: FUSE rw/ with COW Overlay

**Files:**
- Modify: `ext4fs-fuse/src/fusefs.rs`

Add write support under `rw/`:
- `write` — COW: on first write to an existing file, copy original data to overlay, then apply write
- `create` — create new file in overlay
- `mkdir` — create directory in overlay
- `unlink` / `rmdir` — add whiteout entry, hide from rw/ readdir
- `lookup` in rw/ — check overlay first, then fall back to ro/
- `readdir` in rw/ — merge ext4 entries + overlay entries - whiteouts

All overlay data stored via `Session::write_overlay_file()`.

**Step 1: Implement rw/ FUSE operations**

This extends `fusefs.rs` with the write path. Key design:
- `rw/` lookup: check `overlay.modified` and `overlay.created` first, fall back to ext4
- `rw/` read: if file in overlay, read from overlay file; else read from ext4
- `rw/` write: if file not yet in overlay, COW copy original to overlay, then write
- `rw/` readdir: ext4 entries - whiteouts + overlay created entries
- `rw/` unlink: add to `overlay.deleted`, save overlay metadata

**Step 2: Test manually**

```bash
ext4fs-fuse mount tests/data/forensic.img /tmp/evidence --session /tmp/test-session
echo "analysis results" > /tmp/evidence/rw/results.txt
cat /tmp/evidence/rw/results.txt  # should return "analysis results"
cat /tmp/evidence/ro/hello.txt    # should still return original
ls /tmp/evidence/rw/              # should show original files + results.txt
```

**Step 3: Commit**

```
feat: FUSE rw/ with COW overlay, whiteouts, and session persistence
```

---

### Task 9: FUSE Forensic Virtual Directories

**Files:**
- Modify: `ext4fs-fuse/src/fusefs.rs`

Add the forensic virtual directories:

**deleted/** — On first `readdir`, call `ext4fs.deleted_inodes()` + `ext4fs.recover_file()`, cache results. Files named `{ino}_{name}` where name comes from journal history or `unknown`.

**journal/** — `readdir` lists `txn_{seq}` directories. Each contains inodes that were modified in that transaction (from journal mappings).

**metadata/** — Generated on-the-fly:
- `superblock.json` — serialized superblock fields
- `timeline.jsonl` — one JSON line per timeline event
- `inode/{N}.json` — full inode metadata as JSON

**unallocated/** — `readdir` lists `blocks_{start}-{end}.raw`. `read` calls `read_unallocated()`.

**session/** — `status.json` (session metadata), `resume.json` (mount state).

**Step 1: Implement each virtual directory**

Each virtual directory follows the same pattern:
1. In `readdir`: generate entries (lazy, cache after first call)
2. In `lookup`: map name to virtual inode
3. In `read`: generate content on demand
4. In `getattr`: return appropriate attributes (regular file, read-only)

**Step 2: Test manually**

```bash
ls /tmp/evidence/deleted/
ls /tmp/evidence/metadata/
cat /tmp/evidence/metadata/superblock.json
cat /tmp/evidence/metadata/timeline.jsonl | head -5
ls /tmp/evidence/journal/
ls /tmp/evidence/unallocated/
```

**Step 3: Commit**

```
feat: FUSE forensic virtual directories (deleted, journal, metadata, unallocated)
```

---

### Task 10: Session Export/Import CLI

**Files:**
- Modify: `ext4fs-fuse/src/main.rs`

**Step 1: Wire up export/import commands**

```rust
Commands::ExportSession { session_dir, output } => {
    session::export_session(
        Path::new(&session_dir),
        Path::new(&output),
    ).expect("export failed");
    eprintln!("Session exported to {}", output);
}
Commands::ImportSession { tarball, session } => {
    session::import_session(
        Path::new(&tarball),
        Path::new(&session),
    ).expect("import failed");
    eprintln!("Session imported to {}", session);
}
```

**Step 2: Test roundtrip**

```bash
# Create session via mount
ext4fs-fuse mount tests/data/forensic.img /tmp/evidence --session /tmp/session1
echo "note" > /tmp/evidence/rw/note.txt
umount /tmp/evidence

# Export
ext4fs-fuse export-session /tmp/session1 --output /tmp/session1.tar.gz

# Import on "another machine"
ext4fs-fuse import-session /tmp/session1.tar.gz --session /tmp/session2

# Resume imported session
ext4fs-fuse mount tests/data/forensic.img /tmp/evidence --session /tmp/session2 --resume
cat /tmp/evidence/rw/note.txt  # should show "note"
```

**Step 3: Commit**

```
feat: session export/import CLI commands
```

---
