# ext4fs-forensic

**Forensic-grade ext4 filesystem parser. Pure safe Rust. Zero GPL.**

Parse ext4 images with full forensic metadata — all five timestamps with nanosecond precision, deleted file recovery, journal history reconstruction, slack space analysis, and byte-level block search.

## Why this exists

This project stands on the shoulders of giants. The Sleuth Kit, libext2fs, and the Linux kernel's ext4 implementation pioneered the forensic analysis of ext4 filesystems and taught the community everything we know about on-disk structures. Without their decades of work, documentation, and open source contributions, this crate could not exist. We are deeply grateful.

ext4fs-forensic brings those same forensic capabilities to the Rust ecosystem as a **pure safe Rust library** (`#![forbid(unsafe_code)]`). It parses every ext4 on-disk structure from first principles — no C bindings, no unsafe code, MIT licensed — making it easy to embed in modern forensic toolchains, commercial products, and court-admissible workflows.

## What you get

```rust
let mut fs = Ext4Fs::open(file)?;

// Standard filesystem access
let data = fs.read_file("/etc/passwd")?;
let entries = fs.read_dir("/")?;
let meta = fs.metadata("/var/log/auth.log")?;

// Forensic operations
let deleted = fs.deleted_inodes()?;              // Find all deleted files
let recovered = fs.recover_file(deleted[0].ino)?; // Recover file data
let timeline = fs.timeline()?;                    // Full forensic timeline
let journal = fs.journal()?;                      // jbd2 journal parsing
let history = fs.inode_history(ino)?;             // Metadata over time
let slack = fs.slack_space(ino)?;                 // File slack analysis
let hits = fs.search_blocks(b"password", All)?;   // Keyword search
let hashes = fs.hash_file(ino)?;                  // BLAKE3+SHA-256+MD5+SHA-1
let xattrs = fs.xattrs(ino)?;                    // Extended attributes
let dirs = fs.recover_dir_entries(2)?;            // Deleted filename recovery
let backups = fs.verify_superblock_backups()?;    // Tampering detection
```

## Forensic capabilities

| Capability | What it does |
|-----------|-------------|
| **Deleted file detection** | Scans inode tables for deletion markers (`dtime`) and orphans (crash artifacts) |
| **File recovery** | Follows extent trees to reconstruct deleted file data, reports recoverability percentage |
| **Forensic timeline** | All five timestamps (atime/mtime/ctime/crtime/dtime) with nanosecond precision, sorted chronologically |
| **Journal parsing** | Full jbd2 transaction history — descriptor blocks, commit timestamps, revoked blocks |
| **Inode history** | Reconstructs previous inode states from journaled metadata blocks |
| **Slack space** | Reads beyond file EOF in the last allocated block — where fragments of previous files hide |
| **Keyword search** | Byte pattern search across allocated, unallocated, or all blocks with configurable context |
| **File hashing** | BLAKE3 + SHA-256 + MD5 + SHA-1 via [blazehash](https://crates.io/crates/blazehash) — NSRL/HashKeeper compatible |
| **Deleted dir recovery** | Recovers filenames from `rec_len` gaps in directory blocks |
| **Xattr parsing** | Both inline (ibody) and block-stored extended attributes — SELinux labels, ACLs, user metadata |
| **Superblock backups** | Compares backup superblocks against primary for tampering/corruption detection |
| **CRC32C verification** | Checksums validated on superblock, group descriptors, and inodes |
| **Extent carving** | Scans unallocated blocks for extent tree signatures (0xF30A) |

## Architecture

Six-layer bottom-up design — each layer builds on the one below:

| Layer | Module | Purpose |
|-------|--------|---------|
| 0 | `ondisk/` | Byte-level struct parsing from raw `&[u8]` slices |
| 1 | `block.rs` | Block device abstraction over `Read+Seek` |
| 2 | `inode.rs` | Inode reading, extent tree walking, indirect blocks |
| 3 | `dir.rs` | Directory parsing, path resolution, symlink following |
| 4 | `forensic/` | 10 forensic analysis modules |
| 5 | `lib.rs` | `Ext4Fs<R>` public API — tier 1 (standard) + tier 2 (forensic) |

Accepts **any `Read + Seek` source** — raw image files, EWF/E01 images (via the [ewf](https://crates.io/crates/ewf) crate), or custom readers.

## Install

```toml
[dependencies]
ext4fs = "0.1"
```

## Test coverage

- **220 tests** across unit and integration suites
- **98.85% function coverage**, 87.86% line coverage
- Validated against real forensic images with known deleted files, xattrs, symlinks, and journal transactions

## Design decisions that matter for forensics

- **`#![forbid(unsafe_code)]`** — pure safe Rust, no undefined behavior, no buffer overflows
- **Checksum mismatches are warnings, not errors** — forensic tools must handle damaged filesystems
- **ext4 is little-endian, jbd2 journal is big-endian** — both handled correctly
- **No chrono dependency** — timestamps as raw `(i64 seconds, u32 nanoseconds)` tuples, no timezone assumptions
- **MIT licensed** — use it in commercial tools, government systems, or court-submitted reports without GPL concerns

## Works with

- [**ewf**](https://crates.io/crates/ewf) — Read E01/EWF forensic disk images as a `Read+Seek` source
- [**blazehash**](https://crates.io/crates/blazehash) — Forensic file hashing (BLAKE3, SHA-256, MD5, SHA-1)
- [**4n6mount**](https://github.com/SecurityRonin/4n6mount) — FUSE mount with ro/rw views, deleted file browsing, and evidence filtering

## License

MIT
