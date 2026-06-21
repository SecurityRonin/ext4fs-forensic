# ext4fs-forensic

**Forensic-grade ext4 filesystem parser. Pure safe Rust. Apache-2.0 licensed.**

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Parse ext4 images with full forensic metadata — all five timestamps with nanosecond precision, deleted file recovery, journal history reconstruction, slack space analysis, and byte-level block search.

## Why this exists

This project stands on the shoulders of giants. The Sleuth Kit, libext2fs, and the Linux kernel's ext4 implementation pioneered the forensic analysis of ext4 filesystems and taught the community everything we know about on-disk structures. Without their decades of work, documentation, and open source contributions, this crate could not exist.

ext4fs-forensic brings those same forensic capabilities to the Rust ecosystem as a **pure safe Rust library** (`#![forbid(unsafe_code)]`). It parses ext4 on-disk structures from first principles — no C bindings, no unsafe code, Apache-2.0 licensed — making it easy to embed in modern forensic toolchains, commercial products, and court-admissible workflows.

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

## Trust, but verify

- **263 tests** across the workspace; `unsafe_code = "forbid"`, panic-free bounds-checked parsers, cargo-fuzz targets for the superblock / inode / directory readers.
- **Format-level parsing is cross-checked against `mkfs.ext4` (e2fsprogs) output**: the superblock, group-descriptor, and inode CRC32C checksums e2fsprogs writes are independently recomputed by this crate and required to match — an independent oracle, not a self-graded fixture.
- **Forensic recovery** (deleted inodes, directory-entry recovery, journal, timeline, slack, xattrs, symlinks) is currently validated against self-minted `mkfs.ext4` images with the generator's own bookkeeping as ground truth. An independent differential oracle (`debugfs` / `dumpe2fs` / The Sleuth Kit) is recommended and not yet wired.
- Full per-capability evidence, tiers, and the honest gaps: **[Validation](https://securityronin.github.io/ext4fs-forensic/validation/)**.

## Design decisions that matter for forensics

- **`#![forbid(unsafe_code)]`** — pure safe Rust, no undefined behavior, no buffer overflows
- **Checksum mismatches are warnings, not errors** — forensic tools must handle damaged filesystems
- **ext4 is little-endian, jbd2 journal is big-endian** — both handled correctly
- **No chrono dependency** — timestamps as raw `(i64 seconds, u32 nanoseconds)` tuples, no timezone assumptions
- **Apache-2.0 licensed** — use it in commercial tools, government systems, or court-submitted reports without GPL concerns

## Works with

- [**ewf**](https://crates.io/crates/ewf) — Read E01/EWF forensic disk images as a `Read+Seek` source
- [**blazehash**](https://crates.io/crates/blazehash) — Forensic file hashing (BLAKE3, SHA-256, MD5, SHA-1)
- [**4n6mount**](https://github.com/SecurityRonin/4n6mount) — FUSE mount with ro/rw views, deleted file browsing, and evidence filtering

## Acknowledgments

This project would not exist without the foundational work of those who built the forensic analysis discipline and its tools:

- **Brian Carrier** — for [The Sleuth Kit](https://www.sleuthkit.org/), [Autopsy Forensic Browser](https://www.autopsy.com/), and *File System Forensic Analysis*, which taught a generation of practitioners (including this author) how modern filesystems work at the byte level
- **Rob T. Lee** — for [SANS FOR508](https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting-training/) (Advanced Incident Response, Threat Hunting, and Digital Forensics), which shaped how I think about forensic timelines, evidence handling, and incident response
- **The Linux kernel ext4 developers** — for meticulous documentation of on-disk structures at [kernel.org](https://www.kernel.org/doc/html/latest/filesystems/ext4/)
- **Theodore Ts'o and the e2fsprogs team** — for debugfs, dumpe2fs, and decades of ext4 tooling that served as our validation reference

---

[Privacy Policy](https://securityronin.github.io/ext4fs-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/ext4fs-forensic/terms/) · © 2026 Security Ronin Ltd
