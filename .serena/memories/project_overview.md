# ext4fs-forensic — Project Overview

Forensic-grade ext4 filesystem parser in pure safe Rust (`#![forbid(unsafe_code)]`).

## Purpose
Parse ext4 on-disk structures with full forensic metadata, recover deleted files, parse jbd2 journal, generate forensic timelines, expose via MCP/FUSE.

## Architecture — 6-Layer Bottom-Up
- **Layer 0** (`ondisk/`): Byte-level struct definitions from raw `&[u8]` slices
- **Layer 1** (`block.rs`): `BlockReader<R: Read + Seek>` — block device abstraction
- **Layer 2** (`inode.rs`): `InodeReader` — inode reading, extent trees, bitmaps
- **Layer 3** (`dir.rs`): `DirReader` — directory parsing, path resolution, symlinks
- **Layer 4** (`forensic/`): Deleted detection, jbd2 journal, recovery, timeline, xattrs, carving
- **Layer 5** (`lib.rs`): `Ext4Fs<R>` public API — tier 1 (standard) + tier 2 (forensic)

## Workspace
- Cargo workspace, member: `ext4fs/`
- Future: `ext4fs-cli` (MCP server), `ext4fs-fuse`

## Dependencies
- `bitflags` 2.x, `crc` 3.x (CRC32C)
- No `chrono` — raw `(i64, u32)` timestamps

## Key Decisions
- ext4 = little-endian; jbd2 = big-endian
- Checksum mismatches = warnings (forensic tolerance)
- Accepts any `Read + Seek` source
- Test images in `tests/data/`
