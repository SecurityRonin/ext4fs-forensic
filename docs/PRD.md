# ext4fs-forensic — Product Requirements

*Reverse-written from the shipped code, README, and git history (same-session read
of `ext4fs-core/`, `ext4fs-cli/`, `ext4fs-fuse/`, 2026-07-24). The load-bearing
decisions live as ADRs under [`docs/decisions/`](decisions/); per-capability
validation evidence lives in [`validation.md`](validation.md). This documents what
the tool **is now**, not a roadmap.*

## Executive Summary

ext4fs-forensic is a **pure safe-Rust forensic toolkit for ext2/3/4 filesystem
images**. Its heart is `ext4fs-core` — a `#![forbid(unsafe_code)]`,
input-fuzzed, panic-free-by-lint parser that reads an ext4 image from any
`Read + Seek` source (raw/dd, or EWF/E01) and exposes two tiers: standard
filesystem access and forensic operations (deleted-file detection and recovery,
five-timestamp timelines, jbd2 journal reconstruction, slack analysis, keyword
search, multi-algorithm hashing, xattr parsing, and superblock-backup tamper
comparison).

Three front-ends make it something an examiner (or an agent) **runs**:

- **`ext4fs` CLI** (`ext4fs-cli`) — `info` / `ls` / `read` subcommands plus an
  **MCP server** (`ext4fs mcp`) exposing 12 forensic tools over JSON-RPC stdio.
- **`ext4fs-fuse`** — a forensic FUSE mount (`mount` / `export-session` /
  `import-session`) over the shared `forensic-mount` layer.

The differentiator is trust: no C bindings, no unsafe, no GPL — Apache-2.0,
embeddable in commercial and court-facing workflows — with format-level parsing
cross-checked against `mkfs.ext4` (e2fsprogs) as an independent oracle.

## 1. Problem

Analysts examining Linux/Android evidence need to read ext4 images with *forensic*
fidelity, not just mount them. General-purpose drivers hide exactly what an
examiner needs: they refuse to mount a damaged or tampered filesystem, discard
deleted-inode residue, normalize timestamps through a timezone, and expose nothing
about the jbd2 journal or block slack. The mature reference tooling (The Sleuth
Kit, libext2fs, debugfs) is C, GPL-encumbered, and awkward to embed in a modern
Rust toolchain or an agent-driven workflow.

The gap this fills: a **memory-safe, embeddable, permissively-licensed** ext4
forensic reader that treats corrupted/tampered images as first-class input and
surfaces deletion, timeline, journal, and slack evidence directly.

## 2. Users

- **Digital forensic examiners / IR responders** analyzing Linux and Android
  (ext4-backed) evidence images — via the `ext4fs` CLI, the FUSE mount, or a
  higher-level orchestrator (disk-forensic, Issen) that links `ext4fs-core`.
- **AI/agent-driven triage** — via the MCP server, which hands an agent
  open/ls/read/stat plus deleted/recover/timeline/journal/search/hash tools.
- **Rust developers** building forensic or storage tooling who need an
  `unsafe`-free ext4 parser they can `cargo add` and embed.

## 3. What it does

**Standard access (tier 1)** — `Ext4Fs::open(source)` over any `Read + Seek`:
`read_file(path)`, `read_dir(path)`, `metadata(path)`, superblock inspection,
symlink following, extent-tree and indirect-block reads.

**Forensic operations (tier 2)** — the modules under `core/src/forensic/`:

| Capability | What it does |
|---|---|
| Deleted-file detection | Scans inode tables for `dtime` markers and crash-orphan inodes |
| File recovery | Follows extent trees to reconstruct deleted data; reports a recoverability fraction |
| Forensic timeline | All five timestamps (atime/mtime/ctime/crtime/dtime), nanosecond precision, sorted |
| Journal parsing | Full jbd2 transaction history — descriptor blocks, commit timestamps, revokes |
| Inode history | Reconstructs prior inode states from journaled metadata blocks |
| Slack space | Reads past EOF in the last allocated block (residue of prior files) |
| Keyword search | Byte-pattern search across allocated / unallocated / all blocks |
| File hashing | BLAKE3 + SHA-256 + MD5 + SHA-1 via `blazehash-core` |
| Deleted-dir recovery | Recovers filenames from `rec_len` gaps in directory blocks |
| Xattr parsing | Inline (ibody) and block-stored xattrs — SELinux labels, ACLs |
| Superblock backups | Compares backup superblocks against primary for divergence |
| Unallocated extents | Enumerates free-block ranges from the block bitmaps |
| CRC32C verification | Validates (non-fatally) superblock / group-desc / inode checksums |

**Fleet reporting** — forensic results surface as graded `EXT4-*`
`forensicnomicon::report::Finding`s (`forensic/findings.rs`), so a
disk-forensic / Issen orchestrator aggregates ext4 findings uniformly. Findings
are observations in "consistent with" language, never verdicts.

**Front-ends** — the `ext4fs` CLI (`info`/`ls`/`read`/`mcp`), the 12-tool MCP
server, and the `ext4fs-fuse` mount with session export/import.

## 4. Scope

- ext2 / ext3 / ext4 on-disk parsing from raw and EWF/E01 sources.
- Forensic recovery, timeline, journal, slack, search, hashing, xattr, and
  tamper-comparison over that parse.
- A runnable CLI, an MCP server, and a FUSE mount.
- Composition into the fleet: a `forensic-vfs` `FileSystem` adapter (behind the
  `vfs` feature) and the `EXT4-*` findings adapter.

## 5. Non-goals

- **Writing to the evidence image.** The reader is read-only by construction
  (`Read + Seek`, `forbid(unsafe)`); the FUSE mount's writability is the
  `forensic-mount` overlay's concern, never a write to the source.
- **Being the end-user disk triage CLI.** Whole-disk container decode, partition
  handling, and cross-artifact correlation belong to disk-forensic / Issen;
  `ext4fs` is the ext4 filesystem layer they drive.
- **Non-ext filesystems.** NTFS/APFS/FAT/HFS+ are their own fleet crates.
- **Timezone/calendar rendering in the core.** Timestamps stay raw
  `(i64 seconds, u32 nanoseconds)` (ADR 0006); localization is a consumer job.
- **`mmap`-based zero-copy parsing.** Excluded so `forbid(unsafe)` holds
  (ADR 0003).
- **Carving as a mount surface.** Raw unallocated carving stays with the
  dedicated tools; the mount does not simulate it.

## 6. Artifact family

ext2/3/4 filesystems and their jbd2 journal — the primary Linux and Android
filesystem. Sources: raw/dd images and EWF/E01 (via the `ewf` feature).

## 7. Validation approach

- **Tier-1, independent oracle for format parsing.** Superblock, group-descriptor,
  and inode CRC32C checksums that e2fsprogs (`mkfs.ext4`) writes are independently
  recomputed by this crate and required to match — an external answer key, not a
  self-graded fixture. A Tier-1 TSK `fsstat` reconciliation covers the
  `unallocated()` enumeration (`c546e2a`).
- **Panic-free posture, measured.** `unwrap_used`/`expect_used` denied
  workspace-wide, `forbid(unsafe)`, `safe-read` bounds-checked field reads, and
  cargo-fuzz targets for the superblock / inode / directory readers (ADR 0004).
- **Honest gap.** Forensic *recovery* (deleted inodes, dir-entry recovery,
  journal, timeline, slack, xattrs) is currently validated against self-minted
  `mkfs.ext4` images with the generator's own bookkeeping as ground truth; an
  independent differential oracle (`debugfs` / `dumpe2fs` / TSK) is recommended
  and **not yet wired**. Stated plainly, per the fleet Doer-Checker discipline.
- Full per-capability evidence and tiers: [`validation.md`](validation.md).
