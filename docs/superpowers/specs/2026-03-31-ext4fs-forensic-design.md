# ext4fs-forensic Design Spec

## Overview

A forensic-grade ext4 filesystem library, CLI/MCP server, and FUSE mounter written in pure safe Rust. Designed as the first crate in a suite of forensic filesystem libraries (ext4, NTFS, APFS, HFS+, exFAT/FAT) that feed into a unified forensic FUSE mounting platform.

## Goals

- Parse all ext4 on-disk structures with full forensic metadata (all 5 timestamps with nanosecond precision, xattrs, allocation state)
- Recover deleted files by scanning inode tables and verifying data block allocation
- Parse jbd2 journal for transaction history and inode version recovery
- Generate forensic timelines from all filesystem events
- Mount ext4 images read-only via FUSE with virtual directories for deleted files, journal snapshots, and examiner workflows
- Support virtual writes (tags, annotations, exports) via a sidecar overlay that never modifies the original evidence
- Accept any `Read+Seek` source, enabling E01/EWF image support via the ewf crate
- Expose all capabilities over MCP (JSON-RPC stdio) for AI-assisted forensic analysis

## Non-Goals

- Write support to the actual filesystem (forensic integrity)
- Filesystem repair or fsck functionality
- `no_std` support (forensic tools run on desktops/servers)
- Partition table parsing (will be a separate crate in the unified mounter)

## Architecture

### Workspace Layout

```
~/src/ext4fs-forensic/
├── Cargo.toml              (workspace)
├── ext4fs/                 (library crate)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs          (Ext4Fs public API, Layer 5)
│       ├── ondisk/         (Layer 0: on-disk struct definitions)
│       │   ├── mod.rs
│       │   ├── superblock.rs
│       │   ├── group_desc.rs
│       │   ├── inode.rs
│       │   ├── extent.rs
│       │   ├── dir_entry.rs
│       │   ├── htree.rs
│       │   ├── journal.rs
│       │   └── xattr.rs
│       ├── block.rs        (Layer 1: block device abstraction)
│       ├── inode.rs        (Layer 2: inode operations)
│       ├── dir.rs          (Layer 3: directory operations)
│       └── forensic/       (Layer 4: forensic operations)
│           ├── mod.rs
│           ├── deleted.rs
│           ├── journal.rs
│           ├── timeline.rs
│           ├── recovery.rs
│           ├── xattr.rs
│           └── carving.rs
├── ext4fs-cli/             (CLI + MCP server crate)
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── cli.rs
│       ├── mcp.rs
│       └── handlers.rs
├── ext4fs-fuse/            (FUSE mount crate)
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── mount.rs
│       ├── overlay.rs
│       └── session.rs
└── tests/
    └── data/               (synthetic ext4 test images)
```

### Layer Architecture (ext4fs library)

The library is organized in 6 layers, each building on the one below. This matches how ext4 actually works (blocks -> inodes -> directories -> files) and enables layer-by-layer TDD.

#### Layer 0: On-Disk Structs (`ondisk/`)

Byte-level struct definitions parsed from raw `&[u8]` slices. No I/O operations. All parsing uses `u16::from_le_bytes`, `u32::from_le_bytes`, etc. Journal structs (jbd2) use big-endian parsing.

**Structs:**

- `Superblock` — 1024 bytes at offset 0x400. All fields including 64-bit extensions, feature flags (incompat, ro_compat, compat), UUID, volume label, creation/mount/write/check timestamps, checksum. Feature flag detection for extents, 64-bit, checksums, inline data, flex_bg, HTree, encryption, etc.
- `GroupDescriptor` — 32-byte variant (32-bit filesystems)
- `GroupDescriptor64` — 64-byte variant (64-bit filesystems, `s_desc_size >= 64`)
- `Inode` — 256+ bytes. All fields: mode, uid, gid, size (lo+hi), timestamps (atime, ctime, mtime, crtime, dtime — each with seconds + nanosecond extra field), links count, blocks count, flags (extents, inline data, encrypt, etc.), `i_block` (60 bytes: extent tree root or legacy block pointers or inline data), extra inode size, checksum (lo+hi), generation number
- `ExtentHeader` — 12 bytes. Magic `0xF30A`, entries count, max, depth, generation
- `ExtentIndex` — 12 bytes. Logical block, physical block hi+lo, unused
- `ExtentLeaf` — 12 bytes. Logical block, length (with unwritten flag in MSB), physical block hi+lo
- `DirEntry` — variable-length: inode, rec_len, name_len, file_type, name
- `HTreeRoot` — root of indexed directory: hash version, tree depth, info entries
- `HTreeEntry` — 8 bytes: hash, block
- `JournalSuperblock` — big-endian. Magic `0xC03B3998`, block type, sequence, block size, block count, first transaction block
- `JournalBlockTag` — big-endian. Filesystem block number, flags (escape, same UUID, last, checksum)
- `JournalCommitBlock` — big-endian. Commit timestamp, checksum
- `JournalRevokeBlock` — big-endian. Revoked block numbers
- `XattrHeader` — magic `0xEA020000`, reference count, blocks, hash
- `XattrEntry` — name length, name index (user/system/security/trusted), value offset, value block, value size

All structs implement `TryFrom<&[u8]>` returning a `ParseError` on insufficient or invalid data.

#### Layer 1: Block Device (`block.rs`)

Wraps a `Read+Seek` source and provides block-level access.

```rust
pub struct BlockReader<R: Read + Seek> {
    source: R,
    block_size: u32,         // from superblock (1024, 2048, or 4096)
    blocks_count: u64,       // total blocks
    groups_count: u32,       // total block groups
    superblock: Superblock,  // cached
    group_descs: Vec<GroupDescriptor64>, // cached, normalized to 64-bit
}
```

Methods:
- `BlockReader::open(source: R) -> Result<Self>` — read superblock at offset 1024, validate magic `0xEF53`, parse group descriptors
- `read_block(&mut self, block_num: u64) -> Result<Vec<u8>>`
- `read_blocks(&mut self, start: u64, count: u64) -> Result<Vec<u8>>`
- `read_bytes(&mut self, offset: u64, len: usize) -> Result<Vec<u8>>`
- `superblock(&self) -> &Superblock`
- `group_descriptor(&self, group: u32) -> &GroupDescriptor64`
- `inode_bitmap_block(&self, group: u32) -> u64`
- `block_bitmap_block(&self, group: u32) -> u64`
- `inode_table_block(&self, group: u32) -> u64`

#### Layer 2: Inode Operations (`inode.rs`)

Reads inodes from the inode table and maps their data blocks.

Methods:
- `read_inode(&mut self, ino: u64) -> Result<Inode>` — calculate group and offset, read from inode table
- `inode_block_map(&mut self, ino: u64) -> Result<Vec<BlockMapping>>` — follow extent tree (or legacy indirect blocks) to produce `Vec<(logical_block, physical_block, length)>`
- `read_inode_data(&mut self, ino: u64) -> Result<Vec<u8>>` — assemble complete file data from block map; handle inline data (from `i_block` + `system.data` xattr)
- `read_inode_data_range(&mut self, ino: u64, offset: u64, len: u64) -> Result<Vec<u8>>` — partial read for FUSE
- `iter_inodes_in_group(&mut self, group: u32) -> Result<Vec<(u64, Inode)>>` — all inodes in a block group
- `iter_all_inodes(&mut self) -> Result<Vec<(u64, Inode)>>` — all inodes on the filesystem
- `is_inode_allocated(&mut self, ino: u64) -> Result<bool>` — check inode bitmap
- `is_block_allocated(&mut self, block: u64) -> Result<bool>` — check block bitmap

`BlockMapping` struct:
```rust
pub struct BlockMapping {
    pub logical_block: u64,
    pub physical_block: u64,
    pub length: u64,        // in blocks
    pub unwritten: bool,    // extent marked unwritten
}
```

#### Layer 3: Directory Operations (`dir.rs`)

Path resolution and directory traversal.

Methods:
- `read_dir(&mut self, ino: u64) -> Result<Vec<DirEntry>>` — parse all entries in a directory inode
- `lookup(&mut self, dir_ino: u64, name: &[u8]) -> Result<Option<u64>>` — find inode by name in directory (linear scan; HTree optimization when available)
- `resolve_path(&mut self, path: &str) -> Result<u64>` — walk from root inode (2), resolving each component; follow symlinks up to depth limit (40)
- `read_link(&mut self, ino: u64) -> Result<Vec<u8>>` — read symlink target (inline if < 60 bytes, otherwise from data blocks)

#### Layer 4: Forensic Operations (`forensic/`)

**`deleted.rs` — Deleted file detection and enumeration:**
- `find_deleted_inodes(&mut self) -> Result<Vec<DeletedInode>>` — scan all inodes for deletion markers: `i_dtime != 0`, `i_links_count == 0` with non-zero `i_mode`, or allocated inode with bitmap showing unallocated
- `DeletedInode` includes: inode number, original mode/type, size, all timestamps including dtime, estimated recoverability (what percentage of data blocks are still unallocated)

**`journal.rs` — jbd2 journal parsing:**
- `parse_journal(&mut self) -> Result<Journal>` — read journal inode (8), parse journal superblock, scan all blocks for descriptor/commit/revoke blocks
- `Journal::transactions(&self) -> &[Transaction]` — all transactions in sequence order
- `Transaction` — sequence number, commit timestamp, list of (filesystem_block, journal_block) mappings, revoke list
- `inode_history(&mut self, ino: u64) -> Result<Vec<InodeVersion>>` — find all journal blocks that contain copies of the inode's metadata block, parse each version, return in chronological order with commit timestamps

**`timeline.rs` — Forensic timeline generation:**
- `generate_timeline(&mut self) -> Result<Vec<TimelineEvent>>` — aggregate all timestamps from: inode mtime/atime/ctime/crtime/dtime, journal commit timestamps, superblock mount/write/check times
- `TimelineEvent` — timestamp (nanosecond precision), event type (created/modified/accessed/changed/deleted/journal_commit/mounted), source inode, path (if resolvable), metadata snapshot

**`recovery.rs` — Deleted file recovery:**
- `recover_file(&mut self, ino: u64) -> Result<RecoveryResult>` — attempt to recover a deleted file's data. Check if extent root in `i_block` is still intact (non-zero). If so, follow extent tree and read data blocks, checking each against block bitmap for overwrite status.
- `RecoveryResult` — recovered bytes, total expected size, percentage recovered, list of overwritten block ranges

**`xattr.rs` — Extended attribute parsing:**
- `read_xattrs(&mut self, ino: u64) -> Result<Vec<Xattr>>` — parse inline xattrs (in inode extra space) and block xattrs (from `i_file_acl` block)
- `Xattr` — namespace (user/system/security/trusted), name, value bytes

**`carving.rs` — Unallocated block access:**
- `unallocated_blocks(&mut self) -> Result<Vec<BlockRange>>` — iterate block bitmaps, yield contiguous unallocated ranges
- `read_unallocated(&mut self, range: &BlockRange) -> Result<Vec<u8>>` — read raw unallocated data for carving tools
- `find_extent_signatures(&mut self) -> Result<Vec<CarvedInode>>` — scan unallocated blocks for `0xF30A` extent magic to find orphaned inodes

#### Layer 5: Public API (`lib.rs`)

```rust
pub struct Ext4Fs<R: Read + Seek> {
    // internal layers
}

impl<R: Read + Seek> Ext4Fs<R> {
    // --- Tier 1: Standard filesystem access ---
    pub fn open(source: R) -> Result<Self>;
    pub fn superblock(&self) -> &Superblock;
    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>>;
    pub fn read_dir(&mut self, path: &str) -> Result<Vec<DirEntry>>;
    pub fn metadata(&mut self, path: &str) -> Result<InodeMetadata>;
    pub fn symlink_target(&mut self, path: &str) -> Result<Vec<u8>>;
    pub fn exists(&mut self, path: &str) -> Result<bool>;

    // --- Tier 2: Forensic access ---
    pub fn inode(&mut self, ino: u64) -> Result<Inode>;
    pub fn all_inodes(&mut self) -> Result<Vec<(u64, Inode)>>;
    pub fn deleted_inodes(&mut self) -> Result<Vec<DeletedInode>>;
    pub fn recover_file(&mut self, ino: u64) -> Result<RecoveryResult>;
    pub fn journal(&mut self) -> Result<Journal>;
    pub fn timeline(&mut self) -> Result<Vec<TimelineEvent>>;
    pub fn xattrs(&mut self, ino: u64) -> Result<Vec<Xattr>>;
    pub fn unallocated_blocks(&mut self) -> Result<Vec<BlockRange>>;
    pub fn read_unallocated(&mut self, range: &BlockRange) -> Result<Vec<u8>>;
    pub fn is_inode_allocated(&mut self, ino: u64) -> Result<bool>;
    pub fn is_block_allocated(&mut self, block: u64) -> Result<bool>;
    pub fn read_block(&mut self, block: u64) -> Result<Vec<u8>>;
}
```

`InodeMetadata` includes: inode number, file type, mode, uid, gid, size, link count, all 5 timestamps (atime, mtime, ctime, crtime, dtime) as `Timestamp` with nanosecond precision, flags, generation, allocation state.

### Checksum Verification

CRC32C verification on all metadata structures: superblock, group descriptors, inodes, directory entries, extent tree nodes, xattr blocks. Each parsed struct carries a `checksum_valid: Option<bool>` field (`None` if filesystem doesn't enable checksums, `Some(true/false)` if it does). Invalid checksums produce warnings, not errors — forensic tools must handle damaged filesystems.

### MCP Server (ext4fs-cli)

#### Tools

| Tool | Parameters | Description |
|------|-----------|-------------|
| `ext4fs_open` | `path` | Open image (auto-detects E01 from extension), return session ID |
| `ext4fs_close` | `session` | Release session |
| `ext4fs_info` | `path` or `session` | Superblock: label, UUID, block/inode counts, features, timestamps, free space |
| `ext4fs_ls` | `path` or `session`, `dir_path`, `recursive` (optional) | Directory listing with full metadata |
| `ext4fs_read` | `path` or `session`, `file_path`, `encoding` (text/base64) | Read file contents |
| `ext4fs_stat` | `path` or `session`, `file_path` | Full inode metadata, xattrs, block map |
| `ext4fs_inode` | `path` or `session`, `inode_num` | Read any inode by number |
| `ext4fs_deleted` | `path` or `session`, `min_size` (optional), `file_type` (optional) | List deleted inodes with recoverability |
| `ext4fs_recover` | `path` or `session`, `inode_num`, `encoding` (base64) | Recover deleted file data |
| `ext4fs_journal` | `path` or `session`, `inode_num` (optional), `limit` (optional) | Journal transactions, optionally filtered to one inode |
| `ext4fs_timeline` | `path` or `session`, `start_time` (optional), `end_time` (optional) | Forensic timeline, optionally time-bounded |
| `ext4fs_search` | `path` or `session`, `name` (glob), `min_size`, `max_size`, `after`, `before` | Search files by criteria |

#### Session Management

The MCP server maintains a `HashMap<String, Ext4Fs<Box<dyn ReadSeek>>>` for active sessions. Session IDs are UUIDs. Sessions are cleaned up on `ext4fs_close` or when the MCP server exits.

Every tool that takes `path` or `session`:
- If `path` provided: open image, execute operation, close. No state retained.
- If `session` provided: look up cached `Ext4Fs`, execute operation. Superblock and group descriptors already parsed.

### FUSE Mount (ext4fs-fuse)

#### Usage

```bash
# Mount raw image
ext4fs-fuse /path/to/image.dd /mnt/evidence

# Mount E01 image
ext4fs-fuse /path/to/image.E01 /mnt/evidence

# Mount with session (enables virtual writes, resume)
ext4fs-fuse /path/to/image.E01 /mnt/evidence --session ./case-001/

# Resume previous session
ext4fs-fuse /path/to/image.E01 /mnt/evidence --session ./case-001/ --resume

# Export session for sharing
ext4fs-fuse --export-session ./case-001/ --output case-001-session.tar.gz

# Import session on another machine
ext4fs-fuse /path/to/image.E01 /mnt/evidence --import-session case-001-session.tar.gz
```

#### Virtual Directory Structure

```
/mnt/evidence/
├── fs/                  # allocated filesystem tree (read from image)
│   ├── etc/
│   ├── home/
│   └── ...
├── .deleted/            # recovered deleted files
│   ├── 12345_passwd         # {inode}_{original_name}
│   └── 67890_document.pdf
├── .journal/            # journal transaction snapshots
│   ├── txn_00042/       # filesystem state at transaction 42
│   └── ...
├── .metadata/           # filesystem metadata as JSON
│   ├── superblock.json
│   ├── timeline.jsonl
│   └── inode/
│       └── 12345.json
├── .unallocated/        # raw unallocated blocks for carving
│   ├── blocks_1000-1500.raw
│   └── ...
├── .tags/               # examiner tags and bookmarks (virtual write)
│   ├── evidence/        # symlinks to tagged files
│   └── tags.json
├── .annotations/        # examiner notes (virtual write)
│   └── annotations.jsonl
├── .exports/            # export manifest and extracted files (virtual write)
│   ├── manifest.json
│   └── files/
├── .carved/             # carving results (virtual write)
└── .session/            # session state
    ├── status.json
    └── resume.json
```

#### Virtual Write / Sidecar Overlay

All virtual writes are stored in a sidecar directory alongside the image:

```
/path/to/case/
├── image.E01                        # original evidence (NEVER modified)
└── image.E01.ext4fs-session/        # sidecar directory
    ├── session.json                 # session metadata: image hash, mount time, examiner
    ├── overlay/                     # copy-on-write overlay data
    ├── tags.jsonl                   # file tags: {inode, path, tag, timestamp, examiner}
    ├── annotations.jsonl            # notes: {inode, path, note, timestamp, examiner}
    ├── exports.jsonl                # export log: {inode, path, dest, hash, timestamp}
    └── carved/                      # saved carving results
```

The FUSE layer intercepts write operations:
- Writes to `.tags/`, `.annotations/`, `.exports/` append to the corresponding JSONL files in the sidecar
- Writes to `.carved/` store extracted data in the sidecar's `carved/` directory
- Writes to `fs/` are rejected (preserving forensic integrity of the allocated tree)
- All sidecar writes are fsync'd immediately for crash safety

**Resume:** On `--resume`, the FUSE layer reads `session.json`, verifies the image hash matches (evidence integrity check), and reloads all tags, annotations, and export state.

**Export/Import:** `--export-session` packages the sidecar into a portable tarball. `--import-session` extracts it and associates with the current image mount. This enables collaboration between examiners.

### Dependencies

#### ext4fs (library)

| Crate | Version | Purpose |
|-------|---------|---------|
| `crc` | 3.x | CRC32C checksum verification |
| `bitflags` | 2.x | Feature flag parsing |

No `chrono` — timestamps stored as raw `(i64 seconds, u32 nanoseconds)` tuples with conversion methods. Keeps the library dependency-light.

#### ext4fs-cli

| Crate | Version | Purpose |
|-------|---------|---------|
| `ext4fs` | path | The library |
| `clap` | 4.x | CLI argument parsing |
| `serde_json` | 1.x | MCP JSON-RPC |
| `serde` | 1.x | Serialization |
| `uuid` | 1.x | Session IDs |
| `ewf` | 0.2 | E01 image support (optional feature) |

#### ext4fs-fuse

| Crate | Version | Purpose |
|-------|---------|---------|
| `ext4fs` | path | The library |
| `fuser` | 0.15 | FUSE filesystem |
| `clap` | 4.x | CLI arguments |
| `serde_json` | 1.x | Session/metadata serialization |
| `serde` | 1.x | Serialization |
| `ewf` | 0.2 | E01 image support (optional feature) |
| `sha2` | 0.10 | Image hash for session integrity verification |
| `flate2` | 1.x | Session export/import compression |
| `tar` | 0.4 | Session export/import archiving |

### Error Handling

A unified `Ext4Error` enum:

```rust
pub enum Ext4Error {
    Io(std::io::Error),
    InvalidMagic { expected: u16, found: u16 },
    InvalidSuperblock(String),
    UnsupportedFeature(String),
    InodeOutOfRange { ino: u64, max: u64 },
    BlockOutOfRange { block: u64, max: u64 },
    CorruptMetadata { structure: &'static str, detail: String },
    ChecksumMismatch { structure: &'static str, expected: u32, computed: u32 },
    PathNotFound(String),
    NotADirectory(String),
    NotASymlink(String),
    SymlinkLoop { path: String, depth: u32 },
    NoJournal,
    JournalCorrupt(String),
    RecoveryFailed { ino: u64, reason: String },
}
```

Checksum mismatches are warnings by default (logged, not returned as errors) since forensic tools must handle damaged filesystems. An `Ext4Fs::strict_checksums(true)` option makes them errors.

### Test Strategy

#### Synthetic Test Images

Small ext4 images created with `mkfs.ext4` and `debugfs`, committed to `tests/data/`:

| Image | Purpose | Features |
|-------|---------|----------|
| `minimal.img` | Basic parsing | Smallest valid ext4, one file, one directory |
| `features.img` | Feature coverage | 64-bit, checksums, extents, inline data, flex_bg |
| `htree.img` | HTree directories | Directory with enough entries to trigger HTree indexing |
| `deleted.img` | Deletion recovery | Files created then deleted with known content |
| `journal.img` | Journal parsing | Known sequence of file operations with journal intact |
| `xattr.img` | Extended attributes | Files with user, security, and system xattrs |
| `symlinks.img` | Symlink handling | Short symlinks (inline), long symlinks (block), chains, loops |
| `large.img` | Large file extents | File spanning multiple extent tree levels |

Creation script: `tests/create-test-images.sh` (requires Linux with `mkfs.ext4`, `debugfs`, `mount` — runs in CI, images committed to repo).

#### Testing Approach

- **Layer 0:** Parse known byte sequences. Test each struct's `TryFrom<&[u8]>` with hand-crafted bytes and with bytes extracted from synthetic images using `debugfs`.
- **Layer 1:** Read blocks from synthetic images. Verify superblock fields match `dumpe2fs` output.
- **Layer 2:** Read specific inodes by number. Verify metadata matches `debugfs stat` output. Verify block maps match `debugfs blocks` output.
- **Layer 3:** List directories, resolve paths. Verify against `ls -la` on mounted image.
- **Layer 4:** Verify deleted inode detection against known deletions. Verify journal transaction parsing. Verify recovery produces correct file contents.
- **Layer 5:** Integration tests using the public API on all synthetic images.
- **Cross-validation:** Compare library output against `debugfs`, `dumpe2fs`, `stat` on natively mounted images.

### Future Work (Not In Scope)

- Partition table parsing (GPT/MBR/APM) — separate crate for the unified mounter
- Common `ForensicFilesystem` trait — extract after ntfs-forensic is built
- `no_std` support — extract `ext4fs-types` if needed
- Write support — forensic tools are read-only by design
- Filesystem repair — not a forensic tool's job
- ext2/ext3 explicit compatibility testing — ext4 parser handles these as subsets, but dedicated testing deferred
