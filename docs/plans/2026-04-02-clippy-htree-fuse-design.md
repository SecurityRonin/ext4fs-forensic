# Clippy Fixes + HTree/Inline Data + FUSE Mount — Design

## Part 1: Clippy Fixes

13 pre-existing warnings — mechanical fixes, no behavior changes:
- 6x format string inlining (`format!("{}", x)` → `format!("{x}")`)
- 2x `repeat().take()` → `vec![0u8; n]`
- 2x `match` single pattern → `if let`
- 1x unused variable `block_size` → `_block_size`
- 1x `div_ceil` reimplementation → `.div_ceil()`
- 1x unnecessary `mut`

## Part 2: HTree Directories + Inline Data with Xattr Overflow

### HTree (Fallback Approach)
- When `DirReader` encounters a directory with `INDEX` flag, ignore hash tree structure and scan all data blocks linearly
- Detect HTree root block (first block of an HTree directory), skip the HTree header, parse entries from remaining space
- Correct results, just slower than hash-indexed lookup for large directories
- Forensic benefit: linear scan finds deleted entries between live entries

### Inline Data with Xattr Overflow
- Current `read_inode_data()` reads up to 60 bytes from `i_block` for `INLINE_DATA` files
- For files > 60 bytes, overflow stored in `system.data` xattr
- Update `read_inode_data()`: after reading `i_block`, check for `system.data` xattr and append value
- Uses inline xattr reader built in previous session

## Part 3: FUSE Mount (`ext4fs-fuse`)

### Dependencies
| Crate | Version | Purpose |
|-------|---------|---------|
| `ext4fs` | path | The library |
| `fuser` | 0.15 | FUSE filesystem |
| `clap` | 4.x | CLI arguments |
| `serde` | 1.x | Serialization |
| `serde_json` | 1.x | JSON for metadata/session |
| `sha2` | 0.10 | Image hash verification |

### CLI
```bash
ext4fs-fuse mount <image> <mountpoint> [--session <dir>] [--resume]
ext4fs-fuse export-session <session-dir> --output <tarball>
ext4fs-fuse import-session <tarball> --session <dir>
```

### Virtual Directory Layout
```
/mnt/evidence/
├── ro/              # read-only pristine evidence (direct from image)
├── rw/              # union: ro + COW overlay (writable)
├── deleted/         # {inode}_{name} recovered deleted files
├── journal/         # txn_{seq}/ snapshot dirs
├── metadata/        # superblock.json, timeline.jsonl, inode/{ino}.json
├── unallocated/     # blocks_{start}-{end}.raw
└── session/         # status.json, resume.json
```

### FUSE Implementation (`Ext4FuseFs` implementing `fuser::Filesystem`)

**Inode mapping:**
- FUSE inodes are synthetic — root=1, `ro/`=2, `rw/`=3, `deleted/`=4, `journal/`=5, `metadata/`=6, `unallocated/`=7, `session/`=8
- Real ext4 inodes under `ro/` offset by constant (e.g., +1000) to avoid collisions
- `rw/` overlay inodes offset by another constant (e.g., +10_000_000)

**ro/ operations:**
- `lookup`, `getattr`, `readdir`, `read`, `readlink` — delegate to `Ext4Fs` library
- All write ops return `EROFS`

**rw/ operations (COW overlay):**
- Reads: check overlay first, fall back to `ro/`
- Writes: new files stored in `overlay/files/`, metadata tracked in `overlay/metadata.json`
- Modified files: original block ranges copied to overlay on first write (COW), subsequent writes hit overlay only
- Deleted files: whiteout entry in `metadata.json`, hidden in `rw/` but still visible in `ro/`
- All overlay writes fsync'd immediately

**deleted/:**
- On first access, enumerate deleted inodes, attempt recovery, cache results
- Files named `{ino}_{original_name}` (name from journal or `unknown`)

**journal/:**
- Lazy — `readdir` lists transaction sequence numbers
- Opening file under `txn_N/` reconstructs inode state at that transaction

**metadata/:**
- Generated on-the-fly
- `superblock.json` from superblock fields
- `timeline.jsonl` from timeline generator
- `inode/{N}.json` from inode metadata

**unallocated/:**
- Lazy — `readdir` lists block ranges
- `read` calls `read_unallocated()`

### Session / COW Overlay Structure
```
session-dir/
├── session.json          # {image_path, image_sha256, created, examiner}
├── overlay/
│   ├── files/            # written file contents keyed by synthetic inode
│   └── metadata.json     # {created, modified, deleted (whiteouts), dirs}
├── resume.json           # mount state for --resume
└── exports/              # export tarballs
```

### Session Export/Import
- `export-session`: tar.gz the session directory, include `session.json` for verification
- `import-session`: extract tarball, verify `session.json` exists
- On `--resume`: read `session.json`, compute image SHA-256, verify match, reload overlay state
