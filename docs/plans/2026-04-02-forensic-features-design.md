# Six Forensic Features + Evidence View — Design

## Features

### 1. Slack Space Analysis (`forensic/slack.rs`)

Read data beyond file EOF within the last allocated block. Slack space often contains fragments of previously deleted files.

```rust
pub struct SlackSpace {
    pub ino: u64,
    pub file_size: u64,
    pub block_offset: u64,
    pub slack_offset: usize,
    pub data: Vec<u8>,
}

pub fn read_slack_space(reader, ino) -> Result<SlackSpace>
pub fn scan_all_slack(reader) -> Result<Vec<SlackSpace>>
```

### 2. File Hash Computation (`forensic/hash.rs`)

Compute BLAKE3 + SHA-256 + MD5 + SHA-1 for any file by inode. Uses `blazehash = "0.2"` as the single hashing dependency — all four algorithms in one crate via `blazehash::algorithm::hash_bytes()`.

```rust
pub struct FileHash {
    pub ino: u64,
    pub size: u64,
    pub blake3: String,
    pub sha256: String,
    pub md5: String,
    pub sha1: String,
}

pub fn hash_file(reader, ino) -> Result<FileHash>
pub fn hash_all_files(reader) -> Result<Vec<FileHash>>
```

### 3. Deleted Directory Entry Recovery (`forensic/dir_recovery.rs`)

Re-parse directory blocks looking at rec_len gaps between live entries. Deleted entries often retain name and inode number in the padding space.

```rust
pub struct RecoveredDirEntry {
    pub parent_ino: u64,
    pub inode: u32,
    pub name: String,
    pub file_type: DirEntryType,
}

pub fn recover_dir_entries(reader, dir_ino) -> Result<Vec<RecoveredDirEntry>>
pub fn recover_all_dir_entries(reader) -> Result<Vec<RecoveredDirEntry>>
```

### 4. Inode Version History from Journal (`forensic/history.rs`)

Use journal block mappings to find journaled inode table blocks. Parse previous inode states from each journaled copy.

```rust
pub struct InodeVersion {
    pub sequence: u64,
    pub commit_time: u64,
    pub inode: Inode,
}

pub fn inode_history(reader, journal, ino) -> Result<Vec<InodeVersion>>
```

### 5. String/Pattern Search (`forensic/search.rs`)

Scan blocks for byte patterns. Returns block + offset for each hit with surrounding context.

```rust
pub struct SearchHit {
    pub block: u64,
    pub offset: usize,
    pub context: Vec<u8>,
}

pub enum SearchScope { Allocated, Unallocated, All }

pub fn search_blocks(reader, pattern: &[u8], scope: SearchScope) -> Result<Vec<SearchHit>>
```

### 6. Superblock Backup Verification (`forensic/superblock_verify.rs`)

ext4 stores backup superblocks at groups 0, 1, 3^n, 5^n, 7^n. Compare each against primary.

```rust
pub struct SuperblockComparison {
    pub group: u32,
    pub block: u64,
    pub matches_primary: bool,
    pub differences: Vec<String>,
}

pub fn verify_superblock_backups(reader) -> Result<Vec<SuperblockComparison>>
```

### 7. FUSE `evidence/` Filtered View

A virtual directory identical to `rw/` but hiding files found in known-good hash databases.

**Behavior:**
- Only shown when `--filter-db` is provided at mount time
- On first `evidence/` readdir, ext4fs-fuse hashes files to MD5, looks up against databases, hides matches
- MD5 only (universal across NSRL, HashKeeper, custom databases)
- Results cached in `session/filter-cache.json` for `--resume`
- Incremental — only hashes files not yet cached

**Supported database formats:**
- NSRL RDSv3 SQLite (`SELECT md5 FROM FILE WHERE md5 = ?`)
- HashKeeper text (MD5 + filename per line)
- Custom hash list (one MD5 per line)

**CLI:**
```bash
ext4fs-fuse mount image.dd /mnt/evidence \
  --session ./case-001 \
  --filter-db /path/to/nsrl.db \
  --filter-db /path/to/hashkeeper.txt
```

**Dependencies added:**
- ext4fs: `blazehash = "0.2"` (for hash module only)
- ext4fs-fuse: `md-5 = "0.10"` (RustCrypto, MD5 for filter lookups), `rusqlite = "0.31"` (NSRL SQLite)

**Layout:**
```
/mnt/evidence/
├── ro/              # read-only pristine
├── rw/              # writable COW overlay
├── evidence/        # rw/ minus known-good files
├── deleted/
├── journal/
├── metadata/
├── unallocated/
└── session/
```
