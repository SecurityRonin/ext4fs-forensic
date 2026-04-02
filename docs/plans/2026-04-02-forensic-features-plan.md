# Six Forensic Features + Evidence View Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add six forensic analysis modules to ext4fs (slack space, hashing, deleted dir recovery, inode history, string search, superblock backup verification) plus FUSE evidence/ filtered view.

**Architecture:** Each forensic feature is a new module under `ext4fs/src/forensic/`, exposed via public methods on `Ext4Fs`. The evidence/ view is a new FUSE virtual directory in ext4fs-fuse that filters files by MD5 lookup against known-good databases.

**Tech Stack:** Rust, `blazehash` 0.2 (hashing), `md-5` 0.10 (FUSE MD5 filter), `rusqlite` 0.31 (NSRL SQLite)

---

### Task 1: Slack Space Analysis

**Files:**
- Create: `ext4fs/src/forensic/slack.rs`
- Modify: `ext4fs/src/forensic/mod.rs` (add `pub mod slack;`)
- Modify: `ext4fs/src/lib.rs` (add `slack_space` and `scan_all_slack` to Ext4Fs)

**Implementation:**
- `SlackSpace` struct: ino, file_size, block_offset, slack_offset, data
- `read_slack_space(reader, ino)`: get inode, compute last block from extent map, read full block, extract bytes from `(file_size % block_size)..block_size`
- `scan_all_slack(reader)`: iterate all allocated regular file inodes, call `read_slack_space` on each
- Skip if file_size == 0 or file_size is block-aligned (no slack)

**Tests (TDD):**
1. `read_slack_space_hello_txt` — hello.txt is 12 bytes on a 4096-byte block, slack should be 4084 bytes
2. `read_slack_space_zero_size_file` — should return empty slack
3. `scan_all_slack_finds_entries` — forensic.img should have multiple slack entries
4. Ext4Fs API: `slack_space(ino)` and `scan_all_slack()`

**Commit:** `feat: slack space analysis for forensic file fragment recovery`

---

### Task 2: File Hash Computation

**Files:**
- Create: `ext4fs/src/forensic/hash.rs`
- Modify: `ext4fs/Cargo.toml` (add `blazehash = "0.2"`)
- Modify: `ext4fs/src/forensic/mod.rs` (add `pub mod hash;`)
- Modify: `ext4fs/src/lib.rs` (add `hash_file` and `hash_all_files` to Ext4Fs)

**Implementation:**
- `FileHash` struct: ino, size, blake3, sha256, md5, sha1 (all hex strings)
- `hash_file(reader, ino)`: read inode data, call `blazehash::algorithm::hash_bytes()` for each of 4 algorithms
- `hash_all_files(reader)`: iterate all allocated regular file inodes, hash each
- Use `blazehash::algorithm::Algorithm::{Blake3, Sha256, Md5, Sha1}` and `blazehash::algorithm::hash_bytes(algo, &data)`

**Tests (TDD):**
1. `hash_hello_txt` — hash hello.txt (inode 12), verify all 4 hashes are 
   valid hex strings of correct length (BLAKE3=64, SHA-256=64, MD5=32, SHA-1=40)
2. `hash_hello_txt_sha256_stable` — compute SHA-256 of "Hello, ext4!" independently, compare
3. `hash_all_files_on_minimal` — should return multiple hashes
4. Ext4Fs API: `hash_file(ino)` and `hash_all_files()`

**Commit:** `feat: file hash computation via blazehash (BLAKE3, SHA-256, MD5, SHA-1)`

---

### Task 3: Deleted Directory Entry Recovery

**Files:**
- Create: `ext4fs/src/forensic/dir_recovery.rs`
- Modify: `ext4fs/src/forensic/mod.rs`
- Modify: `ext4fs/src/lib.rs` (add `recover_dir_entries` to Ext4Fs)

**Implementation:**
- `RecoveredDirEntry` struct: parent_ino, inode, name, file_type
- `recover_dir_entries(reader, dir_ino)`: read dir data blocks, for each live entry check if `rec_len` is larger than the entry's actual size. If so, try parsing a deleted entry in the gap. A valid deleted entry has: nonzero inode, reasonable name_len (1-255), name_len + 8 <= gap size.
- `recover_all_dir_entries(reader)`: iterate all directory inodes, call `recover_dir_entries` on each

**Tests (TDD):**
1. `recover_dir_entries_on_forensic_root` — forensic.img root had deleted-file.txt and deleted-large.txt removed, should find their names
2. `recover_dir_entries_on_clean_dir` — minimal.img subdir should have no recovered entries (nothing deleted)
3. Ext4Fs API: `recover_dir_entries(dir_ino)`

**Commit:** `feat: deleted directory entry recovery from rec_len gaps`

---

### Task 4: Inode Version History from Journal

**Files:**
- Create: `ext4fs/src/forensic/history.rs`
- Modify: `ext4fs/src/forensic/mod.rs`
- Modify: `ext4fs/src/lib.rs` (add `inode_history` to Ext4Fs)

**Implementation:**
- `InodeVersion` struct: sequence, commit_time, inode (parsed Inode)
- `inode_history(reader, journal, ino)`: for each transaction in journal.transactions, check if any mapping's filesystem_block falls within the inode table block range for the target inode. If so, read the journaled block data (from journal data area), parse the inode at the correct offset within that block, add to version list.
- Need to compute: which block in the inode table contains `ino`, and at what offset within that block

**Tests (TDD):**
1. `inode_history_hello_txt` — hello.txt (ino 12) on forensic.img should have at least one journal version (it was created, then synced)
2. `inode_history_deleted_file` — ino 21 should show versions before/after deletion
3. `inode_history_nonexistent` — high inode number should return empty vec
4. Ext4Fs API: `inode_history(ino)`

**Commit:** `feat: inode version history reconstruction from journal`

---

### Task 5: String/Pattern Search

**Files:**
- Create: `ext4fs/src/forensic/search.rs`
- Modify: `ext4fs/src/forensic/mod.rs`
- Modify: `ext4fs/src/lib.rs` (add `search_blocks` to Ext4Fs)

**Implementation:**
- `SearchHit` struct: block, offset, context (32 bytes around hit)
- `SearchScope` enum: Allocated, Unallocated, All
- `search_blocks(reader, pattern, scope, context_size)`:
  - Allocated: iterate block bitmap, read each allocated block, search for pattern
  - Unallocated: use existing `unallocated_blocks()`, read each range, search
  - All: iterate all blocks sequentially
- Use simple byte pattern search (no regex — forensic tools need exact byte matching)
- Return block number + byte offset within block for each hit

**Tests (TDD):**
1. `search_hello_in_allocated` — search for b"Hello" in allocated blocks on forensic.img, should find at least one hit
2. `search_deleted_content_in_unallocated` — search for b"recover me" in unallocated blocks (deleted-file.txt content), may find hit if not overwritten
3. `search_nonexistent_pattern` — search for random bytes, should return empty
4. `search_all_scope` — search for b"ext4" in All scope, should find hits (superblock contains "ext4")
5. Ext4Fs API: `search_blocks(pattern, scope)`

**Commit:** `feat: byte pattern search across allocated/unallocated blocks`

---

### Task 6: Superblock Backup Verification

**Files:**
- Create: `ext4fs/src/forensic/superblock_verify.rs`
- Modify: `ext4fs/src/forensic/mod.rs`
- Modify: `ext4fs/src/lib.rs` (add `verify_superblock_backups` to Ext4Fs)

**Implementation:**
- `SuperblockComparison` struct: group, block, matches_primary, differences
- `verify_superblock_backups(reader)`: ext4 stores backup superblocks at block groups that are 0, 1, or powers of 3, 5, 7 (i.e., groups 0, 1, 3, 5, 7, 9, 25, 27, 49, ...). For each backup group:
  1. Compute block offset: `group * blocks_per_group`
  2. Read 1024 bytes at that block offset + 1024 (superblock always at byte 1024 within its block group, except group 0 where it's at absolute byte 1024)
  3. Parse as Superblock
  4. Compare key fields against primary: magic, block_size, blocks_count, inodes_count, uuid, feature flags
  5. Record differences

**Tests (TDD):**
1. `verify_backups_on_forensic_img` — 32MB image with 4096-byte blocks = 1 block group, so only group 0 primary (no backups). Verify function returns empty or single entry.
2. `verify_backups_on_minimal_img` — similar small image check
3. `backup_group_numbers_correct` — unit test the group selection algorithm (0, 1, 3, 5, 7, 9, 25, 27, ...)
4. Ext4Fs API: `verify_superblock_backups()`

**Commit:** `feat: superblock backup verification for tampering detection`

---

### Task 7: FUSE `evidence/` Filtered View

**Files:**
- Modify: `ext4fs-fuse/Cargo.toml` (add `md-5 = "0.10"`, `rusqlite = { version = "0.31", features = ["bundled"] }`)
- Create: `ext4fs-fuse/src/filter.rs`
- Modify: `ext4fs-fuse/src/fusefs.rs` (add evidence/ virtual dir)
- Modify: `ext4fs-fuse/src/main.rs` (add `--filter-db` CLI arg)
- Modify: `ext4fs-fuse/src/inode_map.rs` (add FUSE_EVIDENCE_INO constant + evidence inode namespace)

**Implementation:**

`filter.rs`:
- `FilterDb` trait: `fn contains_md5(&self, md5: &str) -> bool`
- `NsrlDb`: opens NSRL RDSv3 SQLite, queries `SELECT 1 FROM FILE WHERE md5 = ? LIMIT 1`
- `HashKeeperDb`: loads MD5 set from HashKeeper text file into `HashSet<String>`
- `CustomDb`: loads MD5 set from plain text (one hash per line) into `HashSet<String>`
- `FilterCache`: tracks which inodes have been hashed + their status (known/unknown), persists to `session/filter-cache.json`
- `compute_md5(data: &[u8]) -> String`: uses `md5` crate

`fusefs.rs` changes:
- Add `FUSE_EVIDENCE_INO = 9` to inode_map
- Add evidence/ to root readdir (only when filter DBs configured)
- evidence/ lookup/readdir/read: same as rw/ but filter out inodes whose MD5 is in any FilterDb
- On first evidence/ readdir: lazily hash all files, cache results
- Show progress via eprintln during hashing

**Tests (TDD):**
1. `nsrl_db_lookup` — create tiny SQLite with known MD5, verify lookup
2. `hashkeeper_db_lookup` — create HashKeeper format file, verify lookup
3. `custom_db_lookup` — create plain text hash file, verify lookup
4. `filter_cache_roundtrip` — save and reload filter cache
5. `compute_md5_known_value` — MD5 of "Hello, ext4!" matches expected

**Commit:** `feat: FUSE evidence/ filtered view with NSRL/HashKeeper support`

---
