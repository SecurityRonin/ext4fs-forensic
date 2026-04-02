# 4n6mount Extraction — Design

## Goal
Extract the filesystem-agnostic FUSE layer from ext4fs-fuse into a universal `~/src/4n6mount` crate with a `ForensicFs` trait. ext4fs-fuse becomes a thin wrapper implementing the trait.

## ForensicFs Trait

```rust
pub trait ForensicFs {
    // Core (required)
    fn root_ino(&self) -> u64;
    fn read_dir(&mut self, ino: u64) -> Result<Vec<FsDirEntry>>;
    fn lookup(&mut self, parent_ino: u64, name: &[u8]) -> Result<Option<u64>>;
    fn metadata(&mut self, ino: u64) -> Result<FsMetadata>;
    fn read_file(&mut self, ino: u64) -> Result<Vec<u8>>;
    fn read_file_range(&mut self, ino: u64, offset: u64, len: u64) -> Result<Vec<u8>>;
    fn read_link(&mut self, ino: u64) -> Result<Vec<u8>>;
    
    // Forensic (optional)
    fn deleted_inodes(&mut self) -> Result<Vec<FsDeletedInode>> { Ok(vec![]) }
    fn recover_file(&mut self, ino: u64) -> Result<FsRecoveryResult> { Err(not_supported()) }
    fn timeline(&mut self) -> Result<Vec<FsTimelineEvent>> { Ok(vec![]) }
    fn unallocated_blocks(&mut self) -> Result<Vec<FsBlockRange>> { Ok(vec![]) }
    fn read_unallocated(&mut self, range: &FsBlockRange) -> Result<Vec<u8>> { Err(not_supported()) }
    fn journal_transactions(&mut self) -> Result<Vec<FsTransaction>> { Ok(vec![]) }
    fn superblock_info(&self) -> Result<serde_json::Value> { Ok(serde_json::Value::Null) }
}
```

## Crate Structure

```
~/src/4n6mount/
├── Cargo.toml
└── src/
    ├── lib.rs          # ForensicFs trait + mount() entry point
    ├── types.rs        # FsMetadata, FsDirEntry, FsDeletedInode, etc.
    ├── fusefs.rs       # Generic FUSE impl over dyn ForensicFs
    ├── inode_map.rs    # Namespace mapping (moved from ext4fs-fuse)
    ├── session.rs      # COW overlay + session mgmt (moved)
    └── filter.rs       # NSRL/HashKeeper filtering (moved)

~/src/ext4fs-forensic/ext4fs-fuse/
├── Cargo.toml          # depends on ext4fs + 4n6mount
└── src/
    └── main.rs         # impl ForensicFs for Ext4Fs + CLI (~50-80 lines)
```

## Key Decisions
- 4n6mount is lib + bin (library exports trait, binary mounts with --fs flag)
- Filesystem-agnostic types in 4n6mount::types (not in ext4fs)
- session.rs, inode_map.rs, filter.rs move unchanged
- fusefs.rs changes RefCell<Ext4Fs<File>> to RefCell<Box<dyn ForensicFs>>
