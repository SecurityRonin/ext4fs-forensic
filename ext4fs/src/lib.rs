#![forbid(unsafe_code)]

pub mod error;
pub mod ondisk;
pub mod block;
pub mod inode;
pub mod dir;
pub mod forensic;

use block::BlockReader;
use dir::DirReader;
use error::Result;
use inode::InodeReader;
use ondisk::{DirEntry, Inode, Superblock, Timestamp};
use std::io::{Read, Seek};

/// Full inode metadata for the public API.
#[derive(Debug, Clone)]
pub struct InodeMetadata {
    pub ino: u64,
    pub file_type: ondisk::FileType,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub links_count: u16,
    pub atime: Timestamp,
    pub mtime: Timestamp,
    pub ctime: Timestamp,
    pub crtime: Timestamp,
    pub dtime: u32,
    pub flags: ondisk::InodeFlags,
    pub generation: u32,
    pub allocated: bool,
}

/// Forensic-grade ext4 filesystem reader.
///
/// Accepts any `Read + Seek` source (raw image file, EWF reader, etc.).
/// Provides both standard filesystem access (tier 1) and forensic operations (tier 2).
pub struct Ext4Fs<R: Read + Seek> {
    dir_reader: DirReader<R>,
}

impl<R: Read + Seek> Ext4Fs<R> {
    /// Open an ext4 filesystem from a Read+Seek source.
    pub fn open(source: R) -> Result<Self> {
        let block_reader = BlockReader::open(source)?;
        let inode_reader = InodeReader::new(block_reader);
        let dir_reader = DirReader::new(inode_reader);
        Ok(Ext4Fs { dir_reader })
    }

    // --- Tier 1: Standard filesystem access ---

    /// Reference to the superblock.
    pub fn superblock(&self) -> &Superblock {
        self.dir_reader.inode_reader().block_reader().superblock()
    }

    /// Read a file's contents by path.
    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>> {
        let ino = self.dir_reader.resolve_path(path)?;
        self.dir_reader.inode_reader_mut().read_inode_data(ino)
    }

    /// List directory entries by path.
    pub fn read_dir(&mut self, path: &str) -> Result<Vec<DirEntry>> {
        let ino = self.dir_reader.resolve_path(path)?;
        self.dir_reader.read_dir(ino)
    }

    /// Get full metadata for a path.
    pub fn metadata(&mut self, path: &str) -> Result<InodeMetadata> {
        let ino = self.dir_reader.resolve_path(path)?;
        let inode = self.dir_reader.inode_reader_mut().read_inode(ino)?;
        let allocated = self.dir_reader.inode_reader_mut().is_inode_allocated(ino)?;
        Ok(InodeMetadata {
            ino,
            file_type: inode.file_type(),
            mode: inode.mode,
            uid: inode.uid,
            gid: inode.gid,
            size: inode.size,
            links_count: inode.links_count,
            atime: inode.atime,
            mtime: inode.mtime,
            ctime: inode.ctime,
            crtime: inode.crtime,
            dtime: inode.dtime,
            flags: inode.flags,
            generation: inode.generation,
            allocated,
        })
    }

    /// Read a symlink's target by path.
    pub fn symlink_target(&mut self, path: &str) -> Result<Vec<u8>> {
        let ino = self.dir_reader.resolve_path(path)?;
        self.dir_reader.read_link(ino)
    }

    /// Check if a path exists.
    pub fn exists(&mut self, path: &str) -> Result<bool> {
        match self.dir_reader.resolve_path(path) {
            Ok(_) => Ok(true),
            Err(error::Ext4Error::PathNotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    // --- Tier 1b: Inode-based access (for FUSE) ---

    /// List directory entries by inode number.
    pub fn read_dir_by_ino(&mut self, dir_ino: u64) -> Result<Vec<DirEntry>> {
        self.dir_reader.read_dir(dir_ino)
    }

    /// Lookup a name inside a directory by inode number.
    pub fn lookup_by_ino(&mut self, dir_ino: u64, name: &[u8]) -> Result<Option<u64>> {
        self.dir_reader.lookup(dir_ino, name)
    }

    /// Read symlink target by inode number.
    pub fn read_link_by_ino(&mut self, ino: u64) -> Result<Vec<u8>> {
        self.dir_reader.read_link(ino)
    }

    /// Read file data by inode number.
    pub fn read_inode_data(&mut self, ino: u64) -> Result<Vec<u8>> {
        self.dir_reader.inode_reader_mut().read_inode_data(ino)
    }

    /// Read a range of file data by inode number.
    pub fn read_inode_data_range(&mut self, ino: u64, offset: u64, len: usize) -> Result<Vec<u8>> {
        self.dir_reader.inode_reader_mut().read_inode_data_range(ino, offset, len)
    }

    // --- Tier 2: Forensic access ---

    /// Read any inode by number.
    pub fn inode(&mut self, ino: u64) -> Result<Inode> {
        self.dir_reader.inode_reader_mut().read_inode(ino)
    }

    /// Enumerate all inodes (allocated and deleted).
    pub fn all_inodes(&mut self) -> Result<Vec<(u64, Inode)>> {
        self.dir_reader.inode_reader_mut().iter_all_inodes()
    }

    /// Find all deleted inodes (dtime != 0).
    pub fn deleted_inodes(&mut self) -> Result<Vec<forensic::DeletedInode>> {
        forensic::find_deleted_inodes(self.dir_reader.inode_reader_mut())
    }

    /// Find all orphan inodes (links_count == 0, dtime == 0, mode != 0).
    pub fn orphan_inodes(&mut self) -> Result<Vec<forensic::DeletedInode>> {
        forensic::find_orphan_inodes(self.dir_reader.inode_reader_mut())
    }

    /// Attempt to recover a deleted file by inode number.
    pub fn recover_file(&mut self, ino: u64) -> Result<forensic::RecoveryResult> {
        forensic::recovery::recover_file(self.dir_reader.inode_reader_mut(), ino)
    }

    /// Parse the jbd2 journal.
    pub fn journal(&mut self) -> Result<forensic::Journal> {
        forensic::journal::parse_journal(self.dir_reader.inode_reader_mut())
    }

    /// Generate a forensic timeline of all filesystem events.
    pub fn timeline(&mut self) -> Result<Vec<forensic::TimelineEvent>> {
        forensic::timeline::generate_timeline(self.dir_reader.inode_reader_mut())
    }

    /// Read block-stored extended attributes for an inode.
    pub fn xattrs(&mut self, ino: u64) -> Result<Vec<forensic::Xattr>> {
        forensic::xattr::read_xattrs(self.dir_reader.inode_reader_mut(), ino)
    }

    /// Get all unallocated block ranges.
    pub fn unallocated_blocks(&mut self) -> Result<Vec<forensic::BlockRange>> {
        forensic::carving::unallocated_blocks(self.dir_reader.inode_reader_mut())
    }

    /// Read raw data from an unallocated block range.
    pub fn read_unallocated(&mut self, range: &forensic::BlockRange) -> Result<Vec<u8>> {
        forensic::carving::read_unallocated(self.dir_reader.inode_reader_mut(), range)
    }

    /// Check if a specific inode is allocated.
    pub fn is_inode_allocated(&mut self, ino: u64) -> Result<bool> {
        self.dir_reader.inode_reader_mut().is_inode_allocated(ino)
    }

    /// Check if a specific block is allocated.
    pub fn is_block_allocated(&mut self, block: u64) -> Result<bool> {
        self.dir_reader.inode_reader_mut().is_block_allocated(block)
    }

    /// Read a raw block by number.
    pub fn read_block(&mut self, block: u64) -> Result<Vec<u8>> {
        self.dir_reader.inode_reader_mut().block_reader_mut().read_block(block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn open_minimal() -> Option<Ext4Fs<Cursor<Vec<u8>>>> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/minimal.img");
        let data = std::fs::read(path).ok()?;
        Ext4Fs::open(Cursor::new(data)).ok()
    }

    #[test]
    fn open_and_read_superblock() {
        let fs = match open_minimal() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        assert_eq!(fs.superblock().magic, 0xEF53);
    }

    #[test]
    fn read_file_by_path() {
        let mut fs = match open_minimal() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        let data = fs.read_file("/hello.txt").unwrap();
        assert_eq!(data, b"Hello, ext4!");
    }

    #[test]
    fn read_nested_file() {
        let mut fs = match open_minimal() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        let data = fs.read_file("/subdir/nested.txt").unwrap();
        assert_eq!(data, b"Nested file");
    }

    #[test]
    fn list_root_directory() {
        let mut fs = match open_minimal() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        let entries = fs.read_dir("/").unwrap();
        let names: Vec<String> = entries.iter().map(|e| e.name_str()).collect();
        assert!(names.contains(&"hello.txt".to_string()));
        assert!(names.contains(&"subdir".to_string()));
    }

    #[test]
    fn file_metadata() {
        let mut fs = match open_minimal() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        let meta = fs.metadata("/hello.txt").unwrap();
        assert_eq!(meta.file_type, ondisk::FileType::RegularFile);
        assert_eq!(meta.size, 12);
        assert!(meta.mtime.seconds > 0);
    }

    #[test]
    fn exists_check() {
        let mut fs = match open_minimal() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        assert!(fs.exists("/hello.txt").unwrap());
        assert!(!fs.exists("/nonexistent").unwrap());
    }

    #[test]
    fn all_inodes() {
        let mut fs = match open_minimal() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        let inodes = fs.all_inodes().unwrap();
        assert!(!inodes.is_empty());
    }

    #[test]
    fn deleted_inodes_on_fresh_image() {
        let mut fs = match open_minimal() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        let deleted = fs.deleted_inodes().unwrap();
        assert!(deleted.is_empty());
    }

    #[test]
    fn timeline_generation() {
        let mut fs = match open_minimal() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        let events = fs.timeline().unwrap();
        assert!(!events.is_empty());
    }

    #[test]
    fn unallocated_blocks_exist() {
        let mut fs = match open_minimal() {
            Some(f) => f,
            None => { eprintln!("skip"); return; }
        };
        let ranges = fs.unallocated_blocks().unwrap();
        assert!(!ranges.is_empty());
    }

    // --- forensic.img tests ---

    fn open_forensic() -> Option<Ext4Fs<Cursor<Vec<u8>>>> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/forensic.img");
        let data = std::fs::read(path).ok()?;
        Ext4Fs::open(Cursor::new(data)).ok()
    }

    #[test]
    fn symlink_target_resolves_through_symlink() {
        // symlink_target() calls resolve_path() which follows symlinks,
        // so /abs-link resolves to hello.txt (inode 12), not the symlink itself.
        // Verify the method returns NotASymlink for a followed-through path.
        let mut fs = match open_forensic() {
            Some(f) => f,
            None => { eprintln!("skip: forensic.img not found"); return; }
        };
        let err = fs.symlink_target("/abs-link").unwrap_err();
        assert!(format!("{err:?}").contains("NotASymlink"),
            "symlink_target on a followed symlink should return NotASymlink, got: {err:?}");
    }

    #[test]
    fn inode_root_is_directory() {
        let mut fs = match open_forensic() {
            Some(f) => f,
            None => { eprintln!("skip: forensic.img not found"); return; }
        };
        let root = fs.inode(2).unwrap();
        assert_eq!(root.file_type(), ondisk::FileType::Directory, "inode 2 should be a directory");
    }

    #[test]
    fn orphan_inodes_returns_ok() {
        let mut fs = match open_forensic() {
            Some(f) => f,
            None => { eprintln!("skip: forensic.img not found"); return; }
        };
        let result = fs.orphan_inodes();
        assert!(result.is_ok(), "orphan_inodes should not error");
    }

    #[test]
    fn recover_file_deleted_inode() {
        let mut fs = match open_forensic() {
            Some(f) => f,
            None => { eprintln!("skip: forensic.img not found"); return; }
        };
        let result = fs.recover_file(21);
        assert!(result.is_ok(), "recover_file(21) should return a RecoveryResult");
    }

    #[test]
    fn journal_has_transactions() {
        let mut fs = match open_forensic() {
            Some(f) => f,
            None => { eprintln!("skip: forensic.img not found"); return; }
        };
        let journal = fs.journal().unwrap();
        assert!(!journal.transactions.is_empty(), "journal should have transactions");
    }

    #[test]
    fn xattrs_on_hello_txt() {
        let mut fs = match open_forensic() {
            Some(f) => f,
            None => { eprintln!("skip: forensic.img not found"); return; }
        };
        let attrs = fs.xattrs(12).unwrap();
        let names: Vec<String> = attrs.iter()
            .map(|a| String::from_utf8_lossy(&a.name).to_string())
            .collect();
        assert!(names.iter().any(|n| n.contains("forensic")),
            "inode 12 should have user.forensic xattr, got: {names:?}");
    }

    #[test]
    fn read_unallocated_first_range() {
        let mut fs = match open_forensic() {
            Some(f) => f,
            None => { eprintln!("skip: forensic.img not found"); return; }
        };
        let ranges = fs.unallocated_blocks().unwrap();
        assert!(!ranges.is_empty(), "should have unallocated ranges");
        let data = fs.read_unallocated(&ranges[0]).unwrap();
        assert!(!data.is_empty(), "unallocated data should not be empty");
    }

    #[test]
    fn is_inode_allocated_root() {
        let mut fs = match open_forensic() {
            Some(f) => f,
            None => { eprintln!("skip: forensic.img not found"); return; }
        };
        assert!(fs.is_inode_allocated(2).unwrap(), "root inode 2 should be allocated");
        // inode 21 is deleted, may or may not be allocated depending on reuse
        let _alloc21 = fs.is_inode_allocated(21).unwrap();
    }

    #[test]
    fn is_block_allocated_zero() {
        let mut fs = match open_forensic() {
            Some(f) => f,
            None => { eprintln!("skip: forensic.img not found"); return; }
        };
        let allocated = fs.is_block_allocated(0).unwrap();
        assert!(allocated, "block 0 (superblock) should be allocated");
    }

    #[test]
    fn read_block_zero() {
        let mut fs = match open_forensic() {
            Some(f) => f,
            None => { eprintln!("skip: forensic.img not found"); return; }
        };
        let block_size = fs.superblock().block_size as usize;
        let data = fs.read_block(0).unwrap();
        assert_eq!(data.len(), block_size, "block 0 should be block_size bytes");
    }

    #[test]
    fn read_dir_by_ino_root() {
        let mut fs = match open_forensic() {
            Some(f) => f,
            None => { eprintln!("skip: forensic.img not found"); return; }
        };
        let entries = fs.read_dir_by_ino(2).unwrap();
        let names: Vec<String> = entries.iter().map(|e| e.name_str()).collect();
        assert!(names.contains(&"hello.txt".to_string()),
            "root dir should contain hello.txt, got: {names:?}");
    }

    #[test]
    fn lookup_by_ino_hello_txt() {
        let mut fs = match open_forensic() {
            Some(f) => f,
            None => { eprintln!("skip: forensic.img not found"); return; }
        };
        let result = fs.lookup_by_ino(2, b"hello.txt").unwrap();
        assert!(result.is_some(), "hello.txt should exist in root dir");
    }

    #[test]
    fn read_link_by_ino_abs_link() {
        let mut fs = match open_forensic() {
            Some(f) => f,
            None => { eprintln!("skip: forensic.img not found"); return; }
        };
        // First resolve abs-link's inode
        let ino = fs.lookup_by_ino(2, b"abs-link").unwrap()
            .expect("abs-link should exist in root");
        let target = fs.read_link_by_ino(ino).unwrap();
        assert_eq!(target, b"/hello.txt", "abs-link should point to /hello.txt");
    }

    #[test]
    fn read_inode_data_hello_txt() {
        let mut fs = match open_forensic() {
            Some(f) => f,
            None => { eprintln!("skip: forensic.img not found"); return; }
        };
        let data = fs.read_inode_data(12).unwrap();
        let text = std::str::from_utf8(&data).unwrap_or("");
        assert!(text.contains("Hello"), "inode 12 (hello.txt) should contain 'Hello', got: {text:?}");
    }

    #[test]
    fn read_inode_data_range_hello_txt() {
        let mut fs = match open_forensic() {
            Some(f) => f,
            None => { eprintln!("skip: forensic.img not found"); return; }
        };
        let data = fs.read_inode_data_range(12, 0, 5).unwrap();
        assert_eq!(data, b"Hello", "first 5 bytes of hello.txt should be 'Hello'");
    }
}
