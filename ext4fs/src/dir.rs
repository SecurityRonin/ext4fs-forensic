#![forbid(unsafe_code)]
use crate::error::{Ext4Error, Result};
use crate::inode::InodeReader;
use crate::ondisk::{parse_dir_block, DirEntry, FileType};
use std::io::{Read, Seek};

const MAX_SYMLINK_DEPTH: u32 = 40;

pub struct DirReader<R: Read + Seek> {
    inode_reader: InodeReader<R>,
}

impl<R: Read + Seek> DirReader<R> {
    /// Wrap an `InodeReader` to provide directory-level access.
    pub fn new(inode_reader: InodeReader<R>) -> Self {
        Self { inode_reader }
    }

    /// Borrow the underlying `InodeReader`.
    pub fn inode_reader(&self) -> &InodeReader<R> {
        &self.inode_reader
    }

    /// Mutably borrow the underlying `InodeReader`.
    pub fn inode_reader_mut(&mut self) -> &mut InodeReader<R> {
        &mut self.inode_reader
    }

    /// Read all (live) directory entries from inode `dir_ino`.
    ///
    /// Reads the inode's data blocks and calls `parse_dir_block` on each
    /// block-sized chunk, then filters out deleted entries (inode == 0).
    pub fn read_dir(&mut self, dir_ino: u64) -> Result<Vec<DirEntry>> {
        let block_size = self.inode_reader.block_reader().block_size() as usize;
        let data = self.inode_reader.read_inode_data(dir_ino)?;

        let mut entries = Vec::new();
        let mut offset = 0;
        while offset < data.len() {
            let end = (offset + block_size).min(data.len());
            let chunk = &data[offset..end];
            let block_entries = parse_dir_block(chunk);
            for e in block_entries {
                if e.inode != 0 {
                    entries.push(e);
                }
            }
            offset += block_size;
        }
        Ok(entries)
    }

    /// Look up a single name in directory inode `dir_ino`.
    ///
    /// Returns `Ok(Some(ino))` when found, `Ok(None)` when not found.
    pub fn lookup(&mut self, dir_ino: u64, name: &[u8]) -> Result<Option<u64>> {
        let entries = self.read_dir(dir_ino)?;
        for e in entries {
            if e.name.as_slice() == name {
                return Ok(Some(e.inode as u64));
            }
        }
        Ok(None)
    }

    /// Resolve an absolute path to an inode number.
    ///
    /// Always starts at inode 2 (root). Follows symlinks up to
    /// `MAX_SYMLINK_DEPTH` times. Returns `Ext4Error::PathNotFound` when
    /// any component is missing.
    pub fn resolve_path(&mut self, path: &str) -> Result<u64> {
        self.resolve_path_inner(path, 0)
    }

    fn resolve_path_inner(&mut self, path: &str, depth: u32) -> Result<u64> {
        if depth > MAX_SYMLINK_DEPTH {
            return Err(Ext4Error::SymlinkLoop {
                path: path.to_string(),
                depth,
            });
        }

        // All paths are absolute; start from root inode 2.
        let mut cur_ino: u64 = 2;

        let components: Vec<&str> = path
            .trim_start_matches('/')
            .split('/')
            .filter(|c| !c.is_empty())
            .collect();

        for component in components {
            // Resolve next component in cur_ino directory.
            let next = self
                .lookup(cur_ino, component.as_bytes())?
                .ok_or_else(|| Ext4Error::PathNotFound(path.to_string()))?;

            // Check whether the resolved entry is a symlink.
            let inode = self.inode_reader.read_inode(next)?;
            if inode.file_type() == FileType::Symlink {
                let target = self.read_link(next)?;
                let target_str = String::from_utf8_lossy(&target).into_owned();
                if target_str.starts_with('/') {
                    // Absolute symlink — restart from root.
                    cur_ino = self.resolve_path_inner(&target_str, depth + 1)?;
                } else {
                    // Relative symlink — resolve from current directory.
                    // Build a path relative to cur_ino's parent by treating
                    // the symlink target as an absolute path under a synthetic
                    // prefix derived from current directory.
                    cur_ino = self.resolve_relative_link(cur_ino, &target_str, depth + 1)?;
                }
            } else {
                cur_ino = next;
            }
        }

        Ok(cur_ino)
    }

    /// Resolve a relative symlink `target` whose link inode is inside
    /// directory `dir_ino`.
    fn resolve_relative_link(
        &mut self,
        dir_ino: u64,
        target: &str,
        depth: u32,
    ) -> Result<u64> {
        if depth > MAX_SYMLINK_DEPTH {
            return Err(Ext4Error::SymlinkLoop {
                path: target.to_string(),
                depth,
            });
        }

        let mut cur_ino = dir_ino;
        let components: Vec<&str> = target
            .split('/')
            .filter(|c| !c.is_empty())
            .collect();

        for component in components {
            match component {
                "." => {}
                ".." => {
                    if let Some(parent) = self.lookup(cur_ino, b"..")? {
                        cur_ino = parent;
                    }
                }
                name => {
                    let next = self
                        .lookup(cur_ino, name.as_bytes())?
                        .ok_or_else(|| Ext4Error::PathNotFound(target.to_string()))?;

                    let inode = self.inode_reader.read_inode(next)?;
                    if inode.file_type() == FileType::Symlink {
                        let link_target = self.read_link(next)?;
                        let link_str = String::from_utf8_lossy(&link_target).into_owned();
                        if link_str.starts_with('/') {
                            cur_ino = self.resolve_path_inner(&link_str, depth + 1)?;
                        } else {
                            cur_ino =
                                self.resolve_relative_link(cur_ino, &link_str, depth + 1)?;
                        }
                    } else {
                        cur_ino = next;
                    }
                }
            }
        }

        Ok(cur_ino)
    }

    /// Read the target of a symlink inode.
    ///
    /// For short symlinks (size <= 60 and no extents), the path is stored
    /// inline in `i_block`. Otherwise it is read from the data blocks.
    pub fn read_link(&mut self, ino: u64) -> Result<Vec<u8>> {
        let inode = self.inode_reader.read_inode(ino)?;
        if inode.file_type() != FileType::Symlink {
            return Err(Ext4Error::NotASymlink(format!("inode {ino}")));
        }
        // Inline symlink: size <= 60 and not using extents.
        if inode.size <= 60 && !inode.uses_extents() {
            let len = inode.size as usize;
            return Ok(inode.i_block[..len].to_vec());
        }
        // Data-block symlink.
        let data = self.inode_reader.read_inode_data(ino)?;
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::BlockReader;
    use std::io::Cursor;

    fn open_minimal() -> DirReader<Cursor<Vec<u8>>> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/minimal.img");
        let data = std::fs::read(path).expect("minimal.img required");
        let br = BlockReader::open(Cursor::new(data)).unwrap();
        let ir = InodeReader::new(br);
        DirReader::new(ir)
    }

    #[test]
    fn read_root_directory() {
        let mut r = open_minimal();
        let entries = r.read_dir(2).unwrap();
        let names: Vec<String> = entries.iter().map(|e| e.name_str()).collect();
        assert!(names.contains(&".".to_string()));
        assert!(names.contains(&"..".to_string()));
        assert!(names.contains(&"hello.txt".to_string()));
        assert!(names.contains(&"subdir".to_string()));
        assert!(names.contains(&"lost+found".to_string()));
    }

    #[test]
    fn lookup_file_in_root() {
        let mut r = open_minimal();
        let ino = r.lookup(2, b"hello.txt").unwrap();
        assert!(ino.is_some());
        assert!(ino.unwrap() > 0);
    }

    #[test]
    fn lookup_nonexistent() {
        let mut r = open_minimal();
        let ino = r.lookup(2, b"nonexistent.txt").unwrap();
        assert!(ino.is_none());
    }

    #[test]
    fn resolve_path_root() {
        let mut r = open_minimal();
        assert_eq!(r.resolve_path("/").unwrap(), 2);
    }

    #[test]
    fn resolve_path_file() {
        let mut r = open_minimal();
        let ino = r.resolve_path("/hello.txt").unwrap();
        assert!(ino > 0);
    }

    #[test]
    fn resolve_path_nested() {
        let mut r = open_minimal();
        let ino = r.resolve_path("/subdir/nested.txt").unwrap();
        assert!(ino > 0);
    }

    #[test]
    fn resolve_path_not_found() {
        let mut r = open_minimal();
        let err = r.resolve_path("/nonexistent").unwrap_err();
        assert!(matches!(err, Ext4Error::PathNotFound(_)));
    }

    #[test]
    fn read_file_content_via_path() {
        let mut r = open_minimal();
        let ino = r.resolve_path("/hello.txt").unwrap();
        let data = r.inode_reader_mut().read_inode_data(ino).unwrap();
        assert_eq!(data, b"Hello, ext4!");
    }

    fn open_forensic() -> Option<DirReader<Cursor<Vec<u8>>>> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/forensic.img");
        let data = std::fs::read(path).ok()?;
        let br = BlockReader::open(Cursor::new(data)).ok()?;
        let ir = InodeReader::new(br);
        Some(DirReader::new(ir))
    }

    #[test]
    fn read_dir_handles_all_directory_types() {
        let mut r = match open_forensic() {
            Some(r) => r,
            None => {
                eprintln!("skip: forensic.img not found");
                return;
            }
        };
        let all_inodes = r.inode_reader_mut().iter_all_inodes().unwrap();
        let mut dir_count = 0;
        for (ino, inode) in &all_inodes {
            if inode.file_type() == FileType::Directory && inode.mode != 0 {
                let entries = r.read_dir(*ino).unwrap();
                let names: Vec<String> = entries.iter().map(|e| e.name_str()).collect();
                assert!(names.contains(&".".to_string()), "dir ino {} missing '.'", ino);
                assert!(names.contains(&"..".to_string()), "dir ino {} missing '..'", ino);
                dir_count += 1;
            }
        }
        assert!(dir_count > 0, "no directories found");
    }
}
