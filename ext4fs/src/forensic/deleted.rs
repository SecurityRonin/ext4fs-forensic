#![forbid(unsafe_code)]

use crate::error::Result;
use crate::inode::InodeReader;
use crate::ondisk::{FileType, Inode, Timestamp};
use std::io::{Read, Seek};

/// Information about a deleted inode.
#[derive(Debug, Clone)]
pub struct DeletedInode {
    pub ino: u64,
    pub file_type: FileType,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub atime: Timestamp,
    pub mtime: Timestamp,
    pub ctime: Timestamp,
    pub crtime: Timestamp,
    pub dtime: u32,
    /// Estimated recoverability: fraction of data blocks still unallocated (0.0 to 1.0).
    pub recoverability: f64,
}

/// Scan all inodes for deletion markers.
///
/// A deleted inode has: `dtime != 0`, or `links_count == 0` with non-zero mode.
/// Empty inode slots (mode == 0 and dtime == 0) are skipped since they were
/// never allocated rather than deleted.
///
/// For each deleted inode found, the function estimates recoverability by
/// checking what fraction of the file's data blocks are still unallocated
/// in the block bitmap.
pub fn find_deleted_inodes<R: Read + Seek>(
    reader: &mut InodeReader<R>,
) -> Result<Vec<DeletedInode>> {
    let all_inodes = reader.iter_all_inodes()?;
    let mut deleted = Vec::new();

    for (ino, inode) in &all_inodes {
        if !inode.is_deleted() {
            continue;
        }
        // Skip truly empty inodes (mode == 0 and no dtime) — these are
        // unused slots, not deleted files. iter_all_inodes already filters
        // most of these, but be defensive.
        if inode.mode == 0 && inode.dtime == 0 {
            continue;
        }

        // Estimate recoverability by checking if data blocks are still free
        let recoverability = estimate_recoverability(reader, *ino, inode)?;

        deleted.push(DeletedInode {
            ino: *ino,
            file_type: inode.file_type(),
            mode: inode.mode,
            uid: inode.uid,
            gid: inode.gid,
            size: inode.size,
            atime: inode.atime,
            mtime: inode.mtime,
            ctime: inode.ctime,
            crtime: inode.crtime,
            dtime: inode.dtime,
            recoverability,
        });
    }

    Ok(deleted)
}

/// Estimate what fraction of a deleted file's blocks are still unallocated.
///
/// Returns a value between 0.0 (no blocks recoverable) and 1.0 (all blocks
/// still free in the block bitmap). If the inode has no data or the extent
/// tree / indirect block pointers have been zeroed, returns 0.0.
fn estimate_recoverability<R: Read + Seek>(
    reader: &mut InodeReader<R>,
    ino: u64,
    inode: &Inode,
) -> Result<f64> {
    if inode.size == 0 {
        return Ok(0.0);
    }

    // Try to get block mappings. If extent root is zeroed (common for
    // deleted files where the kernel cleared i_block), this will fail
    // and recoverability is 0.
    let mappings = match reader.inode_block_map(ino) {
        Ok(m) => m,
        Err(_) => return Ok(0.0),
    };

    if mappings.is_empty() {
        return Ok(0.0);
    }

    let total_blocks: u64 = mappings.iter().map(|m| m.length).sum();
    if total_blocks == 0 {
        return Ok(0.0);
    }

    let mut free_blocks = 0u64;
    for mapping in &mappings {
        for i in 0..mapping.length {
            let block = mapping.physical_block + i;
            match reader.is_block_allocated(block) {
                Ok(false) => free_blocks += 1,
                _ => {}
            }
        }
    }

    Ok(free_blocks as f64 / total_blocks as f64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::BlockReader;
    use crate::inode::InodeReader;
    use std::io::Cursor;

    fn open_minimal() -> Option<InodeReader<Cursor<Vec<u8>>>> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/minimal.img");
        let data = std::fs::read(path).ok()?;
        let block_reader = BlockReader::open(Cursor::new(data)).ok()?;
        Some(InodeReader::new(block_reader))
    }

    #[test]
    fn no_deleted_inodes_in_fresh_image() {
        let mut reader = match open_minimal() {
            Some(r) => r,
            None => { eprintln!("skip: minimal.img not found"); return; }
        };
        let deleted = find_deleted_inodes(&mut reader).unwrap();
        // A freshly created image should have no deleted inodes
        assert_eq!(deleted.len(), 0);
    }

    #[test]
    fn deleted_inode_detection_logic() {
        // Test the detection logic with a synthetic inode
        use crate::ondisk::Inode;
        let mut buf = vec![0u8; 256];
        buf[0x00] = 0x80; buf[0x01] = 0x81; // regular file, mode 0600
        buf[0x04] = 100; // size = 100
        buf[0x14] = 0x01; // dtime != 0 (low byte)
        buf[0x1A] = 0; // links_count = 0
        let inode = Inode::parse(&buf, 256).unwrap();
        assert!(inode.is_deleted());
        assert_eq!(inode.dtime, 1);
    }
}
