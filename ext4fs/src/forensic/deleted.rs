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

/// Scan all inodes for deletion markers (`dtime != 0`).
///
/// Returns only inodes that were intentionally deleted — the kernel sets
/// `dtime` when a file is removed. Orphan inodes (unlinked but never fully
/// deleted, e.g. from a crash) are **not** included; use [`find_orphan_inodes`]
/// for those.
///
/// For each deleted inode, estimates recoverability by checking what fraction
/// of the file's data blocks are still unallocated in the block bitmap.
pub fn find_deleted_inodes<R: Read + Seek>(
    reader: &mut InodeReader<R>,
) -> Result<Vec<DeletedInode>> {
    let all_inodes = reader.iter_all_inodes()?;
    let mut deleted = Vec::new();

    for (ino, inode) in &all_inodes {
        if !inode.is_deleted() {
            continue;
        }

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

/// Scan all inodes for orphans (`links_count == 0`, `dtime == 0`, `mode != 0`).
///
/// Orphan inodes result from unclean shutdowns: a file was unlinked while
/// still open, or the system crashed before the kernel could set `dtime`.
/// These are forensically distinct from intentionally deleted files.
pub fn find_orphan_inodes<R: Read + Seek>(
    reader: &mut InodeReader<R>,
) -> Result<Vec<DeletedInode>> {
    let all_inodes = reader.iter_all_inodes()?;
    let mut orphans = Vec::new();

    for (ino, inode) in &all_inodes {
        if !inode.is_orphan() {
            continue;
        }

        let recoverability = estimate_recoverability(reader, *ino, inode)?;

        orphans.push(DeletedInode {
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

    Ok(orphans)
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
            if let Ok(false) = reader.is_block_allocated(block) {
                free_blocks += 1;
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
    fn deleted_inode_has_dtime_set() {
        use crate::ondisk::Inode;
        let mut buf = vec![0u8; 256];
        buf[0x00] = 0x80; buf[0x01] = 0x81; // regular file, mode 0600
        buf[0x04] = 100; // size = 100
        buf[0x14] = 0x01; // dtime = 1 (deletion time set)
        buf[0x1A] = 0; // links_count = 0
        let inode = Inode::parse(&buf, 256).unwrap();
        assert!(inode.is_deleted(), "dtime != 0 means deleted");
        assert!(!inode.is_orphan(), "dtime set means not orphan");
        assert_eq!(inode.dtime, 1);
    }

    fn open_forensic() -> Option<InodeReader<Cursor<Vec<u8>>>> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/forensic.img");
        let data = std::fs::read(path).ok()?;
        let block_reader = BlockReader::open(Cursor::new(data)).ok()?;
        Some(InodeReader::new(block_reader))
    }

    #[test]
    fn forensic_image_has_deleted_inodes() {
        let mut reader = match open_forensic() {
            Some(r) => r,
            None => { eprintln!("skip: forensic.img not found"); return; }
        };
        let deleted = find_deleted_inodes(&mut reader).unwrap();
        assert!(deleted.len() >= 2, "expected at least 2 deleted inodes, got {}", deleted.len());
        let inos: Vec<u64> = deleted.iter().map(|d| d.ino).collect();
        assert!(inos.contains(&21), "expected inode 21 in deleted list, got {inos:?}");
        assert!(inos.contains(&22), "expected inode 22 in deleted list, got {inos:?}");
    }

    #[test]
    fn deleted_inode_has_nonzero_dtime() {
        let mut reader = match open_forensic() {
            Some(r) => r,
            None => { eprintln!("skip: forensic.img not found"); return; }
        };
        let deleted = find_deleted_inodes(&mut reader).unwrap();
        assert!(!deleted.is_empty(), "expected deleted inodes");
        for d in &deleted {
            assert!(d.dtime > 0, "inode {} has dtime=0 but should be >0", d.ino);
        }
    }

    #[test]
    fn deleted_inode_recoverability_is_valid() {
        let mut reader = match open_forensic() {
            Some(r) => r,
            None => { eprintln!("skip: forensic.img not found"); return; }
        };
        let deleted = find_deleted_inodes(&mut reader).unwrap();
        assert!(!deleted.is_empty(), "expected deleted inodes");
        for d in &deleted {
            assert!(
                (0.0..=1.0).contains(&d.recoverability),
                "inode {} recoverability {} not in [0.0, 1.0]",
                d.ino, d.recoverability
            );
        }
    }

    #[test]
    fn deleted_inode_21_is_regular_file() {
        let mut reader = match open_forensic() {
            Some(r) => r,
            None => { eprintln!("skip: forensic.img not found"); return; }
        };
        let deleted = find_deleted_inodes(&mut reader).unwrap();
        let ino21 = deleted.iter().find(|d| d.ino == 21)
            .expect("inode 21 should be in deleted list");
        assert_eq!(ino21.file_type, FileType::RegularFile,
            "inode 21 should be RegularFile, got {:?}", ino21.file_type);
    }

    #[test]
    fn find_orphan_inodes_on_forensic_img() {
        let mut reader = match open_forensic() {
            Some(r) => r,
            None => { eprintln!("skip"); return; }
        };
        // Orphans: links_count==0, dtime==0, mode!=0
        // forensic.img may or may not have orphans, but the function should not error
        let orphans = find_orphan_inodes(&mut reader).unwrap();
        // Verify each orphan has the expected properties
        for o in &orphans {
            assert_eq!(o.dtime, 0, "orphan should have dtime=0");
            assert!((0.0..=1.0).contains(&o.recoverability));
        }
    }

    #[test]
    fn orphan_inode_has_no_dtime() {
        // Orphan: links_count == 0, dtime == 0, mode != 0
        // This is what happens during a crash mid-deletion or unlinked-but-open files
        use crate::ondisk::Inode;
        let mut buf = vec![0u8; 256];
        buf[0x00] = 0x80; buf[0x01] = 0x81; // regular file, mode 0600
        buf[0x04] = 100; // size = 100
        // dtime stays 0 (not set)
        buf[0x1A] = 0; // links_count = 0
        let inode = Inode::parse(&buf, 256).unwrap();
        assert!(!inode.is_deleted(), "no dtime means not deleted");
        assert!(inode.is_orphan(), "links_count=0, dtime=0, mode!=0 is orphan");
    }
}
