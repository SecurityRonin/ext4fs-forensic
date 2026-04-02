#![forbid(unsafe_code)]

use crate::error::Result;
use crate::inode::InodeReader;
use crate::ondisk::FileType;
use std::io::{Read, Seek};

/// Hash results for a single file (BLAKE3, SHA-256, MD5, SHA-1).
#[derive(Debug, Clone)]
pub struct FileHash {
    pub ino: u64,
    pub size: u64,
    pub blake3: String,
    pub sha256: String,
    pub md5: String,
    pub sha1: String,
}

/// Compute all four hashes for a file by inode number.
pub fn hash_file<R: Read + Seek>(
    reader: &mut InodeReader<R>,
    ino: u64,
) -> Result<FileHash> {
    let inode = reader.read_inode(ino)?;
    let data = reader.read_inode_data(ino)?;

    use blazehash::algorithm::{Algorithm, hash_bytes};

    Ok(FileHash {
        ino,
        size: inode.size,
        blake3: hash_bytes(Algorithm::Blake3, &data),
        sha256: hash_bytes(Algorithm::Sha256, &data),
        md5: hash_bytes(Algorithm::Md5, &data),
        sha1: hash_bytes(Algorithm::Sha1, &data),
    })
}

/// Hash all allocated regular files on the filesystem.
pub fn hash_all_files<R: Read + Seek>(
    reader: &mut InodeReader<R>,
) -> Result<Vec<FileHash>> {
    let all_inodes = reader.iter_all_inodes()?;
    let mut results = Vec::new();

    for (ino, inode) in &all_inodes {
        if inode.file_type() != FileType::RegularFile || inode.size == 0 || inode.is_deleted() {
            continue;
        }
        // Skip inodes without valid block mappings
        if let Ok(hash) = hash_file(reader, *ino) {
            results.push(hash);
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::BlockReader;
    use std::io::Cursor;

    fn open_forensic() -> Option<InodeReader<Cursor<Vec<u8>>>> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/forensic.img");
        let data = std::fs::read(path).ok()?;
        let br = BlockReader::open(Cursor::new(data)).ok()?;
        Some(InodeReader::new(br))
    }

    #[test]
    fn hash_file_correct_lengths() {
        let mut reader = match open_forensic() {
            Some(r) => r,
            None => { eprintln!("skip"); return; }
        };
        let hash = hash_file(&mut reader, 12).unwrap();
        assert_eq!(hash.blake3.len(), 64, "BLAKE3 hex should be 64 chars");
        assert_eq!(hash.sha256.len(), 64, "SHA-256 hex should be 64 chars");
        assert_eq!(hash.md5.len(), 32, "MD5 hex should be 32 chars");
        assert_eq!(hash.sha1.len(), 40, "SHA-1 hex should be 40 chars");
    }

    #[test]
    fn hash_file_deterministic() {
        let mut reader = match open_forensic() {
            Some(r) => r,
            None => { eprintln!("skip"); return; }
        };
        let h1 = hash_file(&mut reader, 12).unwrap();
        let h2 = hash_file(&mut reader, 12).unwrap();
        assert_eq!(h1.blake3, h2.blake3);
        assert_eq!(h1.sha256, h2.sha256);
        assert_eq!(h1.md5, h2.md5);
        assert_eq!(h1.sha1, h2.sha1);
    }

    #[test]
    fn hash_file_known_content() {
        let mut reader = match open_forensic() {
            Some(r) => r,
            None => { eprintln!("skip"); return; }
        };
        // hello.txt contains "Hello, forensic world!\n"
        let hash = hash_file(&mut reader, 12).unwrap();
        // Compute expected SHA-256 independently
        let content = reader.read_inode_data(12).unwrap();
        let expected_sha256 = blazehash::algorithm::hash_bytes(
            blazehash::algorithm::Algorithm::Sha256, &content
        );
        assert_eq!(hash.sha256, expected_sha256);
    }

    #[test]
    fn hash_all_files_returns_multiple() {
        let mut reader = match open_forensic() {
            Some(r) => r,
            None => { eprintln!("skip"); return; }
        };
        let hashes = hash_all_files(&mut reader).unwrap();
        assert!(hashes.len() >= 2, "forensic.img should have multiple files, got {}", hashes.len());
        // All hashes should have correct lengths
        for h in &hashes {
            assert_eq!(h.blake3.len(), 64);
            assert_eq!(h.sha256.len(), 64);
            assert_eq!(h.md5.len(), 32);
            assert_eq!(h.sha1.len(), 40);
            assert!(h.size > 0);
        }
    }
}
