#![forbid(unsafe_code)]

use crate::error::Result;
use crate::inode::InodeReader;
use crate::ondisk::FileType;
use std::io::{Read, Seek};

/// Slack space data from the end of a file's last allocated block.
#[derive(Debug, Clone)]
pub struct SlackSpace {
    pub ino: u64,
    pub file_size: u64,
    /// Physical block number containing the slack.
    pub block: u64,
    /// Byte offset within the block where slack begins.
    pub slack_offset: usize,
    /// The slack bytes (from slack_offset to end of block).
    pub data: Vec<u8>,
}

/// Read slack space for a single file inode.
pub fn read_slack_space<R: Read + Seek>(
    reader: &mut InodeReader<R>,
    ino: u64,
) -> Result<Option<SlackSpace>> {
    let inode = reader.read_inode(ino)?;

    // Only regular files have meaningful slack
    if inode.file_type() != FileType::RegularFile {
        return Ok(None);
    }
    if inode.size == 0 {
        return Ok(None);
    }

    let block_size = reader.block_reader().superblock().block_size as u64;

    // If file size is block-aligned, no slack
    if inode.size % block_size == 0 {
        return Ok(None);
    }

    // Get block mappings
    let mappings = match reader.inode_block_map(ino) {
        Ok(m) => m,
        Err(_) => return Ok(None),
    };

    if mappings.is_empty() {
        return Ok(None);
    }

    // Find the last mapped block
    let last_mapping = &mappings[mappings.len() - 1];
    let last_phys_block = last_mapping.physical_block + last_mapping.length - 1;

    // Read the full last block
    let block_data = reader.block_reader_mut().read_block(last_phys_block)?;

    let slack_offset = (inode.size % block_size) as usize;
    let slack_data = block_data[slack_offset..].to_vec();

    Ok(Some(SlackSpace {
        ino,
        file_size: inode.size,
        block: last_phys_block,
        slack_offset,
        data: slack_data,
    }))
}

/// Scan all allocated regular file inodes for slack space.
pub fn scan_all_slack<R: Read + Seek>(
    reader: &mut InodeReader<R>,
) -> Result<Vec<SlackSpace>> {
    let all_inodes = reader.iter_all_inodes()?;
    let mut results = Vec::new();

    for (ino, inode) in &all_inodes {
        if inode.file_type() != FileType::RegularFile || inode.size == 0 {
            continue;
        }
        if let Ok(Some(slack)) = read_slack_space(reader, *ino) {
            results.push(slack);
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::BlockReader;
    use std::io::Cursor;

    fn open_minimal() -> Option<InodeReader<Cursor<Vec<u8>>>> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/minimal.img");
        let data = std::fs::read(path).ok()?;
        let br = BlockReader::open(Cursor::new(data)).ok()?;
        Some(InodeReader::new(br))
    }

    fn open_forensic() -> Option<InodeReader<Cursor<Vec<u8>>>> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/forensic.img");
        let data = std::fs::read(path).ok()?;
        let br = BlockReader::open(Cursor::new(data)).ok()?;
        Some(InodeReader::new(br))
    }

    #[test]
    fn slack_space_for_small_file() {
        let mut reader = match open_minimal() {
            Some(r) => r,
            None => { eprintln!("skip"); return; }
        };
        // Find hello.txt's inode by looking for a 12-byte regular file
        let all = reader.iter_all_inodes().unwrap();
        let hello_ino = all.iter()
            .find(|(_, inode)| {
                inode.file_type() == crate::ondisk::FileType::RegularFile
                    && inode.size == 12
            })
            .map(|(ino, _)| *ino)
            .expect("minimal.img should have a 12-byte regular file (hello.txt)");

        let slack = read_slack_space(&mut reader, hello_ino).unwrap();
        assert!(slack.is_some(), "small file should have slack");
        let s = slack.unwrap();
        assert_eq!(s.ino, hello_ino);
        assert_eq!(s.file_size, 12);
        let block_size = reader.block_reader().superblock().block_size as usize;
        assert_eq!(s.data.len(), block_size - 12);
        assert_eq!(s.slack_offset, 12);
    }

    #[test]
    fn no_slack_for_zero_size_file() {
        let mut reader = match open_minimal() {
            Some(r) => r,
            None => { eprintln!("skip"); return; }
        };
        // Inode 0 is invalid, should handle gracefully
        let result = read_slack_space(&mut reader, 0);
        assert!(result.is_err() || result.unwrap().is_none());
    }

    #[test]
    fn scan_all_slack_finds_entries() {
        let mut reader = match open_forensic() {
            Some(r) => r,
            None => { eprintln!("skip"); return; }
        };
        let slacks = scan_all_slack(&mut reader).unwrap();
        assert!(!slacks.is_empty(), "forensic.img should have files with slack");
        for s in &slacks {
            assert!(s.data.len() > 0);
            assert!(s.slack_offset > 0);
            let block_size = reader.block_reader().superblock().block_size as usize;
            assert_eq!(s.data.len() + s.slack_offset, block_size);
        }
    }
}
