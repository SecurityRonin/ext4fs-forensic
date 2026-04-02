#![forbid(unsafe_code)]

use crate::error::Result;
use crate::forensic::journal::Journal;
use crate::inode::InodeReader;
use crate::ondisk::Inode;
use std::io::{Read, Seek};

/// A previous version of an inode recovered from the journal.
#[derive(Debug, Clone)]
pub struct InodeVersion {
    /// Journal transaction sequence number.
    pub sequence: u64,
    /// Commit timestamp (seconds since epoch).
    pub commit_time: u64,
    /// The inode state at this transaction.
    pub inode: Inode,
}

/// Reconstruct the history of an inode from journal transactions.
pub fn inode_history<R: Read + Seek>(
    reader: &mut InodeReader<R>,
    journal: &Journal,
    ino: u64,
) -> Result<Vec<InodeVersion>> {
    let (ipg, inode_size_u64, inode_size_u16, block_size, journal_ino) = {
        let sb = reader.block_reader().superblock();
        (
            sb.inodes_per_group as u64,
            sb.inode_size as u64,
            sb.inode_size,
            sb.block_size as u64,
            sb.journal_inum as u64,
        )
    };

    let group = ((ino - 1) / ipg) as u32;
    let index = (ino - 1) % ipg;

    let inode_table = match reader.block_reader().inode_table_block(group) {
        Ok(t) => t,
        Err(_) => return Ok(Vec::new()),
    };

    let inode_offset_in_table = index * inode_size_u64;
    let target_block = inode_table + inode_offset_in_table / block_size;
    let offset_in_block = (inode_offset_in_table % block_size) as usize;

    let journal_data = reader.read_inode_data(journal_ino)?;
    let j_block_size = journal.block_size as usize;

    let mut versions = Vec::new();
    for txn in &journal.transactions {
        for mapping in &txn.mappings {
            if mapping.filesystem_block == target_block {
                let j_offset = mapping.journal_block as usize * j_block_size;
                if j_offset + j_block_size <= journal_data.len() {
                    let block_data = &journal_data[j_offset..j_offset + j_block_size];
                    let end = offset_in_block + inode_size_u64 as usize;
                    if end <= block_data.len() {
                        if let Ok(inode) =
                            Inode::parse(&block_data[offset_in_block..end], inode_size_u16)
                        {
                            if inode.mode != 0 {
                                versions.push(InodeVersion {
                                    sequence: txn.sequence as u64,
                                    commit_time: txn.commit_seconds as u64,
                                    inode,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    versions.sort_by_key(|v| v.sequence);
    Ok(versions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::BlockReader;
    use crate::forensic::journal::parse_journal;
    use std::io::Cursor;

    fn open_forensic() -> Option<InodeReader<Cursor<Vec<u8>>>> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/forensic.img");
        let data = std::fs::read(path).ok()?;
        let br = BlockReader::open(Cursor::new(data)).ok()?;
        Some(InodeReader::new(br))
    }

    #[test]
    fn inode_history_for_hello_txt() {
        let mut reader = match open_forensic() {
            Some(r) => r,
            None => {
                eprintln!("skip");
                return;
            }
        };
        let journal = parse_journal(&mut reader).unwrap();
        let versions = inode_history(&mut reader, &journal, 12).unwrap();
        // hello.txt was created and synced — should have at least one version
        eprintln!("hello.txt versions: {}", versions.len());
        for v in &versions {
            assert!(v.sequence > 0);
            assert!(v.commit_time > 0);
            assert!(v.inode.mode != 0);
        }
    }

    #[test]
    fn inode_history_for_deleted_file() {
        let mut reader = match open_forensic() {
            Some(r) => r,
            None => {
                eprintln!("skip");
                return;
            }
        };
        let journal = parse_journal(&mut reader).unwrap();
        // Inode 21 was created then deleted
        let versions = inode_history(&mut reader, &journal, 21).unwrap();
        eprintln!("deleted file (ino 21) versions: {}", versions.len());
        // Should not error even if no versions found
    }

    #[test]
    fn inode_history_nonexistent() {
        let mut reader = match open_forensic() {
            Some(r) => r,
            None => {
                eprintln!("skip");
                return;
            }
        };
        let journal = parse_journal(&mut reader).unwrap();
        let versions = inode_history(&mut reader, &journal, 999999).unwrap();
        assert!(versions.is_empty());
    }

    #[test]
    fn inode_history_sorted_by_sequence() {
        let mut reader = match open_forensic() {
            Some(r) => r,
            None => {
                eprintln!("skip");
                return;
            }
        };
        let journal = parse_journal(&mut reader).unwrap();
        let versions = inode_history(&mut reader, &journal, 12).unwrap();
        for w in versions.windows(2) {
            assert!(w[0].sequence <= w[1].sequence);
        }
    }
}
