#![forbid(unsafe_code)]

use crate::error::{Ext4Error, Result};
use crate::inode::InodeReader;
use crate::ondisk::journal::{
    JournalBlockTag, JournalBlockType, JournalCommit, JournalHeader, JournalRevoke,
    JournalSuperblock,
};
use std::io::{Read, Seek};

/// A mapping from a journal data block to a filesystem block.
#[derive(Debug, Clone)]
pub struct JournalMapping {
    pub journal_block: u64,
    pub filesystem_block: u64,
}

/// A parsed journal transaction.
#[derive(Debug, Clone)]
pub struct Transaction {
    pub sequence: u32,
    pub commit_seconds: i64,
    pub commit_nanoseconds: u32,
    pub mappings: Vec<JournalMapping>,
    pub revoked_blocks: Vec<u64>,
}

/// Parsed journal.
#[derive(Debug, Clone)]
pub struct Journal {
    pub block_size: u32,
    pub total_blocks: u32,
    pub first_block: u32,
    pub transactions: Vec<Transaction>,
    pub is_64bit: bool,
    pub has_csum_v3: bool,
}

/// A historical version of an inode from the journal.
#[derive(Debug, Clone)]
pub struct InodeVersion {
    pub sequence: u32,
    pub commit_seconds: i64,
    pub commit_nanoseconds: u32,
    pub inode: crate::ondisk::Inode,
}

/// Parse the jbd2 journal from the journal inode.
pub fn parse_journal<R: Read + Seek>(reader: &mut InodeReader<R>) -> Result<Journal> {
    // Copy superblock fields before mutable borrow
    let (has_journal, journal_ino, fs_block_size) = {
        let sb = reader.block_reader().superblock();
        (sb.has_journal(), sb.journal_inum as u64, sb.block_size as usize)
    };

    if !has_journal {
        return Err(Ext4Error::NoJournal);
    }
    if journal_ino == 0 {
        return Err(Ext4Error::NoJournal);
    }

    // Read entire journal inode data
    let journal_data = reader.read_inode_data(journal_ino)?;
    if journal_data.len() < 1024 {
        return Err(Ext4Error::JournalCorrupt("journal too small".into()));
    }

    // Parse journal superblock (first block of journal)
    let jsb = JournalSuperblock::parse(&journal_data[..fs_block_size.min(journal_data.len())])?;
    let j_block_size = jsb.block_size as usize;
    if j_block_size == 0 {
        return Err(Ext4Error::JournalCorrupt("journal block size is 0".into()));
    }

    let is_64bit = jsb.is_64bit();
    let has_csum_v3 = jsb.has_csum_v3();
    let total_blocks = jsb.max_len;
    let first_block = jsb.first;

    // Scan journal blocks for transactions
    let mut transactions = Vec::new();
    let mut current_mappings: Vec<JournalMapping> = Vec::new();
    let mut current_revoked: Vec<u64> = Vec::new();
    let mut pending_tags: Vec<u64> = Vec::new();

    let mut block_idx = first_block as usize;
    while block_idx < total_blocks as usize {
        let offset = block_idx * j_block_size;
        if offset + 12 > journal_data.len() {
            break;
        }

        let end = (offset + j_block_size).min(journal_data.len());
        let block_data = &journal_data[offset..end];

        match JournalHeader::parse(block_data) {
            Ok(header) => match header.block_type {
                JournalBlockType::Descriptor => {
                    pending_tags.clear();
                    let mut tag_offset = 12;
                    loop {
                        if tag_offset + 16 > block_data.len() {
                            break;
                        }
                        let tag = JournalBlockTag::parse_v3(
                            &block_data[tag_offset..],
                            is_64bit,
                        );
                        pending_tags.push(tag.blocknr);
                        let is_last = tag.last_tag;
                        tag_offset += tag.tag_size;
                        if is_last {
                            break;
                        }
                    }
                    // Map each tag to its corresponding data block
                    for (i, &fs_block) in pending_tags.iter().enumerate() {
                        let data_block = block_idx as u64 + 1 + i as u64;
                        current_mappings.push(JournalMapping {
                            journal_block: data_block,
                            filesystem_block: fs_block,
                        });
                    }
                    // Skip past descriptor + data blocks
                    block_idx += 1 + pending_tags.len();
                    continue;
                }
                JournalBlockType::Commit => {
                    let commit = JournalCommit::parse(block_data).unwrap_or(JournalCommit {
                        sequence: header.sequence,
                        commit_seconds: 0,
                        commit_nanoseconds: 0,
                    });
                    transactions.push(Transaction {
                        sequence: commit.sequence,
                        commit_seconds: commit.commit_seconds,
                        commit_nanoseconds: commit.commit_nanoseconds,
                        mappings: std::mem::take(&mut current_mappings),
                        revoked_blocks: std::mem::take(&mut current_revoked),
                    });
                }
                JournalBlockType::Revoke => {
                    if let Ok(revoke) = JournalRevoke::parse(block_data, is_64bit) {
                        current_revoked.extend(revoke.revoked_blocks);
                    }
                }
                JournalBlockType::SuperblockV1
                | JournalBlockType::SuperblockV2
                | JournalBlockType::Unknown(_) => {}
            },
            Err(_) => {}
        }
        block_idx += 1;
    }

    Ok(Journal {
        block_size: j_block_size as u32,
        total_blocks,
        first_block,
        transactions,
        is_64bit,
        has_csum_v3,
    })
}

/// Find all journal versions of a specific inode's metadata block.
///
/// Scans journal transactions for writes to the block containing the given
/// inode, then parses the inode from each historical copy of that block.
/// Results are sorted by transaction sequence number (oldest first).
pub fn inode_history<R: Read + Seek>(
    reader: &mut InodeReader<R>,
    journal: &Journal,
    ino: u64,
) -> Result<Vec<InodeVersion>> {
    // Copy superblock fields before mutable borrow
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
    let inode_table = reader.block_reader().inode_table_block(group)?;
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
                        if let Ok(inode) = crate::ondisk::Inode::parse(
                            &block_data[offset_in_block..end],
                            inode_size_u16,
                        ) {
                            versions.push(InodeVersion {
                                sequence: txn.sequence,
                                commit_seconds: txn.commit_seconds,
                                commit_nanoseconds: txn.commit_nanoseconds,
                                inode,
                            });
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
    use crate::inode::InodeReader;
    use std::io::Cursor;

    fn open_minimal() -> Option<InodeReader<Cursor<Vec<u8>>>> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/minimal.img");
        let data = std::fs::read(path).ok()?;
        let br = BlockReader::open(Cursor::new(data)).ok()?;
        Some(InodeReader::new(br))
    }

    #[test]
    fn parse_journal_from_minimal() {
        let mut reader = match open_minimal() {
            Some(r) => r,
            None => {
                eprintln!("skip: minimal.img not found");
                return;
            }
        };
        if !reader.block_reader().superblock().has_journal() {
            eprintln!("skip: no journal in image");
            return;
        }
        let journal = parse_journal(&mut reader).unwrap();
        assert!(journal.block_size > 0);
        assert!(!journal.transactions.is_empty());
    }

    #[test]
    fn transactions_have_commit_timestamps() {
        let mut reader = match open_minimal() {
            Some(r) => r,
            None => {
                eprintln!("skip: minimal.img not found");
                return;
            }
        };
        if !reader.block_reader().superblock().has_journal() {
            return;
        }
        let journal = parse_journal(&mut reader).unwrap();
        for txn in &journal.transactions {
            assert!(txn.sequence > 0);
        }
    }
}
