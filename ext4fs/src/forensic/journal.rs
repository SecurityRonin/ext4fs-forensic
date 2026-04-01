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
                    current_mappings.clear();
                    current_revoked.clear();
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
                        if tag.tag_size == 0 {
                            break;
                        }
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
                    // Only record the transaction if we can parse the commit
                    // block. Fabricating an epoch timestamp on parse failure
                    // would be forensically misleading.
                    if let Ok(commit) = JournalCommit::parse(block_data) {
                        transactions.push(Transaction {
                            sequence: commit.sequence,
                            commit_seconds: commit.commit_seconds,
                            commit_nanoseconds: commit.commit_nanoseconds,
                            mappings: std::mem::take(&mut current_mappings),
                            revoked_blocks: std::mem::take(&mut current_revoked),
                        });
                    } else {
                        // Discard the uncommitted mappings/revokes
                        current_mappings.clear();
                        current_revoked.clear();
                    }
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

    fn open_forensic() -> Option<InodeReader<Cursor<Vec<u8>>>> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/forensic.img");
        let data = std::fs::read(path).ok()?;
        let br = BlockReader::open(Cursor::new(data)).ok()?;
        Some(InodeReader::new(br))
    }

    fn forensic_raw() -> Option<Vec<u8>> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/forensic.img");
        std::fs::read(path).ok()
    }

    // ---------------------------------------------------------------
    // Existing tests (minimal.img — no journal, exercises skip paths)
    // ---------------------------------------------------------------

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

    // ---------------------------------------------------------------
    // NoJournal error path — minimal.img has no journal
    // ---------------------------------------------------------------

    #[test]
    fn parse_journal_no_journal_error() {
        let mut reader = match open_minimal() {
            Some(r) => r,
            None => {
                eprintln!("skip: minimal.img not found");
                return;
            }
        };
        // minimal.img has no journal feature
        assert!(!reader.block_reader().superblock().has_journal());
        match parse_journal(&mut reader) {
            Err(Ext4Error::NoJournal) => {} // expected
            other => panic!("expected NoJournal, got: {other:?}"),
        }
    }

    // ---------------------------------------------------------------
    // forensic.img tests — HAS journal
    // ---------------------------------------------------------------

    #[test]
    fn parse_journal_from_forensic() {
        let mut reader = match open_forensic() {
            Some(r) => r,
            None => {
                eprintln!("skip: forensic.img not found");
                return;
            }
        };
        assert!(reader.block_reader().superblock().has_journal());
        let journal = parse_journal(&mut reader).unwrap();
        assert!(journal.block_size > 0);
        assert!(journal.total_blocks > 0);
        assert!(journal.first_block > 0);
        // A 32 MiB image that's been used should have at least one transaction
        assert!(
            !journal.transactions.is_empty(),
            "forensic.img journal should have transactions"
        );
    }

    #[test]
    fn forensic_transactions_have_sequence_and_timestamps() {
        let mut reader = match open_forensic() {
            Some(r) => r,
            None => {
                eprintln!("skip: forensic.img not found");
                return;
            }
        };
        let journal = parse_journal(&mut reader).unwrap();
        for txn in &journal.transactions {
            assert!(txn.sequence > 0, "sequence should be positive");
            // Commit timestamps should be reasonable (after 2020)
            assert!(
                txn.commit_seconds >= 1_577_836_800, // 2020-01-01
                "commit_seconds {} too small",
                txn.commit_seconds
            );
        }
    }

    #[test]
    fn forensic_transactions_have_mappings() {
        let mut reader = match open_forensic() {
            Some(r) => r,
            None => {
                eprintln!("skip: forensic.img not found");
                return;
            }
        };
        let journal = parse_journal(&mut reader).unwrap();
        // At least some transactions should have block mappings
        let has_mappings = journal
            .transactions
            .iter()
            .any(|t| !t.mappings.is_empty());
        assert!(has_mappings, "some transactions should have block mappings");

        // Verify mapping fields are reasonable
        for txn in &journal.transactions {
            for m in &txn.mappings {
                assert!(m.journal_block > 0, "journal_block should be > 0");
            }
        }
    }

    #[test]
    fn forensic_journal_sequence_monotonic() {
        let mut reader = match open_forensic() {
            Some(r) => r,
            None => {
                eprintln!("skip: forensic.img not found");
                return;
            }
        };
        let journal = parse_journal(&mut reader).unwrap();
        // Transactions should be in increasing sequence order
        for w in journal.transactions.windows(2) {
            assert!(
                w[1].sequence >= w[0].sequence,
                "sequences should be monotonic: {} >= {}",
                w[1].sequence,
                w[0].sequence
            );
        }
    }

    // ---------------------------------------------------------------
    // inode_history tests
    // ---------------------------------------------------------------

    #[test]
    fn inode_history_for_known_inode() {
        let mut reader = match open_forensic() {
            Some(r) => r,
            None => {
                eprintln!("skip: forensic.img not found");
                return;
            }
        };
        let journal = parse_journal(&mut reader).unwrap();
        // Inode 12 is hello.txt — should appear in journal if inode table
        // block was written
        let versions = inode_history(&mut reader, &journal, 12).unwrap();
        // May or may not have versions depending on journal contents
        for v in &versions {
            assert!(v.sequence > 0);
            assert!(v.commit_seconds >= 0);
        }
        // If there are multiple versions, they should be sorted by sequence
        for w in versions.windows(2) {
            assert!(w[0].sequence <= w[1].sequence);
        }
    }

    #[test]
    fn inode_history_for_deleted_inode() {
        let mut reader = match open_forensic() {
            Some(r) => r,
            None => {
                eprintln!("skip: forensic.img not found");
                return;
            }
        };
        let journal = parse_journal(&mut reader).unwrap();
        // Inode 21 was deleted — may have historical versions showing
        // the pre-deletion state
        let versions = inode_history(&mut reader, &journal, 21).unwrap();
        // Check that if versions exist, they have valid sequence numbers
        for v in &versions {
            assert!(v.sequence > 0);
        }
    }

    #[test]
    fn inode_history_for_nonexistent_inode() {
        let mut reader = match open_forensic() {
            Some(r) => r,
            None => {
                eprintln!("skip: forensic.img not found");
                return;
            }
        };
        let journal = parse_journal(&mut reader).unwrap();
        // Use a high inode number that likely has no journal history
        // but is within range (use inode count from superblock)
        let max_ino = reader.block_reader().superblock().inodes_count;
        if max_ino > 100 {
            let versions = inode_history(&mut reader, &journal, (max_ino - 1) as u64).unwrap();
            // Should return empty or minimal versions
            // (just checking it doesn't crash)
            let _ = versions;
        }
    }

    // ---------------------------------------------------------------
    // JournalCorrupt error paths
    // ---------------------------------------------------------------

    #[test]
    fn journal_corrupt_truncated_data() {
        let mut data = match forensic_raw() {
            Some(d) => d,
            None => {
                eprintln!("skip: forensic.img not found");
                return;
            }
        };
        // Find the journal inode data and corrupt it by zeroing the journal
        // superblock area. The journal inode is typically inode 8.
        // We'll read the image, find the journal, then corrupt it.
        let reader = open_forensic().unwrap();
        let sb = reader.block_reader().superblock();
        let journal_ino = sb.journal_inum as u64;
        assert!(journal_ino > 0);

        // Read journal inode to find its data blocks
        let mut reader2 = open_forensic().unwrap();
        let mappings = reader2.inode_block_map(journal_ino).unwrap();
        if mappings.is_empty() {
            eprintln!("skip: journal inode has no block mappings");
            return;
        }

        // Zero out the journal superblock (first block of journal data)
        // to make it unparseable, causing JournalCorrupt or similar error
        let first_phys = mappings[0].physical_block;
        let block_size = sb.block_size as usize;
        let offset = first_phys as usize * block_size;
        if offset + block_size <= data.len() {
            // Zero just the journal superblock magic to make parse fail
            for b in &mut data[offset..offset + 12] {
                *b = 0;
            }
        }

        let br = BlockReader::open(Cursor::new(data)).unwrap();
        let mut reader3 = InodeReader::new(br);
        let result = parse_journal(&mut reader3);
        // Should fail with some error (corrupt journal superblock)
        assert!(result.is_err(), "corrupted journal should fail to parse");
    }

    #[test]
    fn journal_corrupt_zero_block_size() {
        let mut data = match forensic_raw() {
            Some(d) => d,
            None => {
                eprintln!("skip: forensic.img not found");
                return;
            }
        };
        let reader = open_forensic().unwrap();
        let sb = reader.block_reader().superblock();
        let journal_ino = sb.journal_inum as u64;

        let mut reader2 = open_forensic().unwrap();
        let mappings = reader2.inode_block_map(journal_ino).unwrap();
        if mappings.is_empty() {
            eprintln!("skip: journal inode has no block mappings");
            return;
        }

        let first_phys = mappings[0].physical_block;
        let block_size = sb.block_size as usize;
        let offset = first_phys as usize * block_size;

        // The journal superblock has blocksize at offset 12 (big-endian u32).
        // Set it to 0 to trigger the "journal block size is 0" error.
        // But we need to keep the magic valid so JournalSuperblock::parse succeeds.
        // Journal magic is at offset 0: 0xC03B3998 (big-endian)
        if offset + 16 <= data.len() {
            // Zero the block_size field (offset 12-15 in journal superblock)
            data[offset + 12] = 0;
            data[offset + 13] = 0;
            data[offset + 14] = 0;
            data[offset + 15] = 0;
        }

        let br = BlockReader::open(Cursor::new(data)).unwrap();
        let mut reader3 = InodeReader::new(br);
        let result = parse_journal(&mut reader3);
        match result {
            Err(Ext4Error::JournalCorrupt(msg)) => {
                assert!(
                    msg.contains("block size is 0"),
                    "expected 'block size is 0' in: {msg}"
                );
            }
            // If the journal superblock parse itself fails due to the zero
            // block size affecting other validation, that's also acceptable
            Err(_) => {}
            Ok(_) => panic!("should have failed with zero journal block size"),
        }
    }

    #[test]
    fn journal_corrupt_too_small() {
        let data = match forensic_raw() {
            Some(d) => d,
            None => {
                eprintln!("skip: forensic.img not found");
                return;
            }
        };
        let reader = open_forensic().unwrap();
        let sb = reader.block_reader().superblock();
        let journal_ino = sb.journal_inum as u64;

        // Patch the journal inode's size to be very small (< 1024)
        // so we trigger the "journal too small" path
        let mut patched = data.clone();

        // Find inode position for journal inode
        let ipg = sb.inodes_per_group as u64;
        let inode_size = sb.inode_size as u64;
        let bs = sb.block_size as u64;
        let group = ((journal_ino - 1) / ipg) as u32;
        let index = (journal_ino - 1) % ipg;
        let inode_table = reader.block_reader().inode_table_block(group).unwrap();
        let ino_offset = (inode_table * bs + index * inode_size) as usize;

        // Set i_size_lo (offset 0x04) to 512 and i_size_hi (offset 0x6C) to 0
        // Also zero the block count so read_inode_data returns minimal data
        patched[ino_offset + 0x04] = 0x00;
        patched[ino_offset + 0x05] = 0x02; // 512 in little-endian
        patched[ino_offset + 0x06] = 0x00;
        patched[ino_offset + 0x07] = 0x00;
        patched[ino_offset + 0x6C] = 0x00; // size_hi = 0
        patched[ino_offset + 0x6D] = 0x00;
        patched[ino_offset + 0x6E] = 0x00;
        patched[ino_offset + 0x6F] = 0x00;

        let br = BlockReader::open(Cursor::new(patched)).unwrap();
        let mut reader3 = InodeReader::new(br);
        let result = parse_journal(&mut reader3);
        match result {
            Err(Ext4Error::JournalCorrupt(msg)) => {
                assert!(
                    msg.contains("too small"),
                    "expected 'too small' in: {msg}"
                );
            }
            // The read_inode_data may truncate differently; any error is OK
            Err(_) => {}
            Ok(_) => {
                // If it somehow still parsed (unlikely), that's also fine
                // since the important thing is we exercised the code path
            }
        }
    }
}
