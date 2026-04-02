#![forbid(unsafe_code)]

use crate::error::Result;
use crate::inode::InodeReader;
use crate::ondisk::superblock::Superblock;
use std::io::{Read, Seek};

/// Result of comparing a backup superblock against the primary.
#[derive(Debug, Clone)]
pub struct SuperblockComparison {
    /// Block group number containing the backup.
    pub group: u32,
    /// Block number of the backup superblock.
    pub block: u64,
    /// Whether it matches the primary superblock on key fields.
    pub matches_primary: bool,
    /// List of field names that differ from primary.
    pub differences: Vec<String>,
}

/// Compute which block groups contain superblock backups.
///
/// ext4 stores backups at group 0 (primary), group 1, and groups that are
/// powers of 3, 5, or 7 (e.g., 3, 5, 7, 9, 25, 27, 49, 125, ...).
fn backup_groups(group_count: u32) -> Vec<u32> {
    let mut groups = vec![0, 1]; // primary + first backup
    for base in [3u32, 5, 7] {
        let mut power = base;
        while power < group_count {
            if !groups.contains(&power) {
                groups.push(power);
            }
            power = match power.checked_mul(base) {
                Some(p) => p,
                None => break,
            };
        }
    }
    groups.sort();
    groups.retain(|&g| g < group_count);
    groups
}

/// Compare a backup superblock against the primary on key fields.
fn compare_superblocks(primary: &Superblock, backup: &Superblock) -> Vec<String> {
    let mut diffs = Vec::new();

    if primary.magic != backup.magic { diffs.push("magic".to_string()); }
    if primary.block_size != backup.block_size { diffs.push("block_size".to_string()); }
    if primary.blocks_count != backup.blocks_count { diffs.push("blocks_count".to_string()); }
    if primary.inodes_count != backup.inodes_count { diffs.push("inodes_count".to_string()); }
    if primary.blocks_per_group != backup.blocks_per_group { diffs.push("blocks_per_group".to_string()); }
    if primary.inodes_per_group != backup.inodes_per_group { diffs.push("inodes_per_group".to_string()); }
    if primary.uuid != backup.uuid { diffs.push("uuid".to_string()); }
    if primary.inode_size != backup.inode_size { diffs.push("inode_size".to_string()); }
    if primary.feature_compat != backup.feature_compat { diffs.push("feature_compat".to_string()); }
    if primary.feature_incompat != backup.feature_incompat { diffs.push("feature_incompat".to_string()); }
    if primary.feature_ro_compat != backup.feature_ro_compat { diffs.push("feature_ro_compat".to_string()); }

    diffs
}

/// Verify all superblock backups against the primary.
pub fn verify_superblock_backups<R: Read + Seek>(
    reader: &mut InodeReader<R>,
) -> Result<Vec<SuperblockComparison>> {
    let primary = reader.block_reader().superblock().clone();
    let group_count = reader.block_reader().group_count();
    let block_size = primary.block_size as u64;
    let blocks_per_group = primary.blocks_per_group as u64;

    let groups = backup_groups(group_count);
    let mut results = Vec::new();

    for &group in &groups {
        if group == 0 { continue; } // skip primary

        let block = group as u64 * blocks_per_group;

        // Superblock is at byte offset 1024 within its block group,
        // but for block_size >= 2048, it's at the start of the first block.
        // For block_size == 1024, it's at block offset 1.
        let sb_byte_offset = if block_size >= 2048 {
            block * block_size
        } else {
            block * block_size + 1024
        };

        // Read 1024 bytes for superblock
        let buf = match reader.block_reader_mut().read_bytes(sb_byte_offset, 1024) {
            Ok(b) => b,
            Err(_) => continue,
        };

        let backup_sb = match Superblock::parse(&buf) {
            Ok(sb) => sb,
            Err(_) => {
                results.push(SuperblockComparison {
                    group,
                    block,
                    matches_primary: false,
                    differences: vec!["unparseable".to_string()],
                });
                continue;
            }
        };

        let diffs = compare_superblocks(&primary, &backup_sb);
        results.push(SuperblockComparison {
            group,
            block,
            matches_primary: diffs.is_empty(),
            differences: diffs,
        });
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
    fn backup_groups_small_image() {
        // 1 group — only group 0 (primary)
        let groups = backup_groups(1);
        assert_eq!(groups, vec![0]);
    }

    #[test]
    fn backup_groups_medium_image() {
        // 10 groups — should include 0, 1, 3, 5, 7, 9
        let groups = backup_groups(10);
        assert!(groups.contains(&0));
        assert!(groups.contains(&1));
        assert!(groups.contains(&3));
        assert!(groups.contains(&5));
        assert!(groups.contains(&7));
        assert!(groups.contains(&9)); // 3^2
    }

    #[test]
    fn backup_groups_large_image() {
        let groups = backup_groups(200);
        assert!(groups.contains(&0));
        assert!(groups.contains(&1));
        assert!(groups.contains(&25)); // 5^2
        assert!(groups.contains(&27)); // 3^3
        assert!(groups.contains(&49)); // 7^2
        assert!(groups.contains(&125)); // 5^3
        assert!(!groups.contains(&200)); // beyond count
    }

    #[test]
    fn verify_backups_on_forensic_img() {
        let mut reader = match open_forensic() {
            Some(r) => r,
            None => { eprintln!("skip"); return; }
        };
        let results = verify_superblock_backups(&mut reader).unwrap();
        // forensic.img is 32MB / 4096 = 8192 blocks / 32768 bpg = 1 group
        // So no backups to verify (only primary at group 0)
        // The function should return empty or handle gracefully
        eprintln!("Backup verification results: {} entries", results.len());
        for r in &results {
            eprintln!("  group {}: matches={}, diffs={:?}", r.group, r.matches_primary, r.differences);
        }
    }

    #[test]
    fn compare_identical_superblocks() {
        let mut buf = vec![0u8; 1024];
        buf[0x38..0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
        buf[0x18..0x1C].copy_from_slice(&2u32.to_le_bytes()); // log_block_size
        buf[0x28..0x2C].copy_from_slice(&64u32.to_le_bytes()); // inodes_per_group
        buf[0x04..0x08].copy_from_slice(&100u32.to_le_bytes()); // blocks_count
        buf[0x58..0x5A].copy_from_slice(&256u16.to_le_bytes()); // inode_size
        buf[0x4C..0x50].copy_from_slice(&1u32.to_le_bytes()); // rev_level
        let sb = Superblock::parse(&buf).unwrap();
        let diffs = compare_superblocks(&sb, &sb);
        assert!(diffs.is_empty(), "identical superblocks should have no differences");
    }
}
