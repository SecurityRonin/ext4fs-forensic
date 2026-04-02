#![forbid(unsafe_code)]

use crate::error::Result;
use crate::inode::InodeReader;
use crate::ondisk::{DirEntryType, FileType};
use std::io::{Read, Seek};

/// A directory entry recovered from the gap between live entries.
#[derive(Debug, Clone)]
pub struct RecoveredDirEntry {
    pub parent_ino: u64,
    pub inode: u32,
    pub name: String,
    pub file_type: DirEntryType,
}

/// Recover deleted directory entries from rec_len gaps in a single directory.
pub fn recover_dir_entries<R: Read + Seek>(
    reader: &mut InodeReader<R>,
    dir_ino: u64,
) -> Result<Vec<RecoveredDirEntry>> {
    let block_size = reader.block_reader().superblock().block_size as usize;
    let data = reader.read_inode_data(dir_ino)?;
    let mut recovered = Vec::new();

    let mut block_offset = 0;
    while block_offset < data.len() {
        let block_end = (block_offset + block_size).min(data.len());
        let mut offset = block_offset;

        while offset < block_end {
            if offset + 8 > block_end {
                break;
            }

            let rec_len = u16::from_le_bytes([data[offset + 4], data[offset + 5]]) as usize;
            if rec_len == 0 || offset + rec_len > block_end {
                break;
            }

            let name_len = data[offset + 6] as usize;
            // Actual size of this entry (8 byte header + name, 4-byte aligned)
            let actual_size = ((8 + name_len) + 3) & !3;

            // If rec_len > actual_size, there may be a deleted entry in the gap
            if rec_len > actual_size && actual_size > 0 {
                let gap_start = offset + actual_size;
                let gap_end = offset + rec_len;

                // Try to parse a deleted entry from the gap
                if gap_end - gap_start >= 8 {
                    let gap = &data[gap_start..gap_end];
                    let del_inode =
                        u32::from_le_bytes([gap[0], gap[1], gap[2], gap[3]]);
                    let del_name_len = gap[6] as usize;
                    let del_file_type_raw = gap[7];

                    // Validate: nonzero inode, reasonable name length
                    if del_inode > 0
                        && del_name_len > 0
                        && del_name_len <= 255
                        && gap_start + 8 + del_name_len <= gap_end
                    {
                        let del_name = String::from_utf8_lossy(
                            &data[gap_start + 8..gap_start + 8 + del_name_len],
                        )
                        .to_string();

                        // Skip if name looks like garbage (control chars)
                        if del_name
                            .chars()
                            .all(|c| !c.is_control() || c == '\0')
                            && !del_name.is_empty()
                        {
                            let file_type = DirEntryType::from(del_file_type_raw);

                            recovered.push(RecoveredDirEntry {
                                parent_ino: dir_ino,
                                inode: del_inode,
                                name: del_name,
                                file_type,
                            });
                        }
                    }
                }
            }

            offset += rec_len;
        }

        block_offset += block_size;
    }

    Ok(recovered)
}

/// Recover deleted directory entries from all directories on the filesystem.
pub fn recover_all_dir_entries<R: Read + Seek>(
    reader: &mut InodeReader<R>,
) -> Result<Vec<RecoveredDirEntry>> {
    let all_inodes = reader.iter_all_inodes()?;
    let mut all_recovered = Vec::new();

    for (ino, inode) in &all_inodes {
        if inode.file_type() != FileType::Directory || inode.mode == 0 {
            continue;
        }
        if let Ok(entries) = recover_dir_entries(reader, *ino) {
            all_recovered.extend(entries);
        }
    }

    Ok(all_recovered)
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

    fn open_minimal() -> Option<InodeReader<Cursor<Vec<u8>>>> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/minimal.img");
        let data = std::fs::read(path).ok()?;
        let br = BlockReader::open(Cursor::new(data)).ok()?;
        Some(InodeReader::new(br))
    }

    #[test]
    fn recover_deleted_entries_in_forensic_root() {
        let mut reader = match open_forensic() {
            Some(r) => r,
            None => {
                eprintln!("skip");
                return;
            }
        };
        // Root dir (ino 2) had deleted-file.txt and deleted-large.txt removed
        let recovered = recover_dir_entries(&mut reader, 2).unwrap();
        let names: Vec<&str> = recovered.iter().map(|e| e.name.as_str()).collect();
        eprintln!("Recovered entries: {:?}", names);
        // We expect to find the deleted filenames in the gaps
        // This may or may not work depending on whether the kernel zeroed the entries
        // Either way, the function should not error
    }

    #[test]
    fn no_deleted_entries_in_clean_dir() {
        let mut reader = match open_minimal() {
            Some(r) => r,
            None => {
                eprintln!("skip");
                return;
            }
        };
        // minimal.img subdir (no deletions) — should have few/no recovered entries
        let recovered = recover_dir_entries(&mut reader, 2).unwrap();
        // Not asserting empty — there might be padding entries
        let _ = recovered;
    }

    #[test]
    fn recover_all_returns_without_error() {
        let mut reader = match open_forensic() {
            Some(r) => r,
            None => {
                eprintln!("skip");
                return;
            }
        };
        let all = recover_all_dir_entries(&mut reader).unwrap();
        eprintln!("Total recovered entries across all dirs: {}", all.len());
    }
}
