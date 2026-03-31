#![forbid(unsafe_code)]

use crate::error::Result;
use crate::forensic::recovery::BlockRange;
use crate::inode::InodeReader;
use crate::ondisk::extent::EXTENT_MAGIC;
use std::io::{Read, Seek};

/// A potential inode found by carving extent signatures.
#[derive(Debug, Clone)]
pub struct CarvedInode {
    pub block: u64,
    pub offset_in_block: usize,
}

/// Iterate block bitmaps and yield contiguous unallocated block ranges.
pub fn unallocated_blocks<R: Read + Seek>(
    reader: &mut InodeReader<R>,
) -> Result<Vec<BlockRange>> {
    let sb = reader.block_reader().superblock();
    let group_count = reader.block_reader().group_count();
    let bpg = sb.blocks_per_group as u64;
    let blocks_count = sb.blocks_count;
    let mut ranges = Vec::new();

    for g in 0..group_count {
        let bitmap_block = reader.block_reader_mut().block_bitmap_block(g)?;
        let bitmap = reader.block_reader_mut().read_block(bitmap_block)?;
        let base_block = g as u64 * bpg;

        let mut run_start: Option<u64> = None;
        let blocks_in_group = bpg.min(blocks_count.saturating_sub(base_block));

        for bit in 0..blocks_in_group as usize {
            let byte = bit / 8;
            let bit_pos = bit % 8;
            let allocated = if byte < bitmap.len() {
                (bitmap[byte] >> bit_pos) & 1 == 1
            } else {
                false
            };

            if !allocated {
                if run_start.is_none() {
                    run_start = Some(base_block + bit as u64);
                }
            } else if let Some(start) = run_start {
                let current = base_block + bit as u64;
                ranges.push(BlockRange {
                    start,
                    length: current - start,
                });
                run_start = None;
            }
        }
        if let Some(start) = run_start {
            let end = base_block + blocks_in_group;
            ranges.push(BlockRange {
                start,
                length: end - start,
            });
        }
    }

    Ok(ranges)
}

/// Read raw data from a contiguous unallocated range.
pub fn read_unallocated<R: Read + Seek>(
    reader: &mut InodeReader<R>,
    range: &BlockRange,
) -> Result<Vec<u8>> {
    reader.block_reader_mut().read_blocks(range.start, range.length)
}

/// Scan unallocated blocks for extent tree magic (0xF30A) — potential orphaned inodes.
pub fn find_extent_signatures<R: Read + Seek>(
    reader: &mut InodeReader<R>,
    ranges: &[BlockRange],
) -> Result<Vec<CarvedInode>> {
    let mut found = Vec::new();

    for range in ranges {
        for i in 0..range.length {
            let block = range.start + i;
            let data = match reader.block_reader_mut().read_block(block) {
                Ok(d) => d,
                Err(_) => continue,
            };
            let mut offset = 0;
            while offset + 12 <= data.len() {
                if data.len() >= offset + 2 {
                    let magic = u16::from_le_bytes([data[offset], data[offset + 1]]);
                    if magic == EXTENT_MAGIC {
                        found.push(CarvedInode {
                            block,
                            offset_in_block: offset,
                        });
                    }
                }
                offset += 12;
            }
        }
    }

    Ok(found)
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
    fn find_unallocated_blocks() {
        let mut reader = match open_minimal() {
            Some(r) => r,
            None => { eprintln!("skip: minimal.img not found"); return; }
        };
        let ranges = unallocated_blocks(&mut reader).unwrap();
        assert!(!ranges.is_empty());
        for range in &ranges {
            assert!(range.length > 0);
        }
    }
}
