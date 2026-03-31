#![forbid(unsafe_code)]

use crate::error::{Ext4Error, Result};
use crate::inode::InodeReader;
use std::io::{Read, Seek};

/// A contiguous range of blocks.
#[derive(Debug, Clone)]
pub struct BlockRange {
    pub start: u64,
    pub length: u64,
}

/// Result of a deleted file recovery attempt.
#[derive(Debug, Clone)]
pub struct RecoveryResult {
    pub data: Vec<u8>,
    pub expected_size: u64,
    pub recovered_size: u64,
    pub overwritten_ranges: Vec<BlockRange>,
}

impl RecoveryResult {
    pub fn recovery_percentage(&self) -> f64 {
        if self.expected_size == 0 { return 0.0; }
        (self.recovered_size as f64 / self.expected_size as f64) * 100.0
    }
}

/// Attempt to recover a deleted file's data by inode number.
pub fn recover_file<R: Read + Seek>(
    reader: &mut InodeReader<R>,
    ino: u64,
) -> Result<RecoveryResult> {
    let inode = reader.read_inode(ino)?;
    let expected_size = inode.size;

    if expected_size == 0 {
        return Ok(RecoveryResult {
            data: Vec::new(),
            expected_size: 0,
            recovered_size: 0,
            overwritten_ranges: Vec::new(),
        });
    }

    let mappings = match reader.inode_block_map(ino) {
        Ok(m) => m,
        Err(_) => {
            return Err(Ext4Error::RecoveryFailed {
                ino,
                reason: "extent tree root is zeroed (common for small deleted ext4 files)".into(),
            });
        }
    };

    if mappings.is_empty() {
        return Err(Ext4Error::RecoveryFailed {
            ino,
            reason: "no block mappings found".into(),
        });
    }

    let block_size = reader.block_reader().block_size() as u64;
    let mut data = Vec::with_capacity(expected_size as usize);
    let mut overwritten_ranges = Vec::new();

    for mapping in &mappings {
        for i in 0..mapping.length {
            let block = mapping.physical_block + i;
            let is_allocated = reader.is_block_allocated(block).unwrap_or(true);

            if is_allocated {
                overwritten_ranges.push(BlockRange {
                    start: (mapping.logical_block + i) * block_size,
                    length: block_size,
                });
                let remaining = (expected_size as usize).saturating_sub(data.len());
                let fill = remaining.min(block_size as usize);
                data.extend(std::iter::repeat(0u8).take(fill));
            } else {
                match reader.block_reader_mut().read_block(block) {
                    Ok(block_data) => {
                        let remaining = (expected_size as usize).saturating_sub(data.len());
                        let to_copy = remaining.min(block_data.len());
                        data.extend_from_slice(&block_data[..to_copy]);
                    }
                    Err(_) => {
                        let remaining = (expected_size as usize).saturating_sub(data.len());
                        let fill = remaining.min(block_size as usize);
                        data.extend(std::iter::repeat(0u8).take(fill));
                    }
                }
            }
            if data.len() >= expected_size as usize { break; }
        }
        if data.len() >= expected_size as usize { break; }
    }

    data.truncate(expected_size as usize);
    let recovered_size = data.iter().enumerate().filter(|(i, _)| {
        !overwritten_ranges.iter().any(|r| {
            let start = r.start as usize;
            let end = start + r.length as usize;
            *i >= start && *i < end
        })
    }).count() as u64;

    Ok(RecoveryResult {
        data,
        expected_size,
        recovered_size,
        overwritten_ranges,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_result_fields() {
        let result = RecoveryResult {
            data: vec![1, 2, 3],
            expected_size: 100,
            recovered_size: 3,
            overwritten_ranges: vec![BlockRange { start: 10, length: 97 }],
        };
        assert_eq!(result.recovery_percentage(), 3.0);
    }
}
