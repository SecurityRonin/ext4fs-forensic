#![forbid(unsafe_code)]

use crate::error::Result;
use crate::inode::InodeReader;
use std::io::{Read, Seek};

/// A search hit: pattern found at a specific location.
#[derive(Debug, Clone)]
pub struct SearchHit {
    /// Physical block number containing the hit.
    pub block: u64,
    /// Byte offset within the block.
    pub offset: usize,
    /// Context bytes around the hit (surrounding data for examiner review).
    pub context: Vec<u8>,
}

/// Which blocks to search.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchScope {
    /// Only allocated blocks.
    Allocated,
    /// Only unallocated blocks.
    Unallocated,
    /// All blocks on the device.
    All,
}

/// Search for a byte pattern across blocks.
///
/// `context_bytes` controls how many bytes before/after the match to include
/// in each `SearchHit.context` (default suggestion: 32).
pub fn search_blocks<R: Read + Seek>(
    reader: &mut InodeReader<R>,
    pattern: &[u8],
    scope: SearchScope,
    context_bytes: usize,
) -> Result<Vec<SearchHit>> {
    if pattern.is_empty() {
        return Ok(Vec::new());
    }

    let sb = reader.block_reader().superblock();
    let blocks_count = sb.blocks_count;
    let mut hits = Vec::new();

    for block_num in 0..blocks_count {
        // Check if we should search this block based on scope
        let allocated = reader.is_block_allocated(block_num).unwrap_or(true);
        match scope {
            SearchScope::Allocated => {
                if !allocated {
                    continue;
                }
            }
            SearchScope::Unallocated => {
                if allocated {
                    continue;
                }
            }
            SearchScope::All => {}
        }

        let data = match reader.block_reader_mut().read_block(block_num) {
            Ok(d) => d,
            Err(_) => continue,
        };

        // Simple byte pattern search within this block
        let mut pos = 0;
        while pos + pattern.len() <= data.len() {
            if &data[pos..pos + pattern.len()] == pattern {
                // Extract context
                let ctx_start = pos.saturating_sub(context_bytes);
                let ctx_end = (pos + pattern.len() + context_bytes).min(data.len());
                let context = data[ctx_start..ctx_end].to_vec();

                hits.push(SearchHit {
                    block: block_num,
                    offset: pos,
                    context,
                });
                pos += pattern.len(); // skip past this match
            } else {
                pos += 1;
            }
        }
    }

    Ok(hits)
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
    fn search_hello_in_allocated() {
        let mut reader = match open_forensic() {
            Some(r) => r,
            None => {
                eprintln!("skip");
                return;
            }
        };
        let hits = search_blocks(&mut reader, b"Hello", SearchScope::Allocated, 16).unwrap();
        assert!(!hits.is_empty(), "should find 'Hello' in allocated blocks");
        for h in &hits {
            assert!(h.context.windows(5).any(|w| w == b"Hello"));
        }
    }

    #[test]
    fn search_nonexistent_pattern() {
        let mut reader = match open_forensic() {
            Some(r) => r,
            None => {
                eprintln!("skip");
                return;
            }
        };
        let hits = search_blocks(
            &mut reader,
            b"ZZZZZ_DEFINITELY_NOT_HERE_12345",
            SearchScope::All,
            16,
        )
        .unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn search_empty_pattern_returns_empty() {
        let mut reader = match open_forensic() {
            Some(r) => r,
            None => {
                eprintln!("skip");
                return;
            }
        };
        let hits = search_blocks(&mut reader, b"", SearchScope::All, 16).unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn search_ext4_magic_in_all() {
        let mut reader = match open_forensic() {
            Some(r) => r,
            None => {
                eprintln!("skip");
                return;
            }
        };
        // Search for the label "forensic-test" which was set during mkfs
        let hits = search_blocks(&mut reader, b"forensic-test", SearchScope::All, 8).unwrap();
        assert!(
            !hits.is_empty(),
            "should find 'forensic-test' label in superblock"
        );
    }

    #[test]
    fn search_unallocated_scope() {
        let mut reader = match open_forensic() {
            Some(r) => r,
            None => {
                eprintln!("skip");
                return;
            }
        };
        // Search for deleted file content in unallocated blocks
        // "recover me" was in deleted-file.txt
        let hits =
            search_blocks(&mut reader, b"recover me", SearchScope::Unallocated, 16).unwrap();
        // May or may not find it depending on whether blocks were zeroed
        let _ = hits; // just verify no error
    }

    #[test]
    fn search_hit_has_valid_context() {
        let mut reader = match open_forensic() {
            Some(r) => r,
            None => {
                eprintln!("skip");
                return;
            }
        };
        let hits = search_blocks(&mut reader, b"Hello", SearchScope::Allocated, 32).unwrap();
        if let Some(hit) = hits.first() {
            assert!(!hit.context.is_empty());
            // Context should be at least pattern length
            assert!(hit.context.len() >= 5);
        }
    }
}
