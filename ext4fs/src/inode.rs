#![forbid(unsafe_code)]
use crate::block::BlockReader;
use crate::error::{Ext4Error, Result};
use crate::ondisk::{ExtentHeader, ExtentIndex, ExtentLeaf, Inode};
use std::io::{Read, Seek};

// ---------------------------------------------------------------------------
// BlockMapping
// ---------------------------------------------------------------------------

/// A single logical→physical block mapping produced by the extent tree or
/// indirect-block walk.
#[derive(Debug, Clone)]
pub struct BlockMapping {
    pub logical_block: u64,
    pub physical_block: u64,
    pub length: u64,
    pub unwritten: bool,
}

// ---------------------------------------------------------------------------
// InodeReader
// ---------------------------------------------------------------------------

pub struct InodeReader<R: Read + Seek> {
    pub(crate) block_reader: BlockReader<R>,
}

impl<R: Read + Seek> InodeReader<R> {
    /// Wrap a `BlockReader` to provide inode-level access.
    pub fn new(br: BlockReader<R>) -> Self {
        Self { block_reader: br }
    }

    /// Borrow the underlying `BlockReader`.
    pub fn block_reader(&self) -> &BlockReader<R> {
        &self.block_reader
    }

    /// Mutably borrow the underlying `BlockReader`.
    pub fn block_reader_mut(&mut self) -> &mut BlockReader<R> {
        &mut self.block_reader
    }

    // -----------------------------------------------------------------------
    // Inode lookup
    // -----------------------------------------------------------------------

    /// Read and parse inode `ino` (1-based).
    ///
    /// Returns `Ext4Error::InodeOutOfRange` when `ino == 0` or exceeds
    /// the filesystem's inode count.
    pub fn read_inode(&mut self, ino: u64) -> Result<Inode> {
        let sb = self.block_reader.superblock();
        let max = sb.inodes_count as u64;
        if ino == 0 || ino > max {
            return Err(Ext4Error::InodeOutOfRange { ino, max });
        }

        let inodes_per_group = sb.inodes_per_group as u64;
        let inode_size = sb.inode_size as u64;
        let block_size = sb.block_size as u64;

        let group = ((ino - 1) / inodes_per_group) as u32;
        let index = (ino - 1) % inodes_per_group;

        let inode_table = self.block_reader.inode_table_block(group)?;
        let offset = inode_table * block_size + index * inode_size;

        let buf = self.block_reader.read_bytes(offset, inode_size as usize)?;
        Inode::parse(&buf, self.block_reader.superblock().inode_size)
    }

    // -----------------------------------------------------------------------
    // Block map / extent tree
    // -----------------------------------------------------------------------

    /// Return the full logical→physical block mapping for inode `ino`.
    pub fn inode_block_map(&mut self, ino: u64) -> Result<Vec<BlockMapping>> {
        let inode = self.read_inode(ino)?;
        if inode.uses_extents() {
            self.walk_extent_tree(&inode.i_block)
        } else {
            self.walk_indirect_blocks(&inode.i_block)
        }
    }

    /// Walk the extent tree rooted at `i_block` (60-byte raw field).
    ///
    /// The first 12 bytes are the `ExtentHeader`; subsequent 12-byte slots
    /// are either `ExtentLeaf` entries (depth == 0) or `ExtentIndex` entries
    /// (depth > 0) whose child blocks must be read and recursed into.
    pub fn walk_extent_tree(&mut self, i_block: &[u8; 60]) -> Result<Vec<BlockMapping>> {
        let mut mappings = Vec::new();
        self.walk_extent_node(i_block.as_slice(), &mut mappings)?;
        Ok(mappings)
    }

    fn walk_extent_node(&mut self, buf: &[u8], out: &mut Vec<BlockMapping>) -> Result<()> {
        let header = ExtentHeader::parse(buf)?;
        let entries = header.entries as usize;

        if header.depth == 0 {
            // Leaf node — entries are ExtentLeaf structs at offsets 12, 24, …
            for i in 0..entries {
                let off = 12 + i * 12;
                if off + 12 > buf.len() {
                    break;
                }
                let leaf = ExtentLeaf::parse(&buf[off..]);
                out.push(BlockMapping {
                    logical_block: leaf.logical_block as u64,
                    physical_block: leaf.physical_block,
                    length: leaf.length as u64,
                    unwritten: leaf.unwritten,
                });
            }
        } else {
            // Internal node — entries are ExtentIndex structs; recurse into children.
            for i in 0..entries {
                let off = 12 + i * 12;
                if off + 12 > buf.len() {
                    break;
                }
                let idx = ExtentIndex::parse(&buf[off..]);
                let child_data = self.block_reader.read_block(idx.child_block)?;
                self.walk_extent_node(&child_data, out)?;
            }
        }
        Ok(())
    }

    /// Walk legacy indirect-block pointers stored in `i_block` (60 bytes).
    ///
    /// Layout (u32 LE pointers):
    ///   - offsets  0..48 (12 direct pointers)
    ///   - offset  48     single-indirect pointer
    ///   - offset  52     double-indirect pointer
    ///   - offset  56     triple-indirect pointer
    pub fn walk_indirect_blocks(&mut self, i_block: &[u8; 60]) -> Result<Vec<BlockMapping>> {
        let block_size = self.block_reader.block_size() as usize;
        let ptrs_per_block = block_size / 4;

        let read_u32 = |buf: &[u8], off: usize| -> u32 {
            u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
        };

        let mut out = Vec::new();
        let mut logical = 0u64;

        // 12 direct pointers
        for i in 0..12usize {
            let ptr = read_u32(i_block, i * 4) as u64;
            if ptr != 0 {
                out.push(BlockMapping {
                    logical_block: logical,
                    physical_block: ptr,
                    length: 1,
                    unwritten: false,
                });
            }
            logical += 1;
        }

        // Single indirect
        let sind = read_u32(i_block, 48) as u64;
        if sind != 0 {
            let blk = self.block_reader.read_block(sind)?;
            for i in 0..ptrs_per_block {
                let ptr = read_u32(&blk, i * 4) as u64;
                if ptr != 0 {
                    out.push(BlockMapping {
                        logical_block: logical,
                        physical_block: ptr,
                        length: 1,
                        unwritten: false,
                    });
                }
                logical += 1;
            }
        } else {
            logical += ptrs_per_block as u64;
        }

        // Double indirect
        let dind = read_u32(i_block, 52) as u64;
        if dind != 0 {
            let l1 = self.block_reader.read_block(dind)?;
            for i in 0..ptrs_per_block {
                let ptr1 = read_u32(&l1, i * 4) as u64;
                if ptr1 != 0 {
                    let l2 = self.block_reader.read_block(ptr1)?;
                    for j in 0..ptrs_per_block {
                        let ptr2 = read_u32(&l2, j * 4) as u64;
                        if ptr2 != 0 {
                            out.push(BlockMapping {
                                logical_block: logical,
                                physical_block: ptr2,
                                length: 1,
                                unwritten: false,
                            });
                        }
                        logical += 1;
                    }
                } else {
                    logical += ptrs_per_block as u64;
                }
            }
        } else {
            logical += (ptrs_per_block * ptrs_per_block) as u64;
        }

        // Triple indirect
        let tind = read_u32(i_block, 56) as u64;
        if tind != 0 {
            let l1 = self.block_reader.read_block(tind)?;
            for i in 0..ptrs_per_block {
                let ptr1 = read_u32(&l1, i * 4) as u64;
                if ptr1 != 0 {
                    let l2 = self.block_reader.read_block(ptr1)?;
                    for j in 0..ptrs_per_block {
                        let ptr2 = read_u32(&l2, j * 4) as u64;
                        if ptr2 != 0 {
                            let l3 = self.block_reader.read_block(ptr2)?;
                            for k in 0..ptrs_per_block {
                                let ptr3 = read_u32(&l3, k * 4) as u64;
                                if ptr3 != 0 {
                                    out.push(BlockMapping {
                                        logical_block: logical,
                                        physical_block: ptr3,
                                        length: 1,
                                        unwritten: false,
                                    });
                                }
                                logical += 1;
                            }
                        } else {
                            logical += ptrs_per_block as u64;
                        }
                    }
                } else {
                    logical += (ptrs_per_block * ptrs_per_block) as u64;
                }
            }
        }

        Ok(out)
    }

    // -----------------------------------------------------------------------
    // Data reading
    // -----------------------------------------------------------------------

    /// Read the entire data of inode `ino`, truncated to `inode.size`.
    ///
    /// For inodes with the `INLINE_DATA` flag the content is the first
    /// `size` bytes of `i_block` (up to 60 bytes), returned directly.
    pub fn read_inode_data(&mut self, ino: u64) -> Result<Vec<u8>> {
        let inode = self.read_inode(ino)?;
        if inode.has_inline_data() {
            let len = (inode.size as usize).min(60);
            return Ok(inode.i_block[..len].to_vec());
        }
        let size = inode.size as usize;
        let block_size = self.block_reader.block_size() as usize;
        let map = if inode.uses_extents() {
            self.walk_extent_tree(&inode.i_block)?
        } else {
            self.walk_indirect_blocks(&inode.i_block)?
        };

        let mut data: Vec<u8> = Vec::with_capacity(size);
        for mapping in &map {
            for blk_offset in 0..mapping.length {
                let phys = mapping.physical_block + blk_offset;
                let blk_data = self.block_reader.read_block(phys)?;
                data.extend_from_slice(&blk_data);
                if data.len() >= size {
                    data.truncate(size);
                    return Ok(data);
                }
            }
        }
        data.truncate(size);
        Ok(data)
    }

    /// Read a byte range `[offset, offset+len)` from inode `ino`'s data.
    ///
    /// This is more efficient than `read_inode_data` for partial reads
    /// (e.g. FUSE `read` calls) because it skips blocks that fall entirely
    /// outside the requested window.
    pub fn read_inode_data_range(&mut self, ino: u64, offset: u64, len: usize) -> Result<Vec<u8>> {
        let inode = self.read_inode(ino)?;
        if inode.has_inline_data() {
            let start = offset as usize;
            let end = (start + len).min(60).min(inode.size as usize);
            if start >= end {
                return Ok(Vec::new());
            }
            return Ok(inode.i_block[start..end].to_vec());
        }

        let file_size = inode.size;
        if offset >= file_size {
            return Ok(Vec::new());
        }
        let want_end = (offset + len as u64).min(file_size);
        let want_len = (want_end - offset) as usize;

        let block_size = self.block_reader.block_size() as u64;
        let map = if inode.uses_extents() {
            self.walk_extent_tree(&inode.i_block)?
        } else {
            self.walk_indirect_blocks(&inode.i_block)?
        };

        let mut out = vec![0u8; want_len];
        let mut written = 0usize;

        for mapping in &map {
            for blk_offset in 0..mapping.length {
                let logical = (mapping.logical_block + blk_offset) * block_size;
                let logical_end = logical + block_size;
                if logical_end <= offset || logical >= want_end {
                    continue;
                }
                let src_start = if logical < offset { (offset - logical) as usize } else { 0 };
                let dst_start = if logical > offset { (logical - offset) as usize } else { 0 };
                let phys = mapping.physical_block + blk_offset;
                let blk_data = self.block_reader.read_block(phys)?;
                let src_end = blk_data.len().min(src_start + (want_len - dst_start));
                let copy_len = src_end - src_start;
                if dst_start + copy_len <= out.len() {
                    out[dst_start..dst_start + copy_len]
                        .copy_from_slice(&blk_data[src_start..src_end]);
                    written += copy_len;
                }
            }
        }
        out.truncate(written.min(want_len));
        Ok(out)
    }

    // -----------------------------------------------------------------------
    // Bitmap operations
    // -----------------------------------------------------------------------

    /// Return `true` if inode `ino` (1-based) is marked allocated in its
    /// group's inode bitmap.
    pub fn is_inode_allocated(&mut self, ino: u64) -> Result<bool> {
        let sb = self.block_reader.superblock();
        let max = sb.inodes_count as u64;
        if ino == 0 || ino > max {
            return Err(Ext4Error::InodeOutOfRange { ino, max });
        }
        let inodes_per_group = sb.inodes_per_group as u64;
        let group = ((ino - 1) / inodes_per_group) as u32;
        let index = ((ino - 1) % inodes_per_group) as usize;

        let bitmap_block = self.block_reader.inode_bitmap_block(group)?;
        let bitmap = self.block_reader.read_block(bitmap_block)?;
        Ok((bitmap[index / 8] >> (index % 8)) & 1 == 1)
    }

    /// Return `true` if block `block` is marked allocated in its group's
    /// block bitmap.
    pub fn is_block_allocated(&mut self, block: u64) -> Result<bool> {
        let sb = self.block_reader.superblock();
        let blocks_per_group = sb.blocks_per_group as u64;
        let group = (block / blocks_per_group) as u32;
        let index = (block % blocks_per_group) as usize;

        let bitmap_block = self.block_reader.block_bitmap_block(group)?;
        let bitmap = self.block_reader.read_block(bitmap_block)?;
        Ok((bitmap[index / 8] >> (index % 8)) & 1 == 1)
    }

    // -----------------------------------------------------------------------
    // Iteration helpers
    // -----------------------------------------------------------------------

    /// Return all valid inodes in `group` as `(ino, Inode)` pairs.
    ///
    /// An entry is skipped when `mode == 0 && dtime == 0` (empty slot).
    pub fn iter_inodes_in_group(&mut self, group: u32) -> Result<Vec<(u64, Inode)>> {
        let sb = self.block_reader.superblock();
        let inodes_per_group = sb.inodes_per_group as u64;
        let inode_size = sb.inode_size as usize;
        let block_size = sb.block_size as u64;
        let first_ino = group as u64 * inodes_per_group + 1;

        let inode_table = self.block_reader.inode_table_block(group)?;
        let table_bytes = inode_size as u64 * inodes_per_group;
        let table_offset = inode_table * block_size;
        let buf = self.block_reader.read_bytes(table_offset, table_bytes as usize)?;

        let stored_inode_size = self.block_reader.superblock().inode_size;
        let mut result = Vec::new();
        for i in 0..inodes_per_group as usize {
            let off = i * inode_size;
            let slice = &buf[off..off + inode_size];
            // Skip empty slots: mode == 0 and dtime == 0
            let mode = u16::from_le_bytes([slice[0], slice[1]]);
            let dtime = u32::from_le_bytes([slice[0x14], slice[0x15], slice[0x16], slice[0x17]]);
            if mode == 0 && dtime == 0 {
                continue;
            }
            match Inode::parse(slice, stored_inode_size) {
                Ok(inode) => result.push((first_ino + i as u64, inode)),
                Err(_) => continue,
            }
        }
        Ok(result)
    }

    /// Return all valid inodes across all block groups.
    pub fn iter_all_inodes(&mut self) -> Result<Vec<(u64, Inode)>> {
        let group_count = self.block_reader.group_count();
        let mut all = Vec::new();
        for g in 0..group_count {
            let inodes = self.iter_inodes_in_group(g)?;
            all.extend(inodes);
        }
        Ok(all)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ondisk::FileType;
    use std::io::Cursor;

    fn open_minimal() -> InodeReader<Cursor<Vec<u8>>> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/minimal.img");
        let data = std::fs::read(path).expect("minimal.img required");
        let br = BlockReader::open(Cursor::new(data)).unwrap();
        InodeReader::new(br)
    }

    #[test]
    fn read_root_inode() {
        let mut r = open_minimal();
        let inode = r.read_inode(2).unwrap();
        assert_eq!(inode.file_type(), FileType::Directory);
        assert!(inode.links_count >= 2);
    }

    #[test]
    fn read_inode_out_of_range() {
        let mut r = open_minimal();
        let err = r.read_inode(0).unwrap_err();
        assert!(matches!(err, Ext4Error::InodeOutOfRange { .. }));
    }

    #[test]
    fn read_file_data() {
        let mut r = open_minimal();
        let data = r.read_inode_data(2).unwrap();
        assert!(!data.is_empty());
    }

    #[test]
    fn inode_block_map_for_root() {
        let mut r = open_minimal();
        let inode = r.read_inode(2).unwrap();
        if inode.uses_extents() {
            let map = r.inode_block_map(2).unwrap();
            assert!(!map.is_empty());
            assert!(map[0].physical_block > 0);
        }
    }

    #[test]
    fn is_inode_allocated() {
        let mut r = open_minimal();
        assert!(r.is_inode_allocated(2).unwrap());
    }
}
