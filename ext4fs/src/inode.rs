#![forbid(unsafe_code)]
use crate::block::BlockReader;
use crate::error::{Ext4Error, Result};
use crate::ondisk::xattr::XattrEntry;
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
// Inline data overflow helper
// ---------------------------------------------------------------------------

/// Search the ibody xattr region for a `system.data` xattr (inline data overflow).
///
/// The ibody slice should start immediately after the fixed+extended inode
/// fields, i.e. at offset `0x80 + extra_isize` within the raw inode bytes.
fn find_system_data_xattr(ibody: &[u8]) -> Option<Vec<u8>> {
    let mut offset = 0;
    while offset + 16 <= ibody.len() {
        // A zero first byte (name_len == 0) signals end of entries.
        if ibody[offset] == 0 {
            break;
        }
        match XattrEntry::parse(&ibody[offset..]) {
            Ok(entry) => {
                // system.data: System namespace (index 7) with name "data"
                if entry.name == b"data"
                    && matches!(
                        entry.name_index,
                        crate::ondisk::xattr::XattrNamespace::System
                    )
                {
                    let vs = entry.value_offset as usize;
                    let ve = vs + entry.value_size as usize;
                    if ve <= ibody.len() {
                        return Some(ibody[vs..ve].to_vec());
                    }
                }
                offset += entry.entry_size;
            }
            Err(_) => break,
        }
    }
    None
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
    // Raw inode access
    // -----------------------------------------------------------------------

    /// Read the raw inode bytes for an inode number.
    /// Returns the full inode-sized buffer from the inode table.
    pub fn read_inode_raw(&mut self, ino: u64) -> Result<Vec<u8>> {
        let sb = self.block_reader.superblock();
        let inode_size = sb.inode_size as u64;
        let inodes_per_group = sb.inodes_per_group as u64;
        let max = sb.inodes_count as u64;
        if ino < 1 || ino > max {
            return Err(Ext4Error::InodeOutOfRange { ino, max });
        }
        let group = ((ino - 1) / inodes_per_group) as u32;
        let index = (ino - 1) % inodes_per_group;
        let inode_table_block = self.block_reader.inode_table_block(group)?;
        let block_size = self.block_reader.superblock().block_size as u64;
        let byte_offset = inode_table_block * block_size + index * inode_size;
        self.block_reader.read_bytes(byte_offset, inode_size as usize)
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
            let mut data = inode.i_block[..len].to_vec();
            // For inline data files > 60 bytes, overflow is in system.data xattr
            if inode.size > 60 {
                if let Ok(raw) = self.read_inode_raw(ino) {
                    let inode_size = self.block_reader.superblock().inode_size as usize;
                    let ibody_offset = 0x80 + inode.extra_isize as usize;
                    if inode_size > ibody_offset {
                        let ibody = &raw[ibody_offset..inode_size.min(raw.len())];
                        if let Some(value) = find_system_data_xattr(ibody) {
                            data.extend_from_slice(&value);
                        }
                    }
                }
            }
            data.truncate(inode.size as usize);
            return Ok(data);
        }
        let size = inode.size as usize;
        let _block_size = self.block_reader.block_size() as usize;
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
    use crate::dir::DirReader;
    use crate::ondisk::FileType;
    use std::io::Cursor;

    fn open_minimal() -> InodeReader<Cursor<Vec<u8>>> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/minimal.img");
        let data = std::fs::read(path).expect("minimal.img required");
        let br = BlockReader::open(Cursor::new(data)).unwrap();
        InodeReader::new(br)
    }

    /// Resolve a path on minimal.img and return its inode number.
    fn resolve_minimal(path: &str) -> u64 {
        let img_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/minimal.img");
        let data = std::fs::read(img_path).expect("minimal.img required");
        let br = BlockReader::open(Cursor::new(data)).unwrap();
        let ir = InodeReader::new(br);
        let mut dr = DirReader::new(ir);
        dr.resolve_path(path).unwrap()
    }

    /// Resolve a path on forensic.img and return its inode number.
    fn resolve_forensic(path: &str) -> u64 {
        let img_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/forensic.img");
        let data = std::fs::read(img_path).expect("forensic.img required");
        let br = BlockReader::open(Cursor::new(data)).unwrap();
        let ir = InodeReader::new(br);
        let mut dr = DirReader::new(ir);
        dr.resolve_path(path).unwrap()
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

    #[test]
    fn read_inode_data_extent_path_returns_data() {
        let mut reader = open_minimal();
        // Root inode (2) uses extents — verify the non-inline path works
        let inode = reader.read_inode(2).unwrap();
        assert!(!inode.has_inline_data());
        assert!(inode.uses_extents());
        let data = reader.read_inode_data(2).unwrap();
        assert_eq!(data.len(), inode.size as usize);
        assert!(!data.is_empty());
    }

    // -------------------------------------------------------------------
    // Helper: open forensic.img
    // -------------------------------------------------------------------

    fn open_forensic() -> InodeReader<Cursor<Vec<u8>>> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/forensic.img");
        let data = std::fs::read(path).expect("forensic.img required");
        let br = BlockReader::open(Cursor::new(data)).unwrap();
        InodeReader::new(br)
    }

    // -------------------------------------------------------------------
    // 1. block_reader() and block_reader_mut() accessors
    // -------------------------------------------------------------------

    #[test]
    fn block_reader_accessor() {
        let r = open_minimal();
        let sb = r.block_reader().superblock();
        assert!(sb.block_size >= 1024, "block size should be at least 1024");
        assert!(sb.inodes_count > 0);
    }

    #[test]
    fn block_reader_mut_accessor() {
        let mut r = open_minimal();
        let sb = r.block_reader_mut().superblock();
        assert!(sb.block_size >= 1024);
    }

    // -------------------------------------------------------------------
    // 2. read_inode_raw — raw bytes for inode 2
    // -------------------------------------------------------------------

    #[test]
    fn read_inode_raw_minimal() {
        let mut r = open_minimal();
        let inode_size = r.block_reader().superblock().inode_size as usize;
        let raw = r.read_inode_raw(2).unwrap();
        assert_eq!(raw.len(), inode_size, "raw inode length should equal inode_size");
        // The mode field (u16 LE at offset 0) should be non-zero for root dir
        let mode = u16::from_le_bytes([raw[0], raw[1]]);
        assert_ne!(mode, 0, "root inode mode should be non-zero");
    }

    #[test]
    fn read_inode_raw_out_of_range() {
        let mut r = open_minimal();
        assert!(r.read_inode_raw(0).is_err());
        assert!(r.read_inode_raw(u64::MAX).is_err());
    }

    // -------------------------------------------------------------------
    // 3. inode_block_map — hello.txt (inode 12) on minimal.img
    // -------------------------------------------------------------------

    #[test]
    fn inode_block_map_hello_txt() {
        let hello_ino = resolve_minimal("/hello.txt");
        let mut r = open_minimal();
        let map = r.inode_block_map(hello_ino).unwrap();
        assert!(!map.is_empty(), "hello.txt should have at least one block mapping");
        for m in &map {
            assert!(m.physical_block > 0, "physical block should be non-zero");
            assert!(m.length > 0, "mapping length should be positive");
        }
    }

    // -------------------------------------------------------------------
    // 4. read_inode_data_range — first 5 bytes of hello.txt
    // -------------------------------------------------------------------

    #[test]
    fn read_inode_data_range_hello_prefix() {
        let hello_ino = resolve_minimal("/hello.txt");
        let mut r = open_minimal();
        let data = r.read_inode_data_range(hello_ino, 0, 5).unwrap();
        assert_eq!(&data, b"Hello", "first 5 bytes of hello.txt should be 'Hello'");
    }

    #[test]
    fn read_inode_data_range_past_eof() {
        let hello_ino = resolve_minimal("/hello.txt");
        let mut r = open_minimal();
        let inode = r.read_inode(hello_ino).unwrap();
        let data = r.read_inode_data_range(hello_ino, inode.size + 100, 10).unwrap();
        assert!(data.is_empty(), "reading past EOF should return empty");
    }

    // -------------------------------------------------------------------
    // 5. is_block_allocated — block 0 should be allocated
    // -------------------------------------------------------------------

    #[test]
    fn is_block_allocated_block_zero() {
        let mut r = open_minimal();
        let alloc = r.is_block_allocated(0).unwrap();
        assert!(alloc, "block 0 (superblock) should be allocated");
    }

    // -------------------------------------------------------------------
    // 6. iter_inodes_in_group(0) — includes root inode 2
    // -------------------------------------------------------------------

    #[test]
    fn iter_inodes_in_group_zero() {
        let mut r = open_minimal();
        let inodes = r.iter_inodes_in_group(0).unwrap();
        assert!(!inodes.is_empty(), "group 0 should have inodes");
        let inos: Vec<u64> = inodes.iter().map(|(ino, _)| *ino).collect();
        assert!(inos.contains(&2), "group 0 should contain root inode 2");
    }

    // -------------------------------------------------------------------
    // 7. iter_all_inodes — multiple inodes including inode 2
    // -------------------------------------------------------------------

    #[test]
    fn iter_all_inodes_includes_root() {
        let mut r = open_minimal();
        let all = r.iter_all_inodes().unwrap();
        assert!(all.len() >= 2, "should return multiple inodes");
        let inos: Vec<u64> = all.iter().map(|(ino, _)| *ino).collect();
        assert!(inos.contains(&2), "should include root inode 2");
    }

    // -------------------------------------------------------------------
    // 8. read_inode_data for a directory (inode 2)
    // -------------------------------------------------------------------

    #[test]
    fn read_inode_data_directory() {
        let mut r = open_minimal();
        let inode = r.read_inode(2).unwrap();
        assert_eq!(inode.file_type(), FileType::Directory);
        let data = r.read_inode_data(2).unwrap();
        assert!(!data.is_empty(), "root directory data should not be empty");
        assert_eq!(data.len(), inode.size as usize);
    }

    // -------------------------------------------------------------------
    // 9. read_inode for various inodes
    // -------------------------------------------------------------------

    #[test]
    fn read_inode_hello_txt() {
        let hello_ino = resolve_minimal("/hello.txt");
        let mut r = open_minimal();
        let inode = r.read_inode(hello_ino).unwrap();
        assert_eq!(inode.file_type(), FileType::RegularFile);
        // "Hello, ext4!" without or with trailing newline
        assert!(
            inode.size == 11 || inode.size == 12,
            "hello.txt should be 11 or 12 bytes, got {}",
            inode.size
        );
    }

    #[test]
    fn read_inode_lost_found() {
        let lf_ino = resolve_minimal("/lost+found");
        let mut r = open_minimal();
        let inode = r.read_inode(lf_ino).unwrap();
        assert_eq!(inode.file_type(), FileType::Directory);
        assert!(inode.links_count >= 2, "lost+found should have at least 2 links");
    }

    // -------------------------------------------------------------------
    // 10. read_inode_raw on forensic.img
    // -------------------------------------------------------------------

    #[test]
    fn read_inode_raw_forensic() {
        let mut r = open_forensic();
        let inode_size = r.block_reader().superblock().inode_size as usize;
        let raw = r.read_inode_raw(2).unwrap();
        assert_eq!(raw.len(), inode_size);
        // Verify mode is non-zero for root dir
        let mode = u16::from_le_bytes([raw[0], raw[1]]);
        assert_ne!(mode, 0);
    }

    // -------------------------------------------------------------------
    // 11. read_inode_data_range partial read on forensic.img
    // -------------------------------------------------------------------

    #[test]
    fn read_inode_data_range_forensic_middle() {
        let hello_ino = resolve_forensic("/hello.txt");
        let mut r = open_forensic();
        // hello.txt = "Hello, forensic world!\n" (23 bytes)
        // Read bytes 7..15 → "forensic"
        let data = r.read_inode_data_range(hello_ino, 7, 8).unwrap();
        assert_eq!(
            std::str::from_utf8(&data).unwrap(),
            "forensic",
            "middle bytes of forensic hello.txt"
        );
    }

    #[test]
    fn read_inode_data_range_forensic_start() {
        let hello_ino = resolve_forensic("/hello.txt");
        let mut r = open_forensic();
        let data = r.read_inode_data_range(hello_ino, 0, 5).unwrap();
        assert_eq!(&data, b"Hello");
    }

    // -------------------------------------------------------------------
    // 12. is_block_allocated on forensic.img — various blocks
    // -------------------------------------------------------------------

    #[test]
    fn is_block_allocated_forensic_block_zero() {
        let mut r = open_forensic();
        assert!(
            r.is_block_allocated(0).unwrap(),
            "block 0 should be allocated on forensic.img"
        );
    }

    #[test]
    fn is_block_allocated_forensic_high_block() {
        let mut r = open_forensic();
        // The forensic image is 32MB with 4096-byte blocks = 8192 blocks.
        // The last block should be unallocated (unused space beyond fs data).
        let sb = r.block_reader().superblock();
        let total_blocks = sb.blocks_count;
        // Check a block near the end — likely unallocated
        if total_blocks > 100 {
            let result = r.is_block_allocated(total_blocks - 1);
            // Just verify it doesn't panic/error — the value depends on layout
            assert!(result.is_ok());
        }
    }

    #[test]
    fn is_block_allocated_forensic_superblock_area() {
        let mut r = open_forensic();
        // Block 1 on a 4096-byte blocksize fs holds the superblock backup or GDT
        let alloc = r.is_block_allocated(1).unwrap();
        assert!(alloc, "block 1 should be allocated (GDT/superblock area)");
    }
}
