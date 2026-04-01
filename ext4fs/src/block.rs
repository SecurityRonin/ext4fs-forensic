#![forbid(unsafe_code)]
use crate::error::{Ext4Error, Result};
use crate::ondisk::{GroupDescriptor, Superblock};
use std::io::{Read, Seek, SeekFrom};

#[derive(Debug)]
pub struct BlockReader<R: Read + Seek> {
    source: R,
    superblock: Superblock,
    group_descs: Vec<GroupDescriptor>,
}

impl<R: Read + Seek> BlockReader<R> {
    pub fn open(mut source: R) -> Result<Self> {
        // Read superblock at offset 1024
        source.seek(SeekFrom::Start(1024))?;
        let mut sb_buf = vec![0u8; 1024];
        source.read_exact(&mut sb_buf)?;
        let superblock = Superblock::parse(&sb_buf)?;

        // GDT starts in block after superblock.
        // For 1024-byte blocks, superblock occupies block 1, GDT starts at block 2.
        // For larger blocks, both fit in block 0, GDT starts at block 1.
        let gdt_block = if superblock.block_size == 1024 { 2u64 } else { 1u64 };
        let gdt_offset = gdt_block * superblock.block_size as u64;
        let group_count = superblock.group_count();
        let desc_size = superblock.desc_size as usize;
        let gdt_size = group_count as usize * desc_size;

        source.seek(SeekFrom::Start(gdt_offset))?;
        let mut gdt_buf = vec![0u8; gdt_size];
        source.read_exact(&mut gdt_buf)?;

        let mut group_descs = Vec::with_capacity(group_count as usize);
        for i in 0..group_count as usize {
            let off = i * desc_size;
            let gd = GroupDescriptor::parse(&gdt_buf[off..off + desc_size], superblock.desc_size)?;
            group_descs.push(gd);
        }

        Ok(BlockReader { source, superblock, group_descs })
    }

    pub fn superblock(&self) -> &Superblock {
        &self.superblock
    }

    pub fn group_descriptors(&self) -> &[GroupDescriptor] {
        &self.group_descs
    }

    pub fn group_count(&self) -> u32 {
        self.group_descs.len() as u32
    }

    pub fn block_size(&self) -> u32 {
        self.superblock.block_size
    }

    pub fn read_block(&mut self, block_num: u64) -> Result<Vec<u8>> {
        if block_num >= self.superblock.blocks_count {
            return Err(Ext4Error::BlockOutOfRange {
                block: block_num,
                max: self.superblock.blocks_count,
            });
        }
        let offset = block_num * self.superblock.block_size as u64;
        self.read_bytes(offset, self.superblock.block_size as usize)
    }

    pub fn read_blocks(&mut self, start: u64, count: u64) -> Result<Vec<u8>> {
        let end = start.checked_add(count).ok_or(Ext4Error::BlockOutOfRange {
            block: start,
            max: self.superblock.blocks_count,
        })?;
        if end > self.superblock.blocks_count {
            return Err(Ext4Error::BlockOutOfRange {
                block: end - 1,
                max: self.superblock.blocks_count,
            });
        }
        let offset = start * self.superblock.block_size as u64;
        let len = count as usize * self.superblock.block_size as usize;
        self.read_bytes(offset, len)
    }

    pub fn read_bytes(&mut self, offset: u64, len: usize) -> Result<Vec<u8>> {
        self.source.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; len];
        self.source.read_exact(&mut buf)?;
        Ok(buf)
    }

    pub fn group_descriptor(&self, group: u32) -> Result<&GroupDescriptor> {
        self.group_descs.get(group as usize).ok_or(Ext4Error::CorruptMetadata {
            structure: "group_descriptor",
            detail: format!("group {group} out of range (max {})", self.group_descs.len()),
        })
    }

    pub fn inode_bitmap_block(&self, group: u32) -> Result<u64> {
        Ok(self.group_descriptor(group)?.inode_bitmap)
    }

    pub fn block_bitmap_block(&self, group: u32) -> Result<u64> {
        Ok(self.group_descriptor(group)?.block_bitmap)
    }

    pub fn inode_table_block(&self, group: u32) -> Result<u64> {
        Ok(self.group_descriptor(group)?.inode_table)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn load_minimal_image() -> Option<Vec<u8>> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/minimal.img");
        std::fs::read(path).ok()
    }

    #[test]
    fn open_minimal_image() {
        let data = load_minimal_image().expect("minimal.img required");
        let reader = BlockReader::open(Cursor::new(data)).unwrap();
        assert_eq!(reader.superblock().magic, 0xEF53);
        assert_eq!(reader.superblock().block_size, 4096);
        assert!(reader.group_count() > 0);
        assert!(!reader.group_descriptors().is_empty());
    }

    #[test]
    fn reject_too_small_image() {
        let data = vec![0u8; 512];
        let err = BlockReader::open(Cursor::new(data)).unwrap_err();
        assert!(matches!(err, crate::error::Ext4Error::Io(_) | crate::error::Ext4Error::TooShort { .. }));
    }

    #[test]
    fn read_block_zero() {
        let data = load_minimal_image().expect("minimal.img required");
        let mut reader = BlockReader::open(Cursor::new(data)).unwrap();
        let block = reader.read_block(0).unwrap();
        assert_eq!(block.len(), 4096);
    }

    #[test]
    fn read_block_out_of_range() {
        let data = load_minimal_image().expect("minimal.img required");
        let mut reader = BlockReader::open(Cursor::new(data)).unwrap();
        let err = reader.read_block(u64::MAX).unwrap_err();
        assert!(matches!(err, crate::error::Ext4Error::BlockOutOfRange { .. }));
    }
}
