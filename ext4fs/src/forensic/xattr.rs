#![forbid(unsafe_code)]

use crate::error::Result;
use crate::inode::InodeReader;
use crate::ondisk::xattr::{XattrBlockHeader, XattrEntry, XattrNamespace};
use std::io::{Read, Seek};

/// A parsed extended attribute with its value.
#[derive(Debug, Clone)]
pub struct Xattr {
    pub namespace: XattrNamespace,
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

/// Read block-stored extended attributes for an inode (from `i_file_acl`).
///
/// Inline xattrs stored in the inode body are not yet supported.
pub fn read_xattrs<R: Read + Seek>(
    reader: &mut InodeReader<R>,
    ino: u64,
) -> Result<Vec<Xattr>> {
    let inode = reader.read_inode(ino)?;
    let mut xattrs = Vec::new();

    // Block xattrs (from i_file_acl)
    if inode.file_acl != 0 {
        let block_data = reader.block_reader_mut().read_block(inode.file_acl)?;
        if let Ok(_header) = XattrBlockHeader::parse(&block_data) {
            let mut offset = 32; // skip header
            while offset + 16 <= block_data.len() {
                if block_data[offset] == 0 { break; }
                match XattrEntry::parse(&block_data[offset..]) {
                    Ok(entry) => {
                        let value_start = entry.value_offset as usize;
                        let value_end = value_start + entry.value_size as usize;
                        let value = if value_end <= block_data.len() {
                            block_data[value_start..value_end].to_vec()
                        } else {
                            Vec::new()
                        };

                        xattrs.push(Xattr {
                            namespace: entry.name_index,
                            name: entry.name.clone(),
                            value,
                        });
                        offset += entry.entry_size;
                    }
                    Err(_) => break,
                }
            }
        }
    }

    Ok(xattrs)
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
    fn read_xattrs_from_file() {
        let mut reader = match open_minimal() {
            Some(r) => r,
            None => { eprintln!("skip: minimal.img not found"); return; }
        };
        let xattrs = read_xattrs(&mut reader, 2).unwrap();
        let _ = xattrs;
    }

    fn open_forensic() -> Option<InodeReader<Cursor<Vec<u8>>>> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/forensic.img");
        let data = std::fs::read(path).ok()?;
        let br = BlockReader::open(Cursor::new(data)).ok()?;
        Some(InodeReader::new(br))
    }

    #[test]
    fn read_xattrs_for_hello_txt() {
        let mut reader = match open_forensic() {
            Some(r) => r,
            None => { eprintln!("skip: forensic.img not found"); return; }
        };

        // Read the inode to inspect file_acl
        let inode = reader.read_inode(12).unwrap();
        eprintln!("hello.txt (ino 12) file_acl = {}", inode.file_acl);

        let xattrs = read_xattrs(&mut reader, 12).unwrap();
        eprintln!("xattrs found: {}", xattrs.len());
        for xa in &xattrs {
            eprintln!(
                "  namespace={:?} name={:?} value={:?}",
                xa.namespace,
                String::from_utf8_lossy(&xa.name),
                String::from_utf8_lossy(&xa.value),
            );
        }
        // Don't assert specific xattr names yet — just assert no error occurred.
    }

    #[test]
    fn read_xattrs_for_root_inode() {
        let mut reader = match open_forensic() {
            Some(r) => r,
            None => { eprintln!("skip: forensic.img not found"); return; }
        };

        let xattrs = read_xattrs(&mut reader, 2).unwrap();
        let _ = xattrs;
    }
}
