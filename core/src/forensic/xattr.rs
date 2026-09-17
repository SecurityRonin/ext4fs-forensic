#![forbid(unsafe_code)]

use crate::error::Result;
use crate::inode::InodeReader;
use crate::ondisk::xattr::{XattrBlockHeader, XattrEntry, XattrNamespace, XATTR_MAGIC};
use std::io::{Read, Seek};

/// Where ext4 put an attribute's value.
///
/// A small value rides along in the inode; a large one is pushed out to a block
/// of its own. That is a fact about where the bytes physically are, so the
/// reader reports it rather than flattening the two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XattrStorage {
    /// In the inode body, after `i_extra_isize` (the "ibody" store).
    Ibody,
    /// In the separate block pointed at by `i_file_acl`.
    Block {
        /// The block number holding the value, from `i_file_acl`.
        block: u64,
    },
}

/// A parsed extended attribute with its value.
#[derive(Debug, Clone)]
pub struct Xattr {
    pub namespace: XattrNamespace,
    pub name: Vec<u8>,
    pub value: Vec<u8>,
    /// Which of the two stores this attribute was found in.
    pub storage: XattrStorage,
}

impl Xattr {
    /// The full attribute name as the system presents it — namespace prefix
    /// plus stored name, e.g. `security.selinux` from index 6 + `selinux`.
    ///
    /// Returns `None` for an unrecognised namespace index: the index is shown
    /// by the caller rather than guessed at, because a name invented here would
    /// be reported as one the system gave.
    #[must_use]
    pub fn full_name(&self) -> Option<String> {
        let prefix = self.namespace.prefix()?;
        let mut s = String::with_capacity(prefix.len() + self.name.len());
        s.push_str(prefix);
        s.push_str(&String::from_utf8_lossy(&self.name));
        Some(s)
    }
}

/// Walk a run of `XattrEntry` records and append every attribute found.
///
/// The ibody and block stores use an identical entry format and differ only in
/// where the walk starts and what `value_offset` is measured from. They were
/// two near-identical loops; a correction to one would not have reached the
/// other, which is the cost duplication actually charges.
///
/// A malformed entry ENDS the walk rather than being skipped: the records are
/// sequential and `entry_size` is what advances the cursor, so a bad length
/// leaves no trustworthy place to resume.
fn collect_entries(
    region: &[u8],
    entry_start: usize,
    value_base: usize,
    storage: XattrStorage,
    out: &mut Vec<Xattr>,
) {
    let mut offset = entry_start;
    while offset + 16 <= region.len() {
        // A zero name_length terminates the entry list.
        if region[offset] == 0 {
            break;
        }
        let Ok(entry) = XattrEntry::parse(&region[offset..]) else {
            break;
        };
        let value = (entry.value_offset as usize)
            .checked_add(value_base)
            .and_then(|start| {
                let end = start.checked_add(entry.value_size as usize)?;
                region.get(start..end).map(<[u8]>::to_vec)
            })
            .unwrap_or_default();
        out.push(Xattr {
            namespace: entry.name_index,
            name: entry.name.clone(),
            value,
            storage,
        });
        // A zero entry_size would spin forever on a corrupt record.
        if entry.entry_size == 0 {
            break;
        }
        offset += entry.entry_size;
    }
}

/// Read extended attributes for an inode.
///
/// Reads both inline xattrs stored in the inode body (ibody) and
/// block-stored xattrs from `i_file_acl`.
/// Takes `&InodeReader` rather than `&mut`: every call it makes
/// (`read_inode`, `read_inode_raw`, `read_block`) is already immutable, because
/// `BlockReader` holds its source behind a `Mutex` so one filesystem can back N
/// workers. The exclusive borrow was never needed and blocked the
/// `forensic-vfs` adapter, whose trait methods take `&self`.
pub fn read_xattrs<R: Read + Seek>(reader: &InodeReader<R>, ino: u64) -> Result<Vec<Xattr>> {
    let inode = reader.read_inode(ino)?;
    let mut xattrs = Vec::new();

    // --- Inline xattrs (ibody) ---
    let inode_size = reader.block_reader().superblock().inode_size as usize;
    let ibody_offset = 0x80 + inode.extra_isize as usize;
    if inode.extra_isize > 0 && inode_size > ibody_offset {
        let raw = reader.read_inode_raw(ino)?;
        let ibody_region = &raw[ibody_offset..];
        if ibody_region.len() >= 4 {
            // Check for and skip the 4-byte inline xattr magic (0xEA020000)
            let magic = u32::from_le_bytes([
                ibody_region[0],
                ibody_region[1],
                ibody_region[2],
                ibody_region[3],
            ]);
            let entry_start = if magic == XATTR_MAGIC { 4 } else { 0 };
            // In the ibody store, value_offset is relative to the start of the
            // entry area (just past the magic), so the value base is the same
            // entry_start the walk begins at.
            collect_entries(
                ibody_region,
                entry_start,
                entry_start,
                XattrStorage::Ibody,
                &mut xattrs,
            );
        }
    }

    // --- Block xattrs (from i_file_acl) ---
    if inode.file_acl != 0 {
        let block_data = reader.block_reader().read_block(inode.file_acl)?;
        if let Ok(_header) = XattrBlockHeader::parse(&block_data) {
            // In the block store, entries start after the 32-byte header and
            // value_offset is relative to the start of the BLOCK, so the value
            // base is 0 rather than the entry start.
            collect_entries(
                &block_data,
                32,
                0,
                XattrStorage::Block {
                    block: inode.file_acl,
                },
                &mut xattrs,
            );
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
        let reader = if let Some(r) = open_minimal() {
            r
        } else {
            eprintln!("skip: minimal.img not found");
            return;
        };
        let xattrs = read_xattrs(&reader, 2).unwrap();
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
        let reader = if let Some(r) = open_forensic() {
            r
        } else {
            eprintln!("skip: forensic.img not found");
            return;
        };

        // Read the inode to inspect file_acl
        let inode = reader.read_inode(12).unwrap();
        eprintln!("hello.txt (ino 12) file_acl = {}", inode.file_acl);

        let xattrs = read_xattrs(&reader, 12).unwrap();
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
        let reader = if let Some(r) = open_forensic() {
            r
        } else {
            eprintln!("skip: forensic.img not found");
            return;
        };

        let xattrs = read_xattrs(&reader, 2).unwrap();
        let _ = xattrs;
    }

    #[test]
    fn read_inline_xattrs_for_hello_txt() {
        let reader = if let Some(r) = open_forensic() {
            r
        } else {
            eprintln!("skip: forensic.img not found");
            return;
        };
        // hello.txt is inode 12 in forensic.img
        let xattrs = read_xattrs(&reader, 12).unwrap();
        let names: Vec<String> = xattrs
            .iter()
            .map(|x| String::from_utf8_lossy(&x.name).to_string())
            .collect();
        assert!(
            names.contains(&"forensic".to_string()),
            "expected user.forensic xattr, found: {names:?}"
        );
        assert!(
            names.contains(&"case_id".to_string()),
            "expected user.case_id xattr, found: {names:?}"
        );
    }

    #[test]
    fn inline_xattr_values_are_correct() {
        let reader = if let Some(r) = open_forensic() {
            r
        } else {
            eprintln!("skip: forensic.img not found");
            return;
        };
        let xattrs = read_xattrs(&reader, 12).unwrap();
        let forensic_xattr = xattrs
            .iter()
            .find(|x| x.name == b"forensic")
            .expect("user.forensic xattr not found");
        assert_eq!(
            String::from_utf8_lossy(&forensic_xattr.value),
            "evidence-tag"
        );

        let case_xattr = xattrs
            .iter()
            .find(|x| x.name == b"case_id")
            .expect("user.case_id xattr not found");
        assert_eq!(String::from_utf8_lossy(&case_xattr.value), "2026-0401");
    }
}
