#![no_main]

use ext4fs::Ext4Fs;
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    if data.len() < 9 {
        return;
    }
    let ino = u64::from_le_bytes(data[..8].try_into().unwrap());
    let image = &data[8..];
    let cursor = Cursor::new(image);
    if let Ok(mut fs) = Ext4Fs::open(cursor) {
        let _ = fs.inode(ino);
    }
});
