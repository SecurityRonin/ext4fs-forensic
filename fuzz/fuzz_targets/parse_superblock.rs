#![no_main]

use ext4fs::Ext4Fs;
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let cursor = Cursor::new(data);
    let _ = Ext4Fs::open(cursor);
});
