#![forbid(unsafe_code)]

use ext4fs::Ext4Fs;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, Write};

pub fn run_mcp_server() {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut sessions: HashMap<String, Ext4Fs<File>> = HashMap::new();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.is_empty() {
            continue;
        }

        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let err = json!({
                    "jsonrpc": "2.0",
                    "error": {"code": -32700, "message": format!("Parse error: {e}")},
                    "id": null
                });
                let _ = writeln!(stdout, "{err}");
                continue;
            }
        };

        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");

        let response = match method {
            "initialize" => json!({
                "jsonrpc": "2.0",
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": { "tools": {} },
                    "serverInfo": {
                        "name": "ext4fs",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                },
                "id": id
            }),
            "notifications/initialized" => continue,
            "tools/list" => json!({
                "jsonrpc": "2.0",
                "result": { "tools": tool_definitions() },
                "id": id
            }),
            "tools/call" => {
                let params = req.get("params").cloned().unwrap_or(json!({}));
                let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let args = params.get("arguments").cloned().unwrap_or(json!({}));

                match handle_tool(tool_name, &args, &mut sessions) {
                    Ok(val) => json!({"jsonrpc": "2.0", "result": val, "id": id}),
                    Err(e) => json!({
                        "jsonrpc": "2.0",
                        "result": {
                            "content": [{"type": "text", "text": format!("Error: {e}")}],
                            "isError": true
                        },
                        "id": id
                    }),
                }
            }
            _ => json!({
                "jsonrpc": "2.0",
                "error": {"code": -32601, "message": format!("Method not found: {method}")},
                "id": id
            }),
        };

        let _ = writeln!(stdout, "{response}");
        let _ = stdout.flush();
    }
}

fn tool_definitions() -> Value {
    json!([
        {
            "name": "ext4fs_open",
            "description": "Open an ext4 filesystem image and return a session ID for subsequent operations.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to ext4 image file" }
                },
                "required": ["path"]
            }
        },
        {
            "name": "ext4fs_close",
            "description": "Close a previously opened ext4 session.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session": { "type": "string", "description": "Session ID from ext4fs_open" }
                },
                "required": ["session"]
            }
        },
        {
            "name": "ext4fs_info",
            "description": "Get filesystem info: label, UUID, block size, block/inode counts, features.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session": { "type": "string" }
                },
                "required": ["session"]
            }
        },
        {
            "name": "ext4fs_ls",
            "description": "List directory contents with file types and sizes.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session": { "type": "string" },
                    "path": { "type": "string", "description": "Directory path (default: /)" }
                },
                "required": ["session"]
            }
        },
        {
            "name": "ext4fs_read",
            "description": "Read file contents. Returns text for UTF-8 files, base64 for binary.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session": { "type": "string" },
                    "path": { "type": "string", "description": "File path" },
                    "encoding": { "type": "string", "enum": ["text", "base64"], "description": "Output encoding (default: text)" }
                },
                "required": ["session", "path"]
            }
        },
        {
            "name": "ext4fs_stat",
            "description": "Get full inode metadata for a path: timestamps, permissions, size, flags.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session": { "type": "string" },
                    "path": { "type": "string" }
                },
                "required": ["session", "path"]
            }
        },
        {
            "name": "ext4fs_deleted",
            "description": "List all deleted inodes with file type, size, deletion time, and recoverability estimate.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session": { "type": "string" }
                },
                "required": ["session"]
            }
        },
        {
            "name": "ext4fs_recover",
            "description": "Attempt to recover a deleted file by inode number. Returns base64-encoded data.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session": { "type": "string" },
                    "inode": { "type": "integer", "description": "Inode number to recover" }
                },
                "required": ["session", "inode"]
            }
        },
        {
            "name": "ext4fs_timeline",
            "description": "Generate forensic timeline of all filesystem events (create, modify, access, delete).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session": { "type": "string" }
                },
                "required": ["session"]
            }
        },
        {
            "name": "ext4fs_search",
            "description": "Search for a byte pattern across filesystem blocks.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session": { "type": "string" },
                    "pattern": { "type": "string", "description": "Text pattern to search for" },
                    "scope": { "type": "string", "enum": ["allocated", "unallocated", "all"], "description": "Which blocks to search (default: all)" }
                },
                "required": ["session", "pattern"]
            }
        },
        {
            "name": "ext4fs_hash",
            "description": "Compute BLAKE3, SHA-256, MD5, and SHA-1 hashes for a file by inode number.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session": { "type": "string" },
                    "inode": { "type": "integer" }
                },
                "required": ["session", "inode"]
            }
        },
        {
            "name": "ext4fs_journal",
            "description": "List journal transactions with sequence numbers and commit timestamps.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session": { "type": "string" }
                },
                "required": ["session"]
            }
        }
    ])
}

fn handle_tool(
    name: &str,
    args: &Value,
    sessions: &mut HashMap<String, Ext4Fs<File>>,
) -> Result<Value, String> {
    match name {
        "ext4fs_open" => {
            let path = args
                .get("path")
                .and_then(|p| p.as_str())
                .ok_or("missing 'path' argument")?;
            let file = File::open(path).map_err(|e| format!("cannot open: {e}"))?;
            let fs = Ext4Fs::open(file).map_err(|e| format!("cannot parse ext4: {e}"))?;
            let session_id = uuid::Uuid::new_v4().to_string();
            sessions.insert(session_id.clone(), fs);
            Ok(mcp_text(&format!("Session opened: {session_id}")))
        }
        "ext4fs_close" => {
            let sid = get_session_id(args)?;
            sessions.remove(&sid);
            Ok(mcp_text("Session closed"))
        }
        "ext4fs_info" => {
            let sid = get_session_id(args)?;
            let fs = sessions.get(&sid).ok_or("invalid session")?;
            let sb = fs.superblock();
            Ok(mcp_json(&json!({
                "label": sb.label(),
                "uuid": sb.uuid_string(),
                "block_size": sb.block_size,
                "blocks_count": sb.blocks_count,
                "inodes_count": sb.inodes_count,
                "free_blocks": sb.free_blocks,
                "free_inodes": sb.free_inodes,
            })))
        }
        "ext4fs_ls" => {
            let sid = get_session_id(args)?;
            let fs = sessions.get_mut(&sid).ok_or("invalid session")?;
            let path = args.get("path").and_then(|p| p.as_str()).unwrap_or("/");
            let entries = fs.read_dir(path).map_err(|e| e.to_string())?;
            let list: Vec<Value> = entries
                .iter()
                .map(|e| {
                    json!({
                        "name": e.name_str(),
                        "inode": e.inode,
                        "type": format!("{:?}", e.file_type),
                    })
                })
                .collect();
            Ok(mcp_json(&json!(list)))
        }
        "ext4fs_read" => {
            let sid = get_session_id(args)?;
            let fs = sessions.get_mut(&sid).ok_or("invalid session")?;
            let path = args
                .get("path")
                .and_then(|p| p.as_str())
                .ok_or("missing 'path'")?;
            let encoding = args
                .get("encoding")
                .and_then(|e| e.as_str())
                .unwrap_or("text");
            let data = fs.read_file(path).map_err(|e| e.to_string())?;
            match encoding {
                "base64" => Ok(mcp_text(&base64_encode(&data))),
                _ => {
                    let text = String::from_utf8_lossy(&data);
                    Ok(mcp_text(&text))
                }
            }
        }
        "ext4fs_stat" => {
            let sid = get_session_id(args)?;
            let fs = sessions.get_mut(&sid).ok_or("invalid session")?;
            let path = args
                .get("path")
                .and_then(|p| p.as_str())
                .ok_or("missing 'path'")?;
            let meta = fs.metadata(path).map_err(|e| e.to_string())?;
            Ok(mcp_json(&json!({
                "inode": meta.ino,
                "type": format!("{:?}", meta.file_type),
                "mode": format!("{:o}", meta.mode),
                "uid": meta.uid,
                "gid": meta.gid,
                "size": meta.size,
                "links": meta.links_count,
                "atime": format_ts(&meta.atime),
                "mtime": format_ts(&meta.mtime),
                "ctime": format_ts(&meta.ctime),
                "crtime": format_ts(&meta.crtime),
                "allocated": meta.allocated,
            })))
        }
        "ext4fs_deleted" => {
            let sid = get_session_id(args)?;
            let fs = sessions.get_mut(&sid).ok_or("invalid session")?;
            let deleted = fs.deleted_inodes().map_err(|e| e.to_string())?;
            let list: Vec<Value> = deleted
                .iter()
                .map(|d| {
                    json!({
                        "inode": d.ino,
                        "type": format!("{:?}", d.file_type),
                        "size": d.size,
                        "dtime": d.dtime,
                        "recoverability": d.recoverability,
                    })
                })
                .collect();
            Ok(mcp_json(&json!(list)))
        }
        "ext4fs_recover" => {
            let sid = get_session_id(args)?;
            let fs = sessions.get_mut(&sid).ok_or("invalid session")?;
            let ino = args
                .get("inode")
                .and_then(|i| i.as_u64())
                .ok_or("missing 'inode'")?;
            let result = fs.recover_file(ino).map_err(|e| e.to_string())?;
            Ok(mcp_json(&json!({
                "inode": ino,
                "expected_size": result.expected_size,
                "recovered_bytes": result.recovered_size,
                "recovery_percentage": result.recovery_percentage(),
                "data_base64": base64_encode(&result.data),
            })))
        }
        "ext4fs_timeline" => {
            let sid = get_session_id(args)?;
            let fs = sessions.get_mut(&sid).ok_or("invalid session")?;
            let events = fs.timeline().map_err(|e| e.to_string())?;
            let list: Vec<Value> = events
                .iter()
                .map(|e| {
                    json!({
                        "timestamp": format_ts(&e.timestamp),
                        "type": format!("{:?}", e.event_type),
                        "inode": e.inode,
                        "size": e.size,
                    })
                })
                .collect();
            Ok(mcp_json(&json!(list)))
        }
        "ext4fs_search" => {
            let sid = get_session_id(args)?;
            let fs = sessions.get_mut(&sid).ok_or("invalid session")?;
            let pattern = args
                .get("pattern")
                .and_then(|p| p.as_str())
                .ok_or("missing 'pattern'")?;
            let scope_str = args
                .get("scope")
                .and_then(|s| s.as_str())
                .unwrap_or("all");
            let scope = match scope_str {
                "allocated" => ext4fs::forensic::SearchScope::Allocated,
                "unallocated" => ext4fs::forensic::SearchScope::Unallocated,
                _ => ext4fs::forensic::SearchScope::All,
            };
            let hits = fs
                .search_blocks(pattern.as_bytes(), scope)
                .map_err(|e| e.to_string())?;
            let list: Vec<Value> = hits
                .iter()
                .take(100)
                .map(|h| {
                    json!({
                        "block": h.block,
                        "offset": h.offset,
                        "context": String::from_utf8_lossy(&h.context),
                    })
                })
                .collect();
            Ok(mcp_json(&json!({
                "total_hits": hits.len(),
                "hits": list,
            })))
        }
        "ext4fs_hash" => {
            let sid = get_session_id(args)?;
            let fs = sessions.get_mut(&sid).ok_or("invalid session")?;
            let ino = args
                .get("inode")
                .and_then(|i| i.as_u64())
                .ok_or("missing 'inode'")?;
            let hash = fs.hash_file(ino).map_err(|e| e.to_string())?;
            Ok(mcp_json(&json!({
                "inode": hash.ino,
                "size": hash.size,
                "blake3": hash.blake3,
                "sha256": hash.sha256,
                "md5": hash.md5,
                "sha1": hash.sha1,
            })))
        }
        "ext4fs_journal" => {
            let sid = get_session_id(args)?;
            let fs = sessions.get_mut(&sid).ok_or("invalid session")?;
            let journal = fs.journal().map_err(|e| e.to_string())?;
            let list: Vec<Value> = journal
                .transactions
                .iter()
                .map(|t| {
                    json!({
                        "sequence": t.sequence,
                        "commit_time": t.commit_seconds,
                        "mappings": t.mappings.len(),
                        "revoked_blocks": t.revoked_blocks.len(),
                    })
                })
                .collect();
            Ok(mcp_json(&json!({
                "block_size": journal.block_size,
                "transactions": list,
            })))
        }
        _ => Err(format!("unknown tool: {name}")),
    }
}

fn get_session_id(args: &Value) -> Result<String, String> {
    args.get("session")
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "missing 'session' argument".to_string())
}

fn mcp_text(text: &str) -> Value {
    json!({"content": [{"type": "text", "text": text}]})
}

fn mcp_json(val: &Value) -> Value {
    json!({"content": [{"type": "text", "text": serde_json::to_string_pretty(val).unwrap_or_default()}]})
}

fn format_ts(ts: &ext4fs::ondisk::Timestamp) -> String {
    format!("{}:{}", ts.seconds, ts.nanoseconds)
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_definitions_has_12_tools() {
        let tools = tool_definitions();
        let arr = tools.as_array().unwrap();
        assert_eq!(arr.len(), 12);
    }

    #[test]
    fn tool_names_correct() {
        let tools = tool_definitions();
        let names: Vec<&str> = tools
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"ext4fs_open"));
        assert!(names.contains(&"ext4fs_ls"));
        assert!(names.contains(&"ext4fs_deleted"));
        assert!(names.contains(&"ext4fs_timeline"));
        assert!(names.contains(&"ext4fs_search"));
        assert!(names.contains(&"ext4fs_hash"));
    }

    #[test]
    fn mcp_text_format() {
        let result = mcp_text("hello");
        assert_eq!(result["content"][0]["type"], "text");
        assert_eq!(result["content"][0]["text"], "hello");
    }

    #[test]
    fn format_timestamp() {
        let ts = ext4fs::ondisk::Timestamp {
            seconds: 1700000000,
            nanoseconds: 500,
        };
        assert_eq!(format_ts(&ts), "1700000000:500");
    }

    #[test]
    fn base64_encode_hello() {
        assert_eq!(base64_encode(b"Hello"), "SGVsbG8=");
    }

    #[test]
    fn base64_encode_empty() {
        assert_eq!(base64_encode(b""), "");
    }

    #[test]
    fn base64_encode_three_bytes() {
        assert_eq!(base64_encode(b"Man"), "TWFu");
    }

    #[test]
    fn base64_encode_one_byte() {
        assert_eq!(base64_encode(b"M"), "TQ==");
    }

    #[test]
    fn handle_open_and_close() {
        let mut sessions = HashMap::new();
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/forensic.img");
        if !std::path::Path::new(path).exists() {
            eprintln!("skip: forensic.img not found");
            return;
        }
        let result =
            handle_tool("ext4fs_open", &json!({"path": path}), &mut sessions).unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with("Session opened:"));
        assert_eq!(sessions.len(), 1);

        let sid = sessions.keys().next().unwrap().clone();
        handle_tool(
            "ext4fs_close",
            &json!({"session": sid}),
            &mut sessions,
        )
        .unwrap();
        assert!(sessions.is_empty());
    }

    #[test]
    fn handle_info() {
        let mut sessions = HashMap::new();
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/forensic.img");
        if !std::path::Path::new(path).exists() {
            eprintln!("skip");
            return;
        }
        handle_tool("ext4fs_open", &json!({"path": path}), &mut sessions).unwrap();
        let sid = sessions.keys().next().unwrap().clone();
        let result = handle_tool("ext4fs_info", &json!({"session": sid}), &mut sessions).unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("block_size"));
    }

    #[test]
    fn handle_ls_root() {
        let mut sessions = HashMap::new();
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/forensic.img");
        if !std::path::Path::new(path).exists() {
            eprintln!("skip");
            return;
        }
        handle_tool("ext4fs_open", &json!({"path": path}), &mut sessions).unwrap();
        let sid = sessions.keys().next().unwrap().clone();
        let result = handle_tool(
            "ext4fs_ls",
            &json!({"session": sid, "path": "/"}),
            &mut sessions,
        )
        .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("hello.txt"));
    }

    #[test]
    fn handle_deleted() {
        let mut sessions = HashMap::new();
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/forensic.img");
        if !std::path::Path::new(path).exists() {
            eprintln!("skip");
            return;
        }
        handle_tool("ext4fs_open", &json!({"path": path}), &mut sessions).unwrap();
        let sid = sessions.keys().next().unwrap().clone();
        let result =
            handle_tool("ext4fs_deleted", &json!({"session": sid}), &mut sessions).unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("inode"));
    }

    #[test]
    fn handle_unknown_tool() {
        let mut sessions = HashMap::new();
        let result = handle_tool("nonexistent_tool", &json!({}), &mut sessions);
        assert!(result.is_err());
    }

    #[test]
    fn handle_invalid_session() {
        let mut sessions = HashMap::new();
        let result = handle_tool("ext4fs_info", &json!({"session": "fake-id"}), &mut sessions);
        assert!(result.is_err());
    }

    #[test]
    fn handle_read_text() {
        let mut sessions = HashMap::new();
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/forensic.img");
        if !std::path::Path::new(path).exists() {
            eprintln!("skip");
            return;
        }
        handle_tool("ext4fs_open", &json!({"path": path}), &mut sessions).unwrap();
        let sid = sessions.keys().next().unwrap().clone();
        let result = handle_tool(
            "ext4fs_read",
            &json!({"session": sid, "path": "/hello.txt"}),
            &mut sessions,
        )
        .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("Hello"));
    }

    #[test]
    fn handle_stat() {
        let mut sessions = HashMap::new();
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/forensic.img");
        if !std::path::Path::new(path).exists() {
            eprintln!("skip");
            return;
        }
        handle_tool("ext4fs_open", &json!({"path": path}), &mut sessions).unwrap();
        let sid = sessions.keys().next().unwrap().clone();
        let result = handle_tool(
            "ext4fs_stat",
            &json!({"session": sid, "path": "/hello.txt"}),
            &mut sessions,
        )
        .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("inode"));
        assert!(text.contains("size"));
    }

    #[test]
    fn handle_hash() {
        let mut sessions = HashMap::new();
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/forensic.img");
        if !std::path::Path::new(path).exists() {
            eprintln!("skip");
            return;
        }
        handle_tool("ext4fs_open", &json!({"path": path}), &mut sessions).unwrap();
        let sid = sessions.keys().next().unwrap().clone();
        let result = handle_tool(
            "ext4fs_hash",
            &json!({"session": sid, "inode": 12}),
            &mut sessions,
        )
        .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("blake3"));
        assert!(text.contains("sha256"));
        assert!(text.contains("md5"));
    }

    #[test]
    fn handle_journal() {
        let mut sessions = HashMap::new();
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/forensic.img");
        if !std::path::Path::new(path).exists() {
            eprintln!("skip");
            return;
        }
        handle_tool("ext4fs_open", &json!({"path": path}), &mut sessions).unwrap();
        let sid = sessions.keys().next().unwrap().clone();
        let result =
            handle_tool("ext4fs_journal", &json!({"session": sid}), &mut sessions).unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("transactions"));
    }

    #[test]
    fn handle_timeline() {
        let mut sessions = HashMap::new();
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/forensic.img");
        if !std::path::Path::new(path).exists() {
            eprintln!("skip");
            return;
        }
        handle_tool("ext4fs_open", &json!({"path": path}), &mut sessions).unwrap();
        let sid = sessions.keys().next().unwrap().clone();
        let result =
            handle_tool("ext4fs_timeline", &json!({"session": sid}), &mut sessions).unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("timestamp"));
    }

    #[test]
    fn handle_search() {
        let mut sessions = HashMap::new();
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/forensic.img");
        if !std::path::Path::new(path).exists() {
            eprintln!("skip");
            return;
        }
        handle_tool("ext4fs_open", &json!({"path": path}), &mut sessions).unwrap();
        let sid = sessions.keys().next().unwrap().clone();
        let result = handle_tool(
            "ext4fs_search",
            &json!({"session": sid, "pattern": "Hello"}),
            &mut sessions,
        )
        .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("hits"));
    }

    #[test]
    fn handle_recover() {
        let mut sessions = HashMap::new();
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/forensic.img");
        if !std::path::Path::new(path).exists() {
            eprintln!("skip");
            return;
        }
        handle_tool("ext4fs_open", &json!({"path": path}), &mut sessions).unwrap();
        let sid = sessions.keys().next().unwrap().clone();
        let result = handle_tool(
            "ext4fs_recover",
            &json!({"session": sid, "inode": 21}),
            &mut sessions,
        )
        .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("recovered_bytes"));
    }

    #[test]
    fn get_session_id_missing() {
        let result = get_session_id(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn get_session_id_present() {
        let result = get_session_id(&json!({"session": "abc-123"}));
        assert_eq!(result.unwrap(), "abc-123");
    }
}
