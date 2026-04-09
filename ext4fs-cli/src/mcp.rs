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
        "ext4fs_open" => todo!("implement ext4fs_open"),
        "ext4fs_close" => todo!("implement ext4fs_close"),
        "ext4fs_info" => todo!("implement ext4fs_info"),
        "ext4fs_ls" => todo!("implement ext4fs_ls"),
        "ext4fs_read" => todo!("implement ext4fs_read"),
        "ext4fs_stat" => todo!("implement ext4fs_stat"),
        "ext4fs_deleted" => todo!("implement ext4fs_deleted"),
        "ext4fs_recover" => todo!("implement ext4fs_recover"),
        "ext4fs_timeline" => todo!("implement ext4fs_timeline"),
        "ext4fs_search" => todo!("implement ext4fs_search"),
        "ext4fs_hash" => todo!("implement ext4fs_hash"),
        "ext4fs_journal" => todo!("implement ext4fs_journal"),
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
