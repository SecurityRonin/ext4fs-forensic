#![forbid(unsafe_code)]
// Production main propagates errors with `?`; test modules (e.g. mcp::tests)
// may unwrap/expect freely on fixtures they construct.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod mcp;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "ext4fs",
    about = "CLI and MCP server for ext4 forensic analysis"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show filesystem info (superblock)
    Info { image: String },
    /// List directory contents
    Ls {
        image: String,
        #[arg(default_value = "/")]
        path: String,
    },
    /// Read file contents
    Read { image: String, path: String },
    /// Start MCP server (JSON-RPC stdio)
    Mcp,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Info { image } => {
            let file = std::fs::File::open(&image)?;
            let fs = ext4fs::Ext4Fs::open(file)?;
            let sb = fs.superblock();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "label": sb.label(),
                    "uuid": sb.uuid_string(),
                    "block_size": sb.block_size,
                    "blocks_count": sb.blocks_count,
                    "inodes_count": sb.inodes_count,
                }))?
            );
        }
        Commands::Ls { image, path } => {
            let file = std::fs::File::open(&image)?;
            let mut fs = ext4fs::Ext4Fs::open(file)?;
            let entries = fs.read_dir(&path)?;
            for e in &entries {
                println!("{}", e.name_str());
            }
        }
        Commands::Read { image, path } => {
            let file = std::fs::File::open(&image)?;
            let mut fs = ext4fs::Ext4Fs::open(file)?;
            let data = fs.read_file(&path)?;
            std::io::Write::write_all(&mut std::io::stdout(), &data)?;
        }
        Commands::Mcp => {
            mcp::run_mcp_server();
        }
    }
    Ok(())
}
