#![forbid(unsafe_code)]

mod fusefs;
mod inode_map;
mod session;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "ext4fs-fuse", about = "Forensic FUSE mount for ext4 images")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Mount an ext4 image
    Mount {
        /// Path to ext4 image file
        image: String,
        /// Mount point directory
        mountpoint: String,
        /// Session directory for COW overlay persistence
        #[arg(long)]
        session: Option<String>,
        /// Resume a previous session
        #[arg(long)]
        resume: bool,
    },
    /// Export session for sharing
    ExportSession {
        /// Session directory to export
        session_dir: String,
        /// Output tarball path
        #[arg(long)]
        output: String,
    },
    /// Import a session from tarball
    ImportSession {
        /// Tarball to import
        tarball: String,
        /// Session directory to extract to
        #[arg(long)]
        session: String,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Mount { image, mountpoint, session: _, resume: _ } => {
            let file = std::fs::File::open(&image)
                .unwrap_or_else(|e| {
                    eprintln!("Cannot open {image}: {e}");
                    std::process::exit(1);
                });
            let fs = ext4fs::Ext4Fs::open(file)
                .unwrap_or_else(|e| {
                    eprintln!("Cannot parse ext4: {e}");
                    std::process::exit(1);
                });
            let fuse_fs = fusefs::Ext4FuseFs::new(fs);
            eprintln!("Mounting {image} at {mountpoint}");
            let options = vec![
                fuser::MountOption::RO,
                fuser::MountOption::FSName("ext4fs-fuse".to_string()),
            ];
            fuser::mount2(fuse_fs, &mountpoint, &options)
                .unwrap_or_else(|e| {
                    eprintln!("Mount failed: {e}");
                    std::process::exit(1);
                });
        }
        Commands::ExportSession { session_dir, output } => {
            eprintln!("Exporting session {session_dir} to {output}");
            todo!("session export")
        }
        Commands::ImportSession { tarball, session } => {
            eprintln!("Importing session from {tarball} to {session}");
            todo!("session import")
        }
    }
}
