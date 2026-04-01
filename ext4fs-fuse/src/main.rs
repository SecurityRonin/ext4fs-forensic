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
        Commands::Mount { image, mountpoint, session, resume } => {
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

            let image_path = std::path::Path::new(&image);
            let session_mgr = session.map(|dir| {
                let session_path = std::path::Path::new(&dir).to_path_buf();
                if resume {
                    crate::session::Session::resume(&session_path, image_path)
                        .unwrap_or_else(|e| {
                            eprintln!("Cannot resume session: {e}");
                            std::process::exit(1);
                        })
                } else {
                    crate::session::Session::create(&session_path, image_path)
                        .unwrap_or_else(|e| {
                            eprintln!("Cannot create session: {e}");
                            std::process::exit(1);
                        })
                }
            });

            let has_session = session_mgr.is_some();
            let fuse_fs = fusefs::Ext4FuseFs::new(fs, session_mgr);
            eprintln!("Mounting {image} at {mountpoint}");
            let mut options = vec![
                fuser::MountOption::FSName("ext4fs-fuse".to_string()),
            ];
            if !has_session {
                options.push(fuser::MountOption::RO);
            }
            fuser::mount2(fuse_fs, &mountpoint, &options)
                .unwrap_or_else(|e| {
                    eprintln!("Mount failed: {e}");
                    std::process::exit(1);
                });
        }
        Commands::ExportSession { session_dir, output } => {
            crate::session::export_session(
                std::path::Path::new(&session_dir),
                std::path::Path::new(&output),
            ).unwrap_or_else(|e| {
                eprintln!("Export failed: {e}");
                std::process::exit(1);
            });
            eprintln!("Session exported to {output}");
        }
        Commands::ImportSession { tarball, session } => {
            crate::session::import_session(
                std::path::Path::new(&tarball),
                std::path::Path::new(&session),
            ).unwrap_or_else(|e| {
                eprintln!("Import failed: {e}");
                std::process::exit(1);
            });
            eprintln!("Session imported to {session}");
        }
    }
}
