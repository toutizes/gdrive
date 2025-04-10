pub mod about;
pub mod account;
pub mod app_config;
pub mod common;
pub mod drives;
pub mod files;
pub mod hub;
pub mod permissions;
pub mod version;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use common::delegate::ChunkSize;
use common::permission;
use files::list::ListQuery;
use files::list::ListSortOrder;
use mime::Mime;
use std::error::Error;
use std::path::PathBuf;
use tokio::runtime::Builder;

#[derive(Parser)]
#[command(author, version, about, long_about = None, disable_version_flag = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Only list what would be done.
    #[arg(long, default_value = "false")]
    pretend: Option<bool>,

    /// Number of workers to use for parallelising operations
    #[arg(long, default_value = "1")]
    workers: usize,
}

#[derive(Subcommand)]
enum Command {
    /// Print information about gdrive
    About,

    /// Commands for managing accounts
    Account {
        #[command(subcommand)]
        command: AccountCommand,
    },

    /// Commands for managing drives
    Drives {
        #[command(subcommand)]
        command: DriveCommand,
    },

    /// Commands for managing files
    Files {
        #[command(subcommand)]
        command: FileCommand,
    },

    /// Commands for managing file permissions
    Permissions {
        #[command(subcommand)]
        command: PermissionCommand,
    },

    /// Print version information
    Version,
}

#[derive(Subcommand)]
enum AccountCommand {
    /// Add an account
    Add,

    /// List all accounts
    List,

    /// Print current account
    Current,

    /// Switch to a different account
    Switch {
        /// Account name
        account_name: String,
    },

    /// Remove an account
    Remove {
        /// Account name
        account_name: String,
    },

    /// Export account, this will create a zip file of the account which can be imported
    Export {
        /// Account name
        account_name: String,
    },

    /// Import account that was created with the export command
    Import {
        /// Path to archive
        file_path: PathBuf,
    },
}

#[derive(Subcommand)]
enum DriveCommand {
    /// List drives
    List {
        /// Don't print header
        #[arg(long)]
        skip_header: bool,

        /// Field separator
        #[arg(long, default_value_t = String::from("\t"))]
        field_separator: String,
    },
}

#[derive(Subcommand)]
enum FileCommand {
    /// Print file info
    Info {
        /// File id
        file_id: String,

        /// Display size in bytes
        #[arg(long, default_value_t = false)]
        size_in_bytes: bool,
    },

    /// List files
    List {
        /// Max files to list
        #[arg(long, default_value_t = 30)]
        max: usize,

        /// Query. See https://developers.google.com/workspace/drive/api/guides/ref-search-terms
        #[arg(long, default_value_t = ListQuery::default())]
        query: ListQuery,

        /// Order by. See https://developers.google.com/drive/api/v3/reference/files/list
        #[arg(long, default_value_t = ListSortOrder::default())]
        order_by: ListSortOrder,

        /// List files in a specific folder
        #[arg(long, value_name = "DIRECTORY_ID")]
        parent: Option<String>,

        /// List files on a shared drive
        #[arg(long, value_name = "DRIVE_ID")]
        drive: Option<String>,

        /// Don't print header
        #[arg(long)]
        skip_header: bool,

        /// Show full file name without truncating
        #[arg(long)]
        full_name: bool,

        /// Field separator
        #[arg(long, default_value_t = String::from("\t"))]
        field_separator: String,
    },

    /// Download a file or a folder from Google Drive to the local
    /// disk.
    ///
    /// If you do not pass --destination <LOCAL FOLDER> the files is
    /// downloaded to the current directory. See also --stdout.
    ///
    /// To download a Google Drive folder you must pass --recursive.
    ///
    /// By default gdrive does not overwrite files that are already
    /// present on the local disk. See --overwrite and --sync for
    /// other options.
    ///
    /// When downloading a folder, it is an error if a folder contains
    /// multiple files with the same name.
    ///
    /// By default Google Drive shortcuts are ignored. See
    /// --follow-shortcuts to follow them.
    Download {
        /// Name of the Google Drive file or folder to download.
        ///
        /// If the name starts with a / it is interpreted as a Google Drive
        /// path, such as /<folder name>/<file name> or
        /// /<folder name>/<folder name>.
        ///
        /// If the name does not start with a / it must be a Google
        /// Drive item id, as returned by "gdrive list". You can use
        /// that to unambiguously download one of multiple files with
        /// the same name from a Google Drive folder.
        #[arg(value_name = "DRIVE FILE OR FOLDER", required = true)]
        drive_path: String,

        /// Local path where the Google Drive or folder will be
        /// downloaded.  Must already exist as a directory on the
        /// local disk. Defaults to the current directory.
        #[arg(long, value_name = "LOCAL FOLDER")]
        destination: Option<PathBuf>,

        /// Recursively download folders. This must be specified when
        /// the path to download is a Google Drive folder.
        #[arg(long, short = 'r')]
        recursive: bool,

        /// Files that already exists on the local disk are
        /// overwritten with their Google Drive current version.
        ///
        /// To save bandwidth files that are identical to the local
        /// version are not downloaded.
        #[arg(long, short = 'f')]
        overwrite: bool,

        /// Like --overwrite plus, when recursively downloading a
        /// folder, also DELETES local files that are not present in
        /// the Google Drive folder.
        ///
        /// Exception: gdrive never deletes a local folder, only local
        /// files.
        #[arg(long, short = 's')]
        sync: bool,

        /// Instead of creating files, just emit the contents of the
        /// downloaded files to the output of the gdrive command.
        /// Might be useful when downloading a single file.
        #[arg(long)]
        stdout: Option<bool>,

        // TODO: review
        /// Follow Google Drive shortcuts, and download the Google
        /// Drive items they point to.
        #[arg(long)]
        follow_shortcuts: bool,
    },

    /// Upload a file or a folder from the local disk to Google Drive.
    ///
    /// If you do not pass --destination <DRIVE FOLDER>, the file or
    /// folder is uploaded at the root of Google Drive.
    ///
    /// To upload a folder, you must pass --recursive.
    ///
    /// By default, gdrive does not overwrite files that are already
    /// present on Google Drive. See --overwrite and --sync for
    /// other options.
    ///
    /// By default, Google Drive shortcuts are ignored. See
    /// --follow-shortcuts to follow them.
    Upload {
        /// Local path of the file or folder to upload.
        #[arg(value_name = "LOCAL_FILE_OR_FOLDER", required = true)]
        file_path: PathBuf,

        /// Optional Google Drive folder where the uploaded contents
        /// go. Defaults to the Google Drive root folder.
        ///
        /// If the name starts with a / it is interpreted as a Google Drive
        /// path, such as /<folder name>/<folder name>...  You can pass
        /// just / to represent the Google Drive root.
        ///
        /// If the name does not start with a / it must be a Google
        /// Drive item id, as returned by "gdrive list".
        #[arg(long, value_name = "DRIVE FOLDER", aliases = &["parent"], default_value="/")]
        destination: String,

        /// Recursively upload folders. This must be specified when
        /// the path to upload is a local folder.
        #[arg(long, short = 'r')]
        recursive: bool,

        /// Overwrite files already present on Google Drive with the
        /// local version.
        ///
        /// It is an error if a Google Drive folder contains multiple
        /// files with the same name as one of the files to upload.
        ///
        /// To save bandwidth files that are identical to the Google
        /// Drive version are not uploaded.
        #[arg(long, short = 'f')]
        overwrite: bool,

        /// Like --overwrite plus, when recursively uploading a
        /// folder, also DELETES Google Drive files that are not
        /// present in the local folder. Exception: gdrive never
        /// deletes a Google Drive folder, only Google Drive files.
        ///
        /// It is an error if a Google Drive folder contains
        /// multiple files with the same name.
        #[arg(long, short = 's')]
        sync: bool,

        // TODO: Review parameters below.
        /// Force mime type [default: auto-detect]
        #[arg(long, value_name = "MIME_TYPE")]
        mime: Option<Mime>,

        /// Set chunk size in MB, must be a power of two.
        #[arg(long, value_name = "1|2|4|8|16|32|64|128|256|512|1024|4096|8192", default_value_t = ChunkSize::default())]
        chunk_size: ChunkSize,

        /// Print errors occuring during chunk upload
        #[arg(long, value_name = "", default_value_t = false)]
        print_chunk_errors: bool,

        /// Print details about each chunk
        #[arg(long, value_name = "", default_value_t = false)]
        print_chunk_info: bool,

        /// Print only id of file/folder
        #[arg(long, default_value_t = false)]
        print_only_id: bool,
    },

    /// Update file. This will create a new version of the file. The older versions will typically be kept for 30 days.
    Update {
        /// File id of the file you want ot update
        file_id: String,

        /// Path of file to upload
        file_path: Option<PathBuf>,

        /// Force mime type [default: auto-detect]
        #[arg(long, value_name = "MIME_TYPE")]
        mime: Option<Mime>,

        /// Set chunk size in MB, must be a power of two.
        #[arg(long, value_name = "1|2|4|8|16|32|64|128|256|512|1024|4096|8192", default_value_t = ChunkSize::default())]
        chunk_size: ChunkSize,

        /// Print errors occuring during chunk upload
        #[arg(long, value_name = "", default_value_t = false)]
        print_chunk_errors: bool,

        /// Print details about each chunk
        #[arg(long, value_name = "", default_value_t = false)]
        print_chunk_info: bool,
    },

    /// Delete file
    Delete {
        /// File id
        file_id: String,

        /// Delete directory and all it's content
        #[arg(long)]
        recursive: bool,
    },

    /// Create directory
    Mkdir {
        /// Name
        name: String,

        /// Create in an existing directory
        #[arg(long, value_name = "DIRECTORY_ID")]
        parent: Option<Vec<String>>,

        /// Print only id of folder
        #[arg(long, default_value_t = false)]
        print_only_id: bool,
    },

    /// Rename file/directory
    Rename {
        /// Id of file or directory
        file_id: String,

        /// New name
        name: String,
    },

    /// Move file/directory
    Move {
        /// Id of file or directory to move
        file_id: String,

        /// Id of folder to move to
        folder_id: String,
    },

    /// Copy file
    Copy {
        /// Id of file or directory to move
        file_id: String,

        /// Id of folder to copy to
        folder_id: String,
    },

    /// Import file as a google document/spreadsheet/presentation.
    /// Example of file types that can be imported: doc, docx, odt, pdf, html, xls, xlsx, csv, ods, ppt, pptx, odp
    Import {
        /// Path to file
        file_path: PathBuf,

        /// Upload to an existing directory
        #[arg(long, value_name = "DRIVE FOLDER")]
        parent: String,

        /// Print only id of file
        #[arg(long, default_value_t = false)]
        print_only_id: bool,
    },

    /// Export google document to file
    Export {
        /// File id
        file_id: String,

        /// File path to export to. The file extension will determine the export format
        file_path: PathBuf,

        /// Overwrite existing files
        #[arg(long)]
        overwrite: bool,
    },
}

#[derive(Subcommand)]
enum PermissionCommand {
    /// Grant permission to file
    Share {
        /// File id
        file_id: String,

        /// The role granted by this permission. Allowed values are: owner, organizer, fileOrganizer, writer, commenter, reader
        #[arg(long, default_value_t = permission::Role::default())]
        role: permission::Role,

        /// The type of the grantee. Valid values are: user, group, domain, anyone
        #[arg(long, default_value_t = permission::Type::default())]
        type_: permission::Type,

        /// Email address. Required for user and group type
        #[arg(long)]
        email: Option<String>,

        /// Domain. Required for domain type
        #[arg(long)]
        domain: Option<String>,

        /// Whether the permission allows the file to be discovered through search. This is only applicable for permissions of type domain or anyone
        #[arg(long)]
        discoverable: bool,
    },

    /// List permissions for a file
    List {
        /// File id
        file_id: String,

        /// Don't print header
        #[arg(long)]
        skip_header: bool,

        /// Field separator
        #[arg(long, default_value_t = String::from("\t"))]
        field_separator: String,
    },

    /// Revoke permissions for a file. If no other options are specified, the 'anyone' permission will be revoked
    Revoke {
        /// File id
        file_id: String,

        /// Revoke all permissions (except owner)
        #[arg(long)]
        all: bool,

        /// Revoke specific permission
        #[arg(long, value_name = "PERMISSION_ID")]
        id: Option<String>,
    },
}

// #[tokio::main]
fn main() -> Result<()> {
    let cli = Cli::parse();

    let rt = Builder::new_multi_thread()
        .worker_threads(cli.workers)
        .enable_all()
        .build()?;

    return rt.block_on(async {
        do_it(cli).await
    });
}

async fn do_it(cli: Cli) -> Result<()> {
    match cli.command {
        Command::About => {
            // fmt
            about::about()
        }

        Command::Account { command } => {
            // fmt
            match command {
                AccountCommand::Add => {
                    // fmt
                    account::add().await.unwrap_or_else(handle_error)
                }

                AccountCommand::List => {
                    // fmt
                    account::list().unwrap_or_else(handle_error)
                }

                AccountCommand::Current => {
                    // fmt
                    account::current().unwrap_or_else(handle_error)
                }

                AccountCommand::Switch { account_name } => {
                    // fmt
                    account::switch(account::switch::Config { account_name })
                        .unwrap_or_else(handle_error)
                }

                AccountCommand::Remove { account_name } => {
                    // fmt
                    account::remove(account::remove::Config { account_name })
                        .unwrap_or_else(handle_error)
                }

                AccountCommand::Export { account_name } => {
                    // fmt
                    account::export(account::export::Config { account_name })
                        .unwrap_or_else(handle_error)
                }

                AccountCommand::Import { file_path } => {
                    // fmt
                    account::import(account::import::Config {
                        archive_path: file_path,
                    })
                    .unwrap_or_else(handle_error)
                }
            }
        }

        Command::Drives { command } => {
            // fmt
            match command {
                DriveCommand::List {
                    skip_header,
                    field_separator,
                } => drives::list(drives::list::Config {
                    skip_header,
                    field_separator,
                })
                .await
                .unwrap_or_else(handle_error),
            }
        }

        Command::Files { command } => {
            match command {
                FileCommand::Info {
                    file_id,
                    size_in_bytes,
                } => {
                    // fmt
                    files::info(files::info::Config {
                        file_id,
                        size_in_bytes,
                    })
                    .await
                    .unwrap_or_else(handle_error)
                }

                FileCommand::List {
                    max,
                    query,
                    order_by,
                    parent,
                    drive,
                    skip_header,
                    full_name,
                    field_separator,
                } => {
                    let parent_query =
                        parent.map(|folder_id| ListQuery::FilesInFolder { folder_id });

                    let drive_query = drive.map(|drive_id| ListQuery::FilesOnDrive { drive_id });

                    let q = parent_query.or(drive_query).unwrap_or(query);

                    files::list(files::list::Config {
                        query: q,
                        order_by,
                        max_files: max,
                        skip_header,
                        truncate_name: !full_name,
                        field_separator,
                    })
                    .await
                    .unwrap_or_else(handle_error)
                }

                FileCommand::Download {
                    drive_path,
                    destination,
                    recursive,
                    overwrite,
                    sync,
                    follow_shortcuts,
                    stdout,
                } => {
                    if sync && overwrite {
                        return Err(anyhow!(
                            "Only one of --sync and --overwrite can be specified"
                        ));
                    }
                    let existing_file_action = if sync {
                        files::download::ExistingFileAction::SyncLocal
                    } else if overwrite {
                        files::download::ExistingFileAction::Overwrite
                    } else {
                        files::download::ExistingFileAction::Abort
                    };

                    let dst: Option<PathBuf>;
                    if !stdout.is_none() {
                        if !destination.is_none() {
                            return Err(anyhow!(
                                "Only one of --stdout and --destination can be specified"
                            ));
                        }
                        dst = None;
                    } else {
                        dst = destination;
                    }

                    let options = files::download::DownloadOptions {
                        existing_file_action,
                        follow_shortcuts,
                        download_directories: recursive,
                    };
                    files::download(&drive_path, &dst, &options, 2 * cli.workers).await?
                }

                FileCommand::Upload {
                    file_path,
                    destination,
                    recursive,
                    overwrite,
                    sync,
                    mime,
                    chunk_size,
                    print_chunk_errors,
                    print_chunk_info,
                    print_only_id,
                } => {
                    if sync && overwrite {
                        return Err(anyhow!(
                            "Only one of --sync and --overwrite can be specified"
                        ));
                    }
                    let existing_file_action = if sync {
                        files::upload::ExistingDriveFileAction::Sync
                    } else if overwrite {
                        files::upload::ExistingDriveFileAction::Replace
                    } else {
                        files::upload::ExistingDriveFileAction::Skip
                    };

                    let options = files::upload::UploadOptions {
                        existing_file_action,
                        upload_directories: recursive,
                        force_mime_type: mime,
                    };
                    files::upload(
                        &file_path,
                        &destination,
                        &options,
                        &chunk_size,
                        print_chunk_errors,
                        print_chunk_info,
                        print_only_id,
                        2 * cli.workers,
                    )
                    .await?
                }

                FileCommand::Update {
                    file_id,
                    file_path,
                    mime,
                    chunk_size,
                    print_chunk_errors,
                    print_chunk_info,
                } => {
                    // fmt
                    files::update(files::update::Config {
                        file_id,
                        file_path,
                        mime_type: mime,
                        chunk_size,
                        print_chunk_errors,
                        print_chunk_info,
                    })
                    .await
                    .unwrap_or_else(handle_error)
                }

                FileCommand::Delete { file_id, recursive } => {
                    // fmt
                    files::delete(files::delete::Config {
                        file_id,
                        delete_directories: recursive,
                    })
                    .await
                    .unwrap_or_else(handle_error)
                }

                FileCommand::Mkdir {
                    name,
                    parent,
                    print_only_id,
                } => {
                    // fmt
                    files::mkdir(files::mkdir::Config {
                        id: None,
                        name,
                        parents: parent,
                        print_only_id,
                    })
                    .await
                    .unwrap_or_else(handle_error)
                }

                FileCommand::Rename { file_id, name } => {
                    // fmt
                    files::rename(files::rename::Config { file_id, name })
                        .await
                        .unwrap_or_else(handle_error)
                }

                FileCommand::Move { file_id, folder_id } => {
                    // fmt
                    files::mv(files::mv::Config {
                        file_id,
                        to_folder_id: folder_id,
                    })
                    .await
                    .unwrap_or_else(handle_error)
                }

                FileCommand::Copy { file_id, folder_id } => {
                    // fmt
                    files::copy(files::copy::Config {
                        file_id,
                        to_folder_id: folder_id,
                    })
                    .await
                    .unwrap_or_else(handle_error)
                }

                FileCommand::Import {
                    file_path,
                    parent,
                    print_only_id,
                } => {
                    // fmt
                    files::import(files::import::Config {
                        file_path,
                        parent,
                        print_only_id,
                    })
                    .await?
                }

                FileCommand::Export {
                    file_id,
                    file_path,
                    overwrite,
                } => {
                    let existing_file_action = if overwrite {
                        files::export::ExistingFileAction::Overwrite
                    } else {
                        files::export::ExistingFileAction::Abort
                    };

                    files::export(files::export::Config {
                        file_id,
                        file_path,
                        existing_file_action,
                    })
                    .await?
                }
            }
        }

        Command::Permissions { command } => {
            match command {
                PermissionCommand::Share {
                    file_id,
                    role,
                    type_,
                    discoverable,
                    email,
                    domain,
                } => {
                    // fmt
                    permissions::share(permissions::share::Config {
                        file_id,
                        role,
                        type_,
                        discoverable,
                        email,
                        domain,
                    })
                    .await
                    .unwrap_or_else(handle_error)
                }

                PermissionCommand::List {
                    file_id,
                    skip_header,
                    field_separator,
                } => {
                    // fmt
                    permissions::list(permissions::list::Config {
                        file_id,
                        skip_header,
                        field_separator,
                    })
                    .await
                    .unwrap_or_else(handle_error)
                }

                PermissionCommand::Revoke { file_id, all, id } => {
                    let action = if all {
                        permissions::revoke::RevokeAction::AllExceptOwner
                    } else if id.is_some() {
                        permissions::revoke::RevokeAction::Id(id.unwrap_or_default())
                    } else {
                        permissions::revoke::RevokeAction::Anyone
                    };

                    permissions::revoke(permissions::revoke::Config { file_id, action })
                        .await
                        .unwrap_or_else(handle_error)
                }
            }
        }

        Command::Version => {
            // fmt
            version::version()
        }
    }
    Ok(())
}

fn handle_error(err: impl Error) {
    eprintln!("Error: {}", err);
    std::process::exit(1);
}
