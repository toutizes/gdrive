use crate::common::drive_file;
use crate::common::file_tree_drive;
use crate::common::file_tree_drive::{FileTreeDrive, Folder};
use crate::common::hub_helper;
use crate::common::md5_writer::Md5Writer;
use crate::files;
use crate::files::tasks::{DriveTask, DriveTaskStatus, TaskManager};
use crate::hub::Hub;
use async_recursion::async_recursion;
use async_trait::async_trait;
use futures::stream::StreamExt;
use google_drive3::hyper;
use human_bytes::human_bytes;
use std::collections::HashSet;
use std::error;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fs;
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub struct Config {
    pub file_id: String,
    pub existing_file_action: ExistingFileAction,
    pub follow_shortcuts: bool,
    pub download_directories: bool,
    pub destination: Destination,
    pub workers: usize,
}

impl Config {
    fn canonical_destination_root(&self) -> Result<PathBuf, Error> {
        match &self.destination {
            Destination::CurrentDir => {
                let current_path = PathBuf::from(".");
                let canonical_current_path = current_path
                    .canonicalize()
                    .map_err(|err| Error::CanonicalizeDestinationPath(current_path.clone(), err))?;
                Ok(canonical_current_path)
            }

            Destination::Path(path) => {
                if !path.exists() {
                    Err(Error::DestinationPathDoesNotExist(path.clone()))
                } else if !path.is_dir() {
                    Err(Error::DestinationPathNotADirectory(path.clone()))
                } else {
                    path.canonicalize()
                        .map_err(|err| Error::CanonicalizeDestinationPath(path.clone(), err))
                }
            }

            Destination::Stdout => {
                // fmt
                Err(Error::StdoutNotValidDestination)
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Destination {
    CurrentDir,
    Path(PathBuf),
    Stdout,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ExistingFileAction {
    Abort,
    Overwrite,
    SyncLocal,
}

// Task for copying a file.
pub struct DownloadTask {
    hub: Arc<Hub>,
    driveid: String,
    // If not specified, download the file to stdout
    filepath: Option<PathBuf>,
    md5: Option<String>,
    pub status: Mutex<DriveTaskStatus>,
}

impl DownloadTask {
    pub fn new(
        hub: Arc<Hub>,
        driveid: String,
        filepath: Option<PathBuf>,
        md5: Option<String>,
    ) -> Self {
        Self {
            hub,
            driveid,
            filepath,
            status: Mutex::new(DriveTaskStatus::Pending),
            md5,
        }
    }

    pub async fn download(&self) -> Result<(), Error> {
        println!("Downloading {:?}", self.filepath);
        let body = download_file(&self.hub, &self.driveid)
            .await
            .map_err(Error::DownloadFile)?;
        match &self.filepath {
            Some(actual_path) => {
                let file_bytes = save_body_to_file(body, &actual_path, self.md5.clone()).await?;
                *(self.status.lock().unwrap()) = DriveTaskStatus::Completed(file_bytes);
            }
            None => {
                save_body_to_stdout(body).await?;
            }
        };
        Ok(())
    }
}

#[async_trait]
impl DriveTask for DownloadTask {
    fn get_status(&self) -> DriveTaskStatus {
        self.status.lock().unwrap().clone()
    }

    async fn process(&self) {
        let result = self.download().await;
        match result {
            Ok(_) => {}
            Err(e) => {
                *(self.status.lock().unwrap()) = DriveTaskStatus::Failed(e.to_string());
            }
        }
    }
}

#[async_recursion]
pub async fn download(config: Config) -> Result<(), Error> {
    let hub = Arc::new(hub_helper::get_hub().await.map_err(Error::Hub)?);

    let file = files::info::get_file(&hub, &config.file_id)
        .await
        .map_err(Error::GetFile)?;

    err_if_file_exists(&file, &config)?;
    err_if_directory(&file, &config)?;
    err_if_shortcut(&file, &config)?;

    if drive_file::is_shortcut(&file) {
        let target_file_id = file.shortcut_details.and_then(|details| details.target_id);

        err_if_shortcut_target_is_missing(&target_file_id)?;

        download(Config {
            file_id: target_file_id.unwrap_or_default(),
            ..config
        })
        .await?;
    } else if drive_file::is_directory(&file) {
        download_directory(&hub, &file, &config).await?;
    } else {
        download_regular(&hub, &file, &config).await?;
    }

    Ok(())
}

pub async fn download_regular(
    hub: &Arc<Hub>,
    file: &google_drive3::api::File,
    config: &Config,
) -> Result<(), Error> {
    match &config.destination {
        Destination::Stdout => {
            let task = DownloadTask::new(hub.clone(), config.file_id.clone(), None, None);
            task.process().await;
        }

        _ => {
            let file_name = file.name.clone().ok_or(Error::MissingFileName)?;
            let root_path = config.canonical_destination_root()?;
            let abs_file_path = root_path.join(&file_name);

            let task = DownloadTask::new(
                hub.clone(),
                config.file_id.clone(),
                Some(abs_file_path.clone()),
                file.md5_checksum.clone(),
            );
            task.process().await;
        }
    }

    Ok(())
}

fn create_dir_if_needed(path: &PathBuf) -> Result<usize, Error> {
    // Only create the directory if it doesn't exist
    if !path.exists() {
        println!("Creating directory {}", path.display());
        fs::create_dir_all(&path).map_err(|err| Error::CreateDirectory(path.clone(), err))?;
    } else {
        let file_type = fs::metadata(&path)
            .map_err(|err| Error::CreateDirectory(path.clone(), err))?
            .file_type();
        if !file_type.is_dir() {
            return Err(Error::IsNotDirectory(path.display().to_string()));
        }
    }
    Ok(1)
}

pub async fn download_directory(
    hub: &Arc<Hub>,
    file: &google_drive3::api::File,
    config: &Config,
) -> Result<(), Error> {
    let tree = FileTreeDrive::from_file(&hub, &file)
        .await
        .map_err(Error::CreateFileTree)?;

    let tree_info = tree.info();
    let mut num_created_directories: usize = 0;
    let mut num_deleted_files: usize = 0;
    let mut tm = TaskManager::new(config.workers);

    println!(
        "Found {} files in {} directories with a total size of {}",
        tree_info.file_count,
        tree_info.folder_count,
        human_bytes(tree_info.total_file_size as f64)
    );

    let root_path = config.canonical_destination_root()?;

    for folder in &tree.folders() {
        let folder_path = folder.relative_path();
        let abs_folder_path = root_path.join(&folder_path);

        num_created_directories += create_dir_if_needed(&abs_folder_path)?;

        for file in folder.files() {
            let file_path = file.relative_path();
            let abs_file_path = root_path.join(&file_path);

            if local_file_is_identical(&abs_file_path, &file) {
                continue;
            }

            let t: DownloadTask = DownloadTask::new(
                hub.clone(),
                file.drive_id.clone(),
                Some(abs_file_path.clone()),
                file.md5.clone(),
            );
            tm.add_task(Box::new(t));
        }
        // NOTE: this runs synchronously, not like the copies.
        if config.existing_file_action == ExistingFileAction::SyncLocal {
            num_deleted_files += delete_extra_local_files(&folder, abs_folder_path.clone())
                .await
                .map_err(|err| Error::ReadDirectory(abs_folder_path.clone(), err))?;
        }
    }
    report_stats(tm.wait().await, num_deleted_files, num_created_directories);

    Ok(())
}

pub fn report_stats(
    tasks: Vec<Arc<Box<dyn DriveTask + Sync + Send>>>,
    num_deleted_files: usize,
    num_created_directories: usize,
) {
    let mut num_success = 0;
    let mut num_failures = 0;
    let mut total_bytes = 0;

    for task in tasks {
        let status = task.get_status();
        match status {
            DriveTaskStatus::Pending => {}
            DriveTaskStatus::Completed(file_bytes) => {
                num_success += 1;
                total_bytes += file_bytes;
            }
            DriveTaskStatus::Failed(_) => {
                num_failures += 1;
            }
        };
    }
    println!(
        "Download finished.\n files: {}\n directories: {}\n bytes: {}\n deletions: {}\n errors: {}",
        num_success,
        num_created_directories,
        human_bytes(total_bytes as f64),
        num_deleted_files,
        num_failures
    );
}

pub async fn delete_extra_local_files(
    folder: &Folder,
    abs_folder_path: PathBuf,
) -> Result<usize, io::Error> {
    let mut drive_files: HashSet<String> = HashSet::new();
    for file in folder.files() {
        drive_files.insert(file.name);
    }

    let mut num_deleted_files: usize = 0;

    for entry in fs::read_dir(&abs_folder_path)? {
        let valid_entry = entry?;
        let file_type = valid_entry.file_type()?;
        if file_type.is_file() || file_type.is_symlink() {
            let relative_file_name = valid_entry.file_name().to_string_lossy().to_string();
            if !drive_files.contains(&relative_file_name) {
                let absolute_file_path = valid_entry.path();
                println!("Deleting: {:?}", absolute_file_path);
                fs::remove_file(absolute_file_path)?;
                num_deleted_files += 1;
            }
            // We should also delete directories recursively
            // Maybe a stronger prompt for allowing deletion of directories?
            // like --full-sync ?
        }
    }

    Ok(num_deleted_files)
}

pub async fn download_file(hub: &Hub, file_id: &str) -> Result<hyper::Body, google_drive3::Error> {
    let (response, _) = hub
        .files()
        .get(file_id)
        .supports_all_drives(true)
        .param("alt", "media")
        .add_scope(google_drive3::api::Scope::Full)
        .doit()
        .await?;

    Ok(response.into_body())
}

#[derive(Debug)]
pub enum Error {
    Hub(hub_helper::Error),
    GetFile(google_drive3::Error),
    DownloadFile(google_drive3::Error),
    MissingFileName,
    FileExists(PathBuf),
    IsDirectory(String),
    IsNotDirectory(String),
    Md5Mismatch { expected: String, actual: String },
    CreateFile(io::Error),
    CreateDirectory(PathBuf, io::Error),
    CopyFile(io::Error),
    RenameFile(io::Error),
    ReadChunk(hyper::Error),
    ReadDirectory(PathBuf, io::Error),
    WriteChunk(io::Error),
    CreateFileTree(file_tree_drive::Error),
    DestinationPathDoesNotExist(PathBuf),
    DestinationPathNotADirectory(PathBuf),
    CanonicalizeDestinationPath(PathBuf, io::Error),
    MissingShortcutTarget,
    IsShortcut(String),
    StdoutNotValidDestination,
}

impl error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Hub(err) => write!(f, "{}", err),
            Error::GetFile(err) => write!(f, "Failed getting file: {}", err),
            Error::DownloadFile(err) => write!(f, "Failed to download file: {}", err),
            Error::MissingFileName => write!(f, "File does not have a name"),
            Error::FileExists(path) => write!(
                f,
                "File '{}' already exists, use --overwrite to overwrite it",
                path.display()
            ),
            Error::IsDirectory(name) => write!(
                f,
                "'{}' is a directory, use --recursive to download directories",
                name
            ),
            Error::IsNotDirectory(name) => write!(
                f,
                "'{}' exists and is not a directory, use --sync to replace",
                name
            ),
            Error::Md5Mismatch { expected, actual } => {
                // fmt
                write!(
                    f,
                    "MD5 mismatch, expected: {}, actual: {}",
                    expected, actual
                )
            }
            Error::CreateFile(err) => write!(f, "Failed to create file: {}", err),
            Error::CreateDirectory(path, err) => write!(
                f,
                "Failed to create directory '{}': {}",
                path.display(),
                err
            ),
            Error::CopyFile(err) => write!(f, "Failed to copy file: {}", err),
            Error::ReadDirectory(path, err) => {
                write!(f, "Failed to read directory '{}': {}", path.display(), err)
            }
            Error::RenameFile(err) => write!(f, "Failed to rename file: {}", err),
            Error::ReadChunk(err) => write!(f, "Failed read from stream: {}", err),
            Error::WriteChunk(err) => write!(f, "Failed write to file: {}", err),
            Error::CreateFileTree(err) => write!(f, "Failed to create file tree: {}", err),
            Error::DestinationPathDoesNotExist(path) => {
                write!(f, "Destination path '{}' does not exist", path.display())
            }
            Error::DestinationPathNotADirectory(path) => {
                write!(
                    f,
                    "Destination path '{}' is not a directory",
                    path.display()
                )
            }
            Error::CanonicalizeDestinationPath(path, err) => write!(
                f,
                "Failed to canonicalize destination path '{}': {}",
                path.display(),
                err
            ),
            Error::MissingShortcutTarget => write!(f, "Shortcut does not have a target"),
            Error::IsShortcut(name) => write!(
                f,
                "'{}' is a shortcut, use --follow-shortcuts to download the file it points to",
                name
            ),
            Error::StdoutNotValidDestination => write!(
                f,
                "Stdout is not a valid destination for this combination of options"
            ),
        }
    }
}

// TODO: move to common
pub async fn save_body_to_file(
    mut body: hyper::Body,
    file_path: &PathBuf,
    expected_md5: Option<String>,
) -> Result<usize, Error> {
    // Create temporary file
    let tmp_file_path = file_path.with_extension("incomplete");
    let file = File::create(&tmp_file_path).map_err(Error::CreateFile)?;

    // Wrap file in writer that calculates md5
    let mut writer = Md5Writer::new(file);
    let mut written_bytes: usize = 0;

    // Read chunks from stream and write to file
    while let Some(chunk_result) = body.next().await {
        let chunk = chunk_result.map_err(Error::ReadChunk)?;
        writer.write_all(&chunk).map_err(Error::WriteChunk)?;
        written_bytes += chunk.len();
    }

    // Check md5
    err_if_md5_mismatch(expected_md5, writer.md5())?;

    // Rename temporary file to final file
    fs::rename(&tmp_file_path, &file_path).map_err(Error::RenameFile)?;

    Ok(written_bytes)
}

// TODO: move to common
pub async fn save_body_to_stdout(mut body: hyper::Body) -> Result<(), Error> {
    let mut stdout = io::stdout();

    // Read chunks from stream and write to stdout
    while let Some(chunk_result) = body.next().await {
        let chunk = chunk_result.map_err(Error::ReadChunk)?;
        stdout.write_all(&chunk).map_err(Error::WriteChunk)?;
    }

    Ok(())
}

fn err_if_file_exists(file: &google_drive3::api::File, config: &Config) -> Result<(), Error> {
    let file_name = file.name.clone().ok_or(Error::MissingFileName)?;

    let file_path = match &config.destination {
        Destination::CurrentDir => Some(PathBuf::from(".").join(file_name)),
        Destination::Path(path) => Some(path.join(file_name)),
        Destination::Stdout => None,
    };

    match file_path {
        Some(path) => {
            if path.exists() && config.existing_file_action == ExistingFileAction::Abort {
                Err(Error::FileExists(path.clone()))
            } else {
                Ok(())
            }
        }

        None => {
            // fmt
            Ok(())
        }
    }
}

fn err_if_directory(file: &google_drive3::api::File, config: &Config) -> Result<(), Error> {
    if drive_file::is_directory(file) && !config.download_directories {
        let name = file
            .name
            .as_ref()
            .map(|s| s.to_string())
            .unwrap_or_default();
        Err(Error::IsDirectory(name))
    } else {
        Ok(())
    }
}

fn err_if_shortcut(file: &google_drive3::api::File, config: &Config) -> Result<(), Error> {
    if drive_file::is_shortcut(file) && !config.follow_shortcuts {
        let name = file
            .name
            .as_ref()
            .map(|s| s.to_string())
            .unwrap_or_default();
        Err(Error::IsShortcut(name))
    } else {
        Ok(())
    }
}

fn err_if_shortcut_target_is_missing(target_id: &Option<String>) -> Result<(), Error> {
    if target_id.is_none() {
        Err(Error::MissingShortcutTarget)
    } else {
        Ok(())
    }
}

fn err_if_md5_mismatch(expected: Option<String>, actual: String) -> Result<(), Error> {
    let is_matching = expected.clone().map(|md5| md5 == actual).unwrap_or(true);

    if is_matching {
        Ok(())
    } else {
        Err(Error::Md5Mismatch {
            expected: expected.unwrap_or_default(),
            actual,
        })
    }
}

fn local_file_is_identical(path: &PathBuf, file: &file_tree_drive::File) -> bool {
    if path.exists() {
        let file_md5 = compute_md5_from_path(path).unwrap_or_else(|err| {
            eprintln!(
                "Warning: Error while computing md5 of '{}': {}",
                path.display(),
                err
            );

            String::new()
        });

        file.md5.clone().map(|md5| md5 == file_md5).unwrap_or(false)
    } else {
        false
    }
}

fn compute_md5_from_path(path: &PathBuf) -> Result<String, io::Error> {
    let input = File::open(path)?;
    let reader = BufReader::new(input);
    compute_md5_from_reader(reader)
}

fn compute_md5_from_reader<R: Read>(mut reader: R) -> Result<String, io::Error> {
    let mut context = md5::Context::new();
    let mut buffer = [0; 4096];

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        context.consume(&buffer[..count]);
    }

    Ok(format!("{:x}", context.compute()))
}
