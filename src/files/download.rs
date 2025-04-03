
use crate::common::drive_item::{DriveItem, DriveItemDetails};
use crate::common::drive_names;
use crate::common::hub_helper;
use crate::common::md5_writer::Md5Writer;
use crate::files;
use crate::files::list;
use crate::files::tasks::{DriveTask, DriveTaskStatus, TaskManager};
use crate::hub::Hub;
use async_trait::async_trait;
use futures::stream::StreamExt;
use google_drive3::hyper;
use human_bytes::human_bytes;
use std::collections::HashSet;
use std::error;
use std::fmt::{Display,Formatter};
use std::fs;
use std::fs::File;
use std::io;
use std::io::{BufReader, Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Clone, Debug)]
pub struct DownloadOptions {
    pub existing_file_action: ExistingFileAction,
    pub follow_shortcuts: bool,
    pub download_directories: bool,
}

pub struct Config {
    pub file_id: Option<String>,
    pub file_name: Option<String>,
    pub destination: Destination,
    pub options: DownloadOptions,
    pub workers: usize,
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

pub async fn download(config: Config) -> Result<(), Error> {
    let hub = Arc::new(hub_helper::get_hub().await.map_err(Error::Hub)?);

    let file_id: String;
    if let Some(ref id) = config.file_id {
        if config.file_name.is_some() {
            return Err(Error::Generic(
                "Only one of file_id or file_name can be specified".to_string(),
            ));
        }
        file_id = id.clone();
    } else if let Some(ref name) = config.file_name {
        file_id = drive_names::resolve(&hub, &name)
            .await
            .map_err(|err| Error::Generic(err.to_string()))?;
    } else {
        return Err(Error::Generic(
            "Either file_id or file_name must be specified".to_string(),
        ));
    }

    let file = files::info::get_file(&hub, &file_id)
        .await
        .map_err(Error::GetFile)?;
    let item =
        DriveItem::from_drive_file(&file).map_err(|err| Error::Generic(format!("{}", err)))?;

    let dest: Option<PathBuf>;
    match &config.destination {
        Destination::Stdout => {
            dest = None;
        }
        Destination::CurrentDir => {
            dest = Some(PathBuf::from(""));
        }

        Destination::Path(path) => {
            dest = Some(path.clone());
        }
    }

    let tm = Arc::new(TaskManager::new(config.workers));
    let context = DownloadContext {
        hub: hub.clone(),
        tm: tm.clone(),
        options: (&config.options).clone(),
    };

    tm.add_task(Box::new(DownloadTask::new(context.clone(), item, dest)));
    tm.wait().await;
    Ok(())
}

#[derive(Clone)]
pub struct DownloadContext {
    hub: Arc<Hub>,
    tm: Arc<TaskManager>,
    options: DownloadOptions,
}

pub struct DownloadTask {
    context: DownloadContext,
    item: DriveItem,
    filepath: Option<PathBuf>, // If None, download the file to stdout
    status: Mutex<DriveTaskStatus>,
}

impl DownloadTask {
    pub fn new(context: DownloadContext, item: DriveItem, filepath: Option<PathBuf>) -> Self {
        Self {
            context,
            item,
            filepath,
            status: Mutex::new(DriveTaskStatus::Pending),
        }
    }

    pub async fn download(&self) -> Result<(), Error> {
        match &self.item.details {
            DriveItemDetails::Directory {} => {
                return self.download_directory().await;
            }
            DriveItemDetails::File { ref md5, .. } => {
                return self.download_file(md5).await;
            }
            DriveItemDetails::Shortcut { ref target_id, .. } => {
                return self.download_shortcut(target_id).await;
            }
        }
    }

    async fn download_directory(&self) -> Result<(), Error> {
        if !self.context.options.download_directories {
            return Err(Error::Generic(format!(
                "{}: drive file is a directory, use --recursive to download directories",
                self.item.name,
            )));
        }

        let filepath: &PathBuf = self
            .filepath
            .as_ref()
            .ok_or(Error::Generic(
                "Directories cannot be downloaded to stdout".to_string(),
            ))
            .unwrap();

        create_dir_if_needed(filepath)?;

        let files = list::list_files(
            &self.context.hub,
            &list::ListFilesConfig {
                query: list::ListQuery::FilesInFolder {
                    folder_id: self.item.id.clone(),
                },
                order_by: Default::default(),
                max_files: usize::MAX,
            },
        )
        .await
        .map_err(|err| Error::Generic(format!("{}", err)))?;

        // Use to collect the existing drive files if we want to delete
        // the extra local files later.
        let mut keep_names: HashSet<String> = HashSet::new();

        // Ge
        for file in &files {
            let item = DriveItem::from_drive_file(&file)
                .map_err(|err| Error::Generic(format!("{}", err)))?;
            keep_names.insert(item.name.clone());

            let itempath = Some(filepath.join(&item.name));

            self.context.tm.add_task(Box::new(DownloadTask::new(
                self.context.clone(),
                item,
                itempath,
            )));
        }

        // NOTE: This runs after we launched the tasks to dowload the directory contents.
        if self.context.options.existing_file_action == ExistingFileAction::SyncLocal {
            delete_extra_local_files(filepath, &keep_names)
                .map_err(|err| Error::Generic(format!("{}", err)))?;
        }

        *(self.status.lock().unwrap()) = DriveTaskStatus::Completed(0);
        Ok(())
    }

    async fn download_file(&self, md5: &String) -> Result<(), Error> {
        match &self.filepath {
            Some(filepath) => {
                let options = &self.context.options;
                if filepath.exists() {
                    if filepath.is_dir() {
                        return Err(Error::Generic(format!(
                            "{}: this drive file exists as a local directory, not downloaded",
                            filepath.display()
                        )));
                    }
                    if options.existing_file_action == ExistingFileAction::Abort {
                        return Err(Error::FileExists(filepath.clone()));
                    }
                    if local_file_is_identical(filepath, md5) {
                        return Ok(());
                    }
                }
                let start = Instant::now();
                let body = download_file(&self.context.hub, &self.item.id)
                    .await
                    .map_err(Error::DownloadFile)?;
                let file_bytes = save_body_to_file(body, &filepath, Some(md5.clone())).await?;
                *(self.status.lock().unwrap()) = DriveTaskStatus::Completed(file_bytes);
                let duration = start.elapsed();
                println!("{}: {}s", filepath.display(), duration.as_secs());
            }
            None => {
                let body = download_file(&self.context.hub, &self.item.id)
                    .await
                    .map_err(Error::DownloadFile)?;
                save_body_to_stdout(body).await?;
            }
        };
        Ok(())
    }

    async fn download_shortcut(&self, target_id: &String) -> Result<(), Error> {
        let target_file = files::info::get_file(&self.context.hub, target_id)
            .await
            .map_err(Error::GetFile)?;
        let target_item = DriveItem::from_drive_file(&target_file)
            .map_err(|err| Error::Generic(format!("{}", err)))?;
        self.context.tm.add_task(Box::new(DownloadTask::new(
            self.context.clone(),
            target_item,
            self.filepath.clone(),
        )));
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

fn delete_extra_local_files(
    path: &PathBuf,
    names_to_keep: &HashSet<String>,
) -> Result<usize, std::io::Error> {
    let mut n: usize = 0;
    for entry in fs::read_dir(path)? {
        let valid_entry = entry?;
        let entry_name = valid_entry.file_name().to_string_lossy().to_string();
        if names_to_keep.contains(&entry_name) {
            continue;
        }
        let entry_type = valid_entry.file_type()?;
        if entry_type.is_file() || entry_type.is_symlink() {
            let absolute_file_path = valid_entry.path();
            println!("Deleting: {:?}", absolute_file_path);
            fs::remove_file(absolute_file_path)?;
            n += 1;
        } else {
            println!(
                "{}: not deleting (not a file or symlink)",
                path.join(entry_name).display(),
            );
        }
    }
    Ok(n)
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
    // CreateFileTree(file_tree_drive::Error),
    DestinationPathDoesNotExist(PathBuf),
    DestinationPathNotADirectory(PathBuf),
    CanonicalizeDestinationPath(PathBuf, io::Error),
    MissingShortcutTarget,
    IsShortcut(String),
    StdoutNotValidDestination,
    Generic(String),
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
            // Error::CreateFileTree(err) => write!(f, "Failed to create file tree: {}", err),
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
            Error::Generic(s) => write!(f, "{}", s),
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

fn local_file_is_identical(path: &PathBuf, drive_md5: &String) -> bool {
    if path.exists() {
        let file_md5 = compute_md5_from_path(path).unwrap_or_else(|err| {
            eprintln!(
                "Warning: Error while computing md5 of '{}': {}",
                path.display(),
                err
            );

            String::new()
        });

        file_md5 == *drive_md5
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
