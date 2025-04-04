use crate::common::drive_file_helper;
use crate::common::drive_item::{DriveItem, DriveItemDetails};
use crate::common::drive_names;
use crate::common::error::CommonError;
use crate::common::hub_helper;
use crate::files;
use crate::files::list;
use crate::files::tasks::{DriveTask, DriveTaskStatus, TaskManager};
use crate::hub::Hub;
use async_trait::async_trait;
use human_bytes::human_bytes;
use std::collections::HashSet;
use std::fs;
use std::fs::File;
use std::io;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

pub async fn download(config: Config) -> Result<(), CommonError> {
    let start = Instant::now();
    let hub = Arc::new(hub_helper::get_hub().await.map_err(CommonError::Hub)?);

    let file_id: String;
    if let Some(ref id) = config.file_id {
        if config.file_name.is_some() {
            return Err(CommonError::Generic(
                "Only one of file_id or file_name can be specified".to_string(),
            ));
        }
        file_id = id.clone();
    } else if let Some(ref name) = config.file_name {
        file_id = drive_names::resolve(&hub, &name)
            .await
            .map_err(|err| CommonError::Generic(err.to_string()))?;
    } else {
        return Err(CommonError::Generic(
            "Either file_id or file_name must be specified".to_string(),
        ));
    }

    let file = files::info::get_file(&hub, &file_id)
        .await
        .map_err(CommonError::GetFile)?;
    let item = DriveItem::from_drive_file(&file)
        .map_err(|err| CommonError::Generic(format!("{}", err)))?;

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

    tm.add_task(DownloadTask::new(context.clone(), item, dest));
    let tasks = tm.wait().await;
    report_stats(tasks, start.elapsed());
    Ok(())
}

fn report_stats(tasks: Vec<Arc<Box<DownloadTask>>>, duration: Duration) {
    let mut acc = DownloadStats {
        num_files: 0,
        num_directories: 0,
        num_bytes: 0,
        num_deleted_files: 0,
        num_errors: 0,
    };
    for task in &tasks {
        let stats = task.stats.lock().unwrap();
        acc.accumulate(&stats);
    }
    println!(
        "Download finished.\n directories: {}\n files: {}\n bytes: {}\n duratin: {:.2}s\n bandwidth: {:.2} Mb/s\n deletions: {}\n errors: {}",
        acc.num_directories,
        acc.num_files,
        human_bytes(acc.num_bytes as f64),
        duration.as_secs_f64(),
        acc.num_bytes as f64/ (1024.0 * 128.0 * duration.as_secs_f64()),
        acc.num_deleted_files,
        acc.num_errors,
    );
}

pub struct DownloadTask {
    context: DownloadContext,
    item: DriveItem,
    filepath: Option<PathBuf>, // If None, download the file to stdout
    status: Mutex<DriveTaskStatus>,
    stats: Mutex<DownloadStats>,
}

#[derive(Clone)]
pub struct DownloadContext {
    hub: Arc<Hub>,
    tm: Arc<TaskManager<DownloadTask>>,
    options: DownloadOptions,
}

#[derive(Debug)]
pub struct DownloadStats {
    pub num_files: usize,
    pub num_directories: usize,
    pub num_bytes: usize,
    pub num_deleted_files: usize,
    pub num_errors: usize,
}

impl DownloadStats {
    pub fn accumulate(&mut self, stat: &DownloadStats) {
        self.num_files += stat.num_files;
        self.num_directories += stat.num_directories;
        self.num_bytes += stat.num_bytes;
        self.num_deleted_files += stat.num_deleted_files;
        self.num_errors += stat.num_errors;
    }
}

impl DownloadTask {
    pub fn new(context: DownloadContext, item: DriveItem, filepath: Option<PathBuf>) -> Self {
        Self {
            context,
            item,
            filepath,
            status: Mutex::new(DriveTaskStatus::Pending),
            stats: Mutex::new(DownloadStats {
                num_files: 0,
                num_directories: 0,
                num_bytes: 0,
                num_deleted_files: 0,
                num_errors: 0,
            }),
        }
    }

    pub async fn download(&self) -> Result<(), CommonError> {
        match &self.item.details {
            DriveItemDetails::Directory {} => {
                self.download_directory().await?;
            }
            DriveItemDetails::File { ref md5, .. } => {
                self.download_file(md5).await?;
            }
            DriveItemDetails::Shortcut { ref target_id, .. } => {
                self.download_shortcut(target_id).await?;
            }
        }
        Ok(())
    }

    async fn download_directory(&self) -> Result<(), CommonError> {
        if !self.context.options.download_directories {
            return Err(CommonError::Generic(format!(
                "{}: drive file is a directory, use --recursive to download directories",
                self.item.name,
            )));
        }

        let filepath: &PathBuf = self
            .filepath
            .as_ref()
            .ok_or(CommonError::Generic(
                "Directories cannot be downloaded to stdout".to_string(),
            ))
            .unwrap();

        let num_dirs_created = create_dir_if_needed(filepath)?;

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
        .map_err(|err| CommonError::Generic(format!("{}", err)))?;

        // Use to collect the existing drive files if we want to delete
        // the extra local files later.
        let mut keep_names: HashSet<String> = HashSet::new();

        for file in &files {
            let item_result = DriveItem::from_drive_file(&file)
                .map_err(|err| CommonError::Generic(format!("{}", err)));
            match item_result {
                Ok(item) => {
                    keep_names.insert(item.name.clone());

                    let itempath = Some(filepath.join(&item.name));

                    self.context.tm.add_task(DownloadTask::new(
                        self.context.clone(),
                        item,
                        itempath,
                    ));
                }
                Err(err) => {
                    println!("{:?}: {}", file.name, err.to_string());
                }
            }
        }

        // NOTE: This runs after we launched the tasks to dowload the directory contents.
        let mut num_files_deleted: usize = 0;
        if self.context.options.existing_file_action == ExistingFileAction::SyncLocal {
            num_files_deleted = delete_extra_local_files(filepath, &keep_names)
                .map_err(|err| CommonError::Generic(format!("{}", err)))?;
        }

        *(self.stats.lock().unwrap()) = DownloadStats {
            num_files: 0,
            num_directories: num_dirs_created,
            num_bytes: 0,
            num_deleted_files: num_files_deleted,
            num_errors: 0,
        };
        *(self.status.lock().unwrap()) = DriveTaskStatus::Completed(0);
        Ok(())
    }

    async fn download_file(&self, md5: &String) -> Result<(), CommonError> {
        match &self.filepath {
            Some(filepath) => {
                let options = &self.context.options;
                if filepath.exists() {
                    if filepath.is_dir() {
                        return Err(CommonError::Generic(format!(
                            "{}: this drive file exists as a local directory, not downloaded",
                            filepath.display()
                        )));
                    }
                    if options.existing_file_action == ExistingFileAction::Abort {
                        return Err(CommonError::FileExists(filepath.clone()));
                    }
                    if local_file_is_identical(filepath, md5) {
                        return Ok(());
                    }
                }
                let start = Instant::now();
                let file_bytes = drive_file_helper::download_file(
                    &self.context.hub,
                    &self.item.id,
                    Some(md5.clone()),
                    Some(&filepath),
                )
                .await?;
                *(self.status.lock().unwrap()) = DriveTaskStatus::Completed(file_bytes);
                let duration = start.elapsed();
                println!("{}: {:.2}s", filepath.display(), duration.as_secs_f64());
                *(self.stats.lock().unwrap()) = DownloadStats {
                    num_files: 1,
                    num_directories: 0,
                    num_bytes: file_bytes,
                    num_deleted_files: 0,
                    num_errors: 0,
                };
            }
            None => {
                let file_bytes =
                    drive_file_helper::download_file(&self.context.hub, &self.item.id, None, None)
                        .await?;
                *(self.stats.lock().unwrap()) = DownloadStats {
                    num_files: 1,
                    num_directories: 0,
                    num_bytes: file_bytes,
                    num_deleted_files: 0,
                    num_errors: 0,
                };
            }
        };
        Ok(())
    }

    async fn download_shortcut(&self, target_id: &String) -> Result<(), CommonError> {
        let target_file = files::info::get_file(&self.context.hub, target_id)
            .await
            .map_err(CommonError::GetFile)?;
        let target_item = DriveItem::from_drive_file(&target_file)
            .map_err(|err| CommonError::Generic(format!("{}", err)))?;
        self.context.tm.add_task(DownloadTask::new(
            self.context.clone(),
            target_item,
            self.filepath.clone(),
        ));
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
                println!("Err: {}", e.to_string());
                *(self.status.lock().unwrap()) = DriveTaskStatus::Failed(e.to_string());
            }
        }
    }
}

fn create_dir_if_needed(path: &PathBuf) -> Result<usize, CommonError> {
    // Only create the directory if it doesn't exist
    if !path.exists() {
        println!("{}: created directory", path.display());
        fs::create_dir_all(&path).map_err(|err| CommonError::CreateDirectory(path.clone(), err))?;
        return Ok(1);
    } else {
        let file_type = fs::metadata(&path)
            .map_err(|err| CommonError::CreateDirectory(path.clone(), err))?
            .file_type();
        if !file_type.is_dir() {
            return Err(CommonError::IsNotDirectory(path.display().to_string()));
        }
    }
    Ok(0)
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
            let delete_path = &valid_entry.path();
            fs::remove_file(delete_path)?;
            println!("{}: deleted", delete_path.display());
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

fn local_file_is_identical(path: &PathBuf, drive_md5: &String) -> bool {
    if path.exists() {
        let file_md5 = compute_md5_from_path(path).unwrap_or_else(|err| {
            eprintln!(
                "Warning: CommonError while computing md5 of '{}': {}",
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
