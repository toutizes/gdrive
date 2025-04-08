use crate::common::disk_item::DiskItem;
use crate::common::drive_item::{DriveItem, DriveItemDetails};
use crate::common::drive_names;
use crate::common::hub_helper;
use crate::files;
use crate::files::tasks::{DriveTask, DriveTaskStatus, TaskManager};
use crate::hub::Hub;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use human_bytes::human_bytes;
use std::collections::HashSet;
use std::fs;
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

pub async fn download(config: Config) -> Result<()> {
    let start = Instant::now();
    let hub = Arc::new(hub_helper::get_hub().await?);

    let file_id: String;
    if let Some(ref id) = config.file_id {
        if config.file_name.is_some() {
            return Err(anyhow!(
                "Only one of file_id or file_name can be specified".to_string(),
            ));
        }
        file_id = id.clone();
    } else if let Some(ref name) = config.file_name {
        file_id = drive_names::resolve(&hub, &name).await?;
    } else {
        return Err(anyhow!(
            "Either file_id or file_name must be specified".to_string(),
        ));
    }

    let file = files::info::get_file(&hub, &file_id).await?;
    let item = DriveItem::from_drive_file(&file)?;
    let dest = match &config.destination {
        Destination::Stdout => None,
        Destination::CurrentDir => Some(PathBuf::from("")),
        Destination::Path(path) => Some(path.clone()),
    };

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

    pub async fn download(&self) -> Result<()> {
        match &self.item.details {
            DriveItemDetails::Directory {} => self.download_directory().await,
            DriveItemDetails::File { ref md5, .. } => self.download_file(md5).await,
            DriveItemDetails::Shortcut { ref target_id, .. } => {
                self.download_shortcut(target_id).await
            }
        }
    }

    async fn download_directory(&self) -> Result<()> {
        if !self.context.options.download_directories {
            return Err(anyhow!(
                "{}: drive file is a directory, use --recursive to download directories",
                self.item.name,
            ));
        }

        let filepath: &PathBuf = self.filepath.as_ref().unwrap();
        let num_dirs_created = create_dir_if_needed(filepath)?;
        let items =
            DriveItem::list_drive_dir(&self.context.hub, &Some(self.item.id.clone())).await?;

        // Use to collect the existing drive files if we want to delete
        // the extra local files later.
        let mut keep_names: HashSet<String> = HashSet::new();

        for item in items {
            keep_names.insert(item.name.clone());
            let itempath = Some(filepath.join(&item.name));
            self.context
                .tm
                .add_task(DownloadTask::new(self.context.clone(), item, itempath));
        }

        // NOTE: This runs after we launched the tasks to dowload the directory contents.
        let mut num_files_deleted: usize = 0;
        if self.context.options.existing_file_action == ExistingFileAction::SyncLocal {
            num_files_deleted = delete_extra_local_files(filepath, &keep_names)?;
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

    async fn download_file(&self, md5: &String) -> Result<()> {
        let (disk_item, display_str): (Option<DiskItem>, String) = match &self.filepath {
            Some(filepath) => {
                let item = DiskItem::for_path(&filepath);
                if filepath.exists() {
                    if filepath.is_dir() {
                        return Err(anyhow!(
                            "{}: this drive file exists as a local directory, not downloaded",
                            filepath.display()
                        ));
                    }
                    if self.context.options.existing_file_action == ExistingFileAction::Abort {
                        return Err(anyhow!("{}: file exists, skipped.", filepath.display()));
                    }
                    if item.matches_md5(md5) {
                        return Ok(());
                    }
                }
                (Some(item), filepath.display().to_string())
            }
            None => (None, self.item.id.clone())
        };
        let start = Instant::now();
        let file_bytes = self
            .item
            .download(&self.context.hub, disk_item.as_ref())
            .await?;
        let duration = start.elapsed();
        println!(
            "{}: {:.2}s",
         display_str,
            duration.as_secs_f64()
        );
        *(self.stats.lock().unwrap()) = DownloadStats {
            num_files: 1,
            num_directories: 0,
            num_bytes: file_bytes,
            num_deleted_files: 0,
            num_errors: 0,
        };
        *(self.status.lock().unwrap()) = DriveTaskStatus::Completed(file_bytes);
        Ok(())
    }

    async fn download_shortcut(&self, target_id: &String) -> Result<()> {
        let target_file = files::info::get_file(&self.context.hub, target_id).await?;
        let target_item = DriveItem::from_drive_file(&target_file)?;
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

fn create_dir_if_needed(path: &PathBuf) -> Result<usize> {
    // Only create the directory if it doesn't exist
    if !path.exists() {
        println!("{}: created directory", path.display());
        fs::create_dir_all(&path)?;
        Ok(1)
    } else {
        let file_type = fs::metadata(&path)?.file_type();
        if !file_type.is_dir() {
            return Err(anyhow!("{}: is not a directory, skipped", path.display()));
        }
        Ok(0)
    }
}

fn delete_extra_local_files(path: &PathBuf, names_to_keep: &HashSet<String>) -> Result<usize> {
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
