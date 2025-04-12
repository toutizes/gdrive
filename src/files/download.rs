use crate::common::disk_item::DiskItem;
use crate::common::drive_item::{DriveItem, DriveItemDetails};
use crate::common::hub_helper;
use crate::files::tasks::{DriveTask, DriveTaskStatus, TaskManager};
use crate::hub::Hub;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use human_bytes::human_bytes;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct DownloadOptions {
    pub existing_file_action: ExistingFileAction,
    pub follow_shortcuts: bool,
    pub download_directories: bool,
    pub dry_run: bool,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ExistingFileAction {
    Abort,
    Overwrite,
    SyncLocal,
}

pub async fn download(
    drive_path: &String,
    destination: &Option<PathBuf>,
    options: &DownloadOptions,
    workers: usize,
) -> Result<()> {
    let start = Instant::now();
    let hub = Arc::new(hub_helper::get_hub().await?);
    let tm = Arc::new(TaskManager::new(workers));

    let context = DownloadContext {
        hub: hub.clone(),
        tm: tm.clone(),
        options: options.clone(),
    };

    let drive_item = DriveItem::for_name(&hub, drive_path).await?;

    let disk_item = match &destination {
        Some(path) => {
            if !path.exists() {
                return Err(anyhow!("{}: does not exists", path.display()));
            }
            let mut item_path = path.clone();
            item_path.push(drive_item.name.clone());
            DiskItem::for_path(Some(item_path))
        }
        _ => DiskItem::for_path(None),
    };

    tm.add_task(DownloadTask::new(context.clone(), drive_item, disk_item));

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
    drive_item: DriveItem,
    disk_item: DiskItem,
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
    pub fn new(context: DownloadContext, drive_item: DriveItem, disk_item: DiskItem) -> Self {
        Self {
            context,
            drive_item,
            disk_item,
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
        match &self.drive_item.details {
            DriveItemDetails::Root {} => Err(anyhow!("Not downloading the full Google Drive")),
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
                self.drive_item.name,
            ));
        }

        let dir_created = self.disk_item.mkdir(self.context.options.dry_run)?;

        // Use to collect the existing drive files if we want to delete
        // the extra local files later.
        let mut keep_names: HashSet<String> = HashSet::new();
        let items = self.drive_item.list(&self.context.hub).await?;

        for item in items {
            keep_names.insert(item.name.clone());
            let item_disk_item = self.disk_item.join(&item.name)?;
            self.context.tm.add_task(DownloadTask::new(
                self.context.clone(),
                item,
                item_disk_item,
            ));
        }

        // NOTE: This runs after we launched the tasks to dowload the directory contents.
        let mut num_files_deleted: usize = 0;
        if self.context.options.existing_file_action == ExistingFileAction::SyncLocal {
            num_files_deleted = self
                .disk_item
                .delete_extra_local_files(&keep_names, self.context.options.dry_run)?;
        }

        *(self.stats.lock().unwrap()) = DownloadStats {
            num_files: 0,
            num_directories: dir_created,
            num_bytes: 0,
            num_deleted_files: num_files_deleted,
            num_errors: 0,
        };
        *(self.status.lock().unwrap()) = DriveTaskStatus::Completed(0);
        Ok(())
    }

    async fn download_file(&self, md5: &String) -> Result<()> {
        match &self.disk_item {
            DiskItem::FileOrDir { path, .. } => {
                if path.exists() {
                    if path.is_dir() {
                        return Err(anyhow!(
                            "{}: this drive file exists as a local directory, not downloaded",
                            self.disk_item
                        ));
                    }
                    if self.context.options.existing_file_action == ExistingFileAction::Abort {
                        println!("{}: file exists, skipped.", self.disk_item);
                    }
                    if self.disk_item.matches_md5(md5) {
                        return Ok(());
                    }
                }
            }
            _ => {}
        };

        let downloaded_bytes = self
            .drive_item
            .download(
                &self.context.hub,
                &self.disk_item,
                self.context.options.dry_run,
            )
            .await?;

        *(self.stats.lock().unwrap()) = DownloadStats {
            num_files: 1,
            num_directories: 0,
            num_bytes: downloaded_bytes,
            num_deleted_files: 0,
            num_errors: 0,
        };
        *(self.status.lock().unwrap()) = DriveTaskStatus::Completed(downloaded_bytes);
        Ok(())
    }

    async fn download_shortcut(&self, target_id: &String) -> Result<()> {
        let target_item = DriveItem::for_drive_id(&self.context.hub, &self.drive_item.path, target_id).await?;
        self.context.tm.add_task(DownloadTask::new(
            self.context.clone(),
            target_item,
            self.disk_item.clone(),
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
