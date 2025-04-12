use crate::common::delegate::{BackoffConfig, ChunkSize, UploadDelegateConfig};
use crate::common::disk_item::DiskItem;
use crate::common::drive_item::{DriveItem, DriveItemDetails};
use crate::common::hub_helper;
use crate::files::tasks::{DriveTask, DriveTaskStatus, TaskManager};
use crate::hub::Hub;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use clap::ValueEnum;
use mime::Mime;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone, ValueEnum, PartialEq)]
pub enum ExistingDriveFileAction {
    Skip,
    Replace,
    Sync,
}

#[derive(Debug, Clone)]
pub struct UploadOptions {
    pub existing_file_action: ExistingDriveFileAction,
    pub upload_directories: bool,
    pub force_mime_type: Option<Mime>,
    pub dry_run: bool,
}

pub async fn upload(
    file_path: &PathBuf,
    destination: &String,
    options: &UploadOptions,
    chunk_size: &ChunkSize,
    print_chunk_errors: bool,
    print_chunk_info: bool,
    _print_only_id: bool,
    workers: usize,
) -> Result<()> {
    let hub = Arc::new(hub_helper::get_hub().await?);

    let delegate_config = UploadDelegateConfig {
        chunk_size: chunk_size.clone(),
        backoff_config: BackoffConfig {
            max_retries: 100000,
            min_sleep: Duration::from_secs(1),
            max_sleep: Duration::from_secs(60),
        },
        print_chunk_errors,
        print_chunk_info,
    };

    let tm = Arc::new(TaskManager::new(workers));
    let disk_item = DiskItem::for_path(Some(file_path.clone()));

    let dest = DriveItem::for_name(&hub, destination).await?;
    let existing_items = dest.list_disk_item(&hub, &disk_item).await?;

    let task = UploadTask::new(
        UploadContext {
            hub: hub.clone(),
            tm: tm.clone(),
            delegate_config,
            options: options.clone(),
        },
        disk_item,
        dest,
        existing_items,
    );

    tm.add_task(task);
    tm.wait().await;

    Ok(())
}

#[derive(Clone)]
pub struct UploadContext {
    hub: Arc<Hub>,
    tm: Arc<TaskManager<UploadTask>>,
    delegate_config: UploadDelegateConfig,
    options: UploadOptions,
}

pub struct UploadTask {
    context: UploadContext,
    item: DiskItem,
    // Parent drive object where to upload the item
    dest_parent: DriveItem,
    // List of items with the name item.name in the parent
    existing_items: Vec<DriveItem>,
    status: Mutex<DriveTaskStatus>,
    // stats: Mutex<UploadStats>,
}

#[derive(Debug)]
pub struct UploadStats {
    pub num_files: usize,
    pub num_directories: usize,
    pub num_bytes: usize,
    pub num_deleted_files: usize,
    pub num_errors: usize,
}

impl UploadTask {
    pub fn new(
        context: UploadContext,
        item: DiskItem,
        dest_parent: DriveItem,
        existing_items: Vec<DriveItem>,
    ) -> Self {
        Self {
            context,
            item,
            dest_parent,
            existing_items,
            status: Mutex::new(DriveTaskStatus::Pending),
            // stats: Mutex::new(UploadStats {
            //     num_files: 0,
            //     num_directories: 0,
            //     num_bytes: 0,
            //     num_deleted_files: 0,
            //     num_errors: 0,
            // }),
        }
    }

    async fn upload(&self) -> Result<()> {
        if self.item.is_dir() {
            self.maybe_upload_directory().await
        } else if self.item.is_file() {
            self.maybe_upload_file().await
        } else {
            Err(anyhow!("{}: not a file or directory, skipped", self.item))
        }
    }

    // Do some checks before uploading the contents of a directory,
    // optionally creating it.
    async fn maybe_upload_directory(&self) -> Result<()> {
        if !self.context.options.upload_directories {
            return Err(anyhow!(
                "{}: is a directory. Use --recursive to upload",
                self.item
            ));
        } else if self.existing_items.is_empty() {
            // Directory does not exist on drive, create it, then continue uploading.
            let name = self.item.require_name()?;
            let drive_folder = self
                .dest_parent
                .mkdir(
                    &self.context.hub,
                    &self.context.delegate_config,
                    &name,
                    self.context.options.dry_run,
                )
                .await?;
            return self.do_upload_directory(drive_folder, vec![]).await;
        } else if self.existing_items.len() > 1 {
            // More than one item with the same exist on drive, abort.
            return Err(anyhow!(
                "{}: multiple drive entries with exist with that name",
                self.item
            ));
        } else {
            // Exactly one item with the same exist on drive, continue if it is a directory.
            let existing_item = self.existing_items[0].clone();
            match &self.existing_items[0].details {
                DriveItemDetails::File { .. } | DriveItemDetails::Shortcut { .. } => {
                    return Err(anyhow!(
                        "{}: exists in Google Drive but is not a directory, skipping",
                        self.item
                    ));
                }
                DriveItemDetails::Directory { .. } | DriveItemDetails::Root {} => {
                    let drive_items = existing_item.list(&self.context.hub).await?;
                    return self.do_upload_directory(existing_item, drive_items).await;
                }
            }
        }
    }

    // Do the actual job of uploading the contents of a directory.  At
    // this point the drive directory exists and we only have to add
    // tasks to upload each entry in the local directory.
    async fn do_upload_directory(
        &self,
        drive_dir: DriveItem,
        drive_items: Vec<DriveItem>,
    ) -> Result<()> {
        // List all the existing drive items.
        let mut drive_item_map: HashMap<String, Vec<DriveItem>> = HashMap::new();

        for drive_item in &drive_items {
            let name = drive_item.name.clone();
            if let Some(in_map_items) = drive_item_map.get_mut(&name) {
                in_map_items.push(drive_item.clone());
            } else {
                drive_item_map.insert(name, vec![drive_item.clone()]);
            }
        }

        // Iterate over all the local items, creating upload tasks.
        let mut disk_item_set: HashSet<String> = HashSet::new();
        for disk_item in self.item.list_dir()? {
            let disk_name = disk_item.require_name()?;
            disk_item_set.insert(disk_name.clone());
            let drive_items = drive_item_map.get(disk_name).cloned().unwrap_or_default();
            let task = UploadTask::new(
                self.context.clone(),
                disk_item,
                drive_dir.clone(),
                drive_items,
            );
            self.context.tm.add_task(task);
        }

        // If in sync mode, delete drive files that do not exist on the local disk.
        if self.context.options.existing_file_action == ExistingDriveFileAction::Sync {
            for drive_item in &drive_items {
                if !disk_item_set.contains(&drive_item.name) {
                    drive_item
                        .delete(&self.context.hub, self.context.options.dry_run)
                        .await?;
                }
            }
        }

        Ok(())
    }

    // Do some checks before uploading a file.
    async fn maybe_upload_file(&self) -> Result<()> {
        if self.existing_items.is_empty() {
            self.dest_parent
                .upload(
                    &self.context.hub,
                    &self.item,
                    &self.context.options.force_mime_type,
                    self.context.delegate_config.clone(),
                    self.context.options.dry_run,
                )
                .await?;
            return Ok(());
        }
        match self.context.options.existing_file_action {
            ExistingDriveFileAction::Skip => {
                println!(
                    "{}: exists in Google Drive, skipped. Use --overwrite or --sync to replace",
                    self.item
                );
                Ok(())
            }
            ExistingDriveFileAction::Sync | ExistingDriveFileAction::Replace => {
                if self.existing_items.len() > 1 {
                    println!(
                        "{}: {} items with the same name on Google Drive, skipped",
                        self.item,
                        self.existing_items.len()
                    );
                    return Ok(());
                }
                let existing_item = &self.existing_items[0];
                match &existing_item.details {
                    DriveItemDetails::Root { .. } => {
                        println!("{}: is a Google Drive root, skipped", self.item);
                        Ok(())
                    }
                    DriveItemDetails::Directory { .. } => {
                        println!("{}: is a folder on Google Drive, skipped", self.item);
                        Ok(())
                    }
                    DriveItemDetails::Shortcut { .. } => {
                        println!("{}: is a shortcut on Google Drive, skipped", self.item);
                        Ok(())
                    }
                    DriveItemDetails::File { md5, .. } => {
                        if self.item.matches_md5(&md5) {
                            println!(
                                "{}: file already exists and is identical on Google Drive, skipped",
                                self.item
                            );
                            return Ok(());
                        }
                        println!("{}: updating existing Google Drive file", self.item);
                        self.do_update_file(existing_item, self.context.options.dry_run)
                            .await
                    }
                }
            }
        }
    }

    async fn do_update_file(&self, drive_item: &DriveItem, dry_run: bool) -> Result<()> {
        match &drive_item.details {
            DriveItemDetails::File { .. } => {
                _ = &drive_item
                    .update(
                        &self.context.hub,
                        &self.item,
                        &None,
                        self.context.delegate_config.clone(),
                        dry_run,
                    )
                    .await?;

                Ok(())
            }
            _ => {
                return Err(anyhow!(
                    "{}: existing drive items is not a file, skipped",
                    self.item
                ));
            }
        }
    }
}

#[async_trait]
impl DriveTask for UploadTask {
    fn get_status(&self) -> DriveTaskStatus {
        self.status.lock().unwrap().clone()
    }

    async fn process(&self) {
        let result = self.upload().await;
        match result {
            Ok(_) => {}
            Err(e) => {
                println!("Err: {}", e.to_string());
                *(self.status.lock().unwrap()) = DriveTaskStatus::Failed(e.to_string());
            }
        }
    }
}
