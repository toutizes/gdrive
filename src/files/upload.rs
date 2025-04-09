use crate::common::delegate::{BackoffConfig, ChunkSize, UploadDelegateConfig};
use crate::common::disk_item::DiskItem;
use crate::common::drive_item::{DriveItem, DriveItemDetails};
use crate::common::drive_names;
use crate::common::file_info::FileInfo;
use crate::common::hub_helper;
use crate::files::mkdir;
use crate::files::tasks::{DriveTask, DriveTaskStatus, TaskManager};
use crate::hub::Hub;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use clap::ValueEnum;
use mime::Mime;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::str::FromStr;
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
    let disk_item = DiskItem::for_path(&file_path);

    let resolved_id = drive_names::resolve(&hub, destination).await?;
    let existing_items = DriveItem::from_disk_item(&hub, &disk_item, &resolved_id).await?;

    let parents: Vec<String> = if let Some(parent_id) = resolved_id {
        vec![parent_id.clone()]
    } else {
        vec![]
    };

    let task = UploadTask::new(
        UploadContext {
            hub: hub.clone(),
            tm: tm.clone(),
            delegate_config,
            options: options.clone(),
        },
        disk_item,
        parents,
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
    // Parent where to upload. TODO: make it an Option<DriveItem> with None => root.
    parent_id: Vec<String>,
    // List of items with the name item.name in the parent_id folder.
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
        parent_id: Vec<String>,
        existing_items: Vec<DriveItem>,
    ) -> Self {
        Self {
            context,
            item,
            parent_id,
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
        if self.item.path.is_dir() {
            self.maybe_upload_directory().await
        } else if self.item.path.is_file() {
            self.maybe_upload_file().await
        } else {
            Err(anyhow!(
                "{}: not a file or directory, skipped",
                self.item.path.display()
            ))
        }
    }

    // Do some checks before uploading the contents of a directory,
    // optionally creating it.
    async fn maybe_upload_directory(&self) -> Result<()> {
        if !self.context.options.upload_directories {
            return Err(anyhow!(
                "{}: is a directory. Use --recursive to upload",
                self.item.path.display()
            ));
        } else if self.existing_items.is_empty() {
            // Directory does not exist on drive, create it, then continue uploading.
            let name = self.item.require_name()?;
            let drive_folder = mkdir::create_directory(
                &self.context.hub,
                &mkdir::Config {
                    id: None,
                    name: name.clone(),
                    parents: Some(self.parent_id.clone()),
                    print_only_id: false,
                },
                self.context.delegate_config.clone(),
            )
            .await?;
            return self
                .do_upload_directory(DriveItem::from_drive_file(&drive_folder)?, vec![])
                .await;
        } else if self.existing_items.len() > 1 {
            // More than one item with the same exist on drive, abort.
            return Err(anyhow!(
                "{}: multiple drive entries with exist with that name",
                self.item.path.display()
            ));
        } else {
            // Exactly one item with the same exist on drive, continue if it is a directory.
            let existing_item = self.existing_items[0].clone();
            match &self.existing_items[0].details {
                DriveItemDetails::File { .. } | DriveItemDetails::Shortcut { .. } => {
                    return Err(anyhow!(
                        "{}: exists in Google Drive but is not a directory, skipping",
                        self.item.path.display()
                    ));
                }
                DriveItemDetails::Directory { .. } => {
                    let drive_items = DriveItem::list_drive_dir(
                        &self.context.hub,
                        &Some(existing_item.id.clone()),
                    )
                    .await?;
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
        let disk_items = self.item.list_dir()?;
        for disk_item in disk_items {
            let disk_name = disk_item.require_name()?;
            disk_item_set.insert(disk_name.clone());
            let drive_items = drive_item_map.get(disk_name).cloned().unwrap_or_default();
            let task = UploadTask::new(
                self.context.clone(),
                disk_item,
                vec![drive_dir.id.clone()],
                drive_items,
            );
            self.context.tm.add_task(task);
        }

        // If in sync mode, delete drive files that do not exist on the local disk.
        if self.context.options.existing_file_action == ExistingDriveFileAction::Sync {
            for drive_item in &drive_items {
                if !disk_item_set.contains(&drive_item.name) {
                    // TODO: Show the Google Drive path when known.
                    println!("{}: deleting existing file", drive_item.name);
                    drive_item.delete(&self.context.hub).await?;
                }
            }
        }

        Ok(())
    }

    // Do some checks before uploading a file.
    async fn maybe_upload_file(&self) -> Result<()> {
        if self.existing_items.is_empty() {
            println!("{}: uploading to Google Drive", self.item.path.display());
            DriveItem::upload(
                &self.context.hub,
                &self.item,
                &self.context.options.force_mime_type,
                self.parent_id.clone(),
                self.context.delegate_config.clone(),
            )
            .await?;
            return Ok(());
        }
        match self.context.options.existing_file_action {
            ExistingDriveFileAction::Skip => {
                println!(
                    "{}: exists in Google Drive, skipped. Use --overwrite or --sync to replace",
                    self.item.path.display()
                );
                Ok(())
            }
            ExistingDriveFileAction::Sync | ExistingDriveFileAction::Replace => {
                if self.existing_items.len() > 1 {
                    println!(
                        "{}: {} items with the same name on Google Drive, skipped",
                        self.item.path.display(),
                        self.existing_items.len()
                    );
                    return Ok(());
                }
                let existing_item = &self.existing_items[0];
                match &existing_item.details {
                    DriveItemDetails::Directory { .. } => {
                        println!(
                            "{}: is a folder on Google Drive, skipped",
                            self.item.path.display()
                        );
                        Ok(())
                    }
                    DriveItemDetails::Shortcut { .. } => {
                        println!(
                            "{}: is a shortcut on Google Drive, skipped",
                            self.item.path.display()
                        );
                        Ok(())
                    }
                    DriveItemDetails::File { md5, .. } => {
                        if self.item.matches_md5(&md5) {
                            println!(
                                "{}: file already exists and is identical on Google Drive, skipped",
                                self.item.path.display()
                            );
                            return Ok(());
                        }
                        println!(
                            "{}: updating existing Google Drive file",
                            self.item.path.display()
                        );
                        self.do_update_file(existing_item).await
                    }
                }
            }
        }
    }

    async fn do_update_file(&self, drive_item: &DriveItem) -> Result<()> {
        match &drive_item.details {
            DriveItemDetails::File {
                mime_type, size, ..
            } => {
                let mime_type_mime = Mime::from_str(&mime_type)?;
                let file_info = FileInfo {
                    name: drive_item.name.clone(),
                    mime_type: mime_type_mime,
                    parents: Some(self.parent_id.clone()),
                    size: *size as u64,
                };

                let file = std::fs::File::open(&self.item.path)?;

                let reader = std::io::BufReader::new(file);

                let _drive_file = &drive_item
                    .update(
                        &self.context.hub,
                        reader,
                        &drive_item.id,
                        file_info,
                        self.context.delegate_config.clone(),
                    )
                    .await?;

                Ok(())
            }
            DriveItemDetails::Directory { .. } | DriveItemDetails::Shortcut { .. } => {
                return Err(anyhow!(
                    "{}: existing drive items is not a file, skipped",
                    self.item.path.display()
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
