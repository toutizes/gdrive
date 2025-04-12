use crate::common::delegate::{UploadDelegate, UploadDelegateConfig};
use crate::common::disk_item::DiskItem;
use crate::common::drive_file;
use crate::common::drive_names;
use crate::files;
use crate::files::mkdir;
use crate::hub::Hub;
use anyhow::{anyhow, Result};
use mime::Mime;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use std::time::Instant;

#[derive(Debug, Clone)]
pub enum DriveItemDetails {
    Root {},
    Directory {},
    File {
        md5: String,
        mime_type: String,
        size: i64,
    },
    Shortcut {
        target_id: String,
        target_mime_type: String,
    },
}

#[derive(Debug, Clone)]
pub struct DriveItem {
    pub name: String,       // Empty name for Root
    id: String,             // Empty id for Root or not created dir
    parent: Option<String>, // Not really used yet.
    pub details: DriveItemDetails,
}

impl DriveItem {
    pub async fn for_name(hub: &Hub, name: &String) -> Result<DriveItem> {
        match drive_names::resolve(&hub, name).await? {
            Some(resolved_id) => DriveItem::for_drive_id(hub, &resolved_id).await,
            None => {
                // A None resolved_id means "root"
                Ok(DriveItem {
                    id: name.clone(),
                    name: name.clone(),
                    parent: None,
                    details: DriveItemDetails::Root {},
                })
            }
        }
    }

    pub async fn for_drive_id(hub: &Hub, drive_id: &String) -> Result<DriveItem> {
        let file = files::info::get_file(&hub, &drive_id).await?;
        DriveItem::for_drive_file(&file)
    }

    fn for_future_dir(name: String, parent: String) -> DriveItem {
        DriveItem {
            id: "".to_string(),
            name,
            parent: Some(parent),
            details: DriveItemDetails::Directory {},
        }
    }

    fn for_future_file(name: String, parent: String) -> DriveItem {
        DriveItem {
            id: "".to_string(),
            name,
            parent: Some(parent),
            details: DriveItemDetails::File {
                md5: "".to_string(),
                mime_type: "".to_string(),
                size: 0,
            },
        }
    }

    fn for_drive_file(file: &google_drive3::api::File) -> Result<DriveItem> {
        let details: DriveItemDetails;
        if drive_file::is_directory(file) {
            details = DriveItemDetails::Directory {};
        } else if drive_file::is_binary(file) {
            details = DriveItemDetails::File {
                md5: get_file_md5(&file)?,
                mime_type: get_file_mime_type(&file)?,
                size: get_file_size(&file)?,
            };
        } else if drive_file::is_shortcut(file) {
            details = get_file_shortcut_details(&file)?;
        } else {
            return Err(anyhow!(
                "Unknown file type: mime_type {:?}, md5 {:?}",
                file.mime_type,
                file.md5_checksum,
            ));
        }

        return Ok(DriveItem {
            id: get_file_id(&file)?,
            name: get_file_name(&file)?,
            parent: get_file_parent(&file)?,
            details,
        });
    }

    pub async fn list(&self, hub: &Hub) -> Result<Vec<DriveItem>> {
        let query: files::list::ListQuery = match &self.details {
            DriveItemDetails::Directory {} => Ok(files::list::ListQuery::FilesInFolder {
                folder_id: self.id.clone(),
            }),
            DriveItemDetails::Root {} => Ok(files::list::ListQuery::RootNotTrashed),
            _ => Err(anyhow!("{}: not a file on Google Drive", self.name)),
        }?;
        let files = files::list::list_files(
            hub,
            &files::list::ListFilesConfig {
                query,
                order_by: Default::default(),
                max_files: usize::MAX,
            },
        )
        .await?;

        let mut drive_items = Vec::new();

        for file in &files {
            let item_or = DriveItem::for_drive_file(&file);
            match item_or {
                Ok(item) => {
                    drive_items.push(item);
                }
                Err(err) => {
                    println!("Ignoring drive item: {:?}", err);
                }
            }
        }

        Ok(drive_items)
    }

    pub async fn list_disk_item(&self, hub: &Hub, disk_item: &DiskItem) -> Result<Vec<DriveItem>> {
        let name = disk_item.require_name()?;
        let mut named_items = Vec::new();
        let items = self.list(hub).await?;
        for item in items {
            if &item.name == name {
                named_items.push(item);
            }
        }
        Ok(named_items)
    }

    pub fn file_mime_type(&self) -> Result<&String> {
        match &self.details {
            DriveItemDetails::File { mime_type, .. } => Ok(mime_type),
            DriveItemDetails::Shortcut {
                target_mime_type, ..
            } => Ok(target_mime_type),
            _ => Err(anyhow!("{}: is a directory on Google Drive", self.name)),
        }
    }

    pub async fn upload(
        &self,
        hub: &Hub,
        disk_item: &DiskItem,
        force_mime_type: &Option<Mime>,
        delegate_config: UploadDelegateConfig,
        dry_run: bool,
    ) -> Result<DriveItem> {
        let parents: Option<Vec<String>> = match &self.details {
            DriveItemDetails::Directory {} => Ok(Some(vec![self.id.clone()])),
            DriveItemDetails::Root {} => Ok(None),
            _ => Err(anyhow!("{}: not a folder on Google Drive", self.name)),
        }?;

        let name = disk_item.require_name()?;
        let mime_type = if let Some(forced_mime_type) = &force_mime_type {
            forced_mime_type.clone()
        } else if let Ok(file_mime_type) = disk_item.mime_type() {
            file_mime_type
        } else {
            mime::APPLICATION_OCTET_STREAM
        };

        if !dry_run {
            let start = Instant::now();
            let dst_file = google_drive3::api::File {
                name: Some(name.clone()),
                mime_type: Some(mime_type.to_string()),
                parents,
                ..google_drive3::api::File::default()
            };

            let mut delegate = UploadDelegate::new(delegate_config);

            let req = hub
            .files()
            .create(dst_file)
            .param("fields", "id,name,size,createdTime,modifiedTime,md5Checksum,mimeType,parents,shared,description,webContentLink,webViewLink")
            .add_scope(google_drive3::api::Scope::Full)
            .delegate(&mut delegate)
            .supports_all_drives(true);

            let (_, file) = req.upload_resumable(disk_item.reader()?, mime_type).await?;
            println!("{}: {:.2}s", disk_item, start.elapsed().as_secs_f64());
            DriveItem::for_drive_file(&file)
        } else {
            println!("{}: would upload", disk_item);
            Ok(DriveItem::for_future_file(name.clone(), self.id.clone()))
        }
    }

    pub async fn download(&self, hub: &Hub, disk_item: &DiskItem, dry_run: bool) -> Result<usize> {
        match &self.details {
            DriveItemDetails::File { md5, size, .. } => {
                if !dry_run {
                    let start = Instant::now();
                    let (response, _) = hub
                        .files()
                        .get(&self.id)
                        .supports_all_drives(true)
                        .param("alt", "media")
                        .add_scope(google_drive3::api::Scope::Full)
                        .doit()
                        .await?;
                    let bytes = disk_item
                        .overwrite(response.into_body(), Some(md5.clone()))
                        .await?;
                    let duration = start.elapsed();
                    println!("{}: {:.2}s", disk_item, duration.as_secs_f64());
                    Ok(bytes)
                } else {
                    println!("{}: would download", disk_item);
                    Ok(*size as usize)
                }
            }
            _ => Err(anyhow!("{}: not a Google Drive file", self.name)),
        }
    }

    pub async fn export(&self, hub: &Hub, disk_item: &DiskItem) -> Result<usize> {
        match &self.details {
            DriveItemDetails::File { mime_type, .. } => {
                let response = hub
                    .files()
                    .export(&self.id, &mime_type.to_string())
                    .add_scope(google_drive3::api::Scope::Full)
                    .doit()
                    .await?;

                disk_item.overwrite(response.into_body(), None).await
            }
            _ => Err(anyhow!("{}: not a file on Google Drive", self.name)),
        }
    }

    pub async fn update(
        &self,
        hub: &Hub,
        disk_item: &DiskItem,
        force_mime_type: &Option<Mime>,
        delegate_config: UploadDelegateConfig,
        dry_run: bool,
    ) -> Result<()> {
        match &self.details {
            DriveItemDetails::File { mime_type, .. } => {
                if !dry_run {
                    let start = Instant::now();
                    let mime_type = if force_mime_type.is_none() {
                        Mime::from_str(&mime_type)?
                    } else {
                        force_mime_type.clone().unwrap()
                    };

                    let file = google_drive3::api::File {
                        mime_type: Some(mime_type.to_string()),
                        ..google_drive3::api::File::default()
                    };
                    let mut delegate = UploadDelegate::new(delegate_config);

                    let req = hub.files()
                    .update(file, &self.id)
                    .param("fields", "id,name,size,createdTime,modifiedTime,md5Checksum,mimeType,parents,shared,description,webContentLink,webViewLink")
                    .add_scope(google_drive3::api::Scope::Full)
                    .delegate(&mut delegate)
                    .supports_all_drives(true);

                    req.upload_resumable(disk_item.reader()?, mime_type).await?;
                    println!("{}: {:.2}s", disk_item, start.elapsed().as_secs_f64());
                } else {
                    println!("{}: would update drive file", disk_item);
                }
                Ok(())
            }
            _ => Err(anyhow!("{}: not a file on Google Drive", self.name)),
        }
    }

    pub async fn delete(&self, hub: &Hub, dry_run: bool) -> Result<()> {
        if !dry_run {
            hub.files()
                .delete(&self.id)
                .supports_all_drives(true)
                .add_scope(google_drive3::api::Scope::Full)
                .doit()
                .await?;
            // TODO: Show the Google Drive path when known.
            println!("{}: delete existing drive file", self.name);
        } else {
            println!("{}: would delete existing drive file", self.name);
        }
        Ok(())
    }

    pub async fn mkdir(
        &self,
        hub: &Hub,
        delegate_config: &UploadDelegateConfig,
        name: &String,
        dry_run: bool,
    ) -> Result<DriveItem> {
        let parents: Option<Vec<String>> = match &self.details {
            DriveItemDetails::Directory {} => Ok(Some(vec![self.id.clone()])),
            DriveItemDetails::Root {} => Ok(None),
            _ => Err(anyhow!("{}: not a folder on Google Drive", self.name)),
        }?;
        if !dry_run {
            let file = mkdir::create_directory(
                hub,
                &mkdir::Config {
                    id: None,
                    name: name.clone(),
                    parents,
                    print_only_id: false,
                },
                delegate_config.clone(),
            )
            .await?;
            let drive_folder = DriveItem::for_drive_file(&file)?;
            println!("{}: created directory ({})", name, drive_folder);
            Ok(drive_folder)
        } else {
            println!("{}: would create drive directory", name);
            Ok(DriveItem::for_future_dir(name.clone(), self.id.clone()))
        }
    }
}

macro_rules! get_file_property {
    ($func_name:ident, $property:ident, $return_type:ty, $error_message:literal) => {
        fn $func_name(file: &google_drive3::api::File) -> Result<$return_type> {
            if let Some(ref value) = file.$property {
                return Ok(value.clone());
            } else {
                return Err(anyhow!($error_message, file));
            }
        }
    };
}

get_file_property!(get_file_id, id, String, "Missing file id: {:?}");
get_file_property!(get_file_name, name, String, "Missing file name: {:?}");
get_file_property!(get_file_md5, md5_checksum, String, "Missing file md5: {:?}");
get_file_property!(
    get_file_mime_type,
    mime_type,
    String,
    "Missing file mime_type: {:?}"
);
get_file_property!(get_file_size, size, i64, "Missing file size: {:?}");

fn get_file_parent(file: &google_drive3::api::File) -> Result<Option<String>> {
    if let Some(ref parents) = file.parents {
        if parents.is_empty() {
            return Ok(None);
        } else if parents.len() == 1 {
            return Ok(Some(parents[0].clone()));
        } else {
            return Err(anyhow!("More than one parent: {:?}", file));
        }
    } else {
        return Ok(None);
    }
}

macro_rules! get_shortcut_property {
    ($func_name:ident, $property:ident, $return_type:ty, $error_message:literal) => {
        fn $func_name(shortcut: &google_drive3::api::FileShortcutDetails) -> Result<$return_type> {
            if let Some(ref value) = shortcut.$property {
                return Ok(value.clone());
            } else {
                return Err(anyhow!($error_message, shortcut));
            }
        }
    };
}

get_shortcut_property!(
    get_shortcut_target_id,
    target_id,
    String,
    "Missing target id: {:?}"
);
get_shortcut_property!(
    get_shortcut_target_mime_type,
    target_mime_type,
    String,
    "Missing target id: {:?}"
);

fn get_file_shortcut_details(file: &google_drive3::api::File) -> Result<DriveItemDetails> {
    if let Some(ref details) = file.shortcut_details {
        return Ok(DriveItemDetails::Shortcut {
            target_id: get_shortcut_target_id(&details)?,
            target_mime_type: get_shortcut_target_mime_type(&details)?,
        });
    } else {
        return Err(anyhow!("Missing file shortcut details: {:?}", file));
    }
}

impl Display for DriveItem {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: parent {:?}", self.id, self.parent)
    }
}
