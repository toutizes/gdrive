use crate::common::delegate::{UploadDelegate, UploadDelegateConfig};
use crate::common::disk_item::DiskItem;
use crate::common::drive_file;
use crate::common::file_info::FileInfo;
use crate::files;
use crate::hub::Hub;
use anyhow::{anyhow, Result};
use futures::stream::StreamExt; // for `next()`
use mime::Mime;
use std::io::Write; // for `write_all()`

#[derive(Debug, Clone)]
pub enum DriveItemDetails {
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
    pub id: String,
    pub name: String,
    pub parent: Option<String>,
    pub details: DriveItemDetails,
}

impl DriveItem {
    pub async fn from_drive_id(hub: &Hub, drive_id: &String) -> Result<DriveItem> {
        let file = files::info::get_file(&hub, &drive_id).await?;
        DriveItem::from_drive_file(&file)
    }

    pub fn from_drive_file(file: &google_drive3::api::File) -> Result<DriveItem> {
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

    pub async fn list_drive_dir(hub: &Hub, parent_id: &Option<String>) -> Result<Vec<DriveItem>> {
        let query: files::list::ListQuery;
        if let Some(ref id) = parent_id {
            query = files::list::ListQuery::FilesInFolder {
                folder_id: id.clone(),
            };
        } else {
            query = files::list::ListQuery::RootNotTrashed;
        }
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
            let item_or = DriveItem::from_drive_file(&file);
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

    pub async fn from_disk_item(
        hub: &Hub,
        disk_item: &DiskItem,
        parent_id: &Option<String>,
    ) -> Result<Vec<DriveItem>> {
        let name = disk_item.require_name()?;
        let mut named_items = Vec::new();
        let items = DriveItem::list_drive_dir(hub, parent_id).await?;
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
        hub: &Hub,
        disk_item: &DiskItem,
        force_mime_type: &Option<Mime>,
        parent_id: Vec<String>,
        delegate_config: UploadDelegateConfig,
    ) -> Result<DriveItem> {
        let name = disk_item.require_name()?;
        let mime_type = if let Some(forced_mime_type) = &force_mime_type {
            forced_mime_type.clone()
        } else if let Ok(file_mime_type) = disk_item.mime_type() {
            file_mime_type
        } else {
            mime::APPLICATION_OCTET_STREAM
        };
        let mut dst_file = google_drive3::api::File {
            name: Some(name.clone()),
            mime_type: Some(mime_type.to_string()),
            ..google_drive3::api::File::default()
        };

        // Do not put parent to upload at the root of the drive.
        if !parent_id.is_empty() {
            dst_file.parents = Some(parent_id.clone());
        }

        let mut delegate = UploadDelegate::new(delegate_config);

        let req = hub
            .files()
            .create(dst_file)
            .param("fields", "id,name,size,createdTime,modifiedTime,md5Checksum,mimeType,parents,shared,description,webContentLink,webViewLink")
            .add_scope(google_drive3::api::Scope::Full)
            .delegate(&mut delegate)
            .supports_all_drives(true);

        let (_, file) = req.upload_resumable(disk_item.reader()?, mime_type).await?;
        DriveItem::from_drive_file(&file)
    }

    pub async fn download(&self, hub: &Hub, disk_item: Option<&DiskItem>) -> Result<usize> {
        match &self.details {
            DriveItemDetails::File { md5, .. } => {
                let (response, _) = hub
                    .files()
                    .get(&self.id)
                    .supports_all_drives(true)
                    .param("alt", "media")
                    .add_scope(google_drive3::api::Scope::Full)
                    .doit()
                    .await?;

                let mut body = response.into_body();
                match &disk_item {
                    Some(item) => item.overwrite(body, Some(md5.clone())).await,
                    None => {
                        let mut stdout = std::io::stdout();
                        let mut written_bytes: usize = 0;
                        while let Some(chunk_result) = body.next().await {
                            let chunk = chunk_result?;
                            stdout.write_all(&chunk)?;
                            written_bytes += chunk.len();
                        }
                        Ok(written_bytes)
                    }
                }
            }
            DriveItemDetails::Directory {} | DriveItemDetails::Shortcut { .. } => {
                Err(anyhow!("{}: not a file on Google Drive", self.name))
            }
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
            DriveItemDetails::Directory {} | DriveItemDetails::Shortcut { .. } => {
                Err(anyhow!("{}: not a file on Google Drive", self.name))
            }
        }
    }

    pub async fn update<RS>(
        &self,
        hub: &Hub,
        src_file: RS,
        file_id: &String,
        file_info: FileInfo,
        delegate_config: UploadDelegateConfig,
    ) -> Result<google_drive3::api::File>
    where
        RS: google_drive3::client::ReadSeek,
    {
        let dst_file = google_drive3::api::File {
            name: Some(file_info.name),
            ..google_drive3::api::File::default()
        };

        let mut delegate = UploadDelegate::new(delegate_config);

        let req = hub
        .files()
        .update(dst_file, &file_id)
        .param("fields", "id,name,size,createdTime,modifiedTime,md5Checksum,mimeType,parents,shared,description,webContentLink,webViewLink")
        .add_scope(google_drive3::api::Scope::Full)
        .delegate(&mut delegate)
        .supports_all_drives(true);

        let (_, file) = if file_info.size > 0 {
            req.upload_resumable(src_file, file_info.mime_type).await?
        } else {
            req.upload(src_file, file_info.mime_type).await?
        };

        Ok(file)
    }

    pub async fn delete(&self, hub: &Hub) -> Result<()> {
        hub.files()
            .delete(&self.id)
            .supports_all_drives(true)
            .add_scope(google_drive3::api::Scope::Full)
            .doit()
            .await?;
        Ok(())
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
