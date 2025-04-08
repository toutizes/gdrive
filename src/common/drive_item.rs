use crate::common::delegate::{UploadDelegate, UploadDelegateConfig};
use crate::common::disk_item::DiskItem;
use crate::common::drive_file;
use crate::common::file_info::FileInfo;
use crate::files::list;
use crate::hub::Hub;
use anyhow::{anyhow, Result};

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
        let query: list::ListQuery;
        if let Some(ref id) = parent_id {
            query = list::ListQuery::FilesInFolder {
                folder_id: id.clone(),
            };
        } else {
            query = list::ListQuery::RootNotTrashed;
        }
        let files = list::list_files(
            hub,
            &list::ListFilesConfig {
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

    pub async fn upload<RS>(
        hub: &Hub,
        src_file: RS,
        file_id: Option<String>,
        file_info: FileInfo,
        delegate_config: UploadDelegateConfig,
    ) -> Result<google_drive3::api::File>
    where
        RS: google_drive3::client::ReadSeek,
    {
        println!("Upload file: {:?}: {:?}", file_id, file_info.name);
        let dst_file = google_drive3::api::File {
            id: file_id,
            name: Some(file_info.name),
            mime_type: Some(file_info.mime_type.to_string()),
            parents: file_info.parents,
            ..google_drive3::api::File::default()
        };

        let chunk_size_bytes = delegate_config.chunk_size.in_bytes();
        let mut delegate = UploadDelegate::new(delegate_config);

        let req = hub
        .files()
        .create(dst_file)
        .param("fields", "id,name,size,createdTime,modifiedTime,md5Checksum,mimeType,parents,shared,description,webContentLink,webViewLink")
        .add_scope(google_drive3::api::Scope::Full)
        .delegate(&mut delegate)
        .supports_all_drives(true);

        let (_, file) = if file_info.size > chunk_size_bytes {
            req.upload_resumable(src_file, file_info.mime_type)
                .await?
        } else {
            req.upload(src_file, file_info.mime_type)
                .await?
        };

        Ok(file)
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
            req.upload_resumable(src_file, file_info.mime_type)
                .await?
        } else {
            req.upload(src_file, file_info.mime_type)
                .await?
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
