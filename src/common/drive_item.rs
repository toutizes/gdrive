use crate::common::disk_item::DiskItem;
use crate::common::drive_file;
use crate::common::error::CommonError;
use crate::files::list;
use crate::hub::Hub;

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
    pub fn from_drive_file(file: &google_drive3::api::File) -> Result<DriveItem, CommonError> {
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
            return Err(CommonError::Generic(format!(
                "Unknown file type: mime_type {:?}, md5 {:?}",
                file.mime_type, file.md5_checksum,
            )));
        }

        return Ok(DriveItem {
            id: get_file_id(&file)?,
            name: get_file_name(&file)?,
            parent: get_file_parent(&file)?,
            details,
        });
    }

    pub async fn list_drive_dir(
        hub: &Hub,
        parent_id: &Option<String>,
    ) -> Result<Vec<DriveItem>, CommonError> {
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
        .await
        .map_err(|err| CommonError::Generic(format!("{}", err)))?;

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
    ) -> Result<Vec<DriveItem>, CommonError> {
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

    pub fn file_mime_type(&self) -> Result<&String, CommonError> {
        match &self.details {
            DriveItemDetails::File { mime_type, .. } => Ok(mime_type),
            DriveItemDetails::Shortcut {
                target_mime_type, ..
            } => Ok(target_mime_type),
            _ => Err(CommonError::Generic(format!(
                "{}: is a directory on Google Drive",
                self.name
            ))),
        }
    }
}

macro_rules! get_file_property {
    ($func_name:ident, $property:ident, $return_type:ty, $error_message:literal) => {
        fn $func_name(file: &google_drive3::api::File) -> Result<$return_type, CommonError> {
            if let Some(ref value) = file.$property {
                return Ok(value.clone());
            } else {
                return Err(CommonError::Generic(format!($error_message, file)));
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

fn get_file_parent(file: &google_drive3::api::File) -> Result<Option<String>, CommonError> {
    if let Some(ref parents) = file.parents {
        if parents.is_empty() {
            return Ok(None);
        } else if parents.len() == 1 {
            return Ok(Some(parents[0].clone()));
        } else {
            return Err(CommonError::Generic(format!(
                "More than one parent: {:?}",
                file
            )));
        }
    } else {
        return Ok(None);
    }
}

macro_rules! get_shortcut_property {
    ($func_name:ident, $property:ident, $return_type:ty, $error_message:literal) => {
        fn $func_name(
            shortcut: &google_drive3::api::FileShortcutDetails,
        ) -> Result<$return_type, CommonError> {
            if let Some(ref value) = shortcut.$property {
                return Ok(value.clone());
            } else {
                return Err(CommonError::Generic(format!($error_message, shortcut)));
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

fn get_file_shortcut_details(
    file: &google_drive3::api::File,
) -> Result<DriveItemDetails, CommonError> {
    if let Some(ref details) = file.shortcut_details {
        return Ok(DriveItemDetails::Shortcut {
            target_id: get_shortcut_target_id(&details)?,
            target_mime_type: get_shortcut_target_mime_type(&details)?,
        });
    } else {
        return Err(CommonError::Generic(format!(
            "Missing file shortcut details: {:?}",
            file
        )));
    }
}
