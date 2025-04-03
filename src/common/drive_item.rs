use crate::common::drive_file;
use crate::common::error::CommonError;

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
                "Unknown file type: {:?}",
                file
            )));
        }

        return Ok(DriveItem {
            id: get_file_id(&file)?,
            name: get_file_name(&file)?,
            parent: get_file_parent(&file)?,
            details,
        });
    }
}

macro_rules! get_file_property {
    ($func_name:ident, $property:ident, $return_type:ty, $error_message:literal) => {
        fn $func_name(file: &google_drive3::api::File) -> Result<$return_type, CommonError> {
            if let Some(ref value) = file.$property {
                return Ok(value.clone());
            } else {
                return Err(CommonError::Generic(format!(
                    $error_message, file
                )));
            }
        }
    };
}

get_file_property!(get_file_id, id, String, "Missing file id: {:?}");
get_file_property!(get_file_name, name, String, "Missing file name: {:?}");
get_file_property!(get_file_md5, md5_checksum, String, "Missing file md5: {:?}");
get_file_property!(get_file_mime_type, mime_type, String, "Missing file mime_type: {:?}");
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

fn get_shortcut_target_id(
    details: &google_drive3::api::FileShortcutDetails,
) -> Result<String, CommonError> {
    if let Some(ref target_id) = details.target_id {
        return Ok(target_id.clone());
    } else {
        return Err(CommonError::Generic(format!(
            "Shortcut details missing target_id: {:?}",
            details,
        )));
    }
}

fn get_shortcut_target_mime_type(
    details: &google_drive3::api::FileShortcutDetails,
) -> Result<String, CommonError> {
    if let Some(ref target_mime_type) = details.target_mime_type {
        return Ok(target_mime_type.clone());
    } else {
        return Err(CommonError::Generic(format!(
            "Shortcut details missing target_mime_type: {:?}",
            details,
        )));
    }
}

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
