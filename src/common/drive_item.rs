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

fn get_file_id(file: &google_drive3::api::File) -> Result<String, CommonError> {
    if let Some(ref id) = file.id {
        return Ok(id.clone());
    } else {
        return Err(CommonError::Generic(format!("Missing file id: {:?}", file)));
    }
}

fn get_file_name(file: &google_drive3::api::File) -> Result<String, CommonError> {
    if let Some(ref name) = file.name {
        return Ok(name.clone());
    } else {
        return Err(CommonError::Generic(format!(
            "Missing file name: {:?}",
            file
        )));
    }
}

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

fn get_file_md5(file: &google_drive3::api::File) -> Result<String, CommonError> {
    if let Some(ref md5) = file.md5_checksum {
        return Ok(md5.clone());
    } else {
        return Err(CommonError::Generic(format!(
            "Missing file md5: {:?}",
            file
        )));
    }
}

fn get_file_mime_type(file: &google_drive3::api::File) -> Result<String, CommonError> {
    if let Some(ref mime_type) = file.mime_type {
        return Ok(mime_type.clone());
    } else {
        return Err(CommonError::Generic(format!(
            "Missing file mime_type: {:?}",
            file
        )));
    }
}

fn get_file_size(file: &google_drive3::api::File) -> Result<i64, CommonError> {
    if let Some(size) = file.size {
        return Ok(size);
    } else {
        return Err(CommonError::Generic(format!(
            "Missing file size: {:?}",
            file
        )));
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
