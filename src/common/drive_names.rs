use crate::common::drive_file;
use crate::common::error::CommonError;
use crate::files::list;
use crate::hub::Hub;

struct DriveIdAndIsDirectory {
    id: Option<String>,
    is_dir: bool,
}

// Find the drive id of `filepath`.
// Returns an error if the file is not found.
//
// TODO: Support <drive name>:path/path/file
pub async fn resolve(hub: &Hub, filepath: &String) -> Result<String, CommonError> {
    let mut last_found = DriveIdAndIsDirectory {
        id: None,
        is_dir: false,
    };

    for part in filepath.split("/").filter(|s| !s.is_empty()) {
        let query = make_query(filepath, &last_found)?;

        let files = list::list_files(
            &hub,
            &list::ListFilesConfig {
                query,
                order_by: Default::default(),
                max_files: usize::MAX,
            },
        )
        .await
        .map_err(CommonError::ListFiles)?;

        last_found = find_part(filepath, part, &files)?;
    }

    if let Some(id) = last_found.id {
        return Ok(id.clone());
    }
    Err(CommonError::Generic(format!("{}: Empty path", filepath)))
}

fn make_query(
    filepath: &String,
    dnd: &DriveIdAndIsDirectory,
) -> Result<list::ListQuery, CommonError> {
    if dnd.id.is_none() {
        // List the root of the drive
        return Ok(list::ListQuery::RootNotTrashed);
    }
    if dnd.is_dir {
        // List the current folder
        return Ok(list::ListQuery::FilesInFolder {
            folder_id: dnd.id.clone().unwrap(),
        });
    }
    // We have more parts but the last part is not a folder.
    Err(CommonError::Generic(format!(
        "{}: does not exist",
        filepath
    )))
}

fn find_part(
    filepath: &String,
    part: &str,
    files: &Vec<google_drive3::api::File>,
) -> Result<DriveIdAndIsDirectory, CommonError> {
    for file in files {
        if let Some(name) = &file.name {
            if name == part {
                if let Some(ref id) = file.id {
                    return Ok(DriveIdAndIsDirectory {
                        id: Some(id.clone()),
                        is_dir: drive_file::is_directory(&file),
                    });
                } else {
                    return Err(CommonError::Generic(format!(
                        "{}: {} has no id in drive",
                        filepath, part
                    )));
                }
            }
        }
    }
    Err(CommonError::Generic(format!(
        "{}: {} does not exist in drive",
        filepath, part
    )))
}
