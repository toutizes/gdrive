use crate::common::disk_item::DiskItem;
use crate::common::drive_file::DocType;
use crate::common::drive_file::FileExtension;
use crate::common::drive_item::{DriveItem, DriveItemDetails};

use crate::common::hub_helper;
use anyhow::{anyhow, Result};
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct Config {
    pub file_id: String,
    pub file_path: PathBuf,
    pub existing_file_action: ExistingFileAction,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ExistingFileAction {
    Abort,
    Overwrite,
}

pub async fn export(config: Config) -> Result<()> {
    let hub = hub_helper::get_hub().await?;

    let filepath = &config.file_path;

    if filepath.exists() && config.existing_file_action == ExistingFileAction::Abort {
        Err(anyhow!(
            "{}: file exist, use --overwrite to export",
            filepath.display(),
        ))?;
    }

    let drive_item = DriveItem::from_drive_id(&hub, &config.file_id).await?;

    match &drive_item.details {
        DriveItemDetails::File { mime_type, .. } => {
            let doc_type: DocType = DocType::from_mime_type(&mime_type).ok_or(anyhow!(
                "{}: unsupported drive mime type {}",
                filepath.display(),
                mime_type
            ))?;

            let extension = FileExtension::from_path(&filepath).ok_or(anyhow!(
                "{}: Cannot guess a mime type from the filename",
                config.file_path.display(),
            ))?;

            if !doc_type.can_export_to(&extension) {
                return Err(anyhow!(
                    "{}: cannot export drive file with type {}",
                    filepath.display(),
                    doc_type
                ));
            };
            let disk_item = DiskItem::for_path(&config.file_path);
            drive_item.export(&hub, &disk_item).await?;
        }
        DriveItemDetails::Directory {} | DriveItemDetails::Shortcut { .. } => {
            Err(anyhow!("{}: not a file on Google Drive", drive_item.id))?;
        }
    };
    println!("Successfully exported {}", config.file_path.display());

    Ok(())
}
