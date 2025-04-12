use crate::common::delegate::UploadDelegateConfig;
use crate::common::disk_item::DiskItem;
use crate::common::drive_item::DriveItem;
use crate::common::hub_helper;
use anyhow::Result;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct Config {
    pub file_path: PathBuf,
    pub parent: String,
    pub print_only_id: bool,
}

pub async fn import(config: Config) -> Result<()> {
    let hub = hub_helper::get_hub().await?;
    let delegate_config = UploadDelegateConfig::default();

    let disk_item = DiskItem::for_path(Some(config.file_path.clone()));

    let parent_item = DriveItem::for_name(&hub, &config.parent).await?;

    let drive_item = parent_item
        .upload(&hub, &disk_item, &None, delegate_config, false)
        .await?;

    print!("{}: imported {}", config.file_path.display(), drive_item);
    Ok(())
}
