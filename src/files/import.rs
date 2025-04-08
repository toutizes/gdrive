use crate::common::delegate::UploadDelegateConfig;
use crate::common::disk_item::DiskItem;
use crate::common::drive_item::DriveItem;
use crate::common::hub_helper;
use anyhow::Result;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct Config {
    pub file_path: PathBuf,
    pub parents: Option<Vec<String>>,
    pub print_only_id: bool,
}

pub async fn import(config: Config) -> Result<()> {
    let hub = hub_helper::get_hub().await?;
    let delegate_config = UploadDelegateConfig::default();

    let disk_item = DiskItem::for_path(&config.file_path);

    let parents = match config.parents {
        Some(parents) => parents,
        None => vec![],
    };

    let drive_item = DriveItem::upload(&hub, &disk_item, &None, parents, delegate_config).await?;

    print!("{}: imported {}", config.file_path.display(), drive_item.id);
    Ok(())
}
