use async_trait::async_trait;
use crate::common::{drive_file, hub_helper};
use crate::files::list;
use crate::files::tasks::{DriveTask, DriveTaskStatus, TaskManager};
use crate::hub::Hub;
use std::collections::HashMap;
use std::error;
use std::fmt;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub enum DriveItem {
    File {
        id: String,
        file: google_drive3::api::File,
        parent_id: Option<String>,
    },
    Folder {
        id: String,
        file: Option<google_drive3::api::File>,
        parent_id: Option<String>,
        // Only populated if the folder has been loaded
        children_ids: Option<Vec<String>>,
    },
    Shortcut {
        id: String,
        file: google_drive3::api::File,
        parent_id: Option<String>,
    },
}

impl fmt::Display for DriveItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DriveItem::File {
                ref id,
                ref file,
                ref parent_id,
                ..
            } => write!(
                f,
                "File: {} ({}) parent: {:?}",
                file.name.as_ref().unwrap_or(&"Unnamed".to_string()),
                id,
                parent_id,
            ),
            DriveItem::Folder {
                ref id,
                ref file,
                ref parent_id,
                ref children_ids,
                ..
            } => write!(
                f,
                "Folder: ({}) has_file {} children: {:?} parent: {:?}",
                id,
                if file.is_some() { "true" } else { "false" },
                children_ids.as_ref().map_or(0, |ids| ids.len()),
                parent_id,
            ),
            DriveItem::Shortcut {
                ref id,
                ref file,
                ref parent_id,
                ..
            } => write!(
                f,
                "Shortcut: {} ({}) parent: {:?}",
                file.name.as_ref().unwrap_or(&"Unnamed".to_string()),
                id,
                parent_id,
            ),
        }
    }
}

impl DriveItem {
    pub fn id(&self) -> &String {
        match self {
            DriveItem::File { id, .. } => id,
            DriveItem::Folder { id, .. } => id,
            DriveItem::Shortcut { id, .. } => id,
        }
    }
}

pub struct DriveTree {
    items: HashMap<String, DriveItem>,
}

impl DriveTree {
    pub fn new() -> Self {
        Self {
            items: HashMap::new(),
        }
    }

    fn add_items(&mut self, items: Vec<DriveItem>) {
        for item in items {
            self.items.insert(item.id().clone(), item);
        }
    }

    pub fn get_item(&self, id: &str) -> Option<&DriveItem> {
        self.items.get(id)
    }

    pub fn items(&self) -> std::collections::hash_map::Values<'_, String, DriveItem> {
        self.items.values()
    }
}

pub async fn load_drive_tree(
    options: DriveTreeLoadOptions,
) -> Result<Arc<Mutex<DriveTree>>, Error> {
    let hub = Arc::new(hub_helper::get_hub().await.map_err(Error::Hub)?);
    let tree = Arc::new(Mutex::new(DriveTree::new()));
    let tm = Arc::new(TaskManager::new(10));
    let task = LoadTask::new(hub.clone(), tm.clone(), tree.clone(), None, options.clone());
    tm.add_task(task);
    tm.wait().await;
    Ok(tree)
}

#[derive(Debug, Clone)]
pub enum DriveTreeLoadOptions {
    UniqueFolder(String),
    RecursiveFolder(String),
}

pub struct LoadTask {
    hub: Arc<Hub>,
    tm: Arc<TaskManager<LoadTask>>,
    tree: Arc<Mutex<DriveTree>>,
    parent_id: Option<String>,
    options: DriveTreeLoadOptions,
    status: Mutex<DriveTaskStatus>,
}

impl LoadTask {
    pub fn new(
        hub: Arc<Hub>,
        tm: Arc<TaskManager<LoadTask>>,
        tree: Arc<Mutex<DriveTree>>,
        parent_id: Option<String>,
        options: DriveTreeLoadOptions,
    ) -> Self {
        Self {
            hub,
            tm,
            tree,
            parent_id,
            options,
            status: Mutex::new(DriveTaskStatus::Pending),
        }
    }

    pub async fn load_folder(&self) -> Result<(), list::Error> {
        let folder_id: String;
        match &self.options {
            DriveTreeLoadOptions::UniqueFolder(this_id) => {
                folder_id = this_id.clone();
            }
            DriveTreeLoadOptions::RecursiveFolder(this_id) => {
                folder_id = this_id.clone();
            }
        }

        let files = list::list_files(
            &self.hub,
            &list::ListFilesConfig {
                query: list::ListQuery::FilesInFolder {
                    folder_id: folder_id.clone(),
                },
                order_by: Default::default(),
                max_files: usize::MAX,
            },
        )
        .await?;

        let mut children_ids = vec![];
        let mut items = vec![];
        let mut sub_folder_ids = vec![];

        for file in files {
            match &file.id {
                Some(item_id) => {
                    if drive_file::is_directory(&file) {
                        items.push(DriveItem::Folder {
                            id: item_id.clone(),
                            file: Some(file.clone()),
                            parent_id: Some(folder_id.clone()),
                            children_ids: None,
                        });
                        sub_folder_ids.push(item_id.clone());
                    } else if drive_file::is_binary(&file) {
                        items.push(DriveItem::File {
                            id: item_id.clone(),
                            file: file.clone(),
                            parent_id: Some(folder_id.clone()),
                        });
                    } else if drive_file::is_shortcut(&file) {
                        items.push(DriveItem::Shortcut {
                            id: item_id.clone(),
                            file: file.clone(),
                            parent_id: Some(folder_id.clone()),
                        });
                    }
                    children_ids.push(item_id.clone());
                }
                None => {
                    println!("Skipping file without id: {:?}", file);
                }
            }
        }

        items.push(DriveItem::Folder {
            id: folder_id.clone(),
            file: None,
            parent_id: self.parent_id.clone(),
            children_ids: Some(children_ids),
        });

        // Add all the new children to the tree.
        self.tree.lock().unwrap().add_items(items);

        if let DriveTreeLoadOptions::RecursiveFolder(this_id) = &self.options {
            for sub_folder_id in &sub_folder_ids {
                let task = LoadTask::new(
                    self.hub.clone(),
                    self.tm.clone(),
                    self.tree.clone(),
                    Some(this_id.clone()),
                    DriveTreeLoadOptions::RecursiveFolder(sub_folder_id.clone()),
                );
                self.tm.add_task(task);
            }
        }

        Ok(())
    }
}

#[async_trait]
impl DriveTask for LoadTask {
    fn get_status(&self) -> DriveTaskStatus {
        self.status.lock().unwrap().clone()
    }

    async fn process(&self) {
        let result = self.load_folder().await;
        match result {
            Ok(_) => {}
            Err(e) => {
                *(self.status.lock().unwrap()) = DriveTaskStatus::Failed(e.to_string());
            }
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Hub(hub_helper::Error),
}

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Hub(err) => write!(f, "{}", err),
        }
    }
}
