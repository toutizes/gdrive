use crate::common::delegate::BackoffConfig;
use crate::common::delegate::ChunkSize;
use crate::common::delegate::UploadDelegate;
use crate::common::delegate::UploadDelegateConfig;
use crate::common::disk_item::DiskItem;
use crate::common::drive_item::{DriveItem, DriveItemDetails};
use crate::common::drive_names;
use crate::common::error::CommonError;
use crate::common::file_helper;
use crate::common::file_info;
use crate::common::file_info::FileInfo;
use crate::common::file_tree;
use crate::common::file_tree::FileTree;
use crate::common::hub_helper;
use crate::common::id_gen::IdGen;
// use crate::files;
// use crate::files::info::DisplayConfig;
use crate::files::mkdir;
use crate::files::tasks::{DriveTask, DriveTaskStatus};
use crate::hub::Hub;
use async_trait::async_trait;
use clap::ValueEnum;
use human_bytes::human_bytes;
use mime::Mime;
use std::error;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone, ValueEnum)]
pub enum ExistingDriveFileAction {
    Skip,
    Replace,
    UploadAnyway,
    Sync,
}

#[derive(Debug, Clone)]
pub struct UploadOptions {
    pub existing_file_action: ExistingDriveFileAction,
    pub upload_directories: bool,
    pub force_mime_type: Option<Mime>,
}

pub struct Config {
    pub file_path: Option<PathBuf>,
    pub parents: Option<Vec<String>>,
    pub parent_paths: Option<Vec<String>>,
    pub chunk_size: ChunkSize,
    pub print_chunk_errors: bool,
    pub print_chunk_info: bool,
    pub print_only_id: bool,
    pub options: UploadOptions,
}

pub async fn upload(cl_config: Config) -> Result<(), CommonError> {
    let hub = Arc::new(
        hub_helper::get_hub()
            .await
            .map_err(|err| CommonError::Hub(err))?,
    );

    let config = config_to_use(&hub, cl_config).await?;

    let delegate_config = UploadDelegateConfig {
        chunk_size: config.chunk_size.clone(),
        backoff_config: BackoffConfig {
            max_retries: 100000,
            min_sleep: Duration::from_secs(1),
            max_sleep: Duration::from_secs(60),
        },
        print_chunk_errors: config.print_chunk_errors,
        print_chunk_info: config.print_chunk_info,
    };

    match &config.file_path {
        Some(path) => {
            err_if_directory(&path, &config)?;

            if path.is_dir() {
                upload_directory(&hub, &config, delegate_config)
                    .await
                    .map_err(|err| CommonError::Generic(err.to_string()))?;
            } else {
                upload_regular(hub.clone(), &config, delegate_config)
                    .await
                    .map_err(|err| CommonError::Generic(err.to_string()))?;
            }
        }
        None => {
            let tmp_file = file_helper::stdin_to_file()
                .map_err(|err| CommonError::Generic(err.to_string()))?;

            upload_regular(
                hub.clone(),
                &Config {
                    file_path: Some(tmp_file.as_ref().to_path_buf()),
                    ..config
                },
                delegate_config,
            )
            .await
            .map_err(|err| CommonError::Generic(err.to_string()))?;
        }
    };

    Ok(())
}

async fn config_to_use(hub: &Hub, config: Config) -> Result<Config, CommonError> {
    if let Some(ref paths) = config.parent_paths {
        if config.parents.is_some() {
            return Err(CommonError::Generic(
                "Only one of --parent or --parent-path can be specified".to_string(),
            ));
        }
        let mut parents = Vec::new();
        for path in paths.iter() {
            parents.push(drive_names::resolve(&hub, &path).await?);
        }
        Ok(Config {
            parents: Some(parents),
            ..config
        })
    } else if config.parents.is_none() {
        Err(CommonError::Generic(
            "Must pass one of --parent or --parent-path".to_string(),
        ))
    } else {
        Ok(config)
    }
}

#[derive(Clone)]
pub struct UploadContext {
    hub: Arc<Hub>,
    // tm: Arc<TaskManager<UploadTask>>,
    delegate_config: UploadDelegateConfig,
    options: UploadOptions,
}

pub struct UploadTask {
    context: UploadContext,
    item: DiskItem,
    parent_id: Vec<String>,
    existing_item: Option<DriveItem>,
    status: Mutex<DriveTaskStatus>,
    // stats: Mutex<UploadStats>,
}

#[derive(Debug)]
pub struct UploadStats {
    pub num_files: usize,
    pub num_directories: usize,
    pub num_bytes: usize,
    pub num_deleted_files: usize,
    pub num_errors: usize,
}

impl UploadTask {
    pub fn new(
        context: UploadContext,
        item: DiskItem,
        parent_id: Vec<String>,
        existing_item: Option<DriveItem>,
    ) -> Self {
        Self {
            context,
            item,
            parent_id,
            existing_item,
            status: Mutex::new(DriveTaskStatus::Pending),
            // stats: Mutex::new(UploadStats {
            //     num_files: 0,
            //     num_directories: 0,
            //     num_bytes: 0,
            //     num_deleted_files: 0,
            //     num_errors: 0,
            // }),
        }
    }

    async fn upload(&self) -> Result<(), CommonError> {
        if self.item.path.is_dir() {
            self.do_upload_directory().await
        } else if self.item.path.is_file() {
            self.maybe_upload_file().await
        } else {
            Err(CommonError::Generic(format!(
                "{}: not a file or directory, skipped",
                self.item.path.display()
            )))
        }
    }

    async fn do_upload_directory(&self) -> Result<(), CommonError> {
        Ok(())
    }

    async fn maybe_upload_file(&self) -> Result<(), CommonError> {
        match &self.existing_item {
            None => {
                return self.do_upload_file().await;
            }
            Some(existing_item) => match &existing_item.details {
                DriveItemDetails::File { .. } => match self.context.options.existing_file_action {
                    ExistingDriveFileAction::Skip => {
                        return Err(CommonError::Generic(format!(
                            "{}: exists in Google Drive. Use --replace or --sync to replace",
                            self.item.path.display()
                        )));
                    }
                    ExistingDriveFileAction::Sync | ExistingDriveFileAction::Replace => {
                        return Err(CommonError::Generic(format!(
                            "{}: replacing existing file not implemented yet",
                            self.item.path.display()
                        )));
                    }
                    ExistingDriveFileAction::UploadAnyway => {
                        return self.do_upload_file().await;
                    }
                },
                _ => {
                    return Err(CommonError::Generic(format!(
                        "{}: is a directory or shortcut on Google Drive, skipping",
                        self.item.path.display()
                    )));
                }
            },
        }
    }

    async fn do_upload_file(&self) -> Result<(), CommonError> {
        // For a file, name has to be specified. (Empty name is root /)
        let name = self.item.require_name()?;

        let file = std::fs::File::open(&self.item.path).map_err(|err| {
            CommonError::Generic(format!("{}: {}", self.item.path.display(), err))
        })?;

        let metadata = file.metadata().map_err(|err| {
            CommonError::Generic(format!("{}: {}", self.item.path.display(), err))
        })?;

        let mime_type = self
            .context
            .options
            .force_mime_type
            .clone()
            .unwrap_or_else(|| {
                mime_guess::from_path(&self.item.path)
                    .first()
                    .unwrap_or(mime::APPLICATION_OCTET_STREAM)
            });

        let file_info = FileInfo {
            name: name.clone(),
            mime_type,
            size: metadata.len(),
            parents: Some(self.parent_id.clone()),
        };

        let reader = std::io::BufReader::new(file);

        let _drive_file = upload_file(
            &self.context.hub,
            reader,
            None,
            file_info,
            self.context.delegate_config.clone(),
        )
        .await
        .map_err(|err| CommonError::Generic(format!("{}: {}", self.item.path.display(), err)))?;

        Ok(())
    }
}

#[async_trait]
impl DriveTask for UploadTask {
    fn get_status(&self) -> DriveTaskStatus {
        self.status.lock().unwrap().clone()
    }

    async fn process(&self) {
        let result = self.upload().await;
        match result {
            Ok(_) => {}
            Err(e) => {
                println!("Err: {}", e.to_string());
                *(self.status.lock().unwrap()) = DriveTaskStatus::Failed(e.to_string());
            }
        }
    }
}

fn single_parent(config: &Config) -> Option<String> {
    if let Some(parents) = &config.parents {
        if parents.len() == 1 {
            return parents.first().cloned();
        }
    }
    None
}

pub async fn upload_regular(
    hub: Arc<Hub>,
    config: &Config,
    delegate_config: UploadDelegateConfig,
) -> Result<(), CommonError> {
    if config.file_path.is_none() {
        return Err(CommonError::Generic("File path is required".to_string()));
    }
    let item = DiskItem::for_path(&config.file_path.as_ref().unwrap())?;
    let drive_item = DriveItem::from_disk_item(&hub, &item, &single_parent(&config)).await?;

    let task = UploadTask::new(
        UploadContext {
            hub: hub.clone(),
            // tm: Arc::new(TaskManager::new()),
            delegate_config,
            options: config.options.clone(),
        },
        item,
        config.parents.clone().unwrap_or_default(),
        drive_item,
    );

    task.process().await;

    Ok(())
}

pub async fn upload_directory(
    hub: &Hub,
    config: &Config,
    delegate_config: UploadDelegateConfig,
) -> Result<(), Error> {
    let mut ids = IdGen::new(hub, &delegate_config);
    let tree = FileTree::from_path(config.file_path.as_ref().unwrap(), &mut ids)
        .await
        .map_err(Error::CreateFileTree)?;

    let tree_info = tree.info();

    if !config.print_only_id {
        println!(
            "Found {} files in {} directories with a total size of {}",
            tree_info.file_count,
            tree_info.folder_count,
            human_bytes(tree_info.total_file_size as f64)
        );
    }

    for folder in &tree.folders() {
        let folder_parents = folder
            .parent
            .as_ref()
            .map(|p| vec![p.drive_id.clone()])
            .or_else(|| config.parents.clone());

        if !config.print_only_id {
            println!(
                "Creating directory '{}' with id: {}",
                folder.relative_path().display(),
                folder.drive_id
            );
        }

        let drive_folder = mkdir::create_directory(
            hub,
            &mkdir::Config {
                id: Some(folder.drive_id.clone()),
                name: folder.name.clone(),
                parents: folder_parents,
                print_only_id: false,
            },
            delegate_config.clone(),
        )
        .await
        .map_err(Error::Mkdir)?;

        if config.print_only_id {
            println!("{}: {}", folder.relative_path().display(), folder.drive_id);
        }

        let folder_id = drive_folder.id.ok_or(Error::DriveFolderMissingId)?;
        let parents = Some(vec![folder_id.clone()]);

        for file in folder.files() {
            let os_file = fs::File::open(&file.path)
                .map_err(|err| Error::OpenFile(config.file_path.as_ref().unwrap().clone(), err))?;

            let file_info = file.info(parents.clone());

            if !config.print_only_id {
                println!(
                    "Uploading file '{}' with id: {}",
                    file.relative_path().display(),
                    file.drive_id
                );
            }

            upload_file(
                hub,
                os_file,
                Some(file.drive_id.clone()),
                file_info,
                delegate_config.clone(),
            )
            .await
            .map_err(Error::Upload)?;

            if config.print_only_id {
                println!("{}: {}", file.relative_path().display(), file.drive_id);
            }
        }
    }

    if !config.print_only_id {
        println!(
            "Uploaded {} files in {} directories with a total size of {}",
            tree_info.file_count,
            tree_info.folder_count,
            human_bytes(tree_info.total_file_size as f64)
        );
    }

    Ok(())
}

pub async fn upload_file<RS>(
    hub: &Hub,
    src_file: RS,
    file_id: Option<String>,
    file_info: FileInfo,
    delegate_config: UploadDelegateConfig,
) -> Result<google_drive3::api::File, google_drive3::Error>
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
        req.upload_resumable(src_file, file_info.mime_type).await?
    } else {
        req.upload(src_file, file_info.mime_type).await?
    };

    Ok(file)
}

#[derive(Debug)]
pub enum Error {
    Hub(hub_helper::Error),
    FileInfo(file_info::Error),
    OpenFile(PathBuf, io::Error),
    Upload(google_drive3::Error),
    IsDirectory(PathBuf),
    DriveFolderMissingId,
    CreateFileTree(file_tree::Error),
    Mkdir(google_drive3::Error),
    Generic(String),
}

impl error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Hub(err) => write!(f, "{}", err),
            Error::FileInfo(err) => write!(f, "{}", err),
            Error::OpenFile(path, err) => {
                write!(f, "Failed to open file '{}': {}", path.display(), err)
            }
            Error::Upload(err) => write!(f, "Failed to upload file: {}", err),
            Error::IsDirectory(path) => write!(
                f,
                "'{}' is a directory, use --recursive to upload directories",
                path.display()
            ),
            Error::DriveFolderMissingId => write!(f, "Folder created on drive does not have an id"),
            Error::CreateFileTree(err) => write!(f, "Failed to create file tree: {}", err),
            Error::Mkdir(err) => write!(f, "Failed to create directory: {}", err),
            Error::Generic(msg) => write!(f, "{}", msg),
        }
    }
}

fn err_if_directory(path: &PathBuf, config: &Config) -> Result<(), CommonError> {
    if path.is_dir() && !config.options.upload_directories {
        Err(CommonError::Generic(format!(
            "{}: is a directory, use --recursive to upload",
            path.display()
        )))
    } else {
        Ok(())
    }
}
