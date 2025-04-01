use crate::files::download::{download_file, save_body_to_file, Error};
use crate::hub::Hub;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub enum TaskStatus {
    Pending,
    Completed(usize),
    Failed(Error),
}

pub struct CopyTask {
    hub: Arc<Hub>,
    download: bool,
    driveid: String,
    filepath: PathBuf,
    md5: Option<String>,
    pub status: Mutex<TaskStatus>,
}

impl CopyTask {
    pub fn new(
        hub: Arc<Hub>,
        download: bool,
        driveid: String,
        filepath: PathBuf,
        md5: Option<String>,
    ) -> Self {
        Self {
            hub,
            download,
            driveid,
            filepath,
            status: Mutex::new(TaskStatus::Pending),
            md5,
        }
    }

    pub async fn process(&self) {
        let result: Result<(), Error> = if self.download {
            self.download().await
        } else {
            self.upload().await
        };

        match result {
            Ok(_) => {}
            Err(e) => {
                *(self.status.lock().unwrap()) = TaskStatus::Failed(e);
            }
        }
    }

    pub async fn download(&self) -> Result<(), Error> {
        println!("Downloading {:?}", self.filepath);
        let body = download_file(&self.hub, &self.driveid)
            .await
            .map_err(Error::DownloadFile)?;
        let file_bytes = save_body_to_file(body, &self.filepath, self.md5.clone()).await?;
        *(self.status.lock().unwrap()) = TaskStatus::Completed(file_bytes);
        Ok(())
    }

    pub async fn upload(&self) -> Result<(), Error> {
        Ok(())
    }
}

pub struct TaskManager {
    tasks: Vec<Arc<CopyTask>>,
    task_handles: Vec<tokio::task::JoinHandle<()>>,
    semaphore: Arc<tokio::sync::Semaphore>,
}

impl TaskManager {
    pub fn new(num_workers: usize) -> Self {
        Self {
            tasks: Vec::new(),
            task_handles: Vec::new(),
            semaphore: Arc::new(tokio::sync::Semaphore::new(num_workers)),
        }
    }

    pub fn add_task(&mut self, task: CopyTask) {
        let task_arc = Arc::new(task);
        *(task_arc.status.lock().unwrap()) = TaskStatus::Pending;
        self.tasks.push(Arc::clone(&task_arc));

        let task_clone = Arc::clone(&task_arc);
        let semaphore_clone = Arc::clone(&self.semaphore);

        let handle = tokio::spawn(async move {
            let _permit = match semaphore_clone.acquire().await {
                Ok(permit) => permit,
                Err(_) => {
                    eprintln!("Semaphore closed for task: {:?}", task_clone.filepath);
                    return; // Semaphore closed, cannot proceed
                }
            };
            task_clone.process().await;
        });
        self.task_handles.push(handle);
    }

    pub async fn wait(&mut self) -> Vec<Arc<CopyTask>> {
        futures::future::join_all(self.task_handles.drain(..)).await;
        self.tasks.clone()
    }
}
