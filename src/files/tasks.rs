use async_trait::async_trait;
use std::sync::{Arc,Mutex};

#[derive(Debug, Clone)]
pub enum DriveTaskStatus {
    Pending,
    Completed(usize),
    Failed(String),
}

#[async_trait]
pub trait DriveTask {
    async fn process(&self);
    fn get_status(&self) -> DriveTaskStatus;
}

pub struct TaskManager<T: DriveTask + Send + Sync + 'static> {
    tasks: Mutex<Vec<Arc<Box<T>>>>,
    task_handles: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    semaphore: Arc<tokio::sync::Semaphore>,
}

impl<T: DriveTask + Send + Sync + 'static> TaskManager<T> {
    pub fn new(num_workers: usize) -> Self {
        Self {
            tasks: Mutex::new(Vec::new()),
            task_handles: Mutex::new(Vec::new()),
            semaphore: Arc::new(tokio::sync::Semaphore::new(num_workers)),
        }
    }

    pub fn add_task(&self, task: T) {
        let task_arc = Arc::new(Box::new(task));
        self.tasks.lock().unwrap().push(Arc::clone(&task_arc));

        let task_clone = Arc::clone(&task_arc);
        let semaphore_clone = Arc::clone(&self.semaphore);

        let handle = tokio::spawn(async move {
            let _permit = match semaphore_clone.acquire().await {
                Ok(permit) => permit,
                Err(_) => {
                    // Happens if we close the sempahore, which we do not.
                    eprintln!("Semaphore closed for task");
                    return;
                }
            };
            task_clone.process().await;
        });
        self.task_handles.lock().unwrap().push(handle);
    }

    pub async fn wait(&self) -> Vec<Arc<Box<T>>> {
        loop {
            let mut remaining_handles = Vec::new();
            {
                // Lock while listing the remaining tasks.
                remaining_handles.extend(self.task_handles.lock().unwrap().drain(..));
                if remaining_handles.is_empty() {
                    break;
                }
            }

            futures::future::join_all(remaining_handles.drain(..)).await;
        }

        self.tasks.lock().unwrap().clone()
    }
}
