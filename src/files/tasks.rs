use async_trait::async_trait;
use std::sync::Arc;

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

pub struct TaskManager {
    tasks: Vec<Arc<Box<dyn DriveTask + Send + Sync>>>,
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

    pub fn add_task(&mut self, task: Box<dyn DriveTask + Sync + Send>) {
        let task_arc = Arc::new(task);
        self.tasks.push(Arc::clone(&task_arc));

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
        self.task_handles.push(handle);
    }

    pub async fn wait(&mut self) -> Vec<Arc<Box<dyn DriveTask + Sync + Send >>> {
        futures::future::join_all(self.task_handles.drain(..)).await;
        self.tasks.clone()
    }
}
