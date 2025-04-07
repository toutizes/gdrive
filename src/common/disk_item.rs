use crate::common::error::CommonError;
use std::fs::{DirEntry, File};
use std::io;
use std::io::{BufReader, Read};
use std::path::PathBuf;

pub struct DiskItem {
    pub path: PathBuf,
    // basename of PathBuf, cleaned-up as a valid String.
    pub name: Option<String>,
}

impl DiskItem {
    pub fn for_path(path: &PathBuf) -> DiskItem {
        DiskItem {
            path: path.clone(),
            name: path
                .components()
                .last()
                .map(|c| c.as_os_str().to_string_lossy().to_string()),
        }
    }

    pub fn list_dir(&self) -> Result<Vec<DiskItem>, CommonError> {
        if !self.path.is_dir() {
            return Err(CommonError::Generic(format!(
                "{}: not a directory",
                self.path.display(),
            )));
        }

        let entries = std::fs::read_dir(&self.path).map_err(|err| {
            CommonError::Generic(format!("{}: {}", self.path.display(), err.to_string()))
        })?;

        let mut disk_entries = Vec::new();
        for entry in entries {
            let valid_entry = entry.map_err(|err| {
                CommonError::Generic(format!(
                    "In dir {}: {}",
                    self.path.display(),
                    err.to_string(),
                ))
            })?;
            disk_entries.push(DiskItem::for_dir_entry(&valid_entry)?);
        }
        Ok(disk_entries)
    }

    fn for_dir_entry(entry: &DirEntry) -> Result<DiskItem, CommonError> {
        Ok(DiskItem {
            path: entry.path(),
            name: Some(entry.file_name().to_string_lossy().to_string()),
        })
    }

    pub fn require_name(&self) -> Result<&String, CommonError> {
        self.name
            .as_ref()
            .ok_or_else(|| CommonError::Generic("File name is required".to_string()))
    }

    pub fn matches_md5(&self, drive_md5: &String) -> bool {
        match compute_md5_from_path(&self.path) {
            Ok(md5) => md5 == *drive_md5,
            Err(err) => {
                eprintln!(
                    "{}: could not compute md5 hash: {}",
                    self.path.display(),
                    err
                );
                false
            }
        }
    }
}

fn compute_md5_from_path(path: &PathBuf) -> Result<String, io::Error> {
    let input = File::open(path)?;
    let reader = BufReader::new(input);
    compute_md5_from_reader(reader)
}

fn compute_md5_from_reader<R: Read>(mut reader: R) -> Result<String, io::Error> {
    let mut context = md5::Context::new();
    let mut buffer = [0; 4096];

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        context.consume(&buffer[..count]);
    }

    Ok(format!("{:x}", context.compute()))
}
