use crate::common::drive_file::DocType;
use crate::common::md5_writer::Md5Writer;
use anyhow::{anyhow, Result};
use futures::stream::StreamExt; // for `next()`
use google_drive3::hyper;
use mime::Mime;
use std::fs::{DirEntry, File};
use std::io::{BufReader, Read, Write}; // Write for `write_all()`
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

    pub fn list_dir(&self) -> Result<Vec<DiskItem>> {
        if !self.path.is_dir() {
            return Err(anyhow!("{}: not a directory", self.path.display(),));
        }

        let entries = std::fs::read_dir(&self.path)
            .map_err(|err| anyhow!("{} : {}", self.path.display(), err.to_string()))?;

        let mut disk_entries = Vec::new();
        for entry in entries {
            let valid_entry = entry
                .map_err(|err| anyhow!("In dir {}: {}", self.path.display(), err.to_string(),))?;
            disk_entries.push(DiskItem::for_dir_entry(&valid_entry)?);
        }
        Ok(disk_entries)
    }

    fn for_dir_entry(entry: &DirEntry) -> Result<DiskItem> {
        Ok(DiskItem {
            path: entry.path(),
            name: Some(entry.file_name().to_string_lossy().to_string()),
        })
    }

    pub fn require_name(&self) -> Result<&String> {
        match &self.name {
            Some(name) => Ok(name),
            None => Err(anyhow!("Filename is required")),
        }
    }

    pub fn reader(&self) -> Result<std::io::BufReader<std::fs::File>> {
        Ok(std::io::BufReader::new(std::fs::File::open(&self.path)?))
    }

    pub fn mime_type(&self) -> Result<Mime> {
        DocType::from_file_path(&self.path)
            .ok_or(anyhow!("Unsupported file type"))?
            .mime()
            .ok_or(anyhow!("Unknown file type"))
    }

    pub async fn overwrite(
        &self,
        mut body: hyper::Body,
        expected_md5: Option<String>,
    ) -> Result<usize> {
        // Create temporary file
        let tmp_file_path = self.path.with_extension("incomplete");
        // Wrap file in writer that calculates md5
        let mut writer = Md5Writer::new(File::create(&tmp_file_path)?);

        let mut written_bytes: usize = 0;

        // Read chunks from stream and write to file
        while let Some(chunk_result) = body.next().await {
            let chunk = chunk_result?;
            writer.write_all(&chunk)?;
            written_bytes += chunk.len();
        }

        // Check md5
        let actual_md5 = writer.md5();
        if let Some(md5) = expected_md5 {
            if md5 != actual_md5 {
                return Err(anyhow!(
                    "Mismatched md5 hashes. Expected {}, got {}",
                    md5,
                    actual_md5,
                ));
            }
        }

        // Rename temporary file to final file
        std::fs::rename(&tmp_file_path, &self.path)?;

        Ok(written_bytes)
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

fn compute_md5_from_path(path: &PathBuf) -> Result<String> {
    let input = File::open(path)?;
    let reader = BufReader::new(input);
    compute_md5_from_reader(reader)
}

fn compute_md5_from_reader<R: Read>(mut reader: R) -> Result<String> {
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
