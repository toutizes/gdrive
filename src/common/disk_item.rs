use crate::common::drive_file::DocType;
use crate::common::md5_writer::Md5Writer;
use anyhow::{anyhow, Result};
use futures::stream::StreamExt; // for `next()`
use google_drive3::hyper;
use mime::Mime;
use std::collections::HashSet;
use std::fmt::{Display, Formatter};
use std::fs;
use std::fs::File;
use std::io::{BufReader, Read, Write}; // Write for `write_all()`
use std::path::PathBuf;

#[derive(Clone)]
pub enum DiskItem {
    Stdout {},
    Root { path: PathBuf },
    FileOrDir { path: PathBuf, name: String },
}

impl DiskItem {
    pub fn for_path(path_opt: Option<PathBuf>) -> DiskItem {
        match path_opt {
            Some(path) => match path.components().last() {
                Some(component) => {
                    let name = component.as_os_str().to_string_lossy().to_string();
                    if name.is_empty() {
                        panic!("{}: empty basename??", path.display())
                    } else {
                        DiskItem::FileOrDir {
                            path,
                            name: name.clone(),
                        }
                    }
                }
                None => DiskItem::Root { path: path.clone() },
            },
            None => DiskItem::Stdout {},
        }
    }

    pub fn is_dir(&self) -> bool {
        match self {
            DiskItem::FileOrDir { path, .. } | DiskItem::Root { path } => path.is_dir(),
            DiskItem::Stdout { .. } => false,
        }
    }

    pub fn is_file(&self) -> bool {
        match self {
            DiskItem::FileOrDir { path, .. } | DiskItem::Root { path } => path.is_file(),
            DiskItem::Stdout { .. } => false,
        }
    }

    pub fn require_name(&self) -> Result<&String> {
        match &self {
            DiskItem::FileOrDir { name, .. } => Ok(name),
            _ => Err(anyhow!("Filename is required")),
        }
    }

    pub fn join(&self, name: &String) -> Result<DiskItem> {
        match self {
            DiskItem::FileOrDir { path, .. } | DiskItem::Root { path } => {
                Ok(DiskItem::for_path(Some(path.join(name))))
            }
            DiskItem::Stdout { .. } => {
                return Err(anyhow!("<stdout>: not a directory"));
            }
        }
    }

    pub fn list_dir(&self) -> Result<Vec<DiskItem>> {
        match self {
            DiskItem::FileOrDir { path, .. } | DiskItem::Root { path } => {
                if !path.is_dir() {
                    return Err(anyhow!("{}: not a directory", self));
                }
                let mut disk_entries: Vec<DiskItem> = Vec::new();
                for entry in std::fs::read_dir(&path)? {
                    disk_entries.push(DiskItem::for_path(Some(entry?.path().clone())));
                }
                Ok(disk_entries)
            }
            DiskItem::Stdout { .. } => {
                return Err(anyhow!("<stdout>: not a directory"));
            }
        }
    }

    pub fn mkdir(&self, dry_run: bool) -> Result<usize> {
        match self {
            DiskItem::FileOrDir { path, .. } => {
                if !path.exists() {
                    if !dry_run {
                        fs::create_dir_all(&path)?;
                    }
                    println!("{}: create directory", self);
                    Ok(1)
                } else {
                    let file_type = fs::metadata(&path)?.file_type();
                    if !file_type.is_dir() {
                        return Err(anyhow!("{}: is not a directory, skipped", self));
                    }
                    Ok(0)
                }
            }
            _ => Ok(0),
        }
    }

    pub fn delete_extra_local_files(
        &self,
        names_to_keep: &HashSet<String>,
        dry_run: bool,
    ) -> Result<usize> {
        match self {
            DiskItem::FileOrDir { path, .. } | DiskItem::Root { path } => {
                let mut n: usize = 0;
                for entry in fs::read_dir(path)? {
                    let valid_entry = entry?;
                    let entry_name = valid_entry.file_name().to_string_lossy().to_string();
                    if names_to_keep.contains(&entry_name) {
                        continue;
                    }
                    let entry_type = valid_entry.file_type()?;
                    if entry_type.is_file() || entry_type.is_symlink() {
                        let delete_path = &valid_entry.path();
                        if !dry_run {
                            fs::remove_file(delete_path)?;
                        }
                        println!("{}: delete", delete_path.display());
                        n += 1;
                    } else {
                        println!(
                            "{}: keep (not a file or symlink)",
                            path.join(entry_name).display(),
                        );
                    }
                }
                Ok(n)
            }
            _ => Err(anyhow!("<stdout>: Nothing to delete")),
        }
    }

    pub fn reader(&self) -> Result<std::io::BufReader<std::fs::File>> {
        match self {
            DiskItem::FileOrDir { path, .. } => {
                Ok(std::io::BufReader::new(std::fs::File::open(&path)?))
            }
            _ => Err(anyhow!("<stdout>: no reader")),
        }
    }

    pub fn mime_type(&self) -> Result<Mime> {
        match self {
            DiskItem::FileOrDir { path, .. } => DocType::from_file_path(&path)
                .ok_or(anyhow!("Unsupported file type"))?
                .mime()
                .ok_or(anyhow!("Unknown file type")),
            _ => Err(anyhow!("<stdout>: no mime type")),
        }
    }

    pub async fn overwrite(
        &self,
        mut body: hyper::Body,
        expected_md5: Option<String>,
    ) -> Result<usize> {
        match self {
            DiskItem::FileOrDir { path, .. } => {
                // Create temporary file
                let tmp_file_path = path.with_extension("incomplete");
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
                std::fs::rename(&tmp_file_path, &path)?;

                Ok(written_bytes)
            }
            DiskItem::Stdout {} => {
                let mut stdout = std::io::stdout();
                let mut written_bytes: usize = 0;
                while let Some(chunk_result) = body.next().await {
                    let chunk = chunk_result?;
                    stdout.write_all(&chunk)?;
                    written_bytes += chunk.len();
                }
                Ok(written_bytes)
            }
            _ => Err(anyhow!("No writing to root folder")),
        }
    }

    pub fn matches_md5(&self, drive_md5: &String) -> bool {
        match self {
            DiskItem::FileOrDir { path, .. } => match compute_md5_from_path(&path) {
                Ok(md5) => md5 == *drive_md5,
                Err(err) => {
                    eprintln!("{}: could not compute md5 hash: {}", self, err);
                    false
                }
            },
            _ => false,
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

impl Display for DiskItem {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            DiskItem::FileOrDir { path, .. } | DiskItem::Root { path, .. } => {
                write!(f, "{}", path.display())
            }
            DiskItem::Stdout {} => {
                write!(f, "<stdout>")
            }
        }
    }
}
