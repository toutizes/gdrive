use std::error;
use std::fmt;
use std::io;
use std::path;

use crate::common::hub_helper;
use crate::files::list;

#[derive(Debug)]
pub enum CommonError {
    Hub(hub_helper::Error),
    Generic(String),
    ListFiles(list::Error),
    NotADriveFolder(String),
    DriveFileWithNoId(String),

    GetFile(google_drive3::Error),
    DownloadFile(google_drive3::Error),
    FileExists(path::PathBuf),
    IsNotDirectory(String),
    Md5Mismatch { expected: String, actual: String },
    CreateFile(io::Error),
    CreateDirectory(path::PathBuf, io::Error),
    RenameFile(io::Error),
    ReadChunk(hyper::Error),
    WriteChunk(io::Error),
}

impl error::Error for CommonError {}

impl fmt::Display for CommonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommonError::Hub(x) => write!(f, "Hub error: {}", x),
            CommonError::Generic(x) => write!(f, "{}", x),
            CommonError::ListFiles(x) => write!(f, "List files error: {}", x),
            CommonError::NotADriveFolder(x) => write!(f, "Not a drive folder: {}", x),
            CommonError::DriveFileWithNoId(x) => write!(f, "Drive file with no id: {}", x),
            CommonError::GetFile(err) => write!(f, "Failed getting file: {}", err),
            CommonError::DownloadFile(err) => write!(f, "Failed to download file: {}", err),
            CommonError::FileExists(path) => write!(
                f,
                "File '{}' already exists, use --overwrite to overwrite it",
                path.display()
            ),
            CommonError::IsNotDirectory(name) => write!(
                f,
                "'{}' exists and is not a directory, use --sync to replace",
                name
            ),
            CommonError::Md5Mismatch { expected, actual } => {
                // fmt
                write!(
                    f,
                    "MD5 mismatch, expected: {}, actual: {}",
                    expected, actual
                )
            }
            CommonError::CreateFile(err) => write!(f, "Failed to create file: {}", err),
            CommonError::CreateDirectory(path, err) => write!(
                f,
                "Failed to create directory '{}': {}",
                path.display(),
                err
            ),
            CommonError::RenameFile(err) => write!(f, "Failed to rename file: {}", err),
            CommonError::ReadChunk(err) => write!(f, "Failed read from stream: {}", err),
            CommonError::WriteChunk(err) => write!(f, "Failed write to file: {}", err),
        }
    }
}
