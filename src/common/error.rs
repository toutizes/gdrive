use std::error;
use std::fmt;

use crate::common::hub_helper;
use crate::files::list;

#[derive(Debug)]
pub enum CommonError {
    Hub(hub_helper::Error),
    Generic(String),
    ListFiles(list::Error),
    NotADriveFolder(String),
    DriveFileWithNoId(String),
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
        }
    }
}
