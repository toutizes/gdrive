use crate::common::md5_writer::Md5Writer;
use crate::hub::Hub;
use anyhow::{anyhow, Result};
use futures::stream::StreamExt;
use google_drive3::hyper;
use mime::Mime;
use std::fs;
use std::fs::File;
use std::io;
use std::io::Write;
use std::path::PathBuf;

// Download `file_id` from Google Drive and save it to `file_path`.
// If `file_path` is None, the file contents are sent to stdout.
// Checks that the md5 hash of the downloaded file matches
// `expected_md5`.  Returns the number of bytes downloaded.
pub async fn download_file(
    hub: &Hub,
    file_id: &str,
    expected_md5: Option<String>,
    file_path: Option<&PathBuf>,
) -> Result<usize> {
    let (response, _) = hub
        .files()
        .get(file_id)
        .supports_all_drives(true)
        .param("alt", "media")
        .add_scope(google_drive3::api::Scope::Full)
        .doit()
        .await?;

    match file_path {
        Some(path) => {
            // Save to file
            save_body_to_file(response.into_body(), path, expected_md5).await
        }
        None => {
            // Save to stdout
            save_body_to_stdout(response.into_body()).await
        }
    }
}

pub async fn export_file(
    hub: &Hub,
    file_id: &str,
    mime_type: &Mime,
    expected_md5: Option<String>,
    file_path: &PathBuf,
) -> Result<usize> {
    let response = hub
        .files()
        .export(file_id, &mime_type.to_string())
        .add_scope(google_drive3::api::Scope::Full)
        .doit()
        .await?;

    save_body_to_file(response.into_body(), file_path, expected_md5).await
}

// TODO: move to common
async fn save_body_to_file(
    mut body: hyper::Body,
    file_path: &PathBuf,
    expected_md5: Option<String>,
) -> Result<usize> {
    // Create temporary file
    let tmp_file_path = file_path.with_extension("incomplete");
    let file = File::create(&tmp_file_path)?;

    // Wrap file in writer that calculates md5
    let mut writer = Md5Writer::new(file);
    let mut written_bytes: usize = 0;

    // Read chunks from stream and write to file
    while let Some(chunk_result) = body.next().await {
        let chunk = chunk_result?;
        writer.write_all(&chunk)?;
        written_bytes += chunk.len();
    }

    // Check md5
    err_if_md5_mismatch(expected_md5, writer.md5())?;

    // Rename temporary file to final file
    fs::rename(&tmp_file_path, &file_path)?;

    Ok(written_bytes)
}

// TODO: move to common
async fn save_body_to_stdout(mut body: hyper::Body) -> Result<usize> {
    let mut stdout = io::stdout();
    let mut written_bytes: usize = 0;

    // Read chunks from stream and write to stdout
    while let Some(chunk_result) = body.next().await {
        let chunk = chunk_result?;
        stdout.write_all(&chunk)?;
        written_bytes += chunk.len();
    }

    Ok(written_bytes)
}

fn err_if_md5_mismatch(expected: Option<String>, actual: String) -> Result<()> {
    let is_matching = expected.clone().map(|md5| md5 == actual).unwrap_or(true);

    if is_matching {
        Ok(())
    } else {
        Err(anyhow!(
            "Mismatched md5 hashes. Expected {}, got {}",
            expected.unwrap_or_default(),
            actual,
        ))
    }
}
