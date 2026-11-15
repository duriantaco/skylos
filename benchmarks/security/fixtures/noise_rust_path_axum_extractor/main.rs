use axum::extract::Path;
use std::fs;

async fn download(Path(name): Path<String>) -> Vec<u8> {
    let target = format!("/srv/files/{}", name);
    fs::read(target).unwrap()
}
