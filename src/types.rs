// src/types.rs
use serde::Serialize;

#[derive(Serialize, Debug, Clone)]
pub struct Unreachable {
    pub file: String,
    pub name: String,
    pub line: usize,
}

#[derive(Debug, Serialize)]
pub struct UnusedImport {
    pub file: String,
    pub name: String,
    pub line: usize,
}