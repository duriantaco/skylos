use crate::model::Json;
use std::fs;

pub fn summarise(Json(record): Json<String>) -> Vec<u8> {
    fs::read(format!("/var/lib/app/{}.json", record)).unwrap()
}
