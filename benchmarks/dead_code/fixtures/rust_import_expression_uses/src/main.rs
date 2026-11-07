use std::{collections::HashMap, fs};
use anyhow::Context;
use clap::{ArgAction, Parser};
use const_format::formatcp;

#[derive(Parser)]
struct Options {
    #[arg(long, action(ArgAction::SetTrue))]
    enabled: bool,
    #[arg(long, default_value(formatcp!("default")))]
    label: String,
}

enum Input {
    File(fs::File),
}

fn contextualize(value: Result<(), std::io::Error>) {
    let _ = value.context("operation");
}

fn main() {
    let _ = std::mem::size_of::<Input>();
    let _ = Options::parse();
    contextualize(Ok(()));
}
