pub mod analyzer;
pub mod visitor;
pub mod framework;
pub mod test_utils;
pub mod rules;
pub mod utils;
pub mod entry_point;


use clap::Parser;
use std::path::PathBuf;
use anyhow::Result;
use crate::analyzer::Skylos;
use colored::*;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to the Python project to analyze
    path: PathBuf,

    /// Confidence threshold (0-100)
    #[arg(short, long, default_value_t = 60)]
    confidence: u8,

    /// Scan for API keys/secrets
    #[arg(long)]
    secrets: bool,

    /// Scan for dangerous code
    #[arg(long)]
    danger: bool,

    /// Scan for code quality issues
    #[arg(long)]
    quality: bool,

    /// Output raw JSON
    #[arg(long)]
    json: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    if !cli.json {
        println!("Analyzing path: {:?}", cli.path);
    }
    
    let skylos = Skylos::new(cli.confidence, cli.secrets, cli.danger, cli.quality);
    let result = skylos.analyze(&cli.path)?;
    
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("\n{}", "Python Static Analysis Results".bold());
        println!("===================================\n");
        
        println!("Summary:");
        if !result.unused_functions.is_empty() {
            println!(" * Unreachable functions: {}", result.unused_functions.len());
        }
        if !result.unused_imports.is_empty() {
            println!(" * Unused imports: {}", result.unused_imports.len());
        }
        if !result.unused_classes.is_empty() {
            println!(" * Unused classes: {}", result.unused_classes.len());
        }
        if !result.unused_variables.is_empty() {
            println!(" * Unused variables: {}", result.unused_variables.len());
        }
        if cli.danger {
            println!(" * Security issues: {}", result.danger.len());
        }
        if cli.secrets {
            println!(" * Secrets found: {}", result.secrets.len());
        }
        if cli.quality {
            println!(" * Quality issues: {}", result.quality.len());
        }

        if !result.unused_functions.is_empty() {
            println!("\n - Unreachable Functions");
            println!("=======================");
            for (i, func) in result.unused_functions.iter().enumerate() {
                println!(" {}. {}", i + 1, func.name);
                println!("    └─ {}:{}", func.file.display(), func.line);
            }
        }
        
        if !result.unused_imports.is_empty() {
            println!("\n - Unused Imports");
            println!("================");
            for (i, imp) in result.unused_imports.iter().enumerate() {
                println!(" {}. {}", i + 1, imp.simple_name);
                println!("    └─ {}:{}", imp.file.display(), imp.line);
            }
        }

        if cli.danger && !result.danger.is_empty() {
            println!("\n - Security Issues");
            println!("================");
            for (i, f) in result.danger.iter().enumerate() {
                println!(" {}. {} [{}] ({}:{}) Severity: {}", i + 1, f.message, f.rule_id, f.file.display(), f.line, f.severity);
            }
        }

        if cli.secrets && !result.secrets.is_empty() {
            println!("\n - Secrets");
            println!("==========");
            for (i, s) in result.secrets.iter().enumerate() {
                println!(" {}. {} [{}] ({}:{}) Severity: {}", i + 1, s.message, s.rule_id, s.file.display(), s.line, s.severity);
            }
        }

        if cli.quality && !result.quality.is_empty() {
            println!("\n - Quality Issues");
            println!("================");
            for (i, q) in result.quality.iter().enumerate() {
                println!(" {}. {} [{}] ({}:{}) Severity: {}", i + 1, q.message, q.rule_id, q.file.display(), q.line, q.severity);
            }
        }
    }
    
    Ok(())
}
