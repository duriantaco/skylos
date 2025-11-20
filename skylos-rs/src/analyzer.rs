use anyhow::Result;
use std::path::Path;
use walkdir::WalkDir;
use rayon::prelude::*;
use rustpython_parser::{parse, Mode};
use std::fs;
use crate::visitor::{SkylosVisitor, Definition};
use crate::framework::FrameworkAwareVisitor;
use crate::test_utils::TestAwareVisitor;
use crate::rules::secrets::{scan_secrets, SecretFinding};
use crate::rules::danger::{DangerVisitor, DangerFinding};
use crate::rules::quality::{QualityVisitor, QualityFinding};
use crate::utils::LineIndex;
use serde::Serialize;
use std::collections::HashMap;

#[derive(Serialize)]
pub struct AnalysisResult {
    pub unused_functions: Vec<Definition>,
    pub unused_imports: Vec<Definition>,
    pub unused_classes: Vec<Definition>,
    pub unused_variables: Vec<Definition>,
    pub secrets: Vec<SecretFinding>,
    pub danger: Vec<DangerFinding>,
    pub quality: Vec<QualityFinding>,
    pub analysis_summary: AnalysisSummary,
}

#[derive(Serialize)]
pub struct AnalysisSummary {
    pub total_files: usize,
    pub secrets_count: usize,
    pub danger_count: usize,
    pub quality_count: usize,
}

pub struct Skylos {
    pub confidence_threshold: u8,
    pub enable_secrets: bool,
    pub enable_danger: bool,
    pub enable_quality: bool,
}

impl Skylos {
    pub fn new(confidence_threshold: u8, enable_secrets: bool, enable_danger: bool, enable_quality: bool) -> Self {
        Self {
            confidence_threshold,
            enable_secrets,
            enable_danger,
            enable_quality,
        }
    }

    pub fn analyze(&self, path: &Path) -> Result<AnalysisResult> {
        let files: Vec<_> = WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |ext| ext == "py"))
            .collect();

        let total_files = files.len();
        
        let results: Vec<(Vec<Definition>, Vec<(String, std::path::PathBuf)>, Vec<SecretFinding>, Vec<DangerFinding>, Vec<QualityFinding>)> = files
            .par_iter()
            .map(|entry| {
                let path = entry.path();
                let source = fs::read_to_string(path).unwrap_or_default();
                let line_index = LineIndex::new(&source);
                let ignored_lines = crate::utils::get_ignored_lines(&source);
                
                let module_name = path.file_stem().unwrap().to_string_lossy().to_string();
                
                let mut visitor = SkylosVisitor::new(path.to_path_buf(), module_name.clone(), &line_index);
                let mut framework_visitor = FrameworkAwareVisitor::new(&line_index);
                let mut test_visitor = TestAwareVisitor::new(path, &line_index);
                
                let mut secrets = Vec::new();
                let mut danger = Vec::new();
                let mut quality = Vec::new();

                if self.enable_secrets {
                    secrets = scan_secrets(&source, &path.to_path_buf());
                }

                if let Ok(ast) = parse(&source, Mode::Module, path.to_str().unwrap()) {
                    if let rustpython_ast::Mod::Module(module) = &ast {
                        // Detect entry point calls (if __name__ == "__main__")
                        let entry_point_calls = crate::entry_point::detect_entry_point_calls(&module.body);
                        
                        // Run visitors
                        for stmt in &module.body {
                             framework_visitor.visit_stmt(stmt);
                             test_visitor.visit_stmt(stmt);
                             visitor.visit_stmt(stmt);
                        }
                        
                        // Add entry point calls as references
                        for call_name in &entry_point_calls {
                            // Try both simple name and qualified name
                            visitor.add_ref(call_name.clone());
                            if !module_name.is_empty() {
                                let qualified = format!("{}.{}", module_name, call_name);
                                visitor.add_ref(qualified);
                            }
                        }
                        
                        if self.enable_danger {
                            let mut danger_visitor = DangerVisitor::new(path.to_path_buf(), &line_index);
                            for stmt in &module.body {
                                danger_visitor.visit_stmt(stmt);
                            }
                            danger = danger_visitor.findings;
                        }

                        if self.enable_quality {
                            let mut quality_visitor = QualityVisitor::new(path.to_path_buf(), &line_index);
                            for stmt in &module.body {
                                quality_visitor.visit_stmt(stmt);
                            }
                            quality = quality_visitor.findings;
                        }
                    }
                }
                
                // Apply penalties/adjustments based on framework/test status and pragmas
                for def in &mut visitor.definitions {
                    apply_penalties(def, &framework_visitor, &test_visitor, &ignored_lines);
                }
                
                (visitor.definitions, visitor.references, secrets, danger, quality)
            })
            .collect();

        let mut all_defs = Vec::new();
        let mut all_refs = Vec::new();
        let mut all_secrets = Vec::new();
        let mut all_danger = Vec::new();
        let mut all_quality = Vec::new();

        for (defs, refs, secrets, danger, quality) in results {
            all_defs.extend(defs);
            all_refs.extend(refs);
            all_secrets.extend(secrets);
            all_danger.extend(danger);
            all_quality.extend(quality);
        }

        let mut ref_counts: HashMap<String, usize> = HashMap::new();
        for (name, _) in &all_refs {
            *ref_counts.entry(name.clone()).or_insert(0) += 1;
        }

        let mut unused_functions = Vec::new();
        let mut unused_classes = Vec::new();
        let mut unused_imports = Vec::new();
        let mut unused_variables = Vec::new();

        for mut def in all_defs {
            if let Some(count) = ref_counts.get(&def.full_name) {
                def.references = *count;
            }
            
            // Filter out low confidence items
            if def.confidence < self.confidence_threshold {
                continue;
            }

            if def.references == 0 {
                match def.def_type.as_str() {
                    "function" => unused_functions.push(def),
                    "class" => unused_classes.push(def),
                    "import" => unused_imports.push(def),
                    "variable" => unused_variables.push(def),
                    _ => {}
                }
            }
        }

        Ok(AnalysisResult {
            unused_functions,
            unused_imports,
            unused_classes,
            unused_variables,
            secrets: all_secrets.clone(),
            danger: all_danger.clone(),
            quality: all_quality.clone(),
            analysis_summary: AnalysisSummary {
                total_files,
                secrets_count: all_secrets.len(),
                danger_count: all_danger.len(),
                quality_count: all_quality.len(),
            },
        })
    }
}

fn apply_penalties(def: &mut Definition, fv: &FrameworkAwareVisitor, tv: &TestAwareVisitor, ignored_lines: &std::collections::HashSet<usize>) {
    // Pragma: no skylos (highest priority - always skip)
    if ignored_lines.contains(&def.line) {
        def.confidence = 0;
        return;
    }
    
    // Test files: confidence 0 (ignore)
    if tv.is_test_file || tv.test_decorated_lines.contains(&def.line) {
        def.confidence = 0;
        return;
    }

    // Framework decorated: confidence 0 (ignore) or lower
    if fv.framework_decorated_lines.contains(&def.line) {
        def.confidence = 20; // Low confidence
    }
    
    // Private names
    if def.simple_name.starts_with('_') && !def.simple_name.starts_with("__") {
        def.confidence = def.confidence.saturating_sub(40);
    }
    
    // Dunder methods
    if def.simple_name.starts_with("__") && def.simple_name.ends_with("__") {
        def.confidence = 0;
    }
}
