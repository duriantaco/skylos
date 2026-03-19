//! Coupling analysis — exact port of coupling.py's analyze_coupling.
//! Parses Python source with rustpython-parser and replicates both AST passes.

use pyo3::prelude::*;
use pyo3::types::PyDict;
use rustpython_parser::ast::{self, Stmt, Expr};
use std::collections::{HashMap, HashSet, BTreeSet};

// Mirrors coupling.py BUILTIN_TYPES
const BUILTIN_TYPES: &[&str] = &[
    "int", "str", "float", "bool", "bytes", "list", "dict", "set", "tuple",
    "frozenset", "type", "object", "None", "complex", "bytearray", "memoryview",
    "range", "slice", "property", "classmethod", "staticmethod",
    "Exception", "BaseException", "ValueError", "TypeError", "KeyError",
    "IndexError", "AttributeError", "RuntimeError", "StopIteration",
    "OSError", "IOError", "FileNotFoundError", "NotImplementedError",
];

const TYPING_WRAPPERS: &[&str] = &[
    "Optional", "Union", "List", "Dict", "Set", "Tuple", "FrozenSet", "Type",
    "ClassVar", "Final", "Literal", "Annotated", "Callable", "Iterator",
    "Iterable", "Generator", "AsyncIterator", "AsyncIterable", "Awaitable",
    "Coroutine", "Sequence", "MutableSequence", "Mapping", "MutableMapping", "Any",
];

fn is_builtin(name: &str) -> bool {
    BUILTIN_TYPES.contains(&name)
}

fn is_typing(name: &str) -> bool {
    TYPING_WRAPPERS.contains(&name)
}

/// Extract type names from an annotation expression — mirrors _extract_type_names
fn extract_type_names(expr: &Expr) -> HashSet<String> {
    let mut names = HashSet::new();
    match expr {
        Expr::Name(n) => {
            let id = n.id.as_str();
            if !is_builtin(id) && !is_typing(id) {
                names.insert(id.to_string());
            }
        }
        Expr::Attribute(_attr) => {
            let full = build_dotted_name(expr);
            if let Some(name) = full {
                names.insert(name);
            }
        }
        Expr::Subscript(sub) => {
            names.extend(extract_type_names(&sub.value));
            names.extend(extract_type_names(&sub.slice));
        }
        Expr::Tuple(tup) => {
            for elt in &tup.elts {
                names.extend(extract_type_names(elt));
            }
        }
        Expr::BinOp(binop) => {
            if matches!(binop.op, ast::Operator::BitOr) {
                names.extend(extract_type_names(&binop.left));
                names.extend(extract_type_names(&binop.right));
            }
        }
        Expr::Constant(_) => {
            // None constant — skip
        }
        Expr::List(l) => {
            for elt in &l.elts {
                names.extend(extract_type_names(elt));
            }
        }
        _ => {}
    }
    names
}

/// Build dotted name from Attribute chain — mirrors coupling.py logic
fn build_dotted_name(expr: &Expr) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    let mut current = expr;
    loop {
        match current {
            Expr::Attribute(attr) => {
                parts.push(attr.attr.to_string());
                current = &attr.value;
            }
            Expr::Name(n) => {
                parts.push(n.id.to_string());
                parts.reverse();
                return Some(parts.join("."));
            }
            _ => return None,
        }
    }
}

/// Get decorator name — mirrors _get_decorator_name
fn get_decorator_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Name(n) => Some(n.id.to_string()),
        Expr::Attribute(_) => build_dotted_name(expr),
        Expr::Call(call) => get_decorator_name(&call.func),
        _ => None,
    }
}

struct ClassInfo {
    name: String,
    lineno: usize,
    col_offset: usize,
    bases: HashSet<String>,
    decorators: HashSet<String>,
    type_deps: HashSet<String>,
    instantiation_deps: HashSet<String>,
    attribute_deps: HashSet<String>,
    decorator_deps: HashSet<String>,
    protocol_abc_deps: HashSet<String>,
    is_protocol: bool,
    is_abc: bool,
    is_dataclass: bool,
    methods: Vec<String>,
}

impl ClassInfo {
    fn new(name: &str, lineno: usize, col_offset: usize) -> Self {
        ClassInfo {
            name: name.to_string(), lineno, col_offset,
            bases: HashSet::new(), decorators: HashSet::new(),
            type_deps: HashSet::new(), instantiation_deps: HashSet::new(),
            attribute_deps: HashSet::new(), decorator_deps: HashSet::new(),
            protocol_abc_deps: HashSet::new(),
            is_protocol: false, is_abc: false, is_dataclass: false,
            methods: Vec::new(),
        }
    }
}

/// Walk all statements recursively, collecting ClassDef/Import/ImportFrom at any depth
fn walk_stmts(stmts: &[Stmt], classes: &mut HashMap<String, ClassInfo>,
              known_classes: &mut HashSet<String>, module_imports: &mut HashMap<String, String>,
              source: &str) {
    for stmt in stmts {
        match stmt {
            Stmt::ClassDef(cls) => {
                let name = cls.name.as_str();
                let offset: usize = cls.range.start().into();
                let mut info = ClassInfo::new(name,
                    line_from_offset(source, offset),
                    col_from_offset(source, offset));
                known_classes.insert(name.to_string());

                // Bases
                for base in &cls.bases {
                    for n in extract_type_names(base) {
                        info.bases.insert(n);
                    }
                }

                // Decorators
                for dec in &cls.decorator_list {
                    if let Some(dec_name) = get_decorator_name(dec) {
                        if dec_name == "dataclass" || dec_name == "dataclasses.dataclass" {
                            info.is_dataclass = true;
                        }
                        info.decorators.insert(dec_name);
                    }
                }

                // Protocol / ABC detection from bases
                for base in &cls.bases {
                    match base {
                        Expr::Name(n) => {
                            if n.id.as_str() == "Protocol" { info.is_protocol = true; }
                            if n.id.as_str() == "ABC" || n.id.as_str() == "ABCMeta" { info.is_abc = true; }
                        }
                        Expr::Attribute(a) => {
                            if a.attr.as_str() == "Protocol" { info.is_protocol = true; }
                            if a.attr.as_str() == "ABC" || a.attr.as_str() == "ABCMeta" { info.is_abc = true; }
                        }
                        _ => {}
                    }
                }

                // Methods (direct body only, not nested)
                for item in &cls.body {
                    match item {
                        Stmt::FunctionDef(f) => info.methods.push(f.name.to_string()),
                        Stmt::AsyncFunctionDef(f) => info.methods.push(f.name.to_string()),
                        _ => {}
                    }
                }

                classes.insert(name.to_string(), info);

                // Recurse into class body for nested classes
                walk_stmts(&cls.body, classes, known_classes, module_imports, source);
            }
            Stmt::Import(imp) => {
                for alias in &imp.names {
                    let key = alias.asname.as_ref().unwrap_or(&alias.name).to_string();
                    module_imports.insert(key, alias.name.to_string());
                }
            }
            Stmt::ImportFrom(imp) => {
                if let Some(ref module) = imp.module {
                    for alias in &imp.names {
                        let key = alias.asname.as_ref().unwrap_or(&alias.name).to_string();
                        module_imports.insert(key, format!("{}.{}", module, alias.name));
                    }
                }
            }
            // Recurse into compound statements
            Stmt::FunctionDef(f) => walk_stmts(&f.body, classes, known_classes, module_imports, source),
            Stmt::AsyncFunctionDef(f) => walk_stmts(&f.body, classes, known_classes, module_imports, source),
            Stmt::If(s) => {
                walk_stmts(&s.body, classes, known_classes, module_imports, source);
                walk_stmts(&s.orelse, classes, known_classes, module_imports, source);
            }
            Stmt::For(s) => {
                walk_stmts(&s.body, classes, known_classes, module_imports, source);
                walk_stmts(&s.orelse, classes, known_classes, module_imports, source);
            }
            Stmt::While(s) => {
                walk_stmts(&s.body, classes, known_classes, module_imports, source);
                walk_stmts(&s.orelse, classes, known_classes, module_imports, source);
            }
            Stmt::Try(s) => {
                walk_stmts(&s.body, classes, known_classes, module_imports, source);
                for handler in &s.handlers {
                    let ast::ExceptHandler::ExceptHandler(h) = handler;
                    walk_stmts(&h.body, classes, known_classes, module_imports, source);
                }
                walk_stmts(&s.orelse, classes, known_classes, module_imports, source);
                walk_stmts(&s.finalbody, classes, known_classes, module_imports, source);
            }
            Stmt::TryStar(s) => {
                walk_stmts(&s.body, classes, known_classes, module_imports, source);
                for handler in &s.handlers {
                    let ast::ExceptHandler::ExceptHandler(h) = handler;
                    walk_stmts(&h.body, classes, known_classes, module_imports, source);
                }
                walk_stmts(&s.orelse, classes, known_classes, module_imports, source);
                walk_stmts(&s.finalbody, classes, known_classes, module_imports, source);
            }
            Stmt::With(s) => walk_stmts(&s.body, classes, known_classes, module_imports, source),
            Stmt::AsyncWith(s) => walk_stmts(&s.body, classes, known_classes, module_imports, source),
            _ => {}
        }
    }
}

/// Walk all expressions in a statement tree, collecting deps for a class
fn walk_class_body_for_deps(stmts: &[Stmt], class_name: &str, info: &mut ClassInfo,
                            known_classes: &HashSet<String>) {
    for stmt in stmts {
        walk_stmt_for_deps(stmt, class_name, info, known_classes);
    }
}

fn process_funcdef(returns: &Option<Box<Expr>>, args: &ast::Arguments,
                   decorator_list: &[Expr], body: &[Stmt],
                   class_name: &str, info: &mut ClassInfo,
                   known_classes: &HashSet<String>) {
    if let Some(ref ret) = returns {
        for name in extract_type_names(ret) {
            if name != class_name && !is_builtin(&name) {
                info.type_deps.insert(name);
            }
        }
    }
    for arg in args.args.iter().chain(args.kwonlyargs.iter()) {
        if let Some(ref ann) = arg.def.annotation {
            for name in extract_type_names(ann) {
                if name != class_name && !is_builtin(&name) {
                    info.type_deps.insert(name);
                }
            }
        }
    }
    for dec in decorator_list {
        if let Some(dec_name) = get_decorator_name(dec) {
            if known_classes.contains(&dec_name) && dec_name != class_name {
                info.decorator_deps.insert(dec_name);
            }
        }
    }
    walk_class_body_for_deps(body, class_name, info, known_classes);
}

fn walk_stmt_for_deps(stmt: &Stmt, class_name: &str, info: &mut ClassInfo,
                      known_classes: &HashSet<String>) {
    match stmt {
        Stmt::AnnAssign(ann) => {
            if let Some(ref annotation) = Some(&ann.annotation) {
                for name in extract_type_names(annotation) {
                    if name != class_name && !is_builtin(&name) {
                        info.type_deps.insert(name);
                    }
                }
            }
        }
        Stmt::FunctionDef(f) => {
            process_funcdef(&f.returns, &f.args, &f.decorator_list, &f.body,
                           class_name, info, known_classes);
        }
        Stmt::AsyncFunctionDef(f) => {
            process_funcdef(&f.returns, &f.args, &f.decorator_list, &f.body,
                           class_name, info, known_classes);
        }
        _ => {
            // Walk child statements
            walk_child_stmts(stmt, class_name, info, known_classes);
        }
    }

    // Walk expressions in this statement for Call and Attribute patterns
    walk_exprs_in_stmt(stmt, class_name, info, known_classes);
}

fn walk_child_stmts(stmt: &Stmt, class_name: &str, info: &mut ClassInfo,
                    known_classes: &HashSet<String>) {
    match stmt {
        Stmt::If(s) => {
            walk_class_body_for_deps(&s.body, class_name, info, known_classes);
            walk_class_body_for_deps(&s.orelse, class_name, info, known_classes);
        }
        Stmt::For(s) => {
            walk_class_body_for_deps(&s.body, class_name, info, known_classes);
            walk_class_body_for_deps(&s.orelse, class_name, info, known_classes);
        }
        Stmt::While(s) => {
            walk_class_body_for_deps(&s.body, class_name, info, known_classes);
            walk_class_body_for_deps(&s.orelse, class_name, info, known_classes);
        }
        Stmt::Try(s) => {
            walk_class_body_for_deps(&s.body, class_name, info, known_classes);
            for handler in &s.handlers {
                let ast::ExceptHandler::ExceptHandler(h) = handler;
                walk_class_body_for_deps(&h.body, class_name, info, known_classes);
            }
            walk_class_body_for_deps(&s.orelse, class_name, info, known_classes);
            walk_class_body_for_deps(&s.finalbody, class_name, info, known_classes);
        }
        Stmt::With(s) => walk_class_body_for_deps(&s.body, class_name, info, known_classes),
        Stmt::AsyncWith(s) => walk_class_body_for_deps(&s.body, class_name, info, known_classes),
        _ => {}
    }
}

/// Walk all expressions in a single statement to find Call and Attribute patterns
fn walk_exprs_in_stmt(stmt: &Stmt, class_name: &str, info: &mut ClassInfo,
                      known_classes: &HashSet<String>) {
    // Collect all expressions from this statement
    let mut exprs: Vec<&Expr> = Vec::new();
    collect_exprs_from_stmt(stmt, &mut exprs);

    for expr in exprs {
        match expr {
            Expr::Call(call) => {
                match call.func.as_ref() {
                    Expr::Name(n) => {
                        let callee = n.id.as_str();
                        if known_classes.contains(callee) && callee != class_name {
                            info.instantiation_deps.insert(callee.to_string());
                        }
                    }
                    Expr::Attribute(a) => {
                        let attr_name = a.attr.as_str();
                        if known_classes.contains(attr_name) && attr_name != class_name {
                            info.instantiation_deps.insert(attr_name.to_string());
                        }
                    }
                    _ => {}
                }
            }
            Expr::Attribute(a) => {
                if let Expr::Name(n) = a.value.as_ref() {
                    let obj_name = n.id.as_str();
                    if known_classes.contains(obj_name) && obj_name != class_name
                        && obj_name != "self" && obj_name != "cls" {
                        info.attribute_deps.insert(obj_name.to_string());
                    }
                }
            }
            _ => {}
        }
    }
}

fn collect_exprs_from_stmt<'a>(stmt: &'a Stmt, out: &mut Vec<&'a Expr>) {
    match stmt {
        Stmt::Expr(e) => collect_exprs(&e.value, out),
        Stmt::Assign(a) => {
            for t in &a.targets { collect_exprs(t, out); }
            collect_exprs(&a.value, out);
        }
        Stmt::AnnAssign(a) => {
            if let Some(ref v) = a.value { collect_exprs(v, out); }
        }
        Stmt::Return(r) => {
            if let Some(ref v) = r.value { collect_exprs(v, out); }
        }
        Stmt::AugAssign(a) => {
            collect_exprs(&a.target, out);
            collect_exprs(&a.value, out);
        }
        Stmt::Raise(r) => {
            if let Some(ref exc) = r.exc { collect_exprs(exc, out); }
            if let Some(ref cause) = r.cause { collect_exprs(cause, out); }
        }
        Stmt::Assert(a) => {
            collect_exprs(&a.test, out);
            if let Some(ref msg) = a.msg { collect_exprs(msg, out); }
        }
        Stmt::Delete(d) => {
            for t in &d.targets { collect_exprs(t, out); }
        }
        Stmt::For(f) => {
            collect_exprs(&f.target, out);
            collect_exprs(&f.iter, out);
        }
        Stmt::While(w) => {
            collect_exprs(&w.test, out);
        }
        Stmt::If(i) => {
            collect_exprs(&i.test, out);
        }
        Stmt::With(w) => {
            for item in &w.items {
                collect_exprs(&item.context_expr, out);
                if let Some(ref v) = item.optional_vars { collect_exprs(v, out); }
            }
        }
        Stmt::AsyncWith(w) => {
            for item in &w.items {
                collect_exprs(&item.context_expr, out);
                if let Some(ref v) = item.optional_vars { collect_exprs(v, out); }
            }
        }
        _ => {}
    }
}

fn collect_exprs<'a>(expr: &'a Expr, out: &mut Vec<&'a Expr>) {
    out.push(expr);
    match expr {
        Expr::Call(c) => {
            collect_exprs(&c.func, out);
            for arg in &c.args { collect_exprs(arg, out); }
            for kw in &c.keywords { collect_exprs(&kw.value, out); }
        }
        Expr::Attribute(a) => collect_exprs(&a.value, out),
        Expr::BinOp(b) => { collect_exprs(&b.left, out); collect_exprs(&b.right, out); }
        Expr::UnaryOp(u) => collect_exprs(&u.operand, out),
        Expr::BoolOp(b) => { for v in &b.values { collect_exprs(v, out); } }
        Expr::Compare(c) => {
            collect_exprs(&c.left, out);
            for v in &c.comparators { collect_exprs(v, out); }
        }
        Expr::IfExp(i) => {
            collect_exprs(&i.test, out);
            collect_exprs(&i.body, out);
            collect_exprs(&i.orelse, out);
        }
        Expr::Subscript(s) => { collect_exprs(&s.value, out); collect_exprs(&s.slice, out); }
        Expr::Starred(s) => collect_exprs(&s.value, out),
        Expr::Tuple(t) => { for e in &t.elts { collect_exprs(e, out); } }
        Expr::List(l) => { for e in &l.elts { collect_exprs(e, out); } }
        Expr::Set(s) => { for e in &s.elts { collect_exprs(e, out); } }
        Expr::Dict(d) => {
            for k in &d.keys { if let Some(k) = k { collect_exprs(k, out); } }
            for v in &d.values { collect_exprs(v, out); }
        }
        Expr::Await(a) => collect_exprs(&a.value, out),
        Expr::Yield(y) => { if let Some(ref v) = y.value { collect_exprs(v, out); } }
        Expr::YieldFrom(y) => collect_exprs(&y.value, out),
        Expr::FormattedValue(f) => {
            collect_exprs(&f.value, out);
            if let Some(ref fs) = f.format_spec { collect_exprs(fs, out); }
        }
        Expr::JoinedStr(j) => { for v in &j.values { collect_exprs(v, out); } }
        Expr::NamedExpr(n) => { collect_exprs(&n.target, out); collect_exprs(&n.value, out); }
        Expr::Lambda(l) => collect_exprs(&l.body, out),
        Expr::ListComp(c) => {
            collect_exprs(&c.elt, out);
            for g in &c.generators { collect_exprs(&g.iter, out); for i in &g.ifs { collect_exprs(i, out); } }
        }
        Expr::SetComp(c) => {
            collect_exprs(&c.elt, out);
            for g in &c.generators { collect_exprs(&g.iter, out); for i in &g.ifs { collect_exprs(i, out); } }
        }
        Expr::DictComp(c) => {
            collect_exprs(&c.key, out);
            collect_exprs(&c.value, out);
            for g in &c.generators { collect_exprs(&g.iter, out); for i in &g.ifs { collect_exprs(i, out); } }
        }
        Expr::GeneratorExp(c) => {
            collect_exprs(&c.elt, out);
            for g in &c.generators { collect_exprs(&g.iter, out); for i in &g.ifs { collect_exprs(i, out); } }
        }
        _ => {}
    }
}


/// Compute 1-indexed line number from a byte offset in source text.
fn line_from_offset(source: &str, offset: usize) -> usize {
    source[..offset.min(source.len())].matches('\n').count() + 1
}

/// Compute 0-indexed column from a byte offset in source text.
fn col_from_offset(source: &str, offset: usize) -> usize {
    let clamped = offset.min(source.len());
    match source[..clamped].rfind('\n') {
        Some(nl) => clamped - nl - 1,
        None => clamped,
    }
}

/// Full coupling analysis — exact port of coupling.py's analyze_coupling.
/// Accepts Python source code, parses it, and returns the same dict structure.
///
/// Args:
///     source: Python source code.
///     filename: File path (for metadata).
///
/// Returns:
///     Dict with "classes" and "coupling_graph" matching Python output exactly.
#[pyfunction]
pub fn analyze_coupling(
    py: Python<'_>,
    source: &str,
    filename: &str,
) -> PyResult<PyObject> {
    let parsed = rustpython_parser::parse(source, rustpython_parser::Mode::Module, filename);
    let stmts = match parsed {
        Ok(ast::Mod::Module(m)) => m.body,
        _ => {
            // Parse failure — return empty result
            let result = PyDict::new_bound(py);
            result.set_item("classes", PyDict::new_bound(py))?;
            result.set_item("coupling_graph", PyDict::new_bound(py))?;
            return Ok(result.into());
        }
    };

    // First pass: collect classes, imports
    let mut classes: HashMap<String, ClassInfo> = HashMap::new();
    let mut known_classes: HashSet<String> = HashSet::new();
    let mut module_imports: HashMap<String, String> = HashMap::new();
    walk_stmts(&stmts, &mut classes, &mut known_classes, &mut module_imports, source);

    // Second pass: walk each class body for deps
    // We need to re-walk the AST to find ClassDef nodes and walk their bodies
    walk_class_deps(&stmts, &mut classes, &known_classes);

    // Compute coupling graph (breakdown per class)
    let mut coupling_graph: HashMap<String, HashMap<String, BTreeSet<String>>> = HashMap::new();

    for (class_name, info) in &classes {
        let mut breakdown: HashMap<String, BTreeSet<String>> = HashMap::new();
        breakdown.insert("inheritance".to_string(),
            info.bases.intersection(&known_classes).cloned().collect());
        breakdown.insert("type_hints".to_string(),
            info.type_deps.intersection(&known_classes).cloned().collect());
        breakdown.insert("instantiation".to_string(),
            info.instantiation_deps.iter().cloned().collect());
        breakdown.insert("attribute_access".to_string(),
            info.attribute_deps.iter().cloned().collect());
        breakdown.insert("decorator".to_string(),
            info.decorator_deps.iter().cloned().collect());
        breakdown.insert("protocol_abc".to_string(), BTreeSet::new());

        // Protocol/ABC shared base detection
        for (other_name, other_info) in &classes {
            if other_name == class_name { continue; }
            let shared_bases: HashSet<_> = info.bases.intersection(&other_info.bases).cloned().collect();
            let has_protocol_base = shared_bases.iter().any(|b| {
                classes.get(b).map_or(false, |ci| ci.is_protocol || ci.is_abc)
            });
            if has_protocol_base {
                breakdown.get_mut("protocol_abc").unwrap().insert(other_name.clone());
            }
        }

        coupling_graph.insert(class_name.clone(), breakdown);
    }

    // Compute afferent coupling
    let mut afferent: HashMap<String, BTreeSet<String>> = HashMap::new();
    for name in classes.keys() {
        afferent.insert(name.clone(), BTreeSet::new());
    }
    for (class_name, breakdown) in &coupling_graph {
        for deps in breakdown.values() {
            for dep in deps {
                if let Some(aff) = afferent.get_mut(dep) {
                    aff.insert(class_name.clone());
                }
            }
        }
    }

    // Build result dicts
    let result = PyDict::new_bound(py);
    let classes_dict = PyDict::new_bound(py);

    for (class_name, info) in &classes {
        let breakdown = coupling_graph.get(class_name).unwrap();
        let mut all_efferent: BTreeSet<String> = BTreeSet::new();
        for deps in breakdown.values() {
            all_efferent.extend(deps.iter().cloned());
        }

        let ce = all_efferent.len();
        let ca = afferent.get(class_name).map_or(0, |a| a.len());
        let total = ce + ca;
        let instability = if total > 0 { ce as f64 / total as f64 } else { 0.0 };

        let cls_dict = PyDict::new_bound(py);
        cls_dict.set_item("efferent_coupling", ce)?;
        cls_dict.set_item("afferent_coupling", ca)?;
        cls_dict.set_item("total_coupling", total)?;
        cls_dict.set_item("efferent_classes", all_efferent.iter().cloned().collect::<Vec<_>>())?;
        cls_dict.set_item("afferent_classes",
            afferent.get(class_name).map_or(Vec::new(), |a| a.iter().cloned().collect()))?;

        let breakdown_dict = PyDict::new_bound(py);
        for (k, v) in breakdown {
            breakdown_dict.set_item(k.as_str(), v.iter().cloned().collect::<Vec<_>>())?;
        }
        cls_dict.set_item("breakdown", breakdown_dict)?;
        cls_dict.set_item("instability", instability)?;
        cls_dict.set_item("is_protocol", info.is_protocol)?;
        cls_dict.set_item("is_abc", info.is_abc)?;
        cls_dict.set_item("is_dataclass", info.is_dataclass)?;
        cls_dict.set_item("line", info.lineno)?;
        cls_dict.set_item("methods", &info.methods)?;

        classes_dict.set_item(class_name.as_str(), cls_dict)?;
    }

    let graph_dict = PyDict::new_bound(py);
    for (name, breakdown) in &coupling_graph {
        let mut combined: BTreeSet<String> = BTreeSet::new();
        for deps in breakdown.values() {
            combined.extend(deps.iter().cloned());
        }
        graph_dict.set_item(name.as_str(), combined.iter().cloned().collect::<Vec<_>>())?;
    }

    result.set_item("classes", classes_dict)?;
    result.set_item("coupling_graph", graph_dict)?;

    Ok(result.into())
}

/// Second pass: find ClassDef nodes and walk their bodies for dependency extraction
fn walk_class_deps(stmts: &[Stmt], classes: &mut HashMap<String, ClassInfo>,
                   known_classes: &HashSet<String>) {
    for stmt in stmts {
        match stmt {
            Stmt::ClassDef(cls) => {
                let name = cls.name.to_string();
                if classes.contains_key(&name) {
                    // Walk the class body collecting deps
                    // We need to temporarily remove info to avoid borrow issues
                    let mut info = classes.remove(&name).unwrap();
                    walk_all_stmts_for_deps(&cls.body, &name, &mut info, known_classes);
                    classes.insert(name.clone(), info);
                }
                // Recurse for nested classes
                walk_class_deps(&cls.body, classes, known_classes);
            }
            Stmt::FunctionDef(f) => walk_class_deps(&f.body, classes, known_classes),
            Stmt::AsyncFunctionDef(f) => walk_class_deps(&f.body, classes, known_classes),
            Stmt::If(s) => {
                walk_class_deps(&s.body, classes, known_classes);
                walk_class_deps(&s.orelse, classes, known_classes);
            }
            Stmt::For(s) => {
                walk_class_deps(&s.body, classes, known_classes);
                walk_class_deps(&s.orelse, classes, known_classes);
            }
            Stmt::While(s) => {
                walk_class_deps(&s.body, classes, known_classes);
                walk_class_deps(&s.orelse, classes, known_classes);
            }
            Stmt::Try(s) => {
                walk_class_deps(&s.body, classes, known_classes);
                for handler in &s.handlers {
                    let ast::ExceptHandler::ExceptHandler(h) = handler;
                    walk_class_deps(&h.body, classes, known_classes);
                }
                walk_class_deps(&s.orelse, classes, known_classes);
                walk_class_deps(&s.finalbody, classes, known_classes);
            }
            Stmt::With(s) => walk_class_deps(&s.body, classes, known_classes),
            Stmt::AsyncWith(s) => walk_class_deps(&s.body, classes, known_classes),
            _ => {}
        }
    }
}

/// Walk all statements in a class body recursively for dep extraction
fn walk_all_stmts_for_deps(stmts: &[Stmt], class_name: &str, info: &mut ClassInfo,
                           known_classes: &HashSet<String>) {
    for stmt in stmts {
        walk_stmt_for_deps(stmt, class_name, info, known_classes);
        // Also recurse into compound statements
        match stmt {
            Stmt::FunctionDef(f) => {
                walk_all_stmts_for_deps(&f.body, class_name, info, known_classes);
            }
            Stmt::AsyncFunctionDef(f) => {
                walk_all_stmts_for_deps(&f.body, class_name, info, known_classes);
            }
            Stmt::If(s) => {
                walk_all_stmts_for_deps(&s.body, class_name, info, known_classes);
                walk_all_stmts_for_deps(&s.orelse, class_name, info, known_classes);
            }
            Stmt::For(s) => {
                walk_all_stmts_for_deps(&s.body, class_name, info, known_classes);
                walk_all_stmts_for_deps(&s.orelse, class_name, info, known_classes);
            }
            Stmt::While(s) => {
                walk_all_stmts_for_deps(&s.body, class_name, info, known_classes);
                walk_all_stmts_for_deps(&s.orelse, class_name, info, known_classes);
            }
            Stmt::Try(s) => {
                walk_all_stmts_for_deps(&s.body, class_name, info, known_classes);
                for handler in &s.handlers {
                    let ast::ExceptHandler::ExceptHandler(h) = handler;
                    walk_all_stmts_for_deps(&h.body, class_name, info, known_classes);
                }
                walk_all_stmts_for_deps(&s.orelse, class_name, info, known_classes);
                walk_all_stmts_for_deps(&s.finalbody, class_name, info, known_classes);
            }
            Stmt::With(s) => walk_all_stmts_for_deps(&s.body, class_name, info, known_classes),
            Stmt::AsyncWith(s) => walk_all_stmts_for_deps(&s.body, class_name, info, known_classes),
            _ => {}
        }
    }
}
