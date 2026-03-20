//! Cycle detection — exact port of circular_deps.py's DFS-based `find_simple_cycles`.
//! NOT Tarjan SCC — this finds individual cycles with the same normalization as Python.

use pyo3::prelude::*;
use std::collections::{HashMap, HashSet};

/// Find all circular dependency cycles using DFS (matches Python's find_simple_cycles exactly).
///
/// Args:
///     edges: List of (from_module, to_module) import edges.
///     modules: List of module names (iteration order matters for determinism).
///
/// Returns:
///     List of cycles, where each cycle is a normalized list of module names.
#[pyfunction]
pub fn find_cycles(
    edges: Vec<(String, String)>,
    modules: Vec<String>,
) -> Vec<Vec<String>> {
    // Build adjacency list
    let mut deps: HashMap<String, Vec<String>> = HashMap::new();
    for (from, to) in &edges {
        deps.entry(from.clone()).or_default().push(to.clone());
    }

    let mut all_cycles: Vec<Vec<String>> = Vec::new();

    // For each starting node, clear visited and run DFS (matches Python exactly)
    for start_node in &modules {
        let mut visited: HashSet<String> = HashSet::new();
        let mut found = dfs(start_node, &mut Vec::new(), &mut HashSet::new(), &mut visited, &deps);
        for cycle in found.drain(..) {
            if !all_cycles.contains(&cycle) {
                all_cycles.push(cycle);
            }
        }
    }

    // Deduplicate by sorted key
    let mut unique: Vec<Vec<String>> = Vec::new();
    let mut seen: HashSet<Vec<String>> = HashSet::new();
    for cycle in all_cycles {
        let mut sort_key = cycle.clone();
        sort_key.sort();
        if !seen.contains(&sort_key) {
            seen.insert(sort_key);
            unique.push(cycle);
        }
    }

    unique
}

fn dfs(
    node: &str,
    path: &mut Vec<String>,
    path_set: &mut HashSet<String>,
    visited: &mut HashSet<String>,
    deps: &HashMap<String, Vec<String>>,
) -> Vec<Vec<String>> {
    if path_set.contains(node) {
        // Found a cycle — extract and normalize
        let cycle_start = path.iter().position(|n| n == node).unwrap();
        let mut cycle: Vec<String> = path[cycle_start..].to_vec();
        cycle.push(node.to_string());

        // Normalize: rotate so minimum element is first
        let min_val = cycle[..cycle.len() - 1].iter().min().unwrap().clone();
        let min_idx = cycle.iter().position(|n| n == &min_val).unwrap();
        let mut normalized: Vec<String> = cycle[min_idx..cycle.len() - 1].to_vec();
        normalized.extend_from_slice(&cycle[..min_idx]);

        return vec![normalized];
    }

    if visited.contains(node) {
        return Vec::new();
    }

    let mut found_cycles: Vec<Vec<String>> = Vec::new();
    path.push(node.to_string());
    path_set.insert(node.to_string());

    if let Some(neighbors) = deps.get(node) {
        for neighbor in neighbors {
            found_cycles.extend(dfs(neighbor, path, path_set, visited, deps));
        }
    }

    path.pop();
    path_set.remove(node);
    visited.insert(node.to_string());

    found_cycles
}
