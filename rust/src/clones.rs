//! Fast clone detection — replaces clones.py's O(n²) SequenceMatcher.
//! Implements Python's SequenceMatcher (Ratcliff/Obershelp) algorithm in Rust.
//! Parallel pairwise comparison via rayon.

use pyo3::prelude::*;
use rayon::prelude::*;
use std::collections::HashMap;

/// Find the longest common substring between a[a_lo..a_hi] and b[b_lo..b_hi].
/// Returns (a_start, b_start, length). Matches Python's find_longest_match.
fn find_longest_match(a: &[char], b: &[char], a_lo: usize, a_hi: usize, b_lo: usize, b_hi: usize) -> (usize, usize, usize) {
    let mut best_a = a_lo;
    let mut best_b = b_lo;
    let mut best_size: usize = 0;

    // j2len[j] = length of longest match ending with a[i-1] and b[j-1]
    let mut j2len: HashMap<usize, usize> = HashMap::new();

    for i in a_lo..a_hi {
        let mut new_j2len: HashMap<usize, usize> = HashMap::new();
        // Find all positions of a[i] in b[b_lo..b_hi]
        for j in b_lo..b_hi {
            if a[i] == b[j] {
                let k = j2len.get(&(j.wrapping_sub(1))).copied().unwrap_or(0) + 1;
                new_j2len.insert(j, k);
                if k > best_size {
                    best_a = i + 1 - k;
                    best_b = j + 1 - k;
                    best_size = k;
                }
            }
        }
        j2len = new_j2len;
    }

    (best_a, best_b, best_size)
}

/// Get matching blocks (Ratcliff/Obershelp) — recursive longest common substring.
/// Returns list of (a_idx, b_idx, size) triples.
fn get_matching_blocks(a: &[char], b: &[char]) -> Vec<(usize, usize, usize)> {
    let mut blocks = Vec::new();
    _get_matching_blocks(a, b, 0, a.len(), 0, b.len(), &mut blocks);
    blocks.sort();
    blocks.push((a.len(), b.len(), 0)); // sentinel
    blocks
}

fn _get_matching_blocks(
    a: &[char], b: &[char],
    a_lo: usize, a_hi: usize,
    b_lo: usize, b_hi: usize,
    blocks: &mut Vec<(usize, usize, usize)>,
) {
    let (ai, bj, size) = find_longest_match(a, b, a_lo, a_hi, b_lo, b_hi);
    if size > 0 {
        if a_lo < ai && b_lo < bj {
            _get_matching_blocks(a, b, a_lo, ai, b_lo, bj, blocks);
        }
        blocks.push((ai, bj, size));
        if ai + size < a_hi && bj + size < b_hi {
            _get_matching_blocks(a, b, ai + size, a_hi, bj + size, b_hi, blocks);
        }
    }
}

/// Compute similarity ratio using Ratcliff/Obershelp (matches Python SequenceMatcher.ratio() exactly).
fn similarity_ratio(a: &str, b: &str) -> f64 {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let total = a_chars.len() + b_chars.len();
    if total == 0 {
        return 1.0;
    }
    let blocks = get_matching_blocks(&a_chars, &b_chars);
    let matching: usize = blocks.iter().map(|(_, _, size)| size).sum();
    (2.0 * matching as f64) / total as f64
}

/// Compute similarity ratio between two strings (equivalent to difflib.SequenceMatcher.ratio()).
#[pyfunction]
pub fn compute_similarity(a: &str, b: &str) -> f64 {
    similarity_ratio(a, b)
}

/// Detect clone pairs from a list of normalized code fragments.
///
/// Args:
///     fragments: List of (index, normalized_text, bucket_key) tuples.
///     threshold: Minimum similarity to report as a clone pair.
///
/// Returns:
///     List of (idx_a, idx_b, similarity) tuples above threshold.
#[pyfunction]
#[pyo3(signature = (fragments, threshold = 0.90))]
pub fn detect_clone_pairs(
    fragments: Vec<(usize, String, String)>,
    threshold: f64,
) -> Vec<(usize, usize, f64)> {
    let mut buckets: std::collections::HashMap<String, Vec<(usize, String)>> =
        std::collections::HashMap::new();

    for (idx, text, key) in fragments {
        buckets.entry(key).or_default().push((idx, text));
    }

    let results: Vec<Vec<(usize, usize, f64)>> = buckets
        .into_values()
        .collect::<Vec<_>>()
        .par_iter()
        .map(|bucket| {
            let mut pairs = Vec::new();
            for i in 0..bucket.len() {
                for j in (i + 1)..bucket.len() {
                    let sim = similarity_ratio(&bucket[i].1, &bucket[j].1);
                    if sim >= threshold {
                        pairs.push((bucket[i].0, bucket[j].0, sim));
                    }
                }
            }
            pairs
        })
        .collect();

    results.into_iter().flatten().collect()
}
