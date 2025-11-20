use rustpython_ast::TextSize;
use std::collections::HashSet;

/// LineIndex converts byte offsets to line numbers
pub struct LineIndex {
    line_starts: Vec<usize>,
}

impl LineIndex {
    pub fn new(source: &str) -> Self {
        let mut line_starts = vec![0];
        for (i, ch) in source.char_indices() {
            if ch == '\n' {
                line_starts.push(i + 1);
            }
        }
        Self { line_starts }
    }

    pub fn line_index(&self, offset: TextSize) -> usize {
        let offset = offset.to_usize();
        match self.line_starts.binary_search(&offset) {
            Ok(line) => line + 1,
            Err(line) => line,
        }
    }
}

/// Detects lines with `# pragma: no skylos` comment
/// Returns a set of line numbers (1-indexed) that should be ignored
pub fn get_ignored_lines(source: &str) -> HashSet<usize> {
    source.lines()
        .enumerate()
        .filter(|(_, line)| line.contains("pragma: no skylos"))
        .map(|(i, _)| i + 1)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pragma_detection() {
        let source = r#"
def used_function():
    return 42

def unused_function():  # pragma: no skylos
    return "ignored"

class MyClass:  # pragma: no skylos
    pass
"#;
        let ignored = get_ignored_lines(source);
        
        // Lines 5 and 8 should be ignored (1-indexed)
        assert!(ignored.contains(&5), "Should detect pragma on line 5");
        assert!(ignored.contains(&8), "Should detect pragma on line 8");
        assert_eq!(ignored.len(), 2, "Should find exactly 2 pragma lines");
    }

    #[test]
    fn test_no_pragmas() {
        let source = r#"
def regular_function():
    return 42
"#;
        let ignored = get_ignored_lines(source);
        assert_eq!(ignored.len(), 0, "Should find no pragma lines");
    }
}
