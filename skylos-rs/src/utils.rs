use rustpython_ast::TextSize;

pub struct LineIndex {
    line_starts: Vec<u32>,
}

impl LineIndex {
    pub fn new(source: &str) -> Self {
        let mut line_starts = vec![0];
        for (i, b) in source.bytes().enumerate() {
            if b == b'\n' {
                line_starts.push((i + 1) as u32);
            }
        }
        Self { line_starts }
    }

    pub fn line_index(&self, offset: TextSize) -> usize {
        let offset_u32: u32 = offset.into();
        match self.line_starts.binary_search(&offset_u32) {
            Ok(i) => i + 1,
            Err(i) => i,
        }
    }
}
