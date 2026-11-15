pub fn version() -> u32 {
    1
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    fn cleanup(dir: &Path) {
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn roundtrip() {
        let dir = std::env::temp_dir().join("fixture-roundtrip");
        cleanup(&dir);
    }
}
