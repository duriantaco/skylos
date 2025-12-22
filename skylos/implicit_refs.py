import re
from pathlib import Path


class ImplicitRefTracker:
    
    def __init__(self):
        self.known_refs = set()
        self.pattern_refs = []
        self.f_string_patterns = {}
        self.coverage_hits = set()
    
    def should_mark_as_used(self, definition):
        simple_name = definition.simple_name
        
        if simple_name in self.known_refs:
            return True, 95, "dynamic reference"
        
        for pattern, confidence in self.pattern_refs:
            regex = "^" + pattern.replace("*", ".*") + "$"
            if re.match(regex, simple_name):
                return True, confidence, f"pattern '{pattern}'"
        
        if self.coverage_hits:
            def_file = Path(definition.filename).name
            for cov_file, line in self.coverage_hits:
                if cov_file.endswith(def_file) or def_file in cov_file:
                    if definition.line == line:
                        return True, 100, "executed (coverage)"
        
        return False, 0, None
    
    def load_coverage(self, coverage_file=".coverage"):
        path = Path(coverage_file)
        if not path.exists():
            return
        
        try:
            import sqlite3
            conn = sqlite3.connect(str(path))
            cursor = conn.cursor()
            
            cursor.execute("SELECT id, path FROM file")
            files = {}
            for row in cursor.fetchall():
                key = row[0]
                value = row[1]
                files[key] = value
            
            cursor.execute("SELECT file_id, numbits FROM line_bits")
            for file_id, numbits in cursor.fetchall():
                if file_id in files:
                    filename = files[file_id]
                    for byte_idx, byte in enumerate(numbits):
                        for bit_idx in range(8):
                            if byte & (1 << bit_idx):
                                line = byte_idx * 8 + bit_idx
                                self.coverage_hits.add((filename, line))
            
            conn.close()
        except Exception as e:
            pass

pattern_tracker = ImplicitRefTracker()
