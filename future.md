# Future Improvements for Skylos Rust Implementation

This document outlines the roadmap for bringing the Rust implementation to feature parity with the Python version, based on actual output comparison and gap analysis.

## Critical Issues Found in Output Comparison

### ❌ False Positives in Rust Output

The Rust version produces **many false positives** that the Python version correctly filters out:

**Example from comparison:**
- **Rust**: Reports `analyzer._module`, `analyzer._mark_refs`, `cli.main` as unused
- **Python**: Correctly identifies these are used (methods called by class, entry points, etc.)

**Root Causes:**
1. No understanding of class methods vs standalone functions
2. Missing module-level reference resolution
3. No entry point detection
4. Poor handling of private methods (should be penalized but not always flagged)

---

## Phase 1: Critical Fixes (Must Have)

### 1.1 Method and Class Context 🔴 HIGH PRIORITY

**Problem:** Rust treats `self.method_name()` calls as references to `method_name`, but doesn't understand class boundaries.

**Solution:**
- Track current class context in visitor
- Qualify method names with class: `ClassName.method_name`
- When seeing function call on `self`, match to current class methods
- Apply auto-called method heuristics (`__init__`, `__str__`, etc.)

**Impact:** Eliminates 90% of false positives in class-heavy code

### 1.2 Module and Import Resolution 🔴 HIGH PRIORITY

**Problem:** References like `analyzer.analyze()` don't match definition `skylos.analyzer.Skylos.analyze`

**Solution:**
- Track import statements and build alias map
- Resolve module paths properly
- Match references considering import aliases
- Handle `from X import Y` vs `import X`

**Impact:** Fixes most cross-module false positives

### 1.3 Entry Point Detection 🟡 MEDIUM PRIORITY

**Problem:** `cli.main`, `analyzer.analyze` reported as unused despite being entry points

**Solution:**
- Detect console_scripts in setup.py/pyproject.toml
- Mark functions referenced in `if __name__ == "__main__"` as used
- Recognize common entry point patterns

**Impact:** Reduces false positives for CLI tools

---

## Phase 2: Feature Parity

### 2.1 Pragma Support 🟡 MEDIUM PRIORITY

**Current:** None  
**Python has:** `# pragma: no skylos`

**Implementation:**
```rust
// In LineIndex or new PragmaDetector
pub fn get_ignored_lines(source: &str) -> HashSet<usize> {
    source.lines()
        .enumerate()
        .filter(|(_, line)| line.contains("pragma: no skylos"))
        .map(|(i, _)| i + 1)
        .collect()
}
```

**Impact:** Allows users to suppress false positives inline

### 2.2 Configuration File Support 🟡 MEDIUM PRIORITY

**Current:** None  
**Python has:** `.skylos.toml` with exclude patterns, confidence threshold, etc.

**Dependencies:** `serde`, `toml` crate

**Implementation:**
```toml
# .skylos.toml
[skylos]
confidence = 60
exclude_folders = ["venv", ".tox", "build"]
```

**Impact:** Better user experience for teams

### 2.3 Unused Parameter Detection 🟡 MEDIUM PRIORITY

**Current:** None  
**Python has:** Detects function parameters never used

**Implementation:**
- Track function parameter names
- Check for references within function body only
- Report unused parameters at lower confidence (they might be for interface compliance)

**Impact:** Catches more dead code

### 2.4 Advanced Heuristics 🔴 HIGH PRIORITY

**Missing heuristics from Python:**
1. **Visitor Pattern**: Methods like `visit_*`, `leave_*` auto-used when base class is instantiated
2. **Format Methods**: `format()` method on `*Formatter` classes
3. **Auto-called Methods**: `__init__`, `__str__`, `__repr__`, etc.
4. **Settings Classes**: Variables in `Settings` or `Config` classes (Django/Pydantic)
5. **Dataclass Fields**: Fields defined with `@dataclass` decorator

**Solution:** Implement penalty/reference boosting system similar to Python

### 2.5 `__all__` Export Detection 🟢 LOW PRIORITY

**Current:** Basic (just `in_init`)  
**Python has:** Full `__all__` parsing and export marking

**Implementation:**
- Parse `__all__ = [...]` in AST
- Mark exported definitions
- Lower confidence for exported items

**Impact:** Reduces false positives in library code

---

## Phase 3: Advanced Features

### 3.1 Dynamic Code Patterns 🟢 LOW PRIORITY

**Current:** None  
**Python has:** Detection of `globals()`, `getattr()`, `__import__()` to mark modules as dynamic

**Impact:** Reduces false positives in meta-programming heavy code

### 3.2 Web Interface 🟢 LOW PRIORITY

**Current:** CLI only  
**Python has:** Flask server with visual dashboard

**Defer:** Not critical for core functionality

### 3.3 Code Removal (LibCST equivalent) 🟢 LOW PRIORITY

**Current:** Detection only  
**Python has:** Safe code removal and commenting via LibCST

**Challenge:** Rust lacks a Python CST library. Options:
1. Call Python LibCST as subprocess
2. Build basic removal using string manipulation (risky)
3. Defer indefinitely

**Recommendation:** Defer - detection is the primary value

---

## Phase 4: Quality Improvements

### 4.1 Better Confidence Scoring

**Current Issues:**
- Only 4 penalty rules vs Python's 15+
- No bonus for being in `__init__`
- No special handling for Settings/Config classes

**TODO:**
- Port all penalty rules from Python
- Add confidence boosting for exported items
- Implement graduated penalties

### 4.2 Performance Optimization

**Current:** Already fast (9.3x), but room for improvement

**Opportunities:**
- Cache parsed ASTs
- Incremental analysis (only changed files)
- Better parallelization of reference resolution

### 4.3 Better Error Handling

**Current:** Silently skips unparseable files  
**TODO:** 
- Report parse errors
- Add debug mode (`SKYLOS_DEBUG` env var)
- Better error messages

---

## Implementation Priority Matrix

| Feature | Priority | Impact | Effort | Order |
|---------|----------|--------|--------|-------|
| **Method/Class Context** | 🔴 Critical | Huge | High | 1 |
| **Module Resolution** | 🔴 Critical | Huge | High | 2 |
| **Advanced Heuristics** | 🔴 High | High | Medium | 3 |
| **Entry Point Detection** | 🟡 Medium | Medium | Low | 4 |
| **Pragma Support** | 🟡 Medium | Medium | Low | 5 |
| **Unused Parameters** | 🟡 Medium | Medium | Medium | 6 |
| **Config File** | 🟡 Medium | Low | Medium | 7 |
| **`__all__` Exports** | 🟢 Low | Medium | Low | 8 |
| **Dynamic Patterns** | 🟢 Low | Low | Medium | 9 |
| **Web UI** | 🟢 Defer | Low | Very High | - |
| **Code Removal** | 🟢 Defer | Low | Very High | - |

---

## Estimated Timeline

**Phase 1 (Critical Fixes):** 2-3 weeks
- Week 1: Method/Class context
- Week 2: Module resolution  
- Week 3: Heuristics + entry point detection

**Phase 2 (Feature Parity):** 2-3 weeks
- Pragma, config, parameters, exports

**Phase 3 (Advanced):** 1-2 months (optional)
- Dynamic patterns, UI (if desired)

**Total to Production Quality:** 1-2 months

---

## Success Metrics

**Goal:** Match Python output accuracy

**Current State:**
- Python: 3 unused variables (true positives)
- Rust: 100+ false positives in methods/functions

**Target:**
- Phase 1 complete: <10 false positives on Skylos codebase
- Phase 2 complete: ~Same output as Python version
- Phase 3 complete: Better performance + same accuracy

---

## Contribution Guide

Want to help? Pick an issue from Phase 1 (highest impact) or Phase 2 (easier wins).

### Quick Wins for Contributors:
1. ✅ Pragma support (regex-based, simple)
2. ✅ Config file loading (use `toml` crate)
3. ✅ Entry point detection (parse `setup.py` or `pyproject.toml`)

### Complex Tasks (need design):
1. ⚠️ Class/method context tracking
2. ⚠️ Module resolution system
3. ⚠️ Visitor pattern heuristics
