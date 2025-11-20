# Future Improvements for Skylos Rust Implementation

This document outlines the roadmap for bringing the Rust implementation to feature parity with the Python version, based on actual output comparison and gap analysis.

> [!NOTE]
> See [`rust_vs_python_benchmark.md`](rust_vs_python_benchmark.md) for performance comparison and feature matrix.

**Quick Links:**
- [Critical Issues](#critical-issues-found-in-output-comparison)
- [Phase 1: Critical Fixes](#phase-1-critical-fixes-must-have)
- [Testing Roadmap](#testing-roadmap)
- [Contribution Guide](#contribution-guide)


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
### 2.1 Pragma Support ✅ **COMPLETED**

**Current:** Implemented!  
**Python has:** `# pragma: no skylos`

**Implementation:** See [`skylos-rs/PRAGMA_IMPLEMENTATION.md`](skylos-rs/PRAGMA_IMPLEMENTATION.md)

**Files Modified:**
- `src/utils.rs` - Added `get_ignored_lines()` function
- `src/analyzer.rs` - Integrated pragma detection into penalty system

**Impact:** Users can now suppress false positives inline


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

## Testing Roadmap

### Current Test Status

**Test Suite Created:**
- ✅ `integration_test.rs` - End-to-end binary tests
- ✅ `visitor_test.rs` - AST visitor unit tests
- ✅ `framework_test.rs` - Framework detection tests
- ✅ `test_utils_test.rs` - Test file detection tests
- ✅ `security_test.rs` - Secrets & dangerous code tests
- ✅ `quality_test.rs` - Code quality tests

**Test Coverage Goals:**
1. **Phase 1**: Fix API mismatches in existing tests → 100% passing unit tests
2. **Phase 2**: Add integration tests for each critical fix
3. **Phase 3**: Property-based testing for reference resolution
4. **Phase 4**: Benchmark regression tests

**Test Files Location:** `skylos-rs/tests/` (see [`tests/README.md`](skylos-rs/tests/README.md))

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
### Quick Wins for Contributors (Good First Issues):

**1. Pragma Support** (2-3 hours)
- Add `get_ignored_lines()` helper in `utils.rs`
- Modify analyzer to skip definitions on ignored lines
- Add test case in `tests/visitor_test.rs`
- **Files to modify**: `src/utils.rs`, `src/analyzer.rs`

**2. Config File Support** (4-6 hours)
- Add `toml = "0.8"` to `Cargo.toml`
- Create `src/config.rs` with config struct
- Load config in `main.rs` before analyzer
- **Files to modify**: `Cargo.toml`, `src/main.rs`, new: `src/config.rs`

**3. Entry Point Detection** (3-4 hours)
- Parse `if __name__ == "__main__"` in visitor
- Detect `setup.py` / `pyproject.toml` entry points
- Mark matched functions as exported
- **Files to modify**: `src/visitor.rs`, `src/analyzer.rs`

**4. Fix Test Suite** (2-3 hours)
- Address API mismatches in test files
- Update `TestAwareVisitor::new()` calls to use `&Path`
- Ensure all tests compile and pass
- **Files to modify**: `tests/*.rs`

### Complex Tasks (Need Design Discussion):

**1. Class/Method Context Tracking**
- **Challenge**: Track class scope during AST traversal
- **Approach**: Add `current_class: Option<String>` to visitor
- **Design Doc Needed**: Yes - discuss in issue/PR
- **Estimated Effort**: 1-2 weeks
- **Files to modify**: `src/visitor.rs`, `src/analyzer.rs`

**2. Module Resolution System**
- **Challenge**: Match `import foo` references to `foo.bar()` calls
- **Approach**: Build import alias map, resolve qualified names
- **Design Doc Needed**: Yes - significant architecture change
- **Estimated Effort**: 2-3 weeks
- **Files to modify**: `src/visitor.rs`, `src/analyzer.rs`, new: `src/resolver.rs`

**3. Advanced Heuristics**
- **Challenge**: Port 15+ penalty rules from Python
- **Approach**: Create penalty rule registry, apply in analyzer
- **Design Doc Needed**: Optional - rules are well-defined in Python
- **Estimated Effort**: 1 week
- **Files to modify**: `src/analyzer.rs`, new: `src/heuristics.rs`

### How to Contribute

1. **Check existing issues** on GitHub
2. **Comment on an issue** to claim it (avoid duplicate work)
3. **Fork and create a branch**: `git checkout -b fix/pragma-support`
4. **Write tests first**: Add failing test, then implement
5. **Run all tests**: `cargo test`
6. **Format code**: `cargo fmt`
7. **Submit PR**: Reference issue number, explain changes

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for full guidelines.
