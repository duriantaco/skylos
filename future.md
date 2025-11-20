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

### ❌ False Positives in Rust Output (279 vs 11 items)

The Rust version produces **268 extra false positives** that the Python version correctly filters out:

**Comparison Results (Skylos repo - 29 files):**
- **Python**: 11 items (2 functions, 9 variables) - All legitimate
- **Rust**: 279 items (184 functions, 79 imports, 16 classes) - Mostly false positives

**Root Causes (After Code Review):**
1. ✅ **Cross-file aggregation EXISTS** (lines 155-172 in `analyzer.rs`)
2. ❌ **Import resolution BROKEN** - `import sys` def doesn't match `sys.exit()` ref
3. ❌ **Method call tracking BROKEN** - `self.method()` doesn't match `ClassName.method` def
4. ❌ **Qualified name mismatches** - `analyzer.Skylos` vs `skylos.analyzer.Skylos`

**Examples from actual output:**
- ❌ `sys`, `json`, `Path` imports marked unused (79 total) - ref names don't match import names
- ❌ `analyzer.Skylos.analyze()` marked unused - ref is `analyze`, def is `analyzer.Skylos.analyze`
- ❌ `visitor.Visitor` class marked unused - methods called but class not instantiated in same file

---

## Phase 1: Critical Fixes (Must Have)

### 1.1 Import Name Resolution 🔴 **HIGHEST PRIORITY**

**Problem:** Import `sys` creates definition `sys`, but usage `sys.exit()` creates reference `sys.exit`

**Current Behavior:**
```python
import sys          # Creates def: "sys"
sys.exit(1)         # Creates ref: "sys.exit" -> NO MATCH!
```

**Solution:**
- When seeing `import foo`, also add reference to `foo` itself
- When seeing `foo.bar()`, also add reference to parent `foo`
- Create import alias tracking system

**Impact:** Fixes 79/279 false positives (all imports)

### 1.2 Method and Class Context 🔴 **HIGH PRIORITY**

**Problem:** `self.method_name()` calls create reference to `method_name`, but definitions are `ClassName.method_name`

**Current Behavior:**
```python
class Skylos:
    def analyze(self):      # Creates def: "analyzer.Skylos.analyze"
        self._module()      # Creates ref: "_module" -> NO MATCH!
```

**Solution:**
- Track current class context in visitor
- Qualify method references with current class name
- Match `self.foo()` to `CurrentClass.foo()`
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

| Feature | Priority | Impact | Effort | Order | Status |
|---------|----------|--------|--------|-------|--------|
| **Import Resolution** | 🔴 Critical | Huge | Medium | 1 | ⏳ TODO |
| **Method/Class Context** | 🔴 Critical | Huge | High | 2 | ⏳ TODO |
| **Qualified Name Matching** | 🔴 Critical | High | Medium | 3 | ⏳ TODO |
| **Advanced Heuristics** | 🔴 High | High | Medium | 4 | ⏳ TODO |
| **Pragma Support** | ✅ Complete | Medium | Low | - | ✅ DONE |
| **Entry Point Detection** | ✅ Complete | Medium | Low | - | ✅ DONE |
| **Unused Parameters** | 🟡 Medium | Medium | Medium | 5 | ⏳ Later |
| **Config File** | 🟡 Medium | Low | Medium | 6 | ⏳ Later |
| **`__all__` Exports** | 🟡 Medium | Medium | Low | 7 | ✅ DONE |
| **Dynamic Patterns** | 🟢 Low | Low | Medium | 8 | ⏳ Later |
| **Web UI** | 🟢 Defer | Low | Very High | - | ⏸️ Defer |
| **Code Removal** | 🟢 Defer | Low | Very High | - | ⏸️ Defer |

---

## Estimated Timeline

**Phase 1 (Critical Fixes):** 2-3 weeks
- Week 1: Import resolution (fix 79 false positives)
- Week 2: Method/class context tracking (fix 184 false positives)
- Week 3: Qualified name matching + advanced heuristics

**Phase 2 (Feature Parity):** 1-2 weeks
- Config file, unused parameters

**Phase 3 (Advanced):** 1-2 months (optional)
- Dynamic patterns, UI (if desired)

**Total to Production Quality:** 1-1.5 months

---
### Quick Wins for Contributors (Good First Issues):

**1. Config File Support** ✅ (4-6 hours)
- Add `toml = "0.8"` to `Cargo.toml`
- Create `src/config.rs` with config struct
- Load config in `main.rs` before analyzer
- **Files to modify**: `Cargo.toml`, `src/main.rs`, new: `src/config.rs`

**2. Fix Test Suite** (2-3 hours)
- Address API mismatches in test files
- Update `TestAwareVisitor::new()` calls to use `&Path`
- Ensure all tests compile and pass
- **Files to modify**: `tests/*.rs`

### Complex Tasks (Need Design Discussion):

**1. Import Resolution System** 🔴 **HIGHEST PRIORITY**
- **Challenge**: Match `import sys` to `sys.exit()` usage
- **Approach**: Track import-to-usage mapping, create parent references
- **Design Doc Needed**: Yes - discuss matching strategy
- **Estimated Effort**: 1 week
- **Files to modify**: `src/visitor.rs`, `src/analyzer.rs`
- **Impact**: Fixes 79/279 false positives

**2. Class/Method Context Tracking** 🔴 **HIGH PRIORITY**
- **Challenge**: Track class scope during AST traversal
- **Approach**: Add `current_class: Option<String>` to visitor
- **Design Doc Needed**: Yes - discuss in issue/PR
- **Estimated Effort**: 1-2 weeks
- **Files to modify**: `src/visitor.rs`, `src/analyzer.rs`
- **Impact**: Fixes 184/279 false positives

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
