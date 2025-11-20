# Skylos: Python vs Rust Benchmark & Comparison

## Performance Benchmarks

### Test Environment
- **Dataset**: Skylos codebase (74 Python files)
- **Hardware**: Windows system
- **Python Version**: 3.11
- **Rust Version**: 1.70+ (release build with optimizations)

### Execution Time

| Implementation | Time (seconds) | Relative Speed |
|---------------|----------------|----------------|
| **Python** | 5.00s | 1.0x (baseline) |
| **Rust** | 0.54s | **9.3x faster** |

> [!IMPORTANT]
> The Rust implementation is approximately **9.3x faster** than the Python version on the same codebase.

### Performance Analysis

**Why is Rust faster?**
1. **Compiled vs Interpreted**: Rust compiles to native machine code, while Python is interpreted
2. **Parallel Processing**: Both use parallel file processing (rayon vs multiprocessing), but Rust has lower overhead
3. **Memory Management**: Rust's zero-cost abstractions and stack allocation vs Python's garbage collection
4. **Type System**: Static typing enables aggressive compiler optimizations

---

## Feature Comparison

### ✅ Implemented Features (Both Versions)

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| **Dead Code Detection** | ✅ | ✅ | Functions, classes, imports, variables |
| **Framework Awareness** | ✅ | ✅ | Flask, Django, FastAPI detection |
| **Test File Exclusion** | ✅ | ✅ | pytest, unittest patterns |
| **Secrets Scanning** | ✅ | ✅ | AWS keys, API tokens |
| **Dangerous Code Detection** | ✅ | ✅ | eval, exec, subprocess |
| **Quality Checks** | ✅ | ✅ | Nesting depth analysis |
| **Parallel Processing** | ✅ | ✅ | Multi-threaded file analysis |
| **JSON Output** | ✅ | ✅ | Machine-readable results |
| **Confidence Scoring** | ✅ | ✅ | Penalty-based confidence system |

### ❌ Missing Features in Rust

| Feature | Python | Rust | Impact |
|---------|--------|------|--------|
| **Pragma Support** | ✅ `# pragma: no skylos` | ❌ | Cannot ignore specific lines |
| **Config File** | ✅ `.skylos.toml` | ❌ | No persistent configuration |
| **Unused Parameters** | ✅ | ❌ | Only detects functions/classes/imports |
| **LibCST Integration** | ✅ Safe removals | ❌ | No automated code removal |
| **Web Interface** | ✅ Flask server | ❌ | CLI only |
| **VS Code Extension** | ✅ | ❌ | No editor integration yet |
| **Heuristics** | ✅ Advanced | ⚠️ Basic | Simpler reference resolution |
| **Dynamic Analysis** | ✅ `globals()`, `getattr` | ⚠️ Limited | Less Python-aware |
| **Export Detection** | ✅ `__all__` | ⚠️ Basic | Simpler export handling |
| **Dataclass Support** | ✅ | ❌ | No special handling |
| **Settings/Config Classes** | ✅ Auto-detect | ❌ | No special handling |

### ⚠️ Partially Implemented

**Reference Resolution**
- **Python**: Sophisticated name resolution with module tracking, import aliases, and dynamic patterns
- **Rust**: Basic name matching without full module resolution

**Confidence Penalties**
- **Python**: 15+ penalty rules (private names, dunder methods, settings classes, etc.)
- **Rust**: 4 basic rules (test files, framework decorators, private names, dunder methods)

---

## Advantages & Disadvantages

### Python Version

**Advantages** ✅
- **Mature & Feature-Complete**: Years of development, handles edge cases
- **Python-Native**: Deep understanding of Python semantics (dynamic imports, `__all__`, etc.)
- **Ecosystem Integration**: LibCST for safe refactoring, Flask for web UI
- **Extensibility**: Easy to add new rules and patterns
- **Pragma Support**: Fine-grained control with inline comments
- **Configuration**: `.skylos.toml` for project-specific settings

**Disadvantages** ❌
- **Performance**: 9.3x slower than Rust
- **Dependencies**: Requires Flask, LibCST, inquirer, etc.
- **Startup Time**: Python interpreter overhead
- **Memory Usage**: Higher due to GC and dynamic typing

### Rust Version

**Advantages** ✅
- **Performance**: **9.3x faster** execution
- **Single Binary**: No runtime dependencies, easy deployment
- **Memory Efficient**: Lower memory footprint
- **Type Safety**: Compile-time guarantees prevent bugs
- **Parallel Processing**: Efficient rayon-based parallelism
- **Cross-Platform**: Easy to distribute as standalone executable

**Disadvantages** ❌
- **Feature Incomplete**: Missing pragma, config, parameters, advanced heuristics
- **Less Python-Aware**: Simpler AST analysis, doesn't handle all dynamic patterns
- **No Refactoring**: Can only detect, not remove dead code
- **No UI**: CLI only, no web interface or editor integration
- **Development Effort**: Harder to extend due to Rust's learning curve

---

## Use Case Recommendations

### Choose **Python** if you need:
- ✅ Automated code removal (LibCST integration)
- ✅ Web interface for team collaboration
- ✅ VS Code integration
- ✅ Advanced Python semantics (dynamic imports, `__all__`, etc.)
- ✅ Configuration files and pragma support
- ✅ Detection of unused parameters

### Choose **Rust** if you need:
- ✅ **Maximum performance** (CI/CD pipelines, large codebases)
- ✅ Single binary deployment (no Python installation)
- ✅ Lower memory usage
- ✅ Cross-platform distribution
- ✅ Core dead code detection only

---

## Future Improvements for Rust

To reach feature parity with Python:

1. **High Priority**
   - [ ] Pragma support (`# pragma: no skylos`)
   - [ ] Config file support (`.skylos.toml`)
   - [ ] Unused parameter detection
   - [ ] Advanced heuristics (visitor patterns, auto-called methods)

2. **Medium Priority**
   - [ ] Better module resolution
   - [ ] `__all__` export detection
   - [ ] Dataclass field tracking
   - [ ] Settings/Config class detection

3. **Low Priority**
   - [ ] Web interface (optional feature)
   - [ ] VS Code extension
   - [ ] LibCST-equivalent for safe removals

---

## Conclusion

The Rust implementation successfully demonstrates **9.3x performance improvement** while maintaining core functionality. However, it's currently best suited for **performance-critical scenarios** where the missing features (pragma, config, parameters) are acceptable trade-offs.

For production use requiring full feature parity, the **Python version remains recommended** until the Rust implementation adds missing features.
