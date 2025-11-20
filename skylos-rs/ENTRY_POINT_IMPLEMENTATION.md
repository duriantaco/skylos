# Entry Point Detection Implementation

## Feature Completed

✅ **Entry Point Detection** - Skylos-RS now recognizes functions called within `if __name__ == "__main__"` blocks

## What Was Implemented

### 1. Entry Point Detection Module (`src/entry_point.rs`)

Created a new module that:
- Detects `if __name__ == "__main__"` blocks in Python AST
- Extracts all function calls within those blocks
- Returns a set of function names that are entry points

**Key Functions:**
- `detect_entry_point_calls()` - Main entry point that scans AST for main guard
- `is_main_guard()` - Checks if a statement is `if __name__ == "__main__"`
- `collect_function_calls()` - Recursively extracts function calls from statements
- `get_call_name()` - Extracts function name from call expression

Supports both orders:
```python
if __name__ == "__main__":  # Standard form
if "__main__" == __name__:  # Reversed form
```

### 2. Analyzer Integration (`src/analyzer.rs`)

Modified analyzer to:
- Call `detect_entry_point_calls()` after parsing AST
- Add detected calls as references (both simple and qualified names)
- This prevents entry point functions from being reported as unused

**Integration Code:**
```rust
// Detect entry point calls
let entry_point_calls = crate::entry_point::detect_entry_point_calls(&module.body);

// Add as references
for call_name in &entry_point_calls {
    visitor.add_ref(call_name.clone());
    if !module_name.is_empty() {
        let qualified = format!("{}.{}", module_name, call_name);
        visitor.add_ref(qualified);
    }
}
```

### 3. Visitor Update (`src/visitor.rs`)

Made `add_ref()` method public so analyzer can add entry point references.

## Testing

**Unit Tests:**
- `test_entry_point_detection()` - Verifies detection of function calls in main block
- `test_no_entry_point()` - Ensures no false positives without main block
- `test_reversed_main_guard()` - Handles reversed comparison order

**Manual Verification:**
```python
# example_pragma.py
def used_function():
    return 42

if __name__ == "__main__":
    result = used_function()  # Now recognized!
    print(result)
```

**Before:**
```json
{
  "unused_functions": ["used_function", "method", "really_unused_no_pragma"]
}
```

**After:**
```json
{
  "unused_functions": ["method", "really_unused_no_pragma"]
}
```

`used_function` is correctly excluded! ✅

## Impact

This was one of the "Quick Win" items from `future.md` (estimated 3-4 hours).

**Benefits:**
- CLI tools and scripts no longer report entry points as unused
- Matches Python version behavior
- Works with both `if __name__ == "__main__"` forms

**Limitations:**
- Only detects direct function calls in the main block
- Doesn't detect functions passed as arguments or stored in variables
- Doesn't parse `setup.py` or `pyproject.toml` for console_scripts yet

## Files Modified

- **NEW:** `src/entry_point.rs` - Entry point detection logic
- **Modified:** `src/lib.rs` - Register entry_point module
- **Modified:** `src/main.rs` - Register entry_point module
- **Modified:** `src/analyzer.rs` - Call detection and add references
- **Modified:** `src/visitor.rs` - Make `add_ref()` public

## Next Steps

From `future.md`, remaining quick wins:
1. ✅ **Pragma Support** (DONE)
2. ✅ **Entry Point Detection** (DONE)
3. ⏳ **Config File Support** (`.skylos.toml`)
4. ⏳ **Fix Test Suite**

See [`future.md`](../future.md#contribution-guide) for more improvements.
