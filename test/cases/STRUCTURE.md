PyDeadBench - Test Case Structure

```
cases/
├── 01_basic/                    # Basic function/class patterns
│   ├── test_001_unused_function/
│   │   ├── code.py              # Test code
│   │   └── ground_truth.json    # Ground truth specification
│   ├── test_002_unused_class/
│   ├── test_003_unused_method/
│   └── test_004_nested_functions/
├── 02_imports/                  # Import patterns
│   ├── test_001_unused_import/
│   ├── test_002_import_alias/
│   └── test_003_conditional_import/
├── 03_dynamic/                  # Dynamic features
│   ├── test_001_getattr/
│   ├── test_002_globals/
│   └── test_003_eval_exec/
├── 04_metaprogramming/          # Decorators, metaclasses, etc.
│   ├── test_001_decorators/
│   ├── test_002_metaclasses/
│   └── test_003_descriptors/
├── 05_oop/                      # Object-oriented patterns
│   ├── test_001_inheritance/
│   ├── test_002_mixins/
│   └── test_003_properties/
├── 06_special_methods/          # Magic methods
│   ├── test_001_dunder_methods/
│   ├── test_002_context_managers/
│   └── test_003_operators/
├── 07_typing/                   # Type annotations
│   ├── test_001_type_checking/
│   ├── test_002_stub_files/
│   └── test_003_protocol_classes/
├── 08_frameworks/               # Framework patterns
│   ├── test_001_django/
│   ├── test_002_flask/
│   └── test_003_fastapi/
├── 09_async/                    # Async patterns
│   ├── test_001_async_functions/
│   ├── test_002_async_for/
│   └── test_003_async_with/
└── 10_real_world/               # Complex real-world examples
    ├── test_001_plugin_system/
    ├── test_002_api_framework/
    └── test_003_orm_model/
```