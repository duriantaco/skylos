# Optional Rust acceleration

Skylos works without this extension and uses Python fallbacks when it cannot
import the native APIs. The extension is a separate source project that
provides the `skylos_fast` module. Skylos does not declare a `fast` pip extra;
`pip install "skylos[fast]"` does not install this extension.

## Build from source

Use the Python environment in which you run Skylos. You need Python 3.10 or
later, a [Rust toolchain with Cargo](https://www.rust-lang.org/tools/install),
and a native compiler/linker. On macOS, install the Xcode Command Line Tools
with `xcode-select --install` if they are missing.

From a checkout of this repository:

```bash
python -m pip install ./rust
python -c "from skylos.core.fast import FAST_AVAILABLE; print(FAST_AVAILABLE)"
skylos doctor
```

The build uses Maturin and compiles for that Python interpreter and platform.
The availability check should print `True`, and doctor should report
`skylos_fast available`. Rebuild the extension when changing Python versions
or CPU architecture. To return to the Python fallbacks, run
`python -m pip uninstall skylos-fast` in the same environment.

## What it accelerates

- Source-file discovery.
- Code-clone similarity comparisons.
- Python class-coupling analysis.
- Import-cycle detection.

This does not accelerate every check. Native AST visitor acceleration and
batch grep are not currently wired into the analyzer.

## Can findings change?

Yes. The native extension is experimental and can change scan speed and
findings. Clone similarity uses a separate implementation that does
not apply the default `difflib.SequenceMatcher` heuristic for frequently
repeated characters. For example, comparing `"x" + "a" * 200` with
`"y" + "a" * 200` scores `0.0` in the Python fallback and about `0.995` in
the native implementation. That can change which pairs exceed a clone
threshold. Native coupling analysis also uses a separate parser.

The [parity workflow](../.github/workflows/parity.yml) builds the extension and
checks selected examples against Python implementations. Those tests do not
guarantee identical findings for every repository. Keep the same backend when
comparing scan results across machines or CI runs.
