"""Tool configuration files that a build, lint or test tool loads by name.

Nothing imports these files: the tool finds them by file name and reads their
default export. Dead-code analysis treats them as roots and keeps their
default export alive.
"""

from __future__ import annotations

import os

_ALL_CONFIG_EXTS = ("js", "mjs", "cjs", "ts", "mts", "cts")

# Test runners and bundlers whose configs also name further entry files.
RUNNER_CONFIG_FILES = frozenset(
    {
        "playwright.config.ts",
        "playwright.config.js",
        "playwright.config.mts",
        "playwright.config.mjs",
        "tsup.config.ts",
        "tsup.config.mts",
        "tsup.config.js",
        "tsup.config.mjs",
        "tsup.config.cjs",
    }
)

TOOL_CONFIG_FILES = frozenset(
    {
        "vitest.config.ts",
        "vitest.config.mts",
        "vitest.config.js",
        "vitest.config.mjs",
        "jest.config.ts",
        "jest.config.js",
        "jest.config.cjs",
        "tsconfig.ts",
        "source.config.ts",
        "source.config.tsx",
        "source.config.js",
        "source.config.jsx",
        "eslint.config.ts",
        "eslint.config.mts",
        "eslint.config.js",
        "eslint.config.mjs",
        "vite.config.ts",
        "vite.config.mts",
        "vite.config.js",
        "vite.config.mjs",
        "playwright.config.ts",
        "playwright.config.js",
        "playwright.config.mts",
        "playwright.config.mjs",
    }
    # Next.js, PostCSS (postcss-load-config) and Tailwind accept every
    # module flavour, and create-next-app writes the .mjs/.ts variants.
    | {
        f"{tool}.config.{ext}"
        for tool in ("next", "postcss", "tailwind")
        for ext in _ALL_CONFIG_EXTS
    }
)


def is_tool_config_file(path: str | os.PathLike[str]) -> bool:
    basename = os.path.basename(path)
    return basename in TOOL_CONFIG_FILES or basename in RUNNER_CONFIG_FILES
