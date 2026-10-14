"""skylos done: code the change left without callers (SKY-A135/A136/A137)."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from textwrap import dedent

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.done.base import open_comparison
from skylos.done.checks import CheckContext, check_branch_orphans
from skylos.done.config import DEFAULT_MODES, DoneConfig, parse_done_config
from skylos.done.engine import CheckOutcome, decide_verdict, run
from skylos.done.orphans import removed_lines
from skylos.done.receipt import build_receipt, render_text, validate_receipt

A135, A136, A137 = "SKY-A135", "SKY-A136", "SKY-A137"


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=t", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, dedent(text))


def _repo(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    for rel, text in files.items():
        _write(root, rel, text)
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    _git(root, "switch", "-qc", "feature")
    return root


def _change(root: Path, files: dict[str, str | None], *, commit: bool = True) -> None:
    for rel, text in files.items():
        if text is None:
            (root / rel).unlink()
        else:
            _write(root, rel, text)
    if commit:
        _git(root, "add", "-A")
        _git(root, "commit", "-qm", "change")


def _check(root: Path, config: DoneConfig | None = None):
    ctx = CheckContext(open_comparison(root, "main"), config or DoneConfig())
    return check_branch_orphans(ctx)


def _found(result) -> list[tuple[str, str, int]]:
    return [(f.rule, f.file, f.line) for f in result.findings]


def _messages(result) -> str:
    return "\n".join(f.message for f in result.findings)


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------

PY_BASE = {
    "app/__init__.py": "",
    "app/pricing.py": """\
        def price_label(cents):
            return "$" + str(cents / 100)


        def tax(cents):
            return cents // 10
    """,
    "app/checkout.py": """\
        from app.pricing import price_label, tax


        def render(cart):
            total = sum(cart) + tax(sum(cart))
            return price_label(total)
    """,
    "main.py": """\
        from app.checkout import render

        if __name__ == "__main__":
            print(render([100, 250]))
    """,
}

CHECKOUT_INLINED = """\
    from app.pricing import tax


    def render(cart):
        total = sum(cart) + tax(sum(cart))
        return f"${total / 100}"
"""


def test_python_symbol_made_unused_in_an_untouched_file_names_the_edit(tmp_path):
    root = _repo(tmp_path, PY_BASE)
    _change(root, {"app/checkout.py": CHECKOUT_INLINED})

    result = _check(root)

    assert _found(result) == [(A135, "app/pricing.py", 1)]
    message = result.findings[0].message
    assert message.startswith(
        "`price_label` (not touched by this change) lost its last caller"
    )
    assert "when app/checkout.py:6 changed (`return price_label(total)`)" in message
    assert result.status == "fail"  # findings; the check advises by default
    assert result.evidence["made_unused"] == 1


def test_python_made_unused_but_still_tested_says_only_tests_call_it(tmp_path):
    root = _repo(
        tmp_path,
        {
            **PY_BASE,
            "tests/test_pricing.py": """\
                from app.pricing import price_label


                def test_label():
                    assert price_label(250) == "$2.5"
            """,
        },
    )
    _change(root, {"app/checkout.py": CHECKOUT_INLINED})

    result = _check(root)

    assert _found(result) == [(A135, "app/pricing.py", 1)]
    assert (
        "only tests call it now (tests/test_pricing.py:5)" in result.findings[0].message
    )


def test_python_new_symbol_nothing_calls_and_new_symbol_only_tests_call(tmp_path):
    root = _repo(tmp_path, PY_BASE)
    _change(
        root,
        {
            "app/discounts.py": """\
                def loyalty_discount(cents, years):
                    return cents * min(years, 10) // 100


                def seasonal_discount(cents):
                    return cents // 20
            """,
            "tests/test_discounts.py": """\
                from app.discounts import loyalty_discount


                def test_loyalty():
                    assert loyalty_discount(1000, 2) == 20
            """,
        },
    )

    result = _check(root)

    assert _found(result) == [
        (A136, "app/discounts.py", 5),
        (A137, "app/discounts.py", 1),
    ]
    assert (
        "`seasonal_discount` was added by this change and nothing calls it"
        in _messages(result)
    )
    assert "only tests call it (tests/test_discounts.py:5)" in _messages(result)


def test_python_uncommitted_and_untracked_changes_count(tmp_path):
    root = _repo(tmp_path, PY_BASE)
    _change(
        root,
        {
            "app/checkout.py": CHECKOUT_INLINED,
            "app/extra.py": "def unused_extra():\n    return 1\n",
        },
        commit=False,
    )

    result = _check(root)

    assert _found(result) == [(A135, "app/pricing.py", 1), (A136, "app/extra.py", 1)]


def test_python_moved_function_with_callers_updated_is_not_reported(tmp_path):
    root = _repo(tmp_path, PY_BASE)
    _change(
        root,
        {
            "app/pricing.py": """\
                def tax(cents):
                    return cents // 10
            """,
            "app/labels.py": """\
                def price_label(cents):
                    return "$" + str(cents / 100)
            """,
            "app/checkout.py": """\
                from app.labels import price_label
                from app.pricing import tax


                def render(cart):
                    total = sum(cart) + tax(sum(cart))
                    return price_label(total)
            """,
        },
    )

    assert _found(_check(root)) == []


def test_python_dead_code_moved_or_renamed_is_not_new(tmp_path):
    base = {
        **PY_BASE,
        "app/legacy.py": """\
            def old_rounding(cents):
                rounded = round(cents / 100) * 100
                return max(rounded, 0)
        """,
    }
    root = _repo(tmp_path, base)
    # Moved to another module and renamed: it was already unused at the base.
    _change(
        root,
        {
            "app/legacy.py": None,
            "app/rounding.py": """\
                def legacy_rounding(cents):
                    rounded = round(cents / 100) * 100
                    return max(rounded, 0)
            """,
        },
    )

    assert _found(_check(root)) == []


def test_python_renamed_with_every_caller_updated_is_not_reported(tmp_path):
    root = _repo(tmp_path, PY_BASE)
    _change(
        root,
        {
            "app/pricing.py": """\
                def format_label(cents):
                    return "$" + str(cents / 100)


                def tax(cents):
                    return cents // 10
            """,
            "app/checkout.py": """\
                from app.pricing import format_label, tax


                def render(cart):
                    total = sum(cart) + tax(sum(cart))
                    return format_label(total)
            """,
        },
    )

    assert _found(_check(root)) == []


def test_python_public_api_entry_points_and_framework_roots_are_not_reported(tmp_path):
    root = _repo(
        tmp_path,
        {
            **PY_BASE,
            "pyproject.toml": """\
                [project]
                name = "shop"
                version = "0.1.0"
            """,
            "app/web.py": """\
                from flask import Flask

                app = Flask(__name__)


                @app.route("/")
                def index():
                    return "ok"
            """,
        },
    )
    _change(
        root,
        {
            # Exported from the package: public API.
            "app/__init__.py": """\
                from app.pricing import price_label

                __all__ = ["price_label", "refund_label"]


                def refund_label(cents):
                    return "-" + price_label(cents)
            """,
            # A Flask route: the framework calls it.
            "app/web.py": """\
                from flask import Flask

                app = Flask(__name__)


                @app.route("/")
                def index():
                    return "ok"


                @app.route("/health")
                def health():
                    return "up"
            """,
            # A console script entry point.
            "pyproject.toml": """\
                [project]
                name = "shop"
                version = "0.1.0"

                [project.scripts]
                shop-report = "app.report:main"
            """,
            "app/report.py": """\
                def main():
                    print("report")
            """,
            # Called through a dispatch table.
            "app/handlers.py": """\
                def handle_refund(event):
                    return event


                HANDLERS = {"refund": handle_refund}


                def dispatch(name, event):
                    return HANDLERS[name](event)
            """,
            "main.py": """\
                from app.checkout import render
                from app.handlers import dispatch

                if __name__ == "__main__":
                    print(render([100, 250]))
                    print(dispatch("refund", {}))
            """,
        },
    )

    assert _found(_check(root)) == []


def test_python_test_code_fixtures_and_test_only_changes_are_not_reported(tmp_path):
    root = _repo(
        tmp_path,
        {**PY_BASE, "tests/test_checkout.py": "def test_x():\n    assert True\n"},
    )
    _change(
        root,
        {
            "tests/conftest.py": """\
                import pytest


                @pytest.fixture
                def cart():
                    return [1, 2]


                def unused_helper():
                    return 3
            """,
            "tests/test_checkout.py": "def test_x(cart):\n    assert cart\n",
        },
    )

    result = _check(root)

    assert _found(result) == []
    assert result.evidence["summary"] == "No production code changed"


def test_python_dead_code_already_unused_at_the_base_is_not_reported(tmp_path):
    root = _repo(
        tmp_path,
        {**PY_BASE, "app/old.py": "def forgotten():\n    return 0\n"},
    )
    _change(
        root,
        {
            "app/checkout.py": PY_BASE["app/checkout.py"] + "\n# reviewed\n",
            "app/old.py": "def forgotten():\n    return 1\n",
        },
    )

    assert _found(_check(root)) == []


def test_python_name_in_an_unparsable_file_is_not_judged(tmp_path):
    root = _repo(tmp_path, PY_BASE)
    _change(
        root,
        {
            "app/checkout.py": CHECKOUT_INLINED,
            "app/broken.py": "def broken(:\n    return price_label(1)\n",
        },
    )

    result = _check(root)

    assert _found(result) == []
    assert result.evidence["not_judged"] == 1
    assert result.evidence["summary"] == (
        "1 symbol lost its callers but couldn't be judged: "
        "`price_label` (app/pricing.py:1)"
    )


def test_python_chain_made_unused_reports_the_caller_and_its_callee(tmp_path):
    root = _repo(
        tmp_path,
        {
            **PY_BASE,
            "app/report.py": """\
                def summarize(rows):
                    return total_of(rows)


                def total_of(rows):
                    return sum(rows)
            """,
            "app/checkout.py": """\
                from app.pricing import price_label, tax
                from app.report import summarize


                def render(cart):
                    total = sum(cart) + tax(sum(cart)) + summarize(cart)
                    return price_label(total)
            """,
        },
    )
    _change(
        root,
        {
            "app/checkout.py": """\
                from app.pricing import price_label, tax


                def render(cart):
                    total = sum(cart) + tax(sum(cart))
                    return price_label(total)
            """,
        },
    )

    result = _check(root)

    assert (A135, "app/report.py", 1) in _found(result)
    assert all(rule == A135 for rule, _, _ in _found(result))
    assert "when app/checkout.py:5 changed" in result.findings[0].message


# ---------------------------------------------------------------------------
# TypeScript / JavaScript
# ---------------------------------------------------------------------------

TS_BASE = {
    "package.json": '{"name": "shop", "version": "1.0.0", "private": true, "main": "src/index.ts"}\n',
    "src/index.ts": """\
        import { renderCart } from "./checkout";

        console.log(renderCart([1, 2]));
    """,
    "src/checkout.ts": """\
        import { priceLabel } from "./pricing";

        export function renderCart(cart: number[]): string {
          return priceLabel(cart.reduce((a, b) => a + b, 0));
        }
    """,
    "src/pricing.ts": """\
        export function priceLabel(cents: number): string {
          return `$${cents / 100}`;
        }
    """,
}


def test_typescript_symbol_and_file_made_unused_and_new_code(tmp_path):
    root = _repo(tmp_path, TS_BASE)
    _change(
        root,
        {
            "src/checkout.ts": """\
                export function renderCart(cart: number[]): string {
                  const total = cart.reduce((a, b) => a + b, 0);
                  return `$${total / 100}`;
                }

                function roundCents(value: number): number {
                  return Math.round(value);
                }

                export function cartSize(cart: number[]): number {
                  return cart.length;
                }
            """,
            "test/checkout.test.ts": """\
                import { cartSize } from "../src/checkout";

                test("size", () => {
                  expect(cartSize([1])).toBe(1);
                });
            """,
        },
    )

    result = _check(root)

    found = _found(result)
    assert (A135, "src/pricing.ts", 1) in found
    assert (A136, "src/checkout.ts", 6) in found
    assert (A137, "src/checkout.ts", 10) in found
    assert "lost its last importer when src/checkout.ts:1 changed" in _messages(result)


def test_typescript_moved_function_and_framework_routes_are_not_reported(tmp_path):
    root = _repo(
        tmp_path,
        {
            **TS_BASE,
            "package.json": '{"name": "shop", "private": true, "main": "src/index.ts", "dependencies": {"next": "14.0.0"}}\n',
            "app/page.tsx": "export default function Page() { return null; }\n",
        },
    )
    _change(
        root,
        {
            "src/pricing.ts": None,
            "src/labels.ts": """\
                export function priceLabel(cents: number): string {
                  return `$${cents / 100}`;
                }
            """,
            "src/checkout.ts": """\
                import { priceLabel } from "./labels";

                export function renderCart(cart: number[]): string {
                  return priceLabel(cart.reduce((a, b) => a + b, 0));
                }
            """,
            "app/api/health/route.ts": """\
                export async function GET() {
                  return new Response("ok");
                }
            """,
        },
    )

    assert _found(_check(root)) == []


# ---------------------------------------------------------------------------
# Java
# ---------------------------------------------------------------------------

JAVA_BASE = {
    "pom.xml": "<project><modelVersion>4.0.0</modelVersion><groupId>shop</groupId><artifactId>shop</artifactId><version>1</version></project>\n",
    "src/main/java/shop/App.java": """\
        package shop;

        public class App {
            public static void main(String[] args) {
                System.out.println(new Checkout().render(new int[] {1, 2}));
            }
        }
    """,
    "src/main/java/shop/Checkout.java": """\
        package shop;

        public class Checkout {
            public String render(int[] cart) {
                int total = sum(cart);
                return label(total);
            }

            private int sum(int[] cart) {
                int total = 0;
                for (int c : cart) {
                    total += c;
                }
                return total;
            }

            private String label(int cents) {
                return "$" + (cents / 100.0);
            }
        }
    """,
}


def test_java_private_method_made_unused_and_new_private_method(tmp_path):
    root = _repo(tmp_path, JAVA_BASE)
    _change(
        root,
        {
            "src/main/java/shop/Checkout.java": """\
                package shop;

                public class Checkout {
                    public String render(int[] cart) {
                        int total = sum(cart);
                        return "$" + (total / 100.0);
                    }

                    private int sum(int[] cart) {
                        int total = 0;
                        for (int c : cart) {
                            total += c;
                        }
                        return total;
                    }

                    private String label(int cents) {
                        return "$" + (cents / 100.0);
                    }

                    private int roundCents(double value) {
                        return (int) Math.round(value);
                    }
                }
            """,
        },
    )

    result = _check(root)

    assert _found(result) == [
        (A135, "src/main/java/shop/Checkout.java", 17),
        (A136, "src/main/java/shop/Checkout.java", 21),
    ]
    assert (
        "`label` (not touched by this change) lost its last caller when "
        "src/main/java/shop/Checkout.java:6 changed (`return label(total);`)"
    ) in _messages(result)


def test_java_public_api_and_renamed_private_method_are_not_reported(tmp_path):
    root = _repo(tmp_path, JAVA_BASE)
    _change(
        root,
        {
            "src/main/java/shop/Checkout.java": """\
                package shop;

                public class Checkout {
                    public String render(int[] cart) {
                        int total = sum(cart);
                        return priceLabel(total);
                    }

                    public String refundLabel(int cents) {
                        return "-" + priceLabel(cents);
                    }

                    private int sum(int[] cart) {
                        int total = 0;
                        for (int c : cart) {
                            total += c;
                        }
                        return total;
                    }

                    private String priceLabel(int cents) {
                        return "$" + (cents / 100.0);
                    }
                }
            """,
        },
    )

    assert _found(_check(root)) == []


# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------

GO_BASE = {
    "go.mod": "module example.com/shop\n\ngo 1.21\n",
    "main.go": """\
        package main

        import (
        	"fmt"

        	"example.com/shop/pricing"
        )

        func main() {
        	fmt.Println(pricing.Render([]int{1, 2}))
        }
    """,
    "pricing/render.go": """\
        package pricing

        func Render(cart []int) string {
        	total := 0
        	for _, c := range cart {
        		total += c
        	}
        	return label(total)
        }
    """,
    "pricing/label.go": """\
        package pricing

        import "fmt"

        func label(cents int) string {
        	return fmt.Sprintf("$%d", cents)
        }
    """,
}


def _go_engine_available() -> bool:
    from skylos.engines.go_runner import get_go_engine_status

    return get_go_engine_status().get("status") == "available"


needs_go = pytest.mark.skipif(not _go_engine_available(), reason="skylos-go not built")


@needs_go
def test_go_unexported_func_made_unused_new_and_test_only(tmp_path):
    root = _repo(tmp_path, GO_BASE)
    _change(
        root,
        {
            "pricing/render.go": """\
                package pricing

                import "fmt"

                func Render(cart []int) string {
                	total := 0
                	for _, c := range cart {
                		total += c
                	}
                	return fmt.Sprintf("%d cents", total)
                }

                func roundCents(v float64) int {
                	return int(v + 0.5)
                }

                func clampCents(v int) int {
                	if v < 0 {
                		return 0
                	}
                	return v
                }
            """,
            "pricing/render_test.go": """\
                package pricing

                import "testing"

                func TestClamp(t *testing.T) {
                	if clampCents(-1) != 0 {
                		t.Fatal("clamp")
                	}
                }
            """,
        },
    )

    result = _check(root)

    assert _found(result) == [
        (A135, "pricing/label.go", 5),
        (A136, "pricing/render.go", 13),
        (A137, "pricing/render.go", 17),
    ]
    assert "when pricing/render.go:10 changed (`return label(total)`)" in _messages(
        result
    )


@needs_go
def test_go_exported_func_and_function_values_are_not_reported(tmp_path):
    root = _repo(tmp_path, GO_BASE)
    _change(
        root,
        {
            "pricing/render.go": """\
                package pricing

                var formatters = map[string]func(int) string{"label": label, "short": short}

                func Render(cart []int) string {
                	total := 0
                	for _, c := range cart {
                		total += c
                	}
                	return formatters["label"](total)
                }

                func short(cents int) string {
                	return label(cents)
                }

                func Total(cart []int) int {
                	return len(cart)
                }
            """,
        },
    )

    assert _found(_check(root)) == []


def test_go_without_the_engine_says_go_was_not_checked(tmp_path, monkeypatch):
    monkeypatch.setenv("SKYLOS_GO_BIN", str(tmp_path / "missing-skylos-go"))
    root = _repo(tmp_path, {**GO_BASE, **PY_BASE})
    _change(root, {"pricing/render.go": GO_BASE["pricing/render.go"] + "\n// note\n"})

    result = _check(root)

    assert result.status == "incomplete"
    assert (
        "not checked: Go (skylos-go engine not installed)" in result.evidence["summary"]
    )
    assert result.evidence["not_checked"] == "Go (skylos-go engine not installed)"


def test_go_engine_missing_still_checks_other_languages(tmp_path, monkeypatch):
    monkeypatch.setenv("SKYLOS_GO_BIN", str(tmp_path / "missing-skylos-go"))
    root = _repo(tmp_path, {**GO_BASE, **PY_BASE})
    _change(root, {"app/checkout.py": CHECKOUT_INLINED})

    result = _check(root)

    assert _found(result) == [(A135, "app/pricing.py", 1)]
    assert "not checked: Go" in result.evidence["summary"]


# ---------------------------------------------------------------------------
# Settings, receipt, cache and helpers
# ---------------------------------------------------------------------------


def test_block_mode_blocks_made_unused_and_new_unused_but_not_test_only(tmp_path):
    config = parse_done_config(
        dedent(
            """\
            [tool.skylos.done.checks]
            branch_orphans = "block"
            """
        )
    )
    assert config.mode("branch_orphans") == "block"
    assert config.orphans_block_rules == (A135, A136)
    root = _repo(tmp_path, PY_BASE)
    _change(
        root,
        {
            "app/extra.py": "def tested_extra():\n    return 1\n",
            "tests/test_extra.py": "from app.extra import tested_extra\n\n\ndef test_e():\n    assert tested_extra() == 1\n",
        },
    )

    result = _check(root, config)

    assert _found(result) == [(A137, "app/extra.py", 1)]
    assert result.status == "pass"  # A137 stays advice
    custom = parse_done_config(
        '[tool.skylos.done]\nbranch_orphans_block_rules = ["SKY-A137", "SKY-X"]\n'
    )
    assert custom.orphans_block_rules == (A137,)
    assert any("SKY-X" in problem for problem in custom.problems)
    assert _check(root, custom).status == "fail"
    assert custom.digest() != config.digest()


def test_default_mode_advises_and_the_receipt_is_valid(tmp_path):
    root = _repo(
        tmp_path,
        {**PY_BASE, "pyproject.toml": '[tool.skylos.done]\ntest_command = "true"\n'},
    )
    _change(root, {"app/checkout.py": CHECKOUT_INLINED})

    result = run(root, base_ref="main", run_tests=False)
    receipt = build_receipt(result)

    orphans = next(c for c in receipt["checks"] if c["id"] == "branch_orphans")
    assert orphans["mode"] == "advise"
    assert orphans["rule"] == A135
    assert orphans["findings"][0]["file"] == "app/pricing.py"
    assert validate_receipt(receipt) == []
    assert "WARN       No code left without callers" in render_text(receipt)


def test_base_analysis_is_cached_by_base_commit(tmp_path):
    root = _repo(tmp_path, PY_BASE)
    _change(root, {"app/checkout.py": CHECKOUT_INLINED})

    first = _check(root)
    second = _check(root)

    assert first.evidence["base_cached"] is False
    assert second.evidence["base_cached"] is True
    assert _found(first) == _found(second)
    assert not _git(root, "status", "--porcelain")


def _forge_base_cache(root: Path, alive: dict) -> None:
    files = sorted((root / ".skylos" / "cache" / "done-orphans").glob("*.json"))
    assert files
    for path in files:
        data = json.loads(path.read_text())
        data["alive"] = alive
        assert write_text_no_symlink(path, json.dumps(data))


def test_block_mode_never_reads_a_forged_base_cache(tmp_path):
    # Anything in the working tree (an agent) can write the cache. A blocking
    # check rebuilds the base view from Git instead, and repairs the cache.
    root = _repo(tmp_path, PY_BASE)
    _change(root, {"app/checkout.py": CHECKOUT_INLINED})
    block = DoneConfig(modes={**DEFAULT_MODES, "branch_orphans": "block"})
    assert _found(_check(root, block)) == [(A135, "app/pricing.py", 1)]
    _forge_base_cache(root, {})

    result = _check(root, block)

    assert result.status == "fail"
    assert result.evidence["base_cached"] is False
    assert _found(result) == [(A135, "app/pricing.py", 1)]
    advise = _check(root)
    assert advise.evidence["base_cached"] is True
    assert _found(advise) == [(A135, "app/pricing.py", 1)]


def test_block_mode_ignores_an_invented_base_cache_entry(tmp_path):
    pricing = PY_BASE["app/pricing.py"] + "\n\n        def legacy(x):\n            return x\n"
    root = _repo(tmp_path, {**PY_BASE, "app/pricing.py": pricing})
    _change(root, {"app/checkout.py": CHECKOUT_INLINED})
    block = DoneConfig(modes={**DEFAULT_MODES, "branch_orphans": "block"})
    _check(root, block)
    # `legacy` is unused at the base too; the forged cache says it was alive.
    invented = {"app/pricing.py": [["app.pricing.legacy", "function", 9]]}
    _forge_base_cache(root, invented)

    result = _check(root, block)

    assert _found(result) == [(A135, "app/pricing.py", 1)]
    # The block run rewrote the cache; forged again, it does reach advice.
    _forge_base_cache(root, invented)
    assert (A135, "app/pricing.py", 9) in _found(_check(root))


def test_advise_mode_trusts_the_cache_for_advice_only(tmp_path):
    # The documented residual: a forged cache can change advice, never a
    # verdict, because advise-mode findings never block.
    root = _repo(tmp_path, PY_BASE)
    _change(root, {"app/checkout.py": CHECKOUT_INLINED})
    _check(root)
    _forge_base_cache(root, {})

    result = _check(root)

    assert result.evidence["base_cached"] is True
    assert result.findings == []
    assert decide_verdict([CheckOutcome("advise", result)]) == "pass"


def test_removed_lines_reads_hunk_lengths_not_line_prefixes():
    diff = dedent(
        """\
        diff --git a/q.sql b/q.sql
        --- a/q.sql
        +++ b/q.sql
        @@ -1,3 +1,2 @@
         select 1;
        --- a comment that looks like a header
        -+++ another
        +select 2;
        @@ -10 +9,0 @@
        -tail
        """
    )
    assert removed_lines(diff) == [
        (2, 2, "-- a comment that looks like a header"),
        (3, 2, "+++ another"),
        (10, 9, "tail"),
    ]


def test_check_is_registered_documented_and_advises_by_default():
    from skylos.done.checks import CHECKS, RUN_ORDER
    from skylos.done.config import CHECK_IDS, DEFAULT_MODES
    from skylos.done.receipt import FIXES, LABELS, PROBLEMS, UNCHECKED
    from skylos.rules.catalog import get_rule_name

    assert "branch_orphans" in CHECK_IDS and "branch_orphans" in RUN_ORDER
    assert DEFAULT_MODES["branch_orphans"] == "advise"
    assert CHECKS["branch_orphans"][1] == A135
    for table in (LABELS, PROBLEMS, UNCHECKED, FIXES):
        assert "branch_orphans" in table
    assert get_rule_name(A135) == "Code left unused by the change"
    assert get_rule_name(A136) == "New code nothing calls"
    assert get_rule_name(A137) == "New code only tests call"
    dictionary = (Path(__file__).parents[1] / "dictionary.md").read_text()
    for rule in ("A135", "A136", "A137"):
        assert f"| {rule} |" in dictionary
    assert os.path.exists(Path(__file__).parents[1] / "docs" / "done-gate.md")


@pytest.mark.parametrize(
    "line, rank",
    [
        ("    return label(total);", 0),
        ("    x = this.label;", 1),
        ('    handlers.put("label", Checkout::label);', 1),
        ('import { label } from "./label";', 2),
        ("    // label(total) used to run here", None),
        ("    private String label(int cents) {", None),
        ("func label(cents int) string {", None),
        ("export function label(cents: number): string {", None),
        ("    const labelText = 1;", None),
    ],
)
def test_removed_line_reference_ranks(line, rank):
    from skylos.done.orphans import _text_reference_rank

    assert _text_reference_rank(line, "label") == rank


def _fake_grep(monkeypatch, alive=(), complete=True):
    from skylos.core import grep_verify

    class Verdicts(dict):
        pass

    def fake(findings, project_root, time_budget=30.0, **kwargs):
        verdicts = Verdicts()
        verdicts.complete = complete
        for item in findings:
            key = item["_verification_key"]
            verdicts[key] = grep_verify.GrepVerdict(alive=item["name"] in alive)
        return verdicts

    monkeypatch.setattr(grep_verify, "grep_verify_findings", fake)


NEW_PAIR = {
    "app/refunds.py": """\
        def refund_all(orders):
            return [refund_one(order) for order in orders]


        def refund_one(order):
            return -order
    """,
}


def test_grep_rescue_drops_the_candidate_and_the_callees_it_names(
    tmp_path, monkeypatch
):
    root = _repo(tmp_path, PY_BASE)
    _change(root, NEW_PAIR)
    # Real grep verification finds refund_all calling refund_one.
    assert _found(_check(root)) == [(A136, "app/refunds.py", 1)]

    _fake_grep(monkeypatch, alive={"refund_all"})

    assert _found(_check(root)) == []


def test_incomplete_grep_verification_judges_no_symbol(tmp_path, monkeypatch):
    root = _repo(tmp_path, PY_BASE)
    _change(root, NEW_PAIR)
    _fake_grep(monkeypatch, complete=False)

    result = _check(root)

    assert _found(result) == []
    assert result.evidence["grep_incomplete"] is True
    assert result.evidence["not_judged"] == 2


def test_python_django_views_signal_receivers_and_tasks_are_not_reported(tmp_path):
    root = _repo(
        tmp_path,
        {
            "manage.py": "import django\n",
            "shop/__init__.py": "",
            "shop/settings.py": 'INSTALLED_APPS = ["shop"]\nROOT_URLCONF = "shop.urls"\n',
            "shop/views.py": """\
                from django.http import HttpResponse


                def index(request):
                    return HttpResponse("ok")
            """,
            "shop/urls.py": """\
                from django.urls import path

                from shop import views

                urlpatterns = [path("", views.index)]
            """,
        },
    )
    _change(
        root,
        {
            "shop/views.py": """\
                from django.http import HttpResponse
                from django.views import View


                def index(request):
                    return HttpResponse("ok")


                def refunds(request):
                    return HttpResponse("refunds")


                class OrderView(View):
                    def get(self, request):
                        return HttpResponse("order")
            """,
            "shop/urls.py": """\
                from django.urls import path

                from shop import views

                urlpatterns = [
                    path("", views.index),
                    path("refunds/", views.refunds),
                    path("orders/", views.OrderView.as_view()),
                ]
            """,
            "shop/signals.py": """\
                from django.db.models.signals import post_save
                from django.dispatch import receiver


                @receiver(post_save)
                def audit_save(sender, **kwargs):
                    return sender
            """,
            "shop/tasks.py": """\
                from celery import shared_task


                @shared_task
                def nightly_report():
                    return 1
            """,
        },
    )

    assert _found(_check(root)) == []


def test_paths_starting_with_a_tilde_are_left_out_of_both_snapshots(tmp_path):
    root = _repo(tmp_path, {**PY_BASE, "~$deck.pptx": "lock file\n"})
    _change(root, {"app/checkout.py": CHECKOUT_INLINED})

    assert _found(_check(root)) == [(A135, "app/pricing.py", 1)]


def test_names_used_from_templates_or_config_are_not_judged(tmp_path):
    root = _repo(
        tmp_path,
        {
            **PY_BASE,
            "web/static/ui.js": "export function showToast(text) {\n  return text;\n}\n",
            "web/templates/page.html": '<script type="module">\n  import { showToast } from "/static/ui.js";\n  showToast("hi");\n</script>\n',
        },
    )
    _change(
        root,
        {
            "web/static/ui.js": """\
                export function showToast(text) {
                  return text;
                }

                export function pollJobStatus(id) {
                  return id;
                }
            """,
            "web/templates/page.html": """\
                <script type="module">
                  import { showToast, pollJobStatus } from "/static/ui.js";
                  showToast("hi");
                  pollJobStatus(1);
                </script>
            """,
            "app/hooks.py": "def on_refund(event):\n    return event\n",
            "hooks.yaml": "refund: app.hooks.on_refund\n",
        },
    )

    result = _check(root)

    assert _found(result) == []
    assert result.evidence["not_judged"] == 2


def test_symbols_a_decorator_may_register_are_not_judged(tmp_path):
    root = _repo(tmp_path, {**PY_BASE, **JAVA_BASE})
    _change(
        root,
        {
            "app/loaders.py": """\
                from webargs.flaskparser import parser


                @parser.location_loader("path_and_files")
                def load_path_and_files(request, schema):
                    return request
            """,
            "src/main/java/shop/Checkout.java": JAVA_BASE[
                "src/main/java/shop/Checkout.java"
            ].replace(
                "    private String label(int cents) {",
                "    @Scheduled(fixedRate = 5000)\n"
                "    private void refreshRates() {\n"
                "    }\n\n"
                "    private String label(int cents) {",
            ),
        },
    )

    result = _check(root)

    assert _found(result) == []
    # The webargs loader is a candidate the guard holds back; the analyzer
    # already keeps annotated Java members alive.
    assert result.evidence["not_judged"] >= 1


def test_a_doctest_or_recursive_call_does_not_count_as_a_caller(tmp_path):
    root = _repo(tmp_path, PY_BASE)
    _change(
        root,
        {
            "app/money.py": '''\
                def cents_to_str(cents):
                    """Format cents.

                    >>> cents_to_str(250)
                    '2.50'
                    """
                    return f"{cents / 100:.2f}"
            ''',
            "tests/test_money.py": """\
                from app.money import cents_to_str


                def test_cents():
                    assert cents_to_str(250) == "2.50"
            """,
        },
    )

    result = _check(root)

    assert _found(result) == [(A137, "app/money.py", 1)]
    assert "only tests call it (tests/test_money.py:5)" in result.findings[0].message


def test_test_reference_names_the_call_not_the_import(tmp_path):
    root = _repo(tmp_path, TS_BASE)
    _change(
        root,
        {
            "src/checkout.ts": TS_BASE["src/checkout.ts"]
            + "\nexport function cartSize(cart: number[]): number {\n  return cart.length;\n}\n",
            "test/checkout.test.ts": 'import { cartSize } from "../src/checkout";\n\ntest("size", () => {\n  expect(cartSize([1])).toBe(1);\n});\n',
        },
    )

    result = _check(root)

    assert _found(result) == [(A137, "src/checkout.ts", 7)]
    assert "(test/checkout.test.ts:4)" in result.findings[0].message


def test_a_bare_wrapper_decorator_does_not_hide_an_orphan(tmp_path):
    base = {
        **PY_BASE,
        "app/db.py": "def as_transaction(fn):\n    return fn\n",
        "app/pricing.py": """\
            from app.db import as_transaction


            @as_transaction
            def price_label(cents):
                return "$" + str(cents / 100)


            def tax(cents):
                return cents // 10
        """,
    }
    root = _repo(tmp_path, base)
    _change(root, {"app/checkout.py": CHECKOUT_INLINED})

    assert _found(_check(root)) == [(A135, "app/pricing.py", 5)]


LEAD_BASE = {
    "util.py": 'def format_price(x):\n    return f"${x:.2f}"\n',
    "checkout.py": """\
        from util import format_price


        def total(items):
            amount = sum(items)
            return format_price(amount)


        if __name__ == "__main__":
            print(total([1.5]))
    """,
}


def test_a_helper_the_analyzer_abstains_on_is_still_reported_as_advice(tmp_path):
    # The analyzer abstains on format_price at the head ("weak helper
    # function"), but the change removed its only caller.
    root = _repo(tmp_path, LEAD_BASE)
    _change(
        root,
        {
            "checkout.py": """\
                def total(items):
                    amount = sum(items)
                    return f"${amount:.2f}"


                if __name__ == "__main__":
                    print(total([1.5]))
            """
        },
    )

    result = _check(root)

    assert _found(result) == [(A135, "util.py", 1)]
    finding = result.findings[0]
    assert finding.message.startswith(
        "`format_price` (not touched by this change) lost its last caller when "
        "checkout.py:3 changed"
    )
    assert finding.message.endswith(
        "Skylos isn't certain nothing else uses it (weak helper function)"
    )
    assert not finding.blocking
    assert result.status == "pass"


def test_an_abstained_helper_unused_at_the_base_too_is_not_reported(tmp_path):
    root = _repo(
        tmp_path,
        {
            **LEAD_BASE,
            "util.py": LEAD_BASE["util.py"]
            + '\n\ndef format_cents(x):\n    return f"{x}c"\n',
        },
    )
    _change(
        root,
        {
            "checkout.py": LEAD_BASE["checkout.py"].replace(
                "sum(items)", "sum(items) + 0"
            )
        },
    )

    result = _check(root)

    assert _found(result) == []
    assert result.evidence["summary"] == "No code left without callers"


def test_an_abstained_helper_named_in_a_template_is_named_as_not_judged(tmp_path):
    root = _repo(
        tmp_path,
        {**LEAD_BASE, "templates/price.html": "<p>{{ format_price(total) }}</p>\n"},
    )
    _change(
        root,
        {
            "checkout.py": LEAD_BASE["checkout.py"]
            .replace("from util import format_price\n\n\n", "")
            .replace("return format_price(amount)", 'return f"${amount:.2f}"')
        },
    )

    result = _check(root)

    assert _found(result) == []
    assert result.evidence["summary"] == (
        "1 symbol lost its callers but couldn't be judged: `format_price` (util.py:1)"
    )


def test_symbols_in_a_file_unused_on_both_sides_are_still_judged(tmp_path):
    # No package.json: both files are unused files at the base and the head.
    root = _repo(
        tmp_path,
        {
            "web/utils.ts": "export function formatDate(d: Date): string {\n  return d.toISOString().slice(0, 10);\n}\n",
            "web/app.ts": 'import { formatDate } from "./utils";\n\nexport function render(): string {\n  return "Today: " + formatDate(new Date());\n}\n\nconsole.log(render());\n',
        },
    )
    _change(
        root,
        {
            "web/app.ts": 'export function render(): string {\n  return "Today: " + new Date().toDateString();\n}\n\nconsole.log(render());\n'
        },
    )

    result = _check(root)

    assert _found(result) == [(A135, "web/utils.ts", 1)]
    assert result.findings[0].message.startswith(
        "`formatDate` (not touched by this change) lost its last caller when "
        "web/app.ts:2 changed"
    )


def test_symbols_of_a_deleted_file_are_not_reported(tmp_path):
    root = _repo(tmp_path, LEAD_BASE)
    _change(
        root,
        {
            "util.py": None,
            "checkout.py": LEAD_BASE["checkout.py"]
            .replace("from util import format_price\n\n\n", "")
            .replace("return format_price(amount)", 'return f"${amount:.2f}"'),
        },
    )

    result = _check(root)

    assert _found(result) == []
    assert result.evidence["summary"] == "No code left without callers"
