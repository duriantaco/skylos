"""Exact PHP callback references without treating arbitrary array data as calls."""

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.visitors.languages.php.core import PhpCore


def _scan(source):
    core = PhpCore("App.php", source.encode())
    core.scan()
    return core, {definition.name: definition for definition in core.defs}


@pytest.mark.parametrize("helper_first", [False, True])
@pytest.mark.parametrize("quote", ["'", '"'])
def test_private_callable_position_keeps_exact_owner_and_declaration_order(helper_first, quote):
    helper = "private function dispatch($value, callable $predicate) { return $predicate($value); }"
    caller = f"public function run() {{ return $this->dispatch(1, [$this, {quote}check{quote}]); }}"
    body = helper + caller if helper_first else caller + helper
    core, definitions = _scan(
        "<?php namespace App; class Active {"
        + body
        + "private function check($value) { return true; } private function spare() {} }"
        + "class Other { private function check() {} }"
    )
    assert definitions["App.Active.run"].calls == {
        "App.Active.dispatch",
        "App.Active.check",
    }
    assert definitions["App.Active.check"].called_by == {"App.Active.run"}
    assert not definitions["App.Other.check"].called_by
    assert not definitions["App.Active.spare"].called_by
    assert "check" not in {name for name, _ in core.refs}


@pytest.mark.parametrize(
    "helper",
    [
        "public function dispatch($value, callable $predicate) { return $predicate($value); }",
        "protected function dispatch($value, callable $predicate) { return $predicate($value); }",
        "private static function dispatch($value, callable $predicate) { return $predicate($value); }",
        "private function dispatch($value, $predicate) { return $predicate($value); }",
        "private function dispatch($value, array $predicate) { return count($predicate); }",
        "private function dispatch($value, ?callable $predicate) { return $predicate($value); }",
        "private function dispatch($value, callable &$predicate) { return $predicate($value); }",
        "private function dispatch($value, callable ...$predicate) { return null; }",
        "private function dispatch($value, callable $predicate) { return $value; }",
        "private function dispatch($value, callable $predicate) { $predicate = 'trim'; return $predicate($value); }",
        "private function dispatch($value, callable $predicate) { replace($predicate); return $predicate($value); }",
        "private function dispatch($value, callable $predicate) { return function () use ($predicate) { return $predicate($value); }; }",
    ],
)
def test_unproven_helper_contract_does_not_invent_callback_edge(helper):
    _, definitions = _scan(
        "<?php class Active {"
        "public function run() { return $this->dispatch(1, [$this, 'check']); }"
        + helper
        + "private function check() {} }"
    )
    assert not definitions["Active.check"].called_by


@pytest.mark.parametrize(
    "call",
    [
        "$this->dispatch([$this, 'check'], 'trim')",
        "$this->dispatch(value: 1, predicate: [$this, 'check'])",
        "$this->dispatch(...[1, [$this, 'check']])",
        "$this->dispatch(1, [0 => $this, 1 => 'check'])",
        "$this->dispatch(1, [$other, 'check'])",
        "$this->dispatch(1, [$this, $name])",
        "$this->dispatch(1, [$this, 'ch' . 'eck'])",
        "$this->dispatch(1, [$this, 'check', 'extra'])",
        "$other->dispatch(1, [$this, 'check'])",
        "self::dispatch(1, [$this, 'check'])",
        "function () { $this->dispatch(1, [$this, 'check']); }",
    ],
)
def test_unsupported_argument_and_receiver_shapes_do_not_expand_scope(call):
    # Some shapes are valid PHP callbacks; this narrow proof intentionally
    # abstains from them. Absence of an edge is not source truth of deadness.
    _, definitions = _scan(
        "<?php class Active { public function run() { "
        + call
        + "; } private function dispatch($value, callable $predicate) { return $predicate($value); }"
        + "private function check() {} }"
    )
    assert not definitions["Active.check"].called_by


def test_same_named_callback_in_another_owner_is_not_rescued():
    core, definitions = _scan(
        "<?php class Active {"
        "public function run() { $this->dispatch([$this, 'check']); }"
        "private function dispatch(callable $predicate) { return $predicate(); } }"
        "class Other { private function check() {} }"
    )
    assert not definitions["Other.check"].called_by
    assert "Other.check" not in {name for name, _ in core.refs}


@pytest.mark.parametrize(
    "mutation",
    [
        "inject(['predicate' => 'strval']);",
        "\\extract(['predicate' => 'strval']);",
        "parse_str('value=1');",
        "$$name = 'strval';",
        "include 'configuration.php';",
        "$operation(['predicate' => 'strval']);",
    ],
)
def test_indirect_scope_mutation_does_not_prove_callback(mutation):
    _, definitions = _scan(
        "<?php use function extract as inject; class Active {"
        "public function run() { $this->dispatch([$this, 'check']); }"
        "private function dispatch(callable $predicate) {"
        + mutation
        + "return $predicate(1); } private function check() {} }"
    )
    assert not definitions["Active.check"].called_by


@pytest.mark.parametrize("grep_verify", [False, True])
def test_full_scan_preserves_dead_callers_siblings_and_unused_imports(tmp_path, grep_verify):
    fixture = (
        Path(__file__).resolve().parents[1]
        / "benchmarks/review_2026_11_17/php_callable_corpus/fixtures/private_helper/app.php"
    )
    (tmp_path / "app.php").write_text(fixture.read_text())
    report = json.loads(analyze(str(tmp_path), grep_verify=grep_verify, grep_cache=False))
    assert report.get("analysis_errors", []) == []
    assert {item["full_name"] for item in report.get("unused_functions", [])} == {
        "Review.Resolver.dormant",
        "Review.Resolver.deadCallback",
        "Review.Resolver.unusedSibling",
        "Review.Other.isRoute",
    }
    assert {item["name"] for item in report.get("unused_imports", [])} == {
        "RuntimeException",
        "htmlentities",
    }
