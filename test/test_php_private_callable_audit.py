"""Independent precision controls for private PHP callback transfer; no PHP execution."""

import pytest

from skylos.visitors.languages.php.core import PhpCore


def _target(source):
    core = PhpCore("App.php", source.encode())
    core.scan()
    return next(d for d in core.defs if d.name == "Active.check")


def test_first_class_callable_creation_is_not_direct_invocation():
    target = _target(
        "<?php class Active { public function run() { $this->dispatch([$this, 'check']); } private function dispatch(callable $predicate) { return $predicate(...); } private function check() {} }"
    )
    assert not target.called_by


def test_dynamic_local_rebinding_does_not_prove_original_callback_invocation():
    target = _target(
        "<?php class Active { public function run() { $this->dispatch([$this, 'check']); } private function dispatch(callable $predicate) { extract(['predicate' => 'strval']); return $predicate(1); } private function check() {} }"
    )
    assert not target.called_by


def test_overridable_callback_is_not_bound_to_declaring_class():
    target = _target(
        "<?php class Active { public function run() { $this->dispatch([$this, 'check']); } private function dispatch(callable $predicate) { return $predicate(); } protected function check() {} } class Child extends Active { protected function check() {} } (new Child())->run();"
    )
    assert not target.called_by


@pytest.mark.parametrize(
    "body",
    [
        "return 1; $predicate();",
        "yield 1; $predicate();",
        "yield from [1]; $predicate();",
        "while (true) {} $predicate();",
        "for (;;) {} $predicate();",
        "do {} while (true); $predicate();",
        "if (false) { $predicate(); } return 1;",
        "if (true) { return 1; } else { $predicate(); }",
        "if (true) { return 1; } elseif ($predicate()) { return 2; }",
        "if ($value) { return 1; } else { return 2; } $predicate();",
        "if ($value) { return 1; } elseif (true) { return 2; } $predicate();",
        "while (false) { $predicate(); }",
        "for (;false;) { $predicate(); }",
        "for (;false;$predicate()) {}",
        "false && $predicate();",
        "true || $predicate();",
        "false ? $predicate() : null;",
    ],
)
def test_unreachable_callback_does_not_manufacture_use(body):
    target = _target(
        "<?php class Active { public function run($value = null) { $this->dispatch([$this, 'check'], $value); } private function dispatch(callable $predicate, $value) {"
        + body
        + "} private function check() {} }"
    )
    assert not target.called_by


@pytest.mark.parametrize(
    "body",
    [
        "return $predicate();",
        "if (true) { return $predicate(); }",
        "if ($value) { return $predicate(); } return 1;",
        "if (false) { return 1; } else { return $predicate(); }",
        "if ($value) { return 1; } else { return $predicate(); }",
        "if (false) { return 1; } elseif ($predicate()) { return 2; }",
        "true && $predicate();",
        "false || $predicate();",
        "true ? $predicate() : null;",
        "do { $predicate(); } while (false);",
        "for ($predicate();false;) {}",
    ],
)
def test_potentially_reachable_callback_preserves_use(body):
    target = _target(
        "<?php class Active { public function run($value = null) { $this->dispatch([$this, 'check'], $value); } private function dispatch(callable $predicate, $value) {"
        + body
        + "} private function check() {} }"
    )
    assert target.called_by == {"Active.run"}
