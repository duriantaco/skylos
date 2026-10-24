from __future__ import annotations

from pathlib import Path

from skylos.visitors.languages.php import scan_php_file


def _scan_php_findings(tmp_path: Path, code: str) -> list[dict]:
    file_path = tmp_path / "app.php"
    file_path.write_text(code, encoding="utf-8")
    return scan_php_file(str(file_path), {})[7]


def _rule_ids(findings: list[dict]) -> set[str]:
    return {finding["rule_id"] for finding in findings}


def test_unserialize_on_superglobal_flags(tmp_path):
    findings = _scan_php_findings(
        tmp_path,
        """<?php
unserialize($_POST['data']);
""",
    )
    assert "SKY-D204" in _rule_ids(findings)


def test_unserialize_on_tainted_assignment_flags(tmp_path):
    findings = _scan_php_findings(
        tmp_path,
        """<?php
$payload = $_REQUEST['payload'];
unserialize($payload);
""",
    )
    assert "SKY-D204" in _rule_ids(findings)


def test_request_controlled_include_flags(tmp_path):
    findings = _scan_php_findings(
        tmp_path,
        """<?php
include $_GET['tpl'];
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_request_controlled_file_sink_flags(tmp_path):
    findings = _scan_php_findings(
        tmp_path,
        """<?php
$path = $_GET['path'];
file_get_contents($path);
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_filter_input_to_file_put_contents_flags(tmp_path):
    findings = _scan_php_findings(
        tmp_path,
        """<?php
$path = filter_input(INPUT_GET, 'path');
file_put_contents($path, 'data');
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_filter_input_to_rename_flags(tmp_path):
    findings = _scan_php_findings(
        tmp_path,
        """<?php
$from = filter_input(INPUT_POST, 'from');
rename($from, '/srv/data/archive.txt');
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_fixed_path_file_sink_is_safe(tmp_path):
    findings = _scan_php_findings(
        tmp_path,
        """<?php
file_get_contents('/srv/data/report.txt');
""",
    )
    assert "SKY-D215" not in _rule_ids(findings)


def test_basename_sanitized_file_sink_is_safe(tmp_path):
    findings = _scan_php_findings(
        tmp_path,
        """<?php
$name = $_GET['name'];
file_get_contents('/srv/data/' . basename($name));
""",
    )
    assert "SKY-D215" not in _rule_ids(findings)


def test_taint_does_not_leak_across_methods_with_same_local_name(tmp_path):
    findings = _scan_php_findings(
        tmp_path,
        """<?php
class Demo {
    public function unsafe() {
        $payload = $_POST['payload'];
        return unserialize($payload);
    }

    public function safe() {
        $payload = '/srv/data/report.txt';
        return file_get_contents($payload);
    }
}
""",
    )
    assert _rule_ids(findings) == {"SKY-D204"}


def test_drupal_request_input_built_into_sql_flags(tmp_path):
    findings = _scan_php_findings(
        tmp_path,
        """<?php
class Page {
    public function view(Request $request) {
        $name = $request->query->get('name');
        $this->database->query("SELECT nid FROM node WHERE title = '$name'");
        \\Drupal::database()->where('title = ' . \\Drupal::request()->request->get('t'));
        db_query('SELECT 1 FROM users WHERE name = ' . $name);
    }
}
""",
    )
    assert [f["rule_id"] for f in findings] == ["SKY-D211"] * 3


def test_drupal_form_values_marked_safe_flag(tmp_path):
    findings = _scan_php_findings(
        tmp_path,
        """<?php
function demo_submit(array &$form, FormStateInterface $form_state) {
    $values = $form_state->getValues();
    $build = ['#markup' => Markup::create($values['title'])];
    $input = Markup::create($form_state->getUserInput()['body']);
    $card = [
        '#type' => 'inline_template',
        '#template' => '<h2>' . $values['title'] . '</h2>',
    ];
    $safe = [
        '#type' => 'inline_template',
        '#template' => '<h2>{{ title }}</h2>',
        '#context' => ['title' => $values['title']],
    ];
}
""",
    )
    assert [f["rule_id"] for f in findings] == ["SKY-D226"] * 2 + ["SKY-D349"]


def test_drupal_placeholders_and_escaping_do_not_flag(tmp_path):
    findings = _scan_php_findings(
        tmp_path,
        """<?php
function demo_page(Request $request, $form_state) {
    $name = $request->query->get('name');
    $nid = (int) $request->query->get('nid');
    \\Drupal::database()->query('SELECT nid FROM node WHERE title = :t', [':t' => $name]);
    \\Drupal::database()->query("SELECT title FROM node WHERE nid = $nid");
    $index->query(['keys' => $name]);
    $safe = Markup::create(Html::escape($name));
    $filtered = Markup::create(Xss::filterAdmin($form_state->getValue('body')));
    $other = $config->get('name');
    \\Drupal::database()->query("SELECT 1 FROM node WHERE title = '$other'");
}
""",
    )
    assert findings == []
