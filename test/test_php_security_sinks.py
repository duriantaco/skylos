from __future__ import annotations

import json

import pytest

from skylos.analyzer import analyze
from skylos.core.gatekeeper import check_gate
from skylos.reporting.advice_policy import apply_advice_policy
from skylos.reporting.listing import is_listed
from skylos.visitors.languages.php import scan_php_file


def _scan(tmp_path, code, name="app.php"):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(code, encoding="utf-8")
    return scan_php_file(str(path), {})[7]


def _rules(tmp_path, code, name="app.php"):
    return [
        (finding["rule_id"], finding["severity"])
        for finding in _scan(tmp_path, "<?php\n" + code, name)
    ]


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("exec('ping -c 1 ' . $_GET['host'], $out);", [("SKY-D212", "CRITICAL")]),
        ("system('nslookup ' . $_POST['name']);", [("SKY-D212", "CRITICAL")]),
        ("$o = `ls {$_GET['dir']}`;", [("SKY-D212", "CRITICAL")]),
        ("proc_open([$_GET['tool'], '-v'], [], $p);", [("SKY-D212", "CRITICAL")]),
        ("proc_open(['git', 'log', $_GET['ref']], [], $p);", []),
        (
            "system('nslookup ' . escapeshellcmd($_GET['n']));",
            [("SKY-D212", "CRITICAL")],
        ),
        (
            "$s = escapeshellarg($_GET['a']); exec('cp ' . $s . ' ' . $_GET['b']);",
            [("SKY-D212", "CRITICAL")],
        ),
        (
            "escapeshellarg($_GET['h']); exec('ping ' . $_GET['h']);",
            [("SKY-D212", "CRITICAL")],
        ),
        ("exec('ping ' . escapeshellarg($_GET['h']));", [("SKY-D203", "LOW")]),
        ("exec('uptime');", [("SKY-D203", "LOW")]),
        (
            "function backup($dir) { exec('tar czf b.tgz ' . $dir); }",
            [("SKY-D203", "HIGH")],
        ),
        ("exec('touch /tmp/' . $_SERVER['REQUEST_TIME']);", [("SKY-D203", "HIGH")]),
        ("exec('log ' . $_SERVER['HTTP_USER_AGENT']);", [("SKY-D212", "CRITICAL")]),
    ],
)
def test_command_execution(tmp_path, code, expected):
    assert _rules(tmp_path, code) == expected


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (
            "system('echo \"' . escapeshellarg($_GET['x']) . '\"');",
            [("SKY-D212", "CRITICAL")],
        ),
        (
            "system(\"echo '\" . escapeshellarg($_GET['x']) . \"'\");",
            [("SKY-D212", "CRITICAL")],
        ),
        (
            "system('sh -c ' . escapeshellarg($_GET['code']));",
            [("SKY-D212", "CRITICAL")],
        ),
        (
            "system('sudo bash -lc ' . escapeshellarg($_GET['code']));",
            [("SKY-D212", "CRITICAL")],
        ),
        (
            "system('powershell -Command ' . escapeshellarg($_GET['code']));",
            [("SKY-D212", "CRITICAL")],
        ),
        (
            "system(escapeshellarg($_GET['bin']) . ' --version');",
            [("SKY-D212", "CRITICAL")],
        ),
        (
            "$b = escapeshellarg($_GET['code']); exec('sh -c ' . $b);",
            [("SKY-D212", "CRITICAL")],
        ),
        (
            "system('grep -- ' . escapeshellarg($_GET['q']) . ' app.log');",
            [("SKY-D203", "LOW")],
        ),
        (
            "system('sh -c ' . escapeshellarg('uptime') . ' ' . escapeshellarg($_GET['x']));",
            [("SKY-D203", "LOW")],
        ),
        (
            "system('sh -c ' . escapeshellarg('ls ' . escapeshellarg($_GET['d'])));",
            [("SKY-D203", "LOW")],
        ),
        (
            "$c = 'tar czf b.tgz ' . escapeshellarg($_GET['d']); exec($c);",
            [("SKY-D203", "LOW")],
        ),
        (
            "$a = escapeshellarg($_GET['x']); $o = `ping -c 1 $a`;",
            [("SKY-D203", "LOW")],
        ),
    ],
)
def test_escapeshellarg_is_safe_only_as_an_unquoted_argument(tmp_path, code, expected):
    assert _rules(tmp_path, code) == expected


@pytest.mark.parametrize(
    "prefix",
    [
        "node --eval=",
        "node --print=",
        "node --input-type module --eval=",
        "node --require /opt/preload.js --eval=",
        "python3 -c",
        "python3 -W ignore -c",
        "perl -e",
        "ruby -e",
        "env -u TERM sh -c ",
        "env --unset TERM -- sh -c ",
        "env --chdir /tmp sh -c ",
        "env -u TERM FOO=1 sh -c ",
        "env --unset=TERM sh -c ",
        "timeout -s TERM 5 sh -c ",
        "timeout --kill-after 1 5 sh -c ",
        "nice -n 5 sh -c ",
        "nice --adjustment=5 sh -c ",
        "sudo -g staff sh -c ",
        "sudo --user nobody -- sh -c ",
        "xargs -I {} sh -c ",
        "env -S ",
        "env --split-string=",
    ],
)
def test_interpreter_code_remains_tainted_with_attached_flags_and_wrapper_options(
    tmp_path, prefix
):
    code = "system(" + repr(prefix) + " . escapeshellarg($_GET['code']));"
    assert _rules(tmp_path, code) == [("SKY-D212", "CRITICAL")]


@pytest.mark.parametrize(
    "prefix",
    [
        "node /opt/app.js --eval=",
        "node -- --eval ",
        "python3 /opt/app.py -c ",
        "python3 -- /opt/app.py -c ",
        "env -u TERM echo ",
        "env --unset TERM -- echo ",
        "env --chdir /tmp echo ",
        "timeout -s TERM 5 echo ",
        "nice -n 5 echo ",
        "sudo -g staff -- echo ",
        "env -- echo ",
        "command -v ",
    ],
)
def test_interpreter_and_wrapper_options_do_not_turn_plain_arguments_into_code(
    tmp_path, prefix
):
    code = "system(" + repr(prefix) + " . escapeshellarg($_GET['value']));"
    assert _rules(tmp_path, code) == [("SKY-D203", "LOW")]


@pytest.mark.parametrize("option", ["--unset=", "-u", "--chdir="])
@pytest.mark.parametrize(
    "command, expected",
    [("sh -c", ("SKY-D212", "CRITICAL")), ("echo", ("SKY-D203", "LOW"))],
)
def test_quoted_wrapper_option_value_preserves_the_following_program(
    tmp_path, option, command, expected
):
    code = (
        f"system('env {option}' . escapeshellarg($_GET['option']) . ' {command} ' "
        ". escapeshellarg($_GET['value']));"
    )
    assert _rules(tmp_path, code) == [expected]


def test_constant_command_is_hidden_as_low_risk(tmp_path):
    findings = _scan(tmp_path, "<?php\nexec('uptime');\n")
    assert findings[0]["low_risk_context"]["reason"] == "constant-shell-command"


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("eval($_POST['code']);", [("SKY-D201", "CRITICAL")]),
        ("eval($template);", [("SKY-D201", "HIGH")]),
        ("eval('return 1;');", []),
        ("eval('return ' . intval($_GET['n']) . ';');", []),
        ("assert($_GET['check']);", [("SKY-D201", "HIGH")]),
        ("assert($count > 0);", []),
        (
            "$f = create_function('$a', 'return $a * ' . $_GET['k'] . ';');",
            [("SKY-D201", "CRITICAL")],
        ),
        (
            "$u = preg_replace('/(.*)/e', 'strtoupper(\"\\\\1\")', $_GET['t']);",
            [("SKY-D201", "CRITICAL")],
        ),
        ("$u = preg_replace('/\\s+/i', ' ', $_GET['t']);", []),
        ("include 'pages/' . $_GET['page'] . '.php';", [("SKY-D255", "CRITICAL")]),
        ("include $_SERVER['DOCUMENT_ROOT'] . '/header.php';", []),
        (
            "$p = $_GET['p']; if (!in_array($p, ['home', 'about'], true)) { exit; } include $p . '.php';",
            [],
        ),
        (
            "$p = $_GET['p']; if (in_array($q, ['home'], true)) { include $p . '.php'; }",
            [("SKY-D255", "CRITICAL")],
        ),
    ],
)
def test_code_execution_and_file_inclusion(tmp_path, code, expected):
    assert _rules(tmp_path, code) == expected


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("echo '<p>' . $_GET['q'] . '</p>';", ["SKY-D228"]),
        ("echo htmlspecialchars($_GET['q']);", []),
        ("$n = $_GET['n']; htmlspecialchars($n); echo $n;", ["SKY-D228"]),
        ("$s = htmlspecialchars($_GET['a']); echo $s . $_GET['b'];", ["SKY-D228"]),
        (
            "echo '<a href=\"' . htmlspecialchars($_GET['u']) . '\">x</a>';",
            ["SKY-D228"],
        ),
        ("echo '<a href=\"/s?q=' . urlencode($_GET['q']) . '\">x</a>';", []),
        ("echo '<div title=\"' . strip_tags($_GET['t']) . '\">';", ["SKY-D228"]),
        ("echo strip_tags($_GET['t']);", []),
        (
            "echo \"<script>var q = '\" . htmlspecialchars($_GET['q']) . \"';</script>\";",
            ["SKY-D228"],
        ),
        ("printf('<b>%d</b>', $_GET['n']);", []),
        ("printf('<b>%s</b>', $_GET['n']);", ["SKY-D228"]),
        ("echo count($_GET), isset($_GET['x']) ? 'y' : 'n';", []),
        ("echo $_SERVER['PHP_SELF'];", ["SKY-D228"]),
        ("echo $_SERVER['SERVER_NAME'];", []),
        ("echo $_FILES['f']['name'] . $_FILES['f']['size'];", ["SKY-D228"]),
        ("echo $_FILES['f']['size'];", []),
        ("print_r($_GET);", ["SKY-D228"]),
        ("$d = print_r($_GET, true);", []),
        ("foreach ($_GET as $k => $v) { echo $v; }", ["SKY-D228"]),
        ("$o = ''; $o .= $_GET['m']; echo $o;", ["SKY-D228"]),
        ("$id = $_GET['id']; if (!ctype_digit($id)) { exit; } echo $id;", []),
        ("$u = get_userdata($_GET['id']); echo $u->display_name;", []),
        ("header('Content-Type: application/json'); echo json_encode($_GET);", []),
        (
            "if ($api) { header('Content-Type: application/json'); } echo $_GET['q'];",
            ["SKY-D228"],
        ),
        ("echo json_encode($_GET);", ["SKY-D228"]),
        ("if ($bad) { die('Bad id ' . $_GET['id']); }", ["SKY-D228"]),
    ],
)
def test_xss_output(tmp_path, code, expected):
    assert [rule for rule, _ in _rules(tmp_path, code)] == expected


@pytest.mark.parametrize(
    ("template", "expected"),
    [
        ("<a href=\"<?= htmlspecialchars($_GET['n']) ?>\">n</a>", ["SKY-D228"]),
        ("<a href=\"/i?id=<?= htmlspecialchars($_GET['id']) ?>\">i</a>", []),
        ("<input value=\"<?= $_GET['v'] ?>\">", ["SKY-D228"]),
        ("<p><?= $title ?></p>", []),
        (
            "<form action=\"<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>\">",
            [],
        ),
        ("<form action=\"<?php echo $_SERVER['PHP_SELF']; ?>\">", ["SKY-D228"]),
        (
            "<form action=\"<?php echo htmlspecialchars($_SERVER['QUERY_STRING']); ?>\">",
            ["SKY-D228"],
        ),
    ],
)
def test_short_echo_uses_the_surrounding_html_context(tmp_path, template, expected):
    findings = _scan(tmp_path, template + "\n")
    assert [finding["rule_id"] for finding in findings] == expected


@pytest.mark.parametrize(
    ("template", "expected"),
    [
        ("<p>{!! request('q') !!}</p>", ["SKY-D226"]),
        ("<p>{!! old('bio') !!}</p>", ["SKY-D226"]),
        ("<p>{{ request('q') }}</p>", []),
        ("<p>{!! e(request('q')) !!}</p>", []),
        ("<p>{!! $html !!}</p>", []),
    ],
)
def test_blade_raw_echo_of_request_data(tmp_path, template, expected):
    findings = _scan(tmp_path, "<h1>x</h1>\n" + template + "\n", "views/page.blade.php")
    assert [(f["rule_id"], f["line"]) for f in findings] == [
        (rule, 2) for rule in expected
    ]


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (
            "mysqli_query($c, \"SELECT * FROM u WHERE id = '{$_GET['id']}'\");",
            ["SKY-D211"],
        ),
        (
            "$e = mysqli_real_escape_string($c, $_GET['n']); mysqli_query($c, \"SELECT * FROM u WHERE n = '$e'\");",
            [],
        ),
        (
            "$e = mysqli_real_escape_string($c, $_GET['n']); mysqli_query($c, \"SELECT * FROM u WHERE id = $e\");",
            ["SKY-D211"],
        ),
        (
            "$q = $pdo->quote($_GET['n']); $pdo->query(\"SELECT * FROM u WHERE n = $q\");",
            [],
        ),
        (
            "$s = $pdo->prepare('SELECT * FROM u WHERE id = ?'); $s->execute([$_GET['id']]);",
            [],
        ),
        (
            "$pdo->exec(\"DELETE FROM t WHERE k = '\" . $_GET['k'] . \"'\");",
            ["SKY-D211"],
        ),
        ("$ssh->exec('ls ' . $_GET['d']);", []),
        (
            "mysqli_query($c, sprintf('SELECT * FROM u WHERE id = %d', $_GET['id']));",
            [],
        ),
        (
            "$wpdb->query($wpdb->prepare('DELETE FROM t WHERE id = %d', $_GET['id']));",
            [],
        ),
        (
            "$wpdb->get_var($wpdb->prepare('SELECT 1 FROM t WHERE id = ' . $_GET['id']));",
            ["SKY-D211"],
        ),
        (
            "$sql = 'SELECT * FROM t WHERE 1=1'; $sql .= \" AND n = '\" . $_GET['n'] . \"'\"; mysqli_query($c, $sql);",
            ["SKY-D211"],
        ),
    ],
)
def test_sql_injection(tmp_path, code, expected):
    assert [rule for rule, _ in _rules(tmp_path, code)] == expected


def test_laravel_request_sources_and_raw_sql(tmp_path):
    code = """<?php
namespace App\\Http\\Controllers;
use Illuminate\\Http\\Request;
use Illuminate\\Support\\Facades\\DB;
class C {
    public function search(Request $request) {
        $name = $request->input('name');
        DB::select("SELECT * FROM users WHERE name = '$name'");
        DB::select('SELECT * FROM users WHERE name = ?', [$name]);
        DB::table('users')->whereRaw("email = '" . $request->get('e') . "'")->get();
        DB::table('users')->where($request->input('filter', []))->get();
        DB::select('SELECT * FROM users LIMIT ' . $request->integer('page'));
        echo request()->input('q');
    }
    public function show($id) {
        return DB::select("SELECT * FROM users WHERE id = $id");
    }
}
"""
    findings = _scan(tmp_path, code)
    assert [(f["rule_id"], f["line"]) for f in findings] == [
        ("SKY-D211", 8),
        ("SKY-D211", 10),
        ("SKY-D228", 13),
    ]


def test_symfony_header_bag_needs_a_request(tmp_path):
    code = """<?php
function index(Request $request, $response) {
    echo $request->headers->get('User-Agent');
    echo $response->headers->get('Location');
}
"""
    assert [(f["rule_id"], f["line"]) for f in _scan(tmp_path, code)] == [
        ("SKY-D228", 3)
    ]


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (
            "$o = explode('.', $_GET['ip']); if (is_numeric($o[0]) && is_numeric($o[1])) { shell_exec('ping ' . $o[0] . '.' . $o[1]); }",
            [("SKY-D203", "LOW")],
        ),
        (
            "$o = explode('.', $_GET['ip']); if (is_numeric($o[0])) { $a = 1; } shell_exec('ping ' . $o[0]);",
            [("SKY-D212", "CRITICAL")],
        ),
        (
            "if (preg_match('/^\\d+$/', $_GET['id'])) { mysqli_query($c, \"SELECT * FROM t WHERE id = '{$_GET['id']}'\"); }",
            [],
        ),
        (
            "if (preg_match('/[0-9]+/', $_GET['id'])) { mysqli_query($c, 'SELECT * FROM t WHERE id = ' . $_GET['id']); }",
            [("SKY-D211", "CRITICAL")],
        ),
        (
            "if (preg_match('/^[a-z]+$/m', $_GET['id'])) { mysqli_query($c, 'SELECT * FROM t WHERE id = ' . $_GET['id']); }",
            [("SKY-D211", "CRITICAL")],
        ),
        (
            "$e = $_GET['e']; if (strtolower($e) == 'jpg' || strtolower($e) == 'png') { echo $e; }",
            [],
        ),
        (
            "$e = $_GET['e']; if (strtolower($e) == 'jpg' || $x == 'png') { echo $e; }",
            [("SKY-D228", "HIGH")],
        ),
    ],
)
def test_allow_list_guards(tmp_path, code, expected):
    assert _rules(tmp_path, code) == expected


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("$c = curl_init($_GET['url']);", ["SKY-D216"]),
        (
            "curl_setopt($c, CURLOPT_URL, 'https://api.example.com/u/' . $_GET['id']);",
            [],
        ),
        (
            "curl_setopt($c, CURLOPT_URL, 'https://api.example.com' . $_GET['p']);",
            ["SKY-D216"],
        ),
        ("curl_setopt_array($c, [CURLOPT_URL => $_POST['u']]);", ["SKY-D216"]),
        ("$h = get_headers('http://' . $_GET['host'] . '/');", ["SKY-D216"]),
        ("unserialize($_POST['d']);", ["SKY-D204"]),
        ("unserialize($_POST['d'], ['allowed_classes' => false]);", []),
        ("unserialize($_POST['d'], ['allowed_classes' => [Prefs::class]]);", []),
        ("unserialize($_POST['d'], ['allowed_classes' => true]);", ["SKY-D204"]),
        ("file_get_contents($_FILES['f']['tmp_name']);", []),
        (
            "$f = filter_input(INPUT_GET, 'p', FILTER_VALIDATE_INT); readfile('/srv/' . $f);",
            [],
        ),
    ],
)
def test_ssrf_deserialization_and_upload_sources(tmp_path, code, expected):
    assert [rule for rule, _ in _rules(tmp_path, code)] == expected


def test_new_php_findings_reach_listing_and_gate(tmp_path):
    path = tmp_path / "ping.php"
    path.write_text(
        "<?php\nexec('ping ' . $_GET['h']);\nexec('uptime');\n", encoding="utf-8"
    )
    result = json.loads(
        analyze(str(path), enable_danger=True, grep_verify=False, grep_cache=False)
    )
    view = apply_advice_policy({"danger": result.get("danger", [])})
    listed = [f["rule_id"] for f in view["danger"] if is_listed(f, "danger")]
    assert listed == ["SKY-D212"]
    passed, _ = check_gate(result, {})
    assert passed is False


def test_fast_discovery_keeps_drupal_procedural_files(tmp_path, monkeypatch):
    from skylos import analyzer as analyzer_module

    module = tmp_path / "demo.module"
    module.write_text("<?php\nfunction demo_page() {}\n", encoding="utf-8")
    seen = {}

    def fast_discover(_root, extensions, _excludes):
        seen["extensions"] = set(extensions)
        return [str(module)]

    monkeypatch.setattr(analyzer_module, "_fast_discover", fast_discover)
    files, _ = analyzer_module.Skylos()._get_python_files(tmp_path)
    assert {"module", "install", "inc", "theme", "profile", "engine"} <= seen[
        "extensions"
    ]
    assert files == [module]
