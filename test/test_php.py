from __future__ import annotations

import json
from pathlib import Path

import pytest

from skylos.visitors.languages.php import scan_php_file


def _scan_php(tmp_path: Path, code: str, filename: str = "App.php") -> tuple:
    file_path = tmp_path / filename
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(code, encoding="utf-8")
    return scan_php_file(str(file_path), {})


def test_php_scanner_collects_defs_refs_and_raw_imports(tmp_path):
    defs, refs, _, _, visitor, _, quality, danger, _, _, _, _, raw_imports = _scan_php(
        tmp_path,
        """<?php
namespace App\\Http;

use Foo\\Bar;
use Foo\\Baz as Quux;

class UserController {
    private string $name;
    public function __construct(private Repo $repo) {}
    private function helper($x) { return $this->name; }
    public function show() { return self::fmt($this->helper($_GET['id'])); }
    private static function fmt($x) { return trim($x); }
}

function topLevel($x) { return trim($x); }

require 'bootstrap.php';
""",
    )

    def_names = {d.name for d in defs}
    ref_names = {r[0] for r in refs}
    exported = {d.name for d in defs if d.is_exported}

    assert "App.Http.UserController" in def_names
    assert "App.Http.UserController.helper" in def_names
    assert "App.Http.UserController.fmt" in def_names
    assert "App.Http.UserController.name" in def_names
    assert "App.Http.UserController.repo" in def_names
    assert "App.Http.topLevel" in def_names
    assert "Bar" in def_names
    assert "Quux" in def_names

    assert "App.Http.UserController.helper" in ref_names
    assert "App.Http.UserController.fmt" in ref_names
    assert "App.Http.UserController.name" in ref_names
    assert "App.Http.trim" in ref_names

    assert "App.Http.UserController.__construct" in exported
    assert "App.Http.UserController.show" in exported
    assert "App.Http.UserController.helper" not in exported

    assert visitor.is_test_file is False
    assert quality == []
    assert danger == []
    assert raw_imports == [
        {"source": "use", "names": ["Bar"], "line": 4},
        {"source": "use", "names": ["Quux"], "line": 5},
        {"source": "bootstrap.php", "names": [], "line": 17},
    ]


def test_php_private_property_and_static_method_references_are_recorded(tmp_path):
    defs, refs, *_ = _scan_php(
        tmp_path,
        """<?php
class Demo {
    private string $name;
    public function run() {
        return self::fmt($this->name);
    }
    private static function fmt($x) { return trim($x); }
}
""",
    )

    def_names = {d.name for d in defs}
    ref_names = {r[0] for r in refs}

    assert "Demo.name" in def_names
    assert "Demo.fmt" in def_names
    assert "Demo.name" in ref_names
    assert "Demo.fmt" in ref_names


def test_php_test_file_marks_phpunit_style_methods_as_test_related(tmp_path):
    defs, _, _, _, visitor, _, _, _, _, _, _, _, _ = _scan_php(
        tmp_path,
        """<?php
class UserTest extends TestCase {
    public function setUp(): void {}
    public function test_it_works(): void {}
}
""",
        filename="tests/UserTest.php",
    )

    def_names = {d.name for d in defs}
    exported = {d.name for d in defs if d.is_exported}

    assert "UserTest.setUp" in def_names
    assert "UserTest.test_it_works" in def_names
    assert "UserTest.setUp" in exported
    assert "UserTest.test_it_works" in exported
    assert visitor.is_test_file is True
    assert visitor.test_decorated_lines


def test_php_scanner_collects_grouped_imports_enums_and_constants(tmp_path):
    defs, _, _, _, _, _, _, _, _, _, _, _, raw_imports = _scan_php(
        tmp_path,
        """<?php
namespace App;

use Foo\\{Bar, Baz as Quux};

const GLOBAL_FLAG = true;

class Demo {
    public const VERSION = '1';
}

enum Role {
    case Admin;
    case User;
}
""",
    )

    def_names = {d.name for d in defs}
    exported = {d.name for d in defs if d.is_exported}

    assert "Bar" in def_names
    assert "Quux" in def_names
    assert "App.GLOBAL_FLAG" in def_names
    assert "App.Demo.VERSION" in def_names
    assert "App.Role" in def_names
    assert "App.Role.Admin" in def_names
    assert "App.Role.User" in def_names

    assert "App.GLOBAL_FLAG" not in exported
    assert "App.Demo.VERSION" in exported
    assert "App.Role" in exported
    assert "App.Role.Admin" in exported

    assert raw_imports == [{"source": "use", "names": ["Bar", "Quux"], "line": 4}]


def test_phpunit_test_attribute_marks_method_as_entrypoint(tmp_path):
    defs, _, _, _, visitor, _, _, _, _, _, _, _, _ = _scan_php(
        tmp_path,
        """<?php
use PHPUnit\\Framework\\Attributes\\Test;

class DemoTest extends TestCase {
    #[Test]
    public function it_works(): void {}
}
""",
        filename="tests/DemoTest.php",
    )

    method = next(d for d in defs if d.name == "DemoTest.it_works")

    assert method.is_exported is True
    assert visitor.test_decorated_lines


def test_non_phpunit_attribute_does_not_mark_method_as_entrypoint(tmp_path):
    defs, _, _, _, visitor, _, _, _, _, _, _, _, _ = _scan_php(
        tmp_path,
        """<?php
class Demo {
    #[Latest]
    private function helper(): void {}
}
""",
    )

    method = next(d for d in defs if d.name == "Demo.helper")

    assert method.is_exported is False
    assert not visitor.test_decorated_lines


def _ref_names(refs) -> set[str]:
    return {name for name, _ in refs}


def test_php_type_positions_reference_imported_classes(tmp_path):
    # laravel/laravel, guzzle and symfony/console reported every import used
    # only as a type as unused at 100% confidence.
    _, refs, *_ = _scan_php(
        tmp_path,
        """<?php
namespace App;

use App\\Contracts\\ParamType;
use App\\Contracts\\ReturnType;
use App\\Contracts\\PropType;
use App\\Contracts\\NullableType;
use App\\Contracts\\UnionA;
use App\\Contracts\\UnionB;
use App\\Contracts\\InterA;
use App\\Contracts\\InterB;
use App\\Contracts\\InstanceType;
use App\\Contracts\\CatchType;
use App\\Contracts\\AttrType;
use App\\Contracts\\ParamAttr;
use App\\Contracts\\ClosureType;
use App\\Contracts\\ArrowType;
use App\\Contracts\\PromotedType;
use App\\Contracts\\ConstType;
use App\\Contracts\\TrulyUnused;

#[AttrType]
final class Service
{
    private PropType $prop;
    private const LIMIT = ConstType::MAX;

    public function __construct(private ?PromotedType $promoted) {}

    public function run(
        #[ParamAttr] ParamType $a,
        ?NullableType $b,
        UnionA|UnionB $c,
        InterA&InterB $d,
    ): ReturnType {
        if ($a instanceof InstanceType) {
            return $a;
        }
        try {
            $f = function (ClosureType $x) { return $x; };
            $g = fn (ArrowType $y) => $y;
        } catch (CatchType $e) {
        }
        return $a;
    }
}
""",
    )

    names = _ref_names(refs)
    for alias in (
        "ParamType",
        "ReturnType",
        "PropType",
        "NullableType",
        "UnionA",
        "UnionB",
        "InterA",
        "InterB",
        "InstanceType",
        "CatchType",
        "AttrType",
        "ParamAttr",
        "ClosureType",
        "ArrowType",
        "PromotedType",
        "ConstType",
    ):
        assert alias in names, alias
        assert f"App.Contracts.{alias}" in names, alias
    assert "TrulyUnused" not in names


def test_php_relative_and_self_types_do_not_reference_their_own_class(tmp_path):
    _, refs, *_ = _scan_php(
        tmp_path,
        """<?php
namespace App;

final class Money
{
    public function add(self $other): static { return $this; }
    public function equals(Money $other): ?self { return null; }
    public function lookup(\\Fully\\Qualified $q, namespace\\Sibling $s): iterable
    {
        return [];
    }
}
""",
    )

    names = _ref_names(refs)
    assert "App.Money" not in names
    assert "Fully.Qualified" in names
    assert "App.Sibling" in names
    assert not {"App.self", "App.static", "App.iterable"} & names


def test_php_docblock_types_reference_imported_classes(tmp_path):
    _, refs, *_ = _scan_php(
        tmp_path,
        """<?php
namespace App;

use App\\Docs\\VarType;
use App\\Docs\\ParamType;
use App\\Docs\\ReturnType;
use App\\Docs\\GenericItem;
use App\\Docs\\ThrowsType;
use App\\Docs\\ShapeType;
use App\\Docs\\TemplateBound;
use App\\Docs\\MethodReturn;
use App\\Docs\\FactoryItem;
use App\\Docs\\InlineSee;
use App\\Docs\\SeeTarget;
use App\\Docs\\CoveredClass;
use App\\Docs\\ProseOnly;
use App\\Docs\\Resource;
use App\\Docs\\Query;

/**
 * @template T of TemplateBound
 * @method static MethodReturn query()
 */
final class Repo
{
    /** @use HasFactory<FactoryItem> */
    use HasFactory;

    /** @var VarType */
    private $value;

    /**
     * Uses ProseOnly to explain things; also see {@see InlineSee}.
     *
     * @param ParamType $param a resource handle
     * @param array{
     *     body?: string|ShapeType,
     * } $options
     * @return list<GenericItem>|ReturnType
     * @throws ThrowsType
     * @see SeeTarget::run()
     * @covers CoveredClass
     */
    public function run($param, array $options)
    {
        return [];
    }
}
""",
    )

    names = _ref_names(refs)
    for alias in (
        "VarType",
        "ParamType",
        "ReturnType",
        "GenericItem",
        "ThrowsType",
        "ShapeType",
        "TemplateBound",
        "MethodReturn",
        "FactoryItem",
    ):
        assert alias in names, alias
        assert f"App.Docs.{alias}" in names, alias
    # Prose and cross-reference tags (@see, {@see}, @covers) keep the import
    # (PHP-CS-Fixer semantics) but do not make the class itself used.
    for alias in ("ProseOnly", "InlineSee", "SeeTarget", "CoveredClass"):
        assert alias in names, alias
        assert f"App.Docs.{alias}" not in names, alias
    # Lower-case pseudo types, prose words and @method names do not match
    # class imports.
    assert "Resource" not in names
    assert "Query" not in names


def test_php_enum_bodies_are_scanned_for_references(tmp_path):
    defs, refs, *_ = _scan_php(
        tmp_path,
        """<?php
namespace App;

use App\\Contracts\\HasLabel;
use App\\Support\\Formatter;
use App\\Attributes\\Description;

enum Status: string implements HasLabel
{
    #[Description('Active')]
    case Active = 'active';

    public function label(): string
    {
        return Formatter::format($this->value);
    }
}
""",
    )

    names = _ref_names(refs)
    assert {"HasLabel", "Formatter", "Description"} <= names
    assert "App.Support.Formatter.format" in names
    assert {"App.Status", "App.Status.Active", "App.Status.label"} <= {
        d.name for d in defs
    }


_LARAVEL_COMPOSER = (
    '{"require": {"laravel/framework": "^11.0"}, "autoload": {"psr-4": '
    '{"App\\\\": "app/", "Database\\\\Factories\\\\": "database/factories/"}}}'
)
# The Laravel 11 application builder turns on event discovery.
_LARAVEL_11_BOOTSTRAP = """<?php
use Illuminate\\Foundation\\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(web: __DIR__.'/../routes/web.php')
    ->create();
"""


def _laravel_app(tmp_path, bootstrap=_LARAVEL_11_BOOTSTRAP):
    (tmp_path / "composer.json").write_text(_LARAVEL_COMPOSER, encoding="utf-8")  # skylos: ignore[SKY-D324] pytest tmp_path fixture
    if bootstrap is not None:
        (tmp_path / "bootstrap").mkdir(exist_ok=True)
        (tmp_path / "bootstrap" / "app.php").write_text(bootstrap, encoding="utf-8")  # skylos: ignore[SKY-D324] pytest tmp_path fixture
    return tmp_path


def _write_php(root, relative, code):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(code, encoding="utf-8")  # skylos: ignore[SKY-D324] pytest tmp_path fixture


def _framework_roots(tmp_path, relative, code):
    defs, _, _, _, _, framework, *_ = _scan_php(tmp_path, code, filename=relative)
    lines = framework.framework_decorated_lines
    return {d.simple_name for d in defs if d.line in lines}, framework


def test_laravel_convention_classes_are_framework_roots(tmp_path):
    app = _laravel_app(tmp_path)
    cases = {
        "app/Listeners/SendWelcome.php": (
            "namespace App\\Listeners;\nuse App\\Events\\UserRegistered;",
            "",
            "public function handle(UserRegistered $event): void { $this->helper(); }",
        ),
        "app/Console/Commands/Prune.php": (
            "namespace App\\Console\\Commands;\nuse Illuminate\\Console\\Command;",
            " extends Command",
            "public function handle(): void { $this->helper(); }",
        ),
        "app/Livewire/Counter.php": (
            "namespace App\\Livewire;",
            "",
            "public function handle(): void { $this->helper(); }",
        ),
        "app/View/Components/Alert.php": (
            "namespace App\\View\\Components;",
            "",
            "public function handle(): void { $this->helper(); }",
        ),
    }
    for relative, (header, extends, method) in cases.items():
        class_name = Path(relative).stem
        roots, framework = _framework_roots(
            app,
            relative,
            f"""<?php
{header}

final class {class_name}{extends}
{{
    {method}
    private function helper(): void {{}}
}}
""",
        )
        assert roots == {class_name, "handle"}, relative
        assert "laravel" in framework.detected_frameworks


def test_laravel_model_named_conventions_need_the_model(tmp_path):
    app = _laravel_app(tmp_path)
    _write_php(
        app,
        "app/Models/User.php",
        "<?php\nnamespace App\\Models;\n"
        "use Illuminate\\Database\\Eloquent\\Factories\\HasFactory;\n"
        "class User { use HasFactory; }\n",
    )
    _write_php(
        app,
        "app/Models/Blog/Post.php",
        "<?php\nnamespace App\\Models\\Blog;\n"
        "use Illuminate\\Database\\Eloquent\\Factories\\HasFactory;\n"
        "class Post { use HasFactory; }\n",
    )
    for relative, live, others in (
        (
            "database/factories/UserFactory.php",
            "UserFactory",
            ("FactoryHelper", "GhostFactory"),
        ),
        ("database/factories/Blog/PostFactory.php", "PostFactory", ()),
        ("app/Policies/UserPolicy.php", "UserPolicy", ("PolicyHelper", "GhostPolicy")),
        (
            "database/seeders/DatabaseSeeder.php",
            "DatabaseSeeder",
            ("SeedHelper",),
        ),
    ):
        classes = "".join(f"class {name} {{}}\n" for name in (live, *others))
        roots, _ = _framework_roots(app, relative, f"<?php\n{classes}")
        assert roots == {live}, relative


def test_laravel_listener_needs_a_typed_event_parameter(tmp_path):
    app = _laravel_app(tmp_path)
    roots, _ = _framework_roots(
        app,
        "app/Listeners/Listeners.php",
        """<?php
namespace App\\Listeners;

final class Typed { public function handleShipped(\\App\\Events\\Shipped $e): void {} }
final class Invokable { public function __invoke(?Shipped $e): void {} }
final class Untyped { public function handle($event): void {} }
final class ScalarTyped { public function handle(string $event): void {} }
final class NoHandler { public static function format(Shipped $e): string { return ''; } }
""",
    )

    assert roots == {"Typed", "handleShipped", "Invokable", "__invoke"}


def test_laravel_command_needs_a_command_base_class(tmp_path):
    app = _laravel_app(tmp_path)
    roots, _ = _framework_roots(
        app,
        "app/Console/Commands/Commands.php",
        """<?php
namespace App\\Console\\Commands;

use Illuminate\\Console\\Command;

final class Sync extends Command { public function handle(): int { return 0; } }
final class Plain { public function handle(): int { return 0; } }
""",
    )

    assert roots == {"Sync", "handle"}


def test_laravel_command_base_must_resolve_to_illuminate_command(tmp_path):
    app = _laravel_app(tmp_path)
    _write_php(
        app,
        "app/Console/Commands/AbstractBusCommand.php",
        "<?php\nnamespace App\\Console\\Commands;\nabstract class AbstractBusCommand {}\n",
    )
    _write_php(
        app,
        "app/Console/BaseCommand.php",
        "<?php\nnamespace App\\Console;\n"
        "use Illuminate\\Console\\Command as IlluminateCommand;\n"
        "abstract class BaseCommand extends IlluminateCommand {}\n",
    )
    cases = {
        # Symfony's Command is not auto-registered by Artisan.
        "SymfonyOnly": "use Symfony\\Component\\Console\\Command\\Command;\n"
        "class SymfonyOnly extends Command {}",
        # A project base that does not extend Illuminate's Command.
        "CreateInvoiceCommand": "class CreateInvoiceCommand extends AbstractBusCommand {}",
        # A project base that does, resolved through PSR-4.
        "Report": "use App\\Console\\BaseCommand;\nclass Report extends BaseCommand {}",
    }
    live = set()
    for name, body in cases.items():
        roots, _ = _framework_roots(
            app,
            f"app/Console/Commands/{name}.php",
            f"<?php\nnamespace App\\Console\\Commands;\n{body}\n",
        )
        live |= roots

    assert live == {"Report"}


def test_laravel_psr4_directories_outside_the_project_are_not_read(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    app = _laravel_app(project)
    outside = tmp_path / "outside"
    # composer.json belongs to the scanned project, so its PSR-4 map may
    # point anywhere: one relative escape, one absolute path.
    composer = {
        "require": {"laravel/framework": "^11.0"},
        "autoload": {
            "psr-4": {
                "App\\": "app/",
                "Up\\": "../outside/up/",
                "Abs\\": f"{(outside / 'abs').as_posix()}/",
            }
        },
    }
    _write_php(app, "composer.json", json.dumps(composer))
    for namespace, directory in (("Up", "up"), ("Abs", "abs")):
        _write_php(
            outside,
            f"{directory}/BaseCommand.php",
            f"<?php\nnamespace {namespace};\n"
            "use Illuminate\\Console\\Command as IlluminateCommand;\n"
            "abstract class BaseCommand extends IlluminateCommand {}\n",
        )
    live = set()
    for name, namespace in (("Escaped", "Up"), ("Absolute", "Abs")):
        roots, _ = _framework_roots(
            app,
            f"app/Console/Commands/{name}.php",
            "<?php\nnamespace App\\Console\\Commands;\n"
            f"use {namespace}\\BaseCommand;\nclass {name} extends BaseCommand {{}}\n",
        )
        live |= roots

    assert live == set()


def test_laravel_model_symlinked_outside_the_project_is_not_read(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    app = _laravel_app(project)
    _write_php(
        tmp_path,
        "outside/Invoice.php",
        "<?php\nnamespace App\\Models;\n"
        "use Illuminate\\Database\\Eloquent\\Factories\\HasFactory;\n"
        "class Invoice { use HasFactory; }\n",
    )
    models = app / "app" / "Models"
    models.mkdir(parents=True)
    try:
        (models / "Invoice.php").symlink_to(tmp_path / "outside" / "Invoice.php")
    except OSError:
        pytest.skip("filesystem does not allow symlink creation")

    roots, _ = _framework_roots(
        app,
        "database/factories/InvoiceFactory.php",
        "<?php\nnamespace Database\\Factories;\nclass InvoiceFactory {}\n",
    )

    assert roots == set()


def test_laravel_factory_needs_a_model_using_has_factory(tmp_path):
    app = _laravel_app(tmp_path)
    _write_php(
        app,
        "app/Models/Legacy.php",
        "<?php\nnamespace App\\Models;\n"
        "use Illuminate\\Database\\Eloquent\\Model;\nclass Legacy extends Model {}\n",
    )
    _write_php(
        app,
        "app/Models/BaseModel.php",
        "<?php\nnamespace App\\Models;\n"
        "use Illuminate\\Database\\Eloquent\\Factories\\HasFactory;\n"
        "abstract class BaseModel { use HasFactory; }\n",
    )
    _write_php(
        app,
        "app/Models/Invoice.php",
        "<?php\nnamespace App\\Models;\nclass Invoice extends BaseModel {}\n",
    )
    live = set()
    for name in ("LegacyFactory", "InvoiceFactory"):
        roots, _ = _framework_roots(
            app,
            f"database/factories/{name}.php",
            f"<?php\nnamespace Database\\Factories;\nclass {name} {{}}\n",
        )
        live |= roots

    # Invoice inherits HasFactory from a project parent; Legacy never asks.
    assert live == {"InvoiceFactory"}


_TYPED_LISTENER = """<?php
namespace App\\Listeners;

use App\\Events\\OrderShipped;

final class SendInvoice { public function handle(OrderShipped $event): void {} }
"""
_EVENT_PROVIDER = """<?php
namespace App\\Providers;

use Illuminate\\Foundation\\Support\\Providers\\EventServiceProvider as ServiceProvider;

class EventServiceProvider extends ServiceProvider
{
    protected $listen = [];

    public function shouldDiscoverEvents(): bool
    {
        return %s;
    }
}
"""


@pytest.mark.parametrize(
    ("bootstrap", "provider", "discovered"),
    [
        # Laravel 10: discovery only when a provider opts in.
        (None, "false", False),
        (None, None, False),
        (None, "true", True),
        # Laravel 11 builder discovers unless withEvents turns it off.
        (_LARAVEL_11_BOOTSTRAP, None, True),
        (
            _LARAVEL_11_BOOTSTRAP.replace(
                "->create();", "->withEvents(discover: [])\n    ->create();"
            ),
            None,
            True,
        ),
        (
            _LARAVEL_11_BOOTSTRAP.replace(
                "->create();", "->withEvents(discover: false)\n    ->create();"
            ),
            None,
            False,
        ),
    ],
)
def test_laravel_listeners_are_roots_only_with_event_discovery(
    tmp_path, bootstrap, provider, discovered
):
    app = _laravel_app(tmp_path, bootstrap=bootstrap)
    if provider is not None:
        _write_php(
            app, "app/Providers/EventServiceProvider.php", _EVENT_PROVIDER % provider
        )
    roots, _ = _framework_roots(app, "app/Listeners/SendInvoice.php", _TYPED_LISTENER)

    assert roots == ({"SendInvoice", "handle"} if discovered else set())


@pytest.mark.parametrize(
    "composer",
    [
        '{"require": {"symfony/console": "^7.0"}}',
        # Lumen and an unrelated script named artisan are not Laravel apps.
        '{"require": {"laravel/lumen-framework": "^10.0"}}',
        '{"require-dev": {"laravel/framework": "^11.0"}}',
    ],
)
def test_laravel_conventions_need_a_laravel_application(tmp_path, composer):
    (tmp_path / "composer.json").write_text(composer, encoding="utf-8")
    (tmp_path / "artisan").write_text("#!/usr/bin/env php\n", encoding="utf-8")
    *_, framework, _, _, _, _, _, _, _ = _scan_php(
        tmp_path,
        "<?php\nnamespace App\\Console\\Commands;\n"
        "use Illuminate\\Console\\Command;\n"
        "final class Sync extends Command { public function handle(): int { return 0; } }\n",
        filename="app/Console/Commands/Sync.php",
    )

    assert not framework.framework_decorated_lines


def test_php_class_docblock_does_not_reference_its_own_class(tmp_path):
    # IDE-helper docblocks name the class they document; that must not keep
    # the class alive.
    _, refs, *_ = _scan_php(
        tmp_path,
        """<?php
namespace App;

use Illuminate\\Database\\Eloquent\\Builder;

/**
 * @method static Builder|IdeHelperModel query()
 * @property-read IdeHelperModel|null $parent
 * @mixin IdeHelperModel
 * @see \\App\\IdeHelperModel::make()
 */
final class IdeHelperModel {}

/** @mixin Other */
interface Contract {}
""",
    )

    names = _ref_names(refs)
    assert "App.IdeHelperModel" not in names
    assert {"Builder", "Illuminate.Database.Eloquent.Builder", "App.Other"} <= names
