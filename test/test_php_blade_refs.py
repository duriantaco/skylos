"""Blade templates, class names written in PHP strings, and Laravel seeders."""

from __future__ import annotations

import json
from pathlib import Path

from skylos.analyzer import analyze
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.visitors.languages.php.blade import (
    blade_template_refs,
    php_string_class_refs,
)

_COMPOSER = (
    '{"require": {"laravel/framework": "^11.0"}, "autoload": {"psr-4": '
    '{"App\\\\": "app/", "Database\\\\Seeders\\\\": "database/seeders/"}}}'
)


def _write(root: Path, files: dict[str, str]) -> None:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        assert write_text_no_symlink(path, text, encoding="utf-8")


def _names(result: dict, key: str) -> set[str]:
    return {item["full_name"] for item in result.get(key) or []}


def test_blade_template_refs_cover_helpers_classes_and_members():
    refs = set(
        blade_template_refs(
            "<link href=\"{{ versioned_asset('dist/app.css') }}\">\n"
            "@if(userCanOnAny('view'))\n"
            '<body class="{{ (new \\App\\Util\\TagClassGenerator($x))->generate() }}">\n'
            "@inject('head', 'App\\Theming\\HeadContent')\n"
            "{{ $book->getUrl() }} {{ \\App\\Facades\\Theme::name() }}\n"
        )
    )

    assert {
        "versioned_asset",
        "userCanOnAny",
        "App.Util.TagClassGenerator",
        "generate",
        "App.Theming.HeadContent",
        "getUrl",
        "App.Facades.Theme",
        "App.Facades.Theme.name",
    } <= refs


def test_php_string_class_refs_need_a_namespace_separator():
    assert php_string_class_refs("App\\Services\\Mailer") == ["App.Services.Mailer"]
    assert php_string_class_refs("\\\\App\\\\Util\\\\SvgIcon") == ["App.Util.SvgIcon"]
    assert php_string_class_refs("plain words") == []
    assert php_string_class_refs("C:\\temp") == []


def test_blade_usage_keeps_helpers_and_classes_alive(tmp_path):
    _write(
        tmp_path,
        {
            "composer.json": _COMPOSER,
            "app/helpers.php": (
                "<?php\n"
                "function versioned_asset(string $p): string { return $p; }\n"
                "function never_used_helper(): int { return 1; }\n"
            ),
            "app/Util/TagClassGenerator.php": (
                "<?php\nnamespace App\\Util;\n"
                "class TagClassGenerator { public function generate(): string "
                "{ return ''; } }\n"
            ),
            "app/Util/SvgIcon.php": (
                "<?php\nnamespace App\\Util;\n"
                "class SvgIcon { public function toHtml(): string { return ''; } }\n"
            ),
            "app/Util/Orphan.php": "<?php\nnamespace App\\Util;\nclass Orphan {}\n",
            "app/Providers/ViewTweaks.php": (
                "<?php\nnamespace App\\Providers;\n"
                "class ViewTweaks { public function boot(): void { $d = "
                '"<?php echo (new \\\\App\\\\Util\\\\SvgIcon($e))->toHtml(); ?>"; } }\n'
            ),
            "config/app.php": (
                "<?php\nreturn ['providers' => [App\\Providers\\ViewTweaks::class]];\n"
            ),
            "resources/views/layout.blade.php": (
                "<link href=\"{{ versioned_asset('app.css') }}\">\n"
                '<body class="{{ (new \\App\\Util\\TagClassGenerator())->generate() }}">\n'
            ),
        },
    )

    result = json.loads(analyze(str(tmp_path), grep_cache=False))
    functions = _names(result, "unused_functions")
    classes = _names(result, "unused_classes")

    assert "versioned_asset" not in functions
    assert "App.Util.TagClassGenerator" not in classes
    assert "App.Util.SvgIcon" not in classes
    assert "never_used_helper" in functions
    assert "App.Util.Orphan" in classes


def test_seeders_run_by_artisan_class_name_are_live(tmp_path):
    _write(
        tmp_path,
        {
            "composer.json": _COMPOSER,
            "database/seeders/DatabaseSeeder.php": (
                "<?php\nnamespace Database\\Seeders;\nuse Illuminate\\Database\\Seeder;\n"
                "class DatabaseSeeder extends Seeder { public function run(): void {} }\n"
            ),
            "database/seeders/LargeContentSeeder.php": (
                "<?php\nnamespace Database\\Seeders;\nuse Illuminate\\Database\\Seeder;\n"
                "class LargeContentSeeder extends Seeder "
                "{ public function run(): void {} }\n"
            ),
            "database/seeders/NotASeeder.php": (
                "<?php\nnamespace Database\\Seeders;\nclass NotASeeder {}\n"
            ),
        },
    )

    classes = _names(
        json.loads(analyze(str(tmp_path), grep_cache=False)), "unused_classes"
    )

    assert "Database.Seeders.LargeContentSeeder" not in classes
    assert "Database.Seeders.NotASeeder" in classes
