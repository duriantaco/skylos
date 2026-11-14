"""JS/TS dead-code liveness for files a tool or path loads and for reads the
import graph does not spell out. Every used shape has a dead lookalike."""

import json
import textwrap

from test.fixture_paths import write_fixture

from skylos.analyzer import analyze


def _write(root, relative, body):
    write_fixture(root, relative, textwrap.dedent(body).lstrip(), overwrite=True)


def _scan(tmp_path):
    return json.loads(analyze(str(tmp_path), conf=60, grep_verify=False))


def _unused_files(result, tmp_path):
    root = str(tmp_path.resolve()).replace("\\", "/") + "/"
    paths = set()
    for item in result.get("unused_files", []):
        path = str(item.get("file", "")).replace("\\", "/")
        if path.startswith(root):
            path = path[len(root) :]
        paths.add(path)
    return paths


def _unused(result, category, tmp_path):
    root = str(tmp_path.resolve()).replace("\\", "/") + "/"
    found = set()
    for item in result.get(category, []):
        path = str(item.get("file", "")).replace("\\", "/")
        if path.startswith(root):
            path = path[len(root) :]
        found.add((path, item.get("full_name") or item.get("name")))
    return found


def test_classic_jsx_reads_the_factory_binding_only_where_jsx_is_compiled(tmp_path):
    _write(
        tmp_path,
        "package.json",
        '{"name": "app", "private": true, "main": "classic/index.tsx"}',
    )
    _write(tmp_path, "classic/tsconfig.json", '{"compilerOptions": {"jsx": "react"}}')
    _write(
        tmp_path,
        "classic/index.tsx",
        """
        import React from 'react';
        import plain from './plain';
        import { Panel } from '../automatic/Panel';

        export function App() {
          return <div><Panel />{plain()}</div>;
        }
        """,
    )
    _write(
        tmp_path,
        "classic/plain.tsx",
        """
        import React from 'react';

        export default function plain() {
          return 1;
        }
        """,
    )
    _write(
        tmp_path,
        "automatic/tsconfig.json",
        '{"compilerOptions": {"jsx": "react-jsx"}}',
    )
    _write(
        tmp_path,
        "automatic/Panel.tsx",
        """
        import React from 'react';

        export const Panel = () => <span>new</span>;
        """,
    )

    imports = _unused(_scan(tmp_path), "unused_imports", tmp_path)

    assert ("classic/index.tsx", "React") not in imports
    assert ("classic/plain.tsx", "React") in imports
    assert ("automatic/Panel.tsx", "React") in imports


def test_jsx_pragma_and_configured_factory_name_the_binding_jsx_reads(tmp_path):
    _write(tmp_path, "package.json", '{"name": "app", "private": true}')
    _write(
        tmp_path,
        "tsconfig.json",
        '{"compilerOptions": {"jsx": "react", "jsxFactory": "h"}}',
    )
    _write(
        tmp_path,
        "src/index.tsx",
        """
        import React from 'react';
        import { h } from 'preact';
        import { Other } from './other';

        export const App = () => <b><Other /></b>;
        """,
    )
    _write(
        tmp_path,
        "src/other.tsx",
        """
        /** @jsx createElement */
        import { createElement } from 'preact';
        import { h } from 'preact';

        export const Other = () => <i>x</i>;
        """,
    )

    imports = _unused(_scan(tmp_path), "unused_imports", tmp_path)

    assert ("src/index.tsx", "h") not in imports
    assert ("src/index.tsx", "React") in imports
    assert ("src/other.tsx", "createElement") not in imports
    assert ("src/other.tsx", "h") in imports


def test_default_values_and_qualified_types_read_their_bindings(tmp_path):
    _write(
        tmp_path,
        "package.json",
        '{"name": "app", "private": true, "main": "src/index.ts", '
        '"dependencies": {"remote-sdk": "1.0.0"}}',
    )
    _write(tmp_path, "src/index.ts", "export { open, size, run } from './panel';\n")
    _write(
        tmp_path,
        "src/panel.ts",
        """
        import type * as sdk from 'remote-sdk';
        import type * as spareNs from 'remote-sdk';
        import { noop, spare } from './util';

        const DEFAULT_MIN = 100;
        const DEFAULT_MAX = 500;

        export function open(options: { onClose?: () => void } = {}) {
          const { onClose = noop } = options;
          onClose();
        }

        export const size = ({ min = DEFAULT_MIN }: { min?: number }) => min;

        export function run(state: sdk.multi.Progress): number {
          return state.n;
        }
        """,
    )
    _write(
        tmp_path,
        "src/util.ts",
        "export const noop = () => {};\nexport const spare = () => {};\n",
    )

    result = _scan(tmp_path)
    imports = _unused(result, "unused_imports", tmp_path)
    variables = _unused(result, "unused_variables", tmp_path)

    assert ("src/panel.ts", "noop") not in imports
    assert ("src/panel.ts", "sdk") not in imports
    assert ("src/panel.ts", "spare") in imports
    assert ("src/panel.ts", "spareNs") in imports
    assert ("src/panel.ts", "DEFAULT_MIN") not in variables
    assert ("src/panel.ts", "DEFAULT_MAX") in variables


def test_methods_overriding_a_dependency_base_stay_while_plain_methods_report(
    tmp_path,
):
    _write(
        tmp_path,
        "package.json",
        '{"name": "app", "private": true, "main": "src/index.ts", '
        '"dependencies": {"@codemirror/view": "6.0.0"}}',
    )
    _write(
        tmp_path,
        "src/index.ts",
        """
        import { WidgetType } from '@codemirror/view';
        import { Base } from './base';
        import service from './service';

        class Label extends WidgetType {
          eq(other: Label) {
            return other === this;
          }

          private unusedPrivate() {
            return 1;
          }
        }

        class Plain {
          eq(other: Plain) {
            return other === this;
          }

          describe() {
            return 'plain';
          }
        }

        class Local extends Base {
          matches(other: Local) {
            return other === this;
          }
        }

        export function check(remote: string) {
          const isNewer = service.isNewer(remote);
          const format = 'plain';
          return [isNewer, format, new Label(), new Plain().describe(), new Local().id()];
        }
        """,
    )
    _write(
        tmp_path,
        "src/base.ts",
        "export class Base {\n  id() {\n    return 1;\n  }\n}\n",
    )
    _write(
        tmp_path,
        "src/service.ts",
        """
        class Service {
          isNewer(remote: string): boolean {
            return remote > '1';
          }

          format(): string {
            return 'x';
          }
        }

        export default new Service();
        """,
    )

    functions = _unused(_scan(tmp_path), "unused_functions", tmp_path)

    assert ("src/index.ts", "Label.eq") not in functions
    assert ("src/index.ts", "Label.unusedPrivate") in functions
    assert ("src/index.ts", "Plain.eq") in functions
    assert ("src/index.ts", "Local.matches") in functions
    assert ("src/service.ts", "Service.isNewer") not in functions
    assert ("src/service.ts", "Service.format") in functions


def test_tool_convention_files_need_the_tool(tmp_path):
    _write(
        tmp_path,
        "with/package.json",
        '{"name": "with", "private": true, "main": "src/index.ts", '
        '"scripts": {"test": "karma start"}, '
        '"devDependencies": {"karma": "6.0.0", "@storybook/react": "6.4.0", '
        '"@wdio/cli": "8.0.0"}}',
    )
    _write(tmp_path, "with/src/index.ts", "export const value = 1;\n")
    _write(tmp_path, "with/karma.conf.ts", "module.exports = function () {};\n")
    _write(
        tmp_path,
        "with/wdio.conf.ts",
        "export const config = { runner: 'local' };\nexport const leftover = 1;\n",
    )
    _write(
        tmp_path,
        "with/.storybook/addons.js",
        "import '@storybook/addon-knobs/register';\n",
    )
    _write(tmp_path, "with/.storybook/leftover.js", "export const leftover = 1;\n")
    _write(
        tmp_path,
        "without/package.json",
        '{"name": "without", "private": true, "main": "src/index.ts"}',
    )
    _write(tmp_path, "without/src/index.ts", "export const value = 1;\n")
    _write(tmp_path, "without/karma.conf.js", "module.exports = function () {};\n")
    _write(tmp_path, "without/.storybook/config.js", "export const stale = 1;\n")

    result = _scan(tmp_path)
    files = _unused_files(result, tmp_path)
    variables = _unused(result, "unused_variables", tmp_path)

    assert "with/karma.conf.ts" not in files
    assert "with/wdio.conf.ts" not in files
    assert "with/.storybook/addons.js" not in files
    assert ("with/wdio.conf.ts", "config") not in variables
    assert ("with/wdio.conf.ts", "leftover") in variables
    assert {
        "with/.storybook/leftover.js",
        "without/karma.conf.js",
        "without/.storybook/config.js",
    } <= files


def test_configuration_that_names_a_file_loads_it(tmp_path):
    _write(
        tmp_path,
        "package.json",
        """
        {
          "name": "app",
          "private": true,
          "description": "see lib/described.ts",
          "main": ".webpack/main",
          "files": ["dist", "templates/run_tool.js", "templates/shipped/"],
          "host": {"extensions": ["./lib/plugin.ts"]},
          "eslintIgnore": ["lib/ignored.ts"]
        }
        """,
    )
    _write(
        tmp_path,
        "tsconfig.json",
        '{"include": ["lib/app.ts", "tools/tester.ts", "extra/**/*.ts"], '
        '"exclude": ["tools/excluded.ts"]}',
    )
    _write(
        tmp_path,
        "forge.config.ts",
        """
        // './lib/mentioned.ts' was the old renderer
        export default {
          packagerConfig: { extraResource: ['lib/resource.js'] },
          plugins: [{ renderer: { entryPoints: [{ js: './lib/renderer.ts' }] } }],
        };
        """,
    )
    _write(tmp_path, "webpack.config.ts", "export default { entry: './lib/app.ts' };\n")
    _write(
        tmp_path,
        "lib/app.ts",
        "import { menu } from './menu';\n\nmenu();\n"
        "export const stalePath = 'lib/stale.ts';\n",
    )
    _write(tmp_path, "lib/menu.ts", "export function menu() {}\n")
    _write(
        tmp_path,
        "lib/plugin.ts",
        "export default function plugin(api: { on(): void }) {\n  api.on();\n}\n",
    )
    for relative in (
        "lib/renderer.ts",
        "lib/resource.js",
        "lib/mentioned.ts",
        "lib/stale.ts",
        "lib/described.ts",
        "lib/ignored.ts",
        "tools/tester.ts",
        "tools/excluded.ts",
        "extra/glob_only.ts",
        "templates/run_tool.js",
        "templates/shipped/inner.js",
    ):
        _write(tmp_path, relative, "console.log('loaded');\n")

    result = _scan(tmp_path)
    files = _unused_files(result, tmp_path)

    assert not files & {
        "lib/app.ts",
        "lib/menu.ts",
        "lib/renderer.ts",
        "lib/resource.js",
        "lib/plugin.ts",
        "tools/tester.ts",
        "templates/run_tool.js",
    }
    assert {
        "lib/mentioned.ts",
        "lib/stale.ts",
        "lib/described.ts",
        "lib/ignored.ts",
        "tools/excluded.ts",
        "extra/glob_only.ts",
        "templates/shipped/inner.js",
    } <= files
    assert ("lib/plugin.ts", "plugin") not in _unused(
        result, "unused_functions", tmp_path
    )


def test_path_calls_commands_and_run_instructions_load_scripts(tmp_path):
    _write(
        tmp_path,
        "package.json",
        '{"name": "app", "private": true, "main": "src/index.ts", '
        '"scripts": {"gen": "node tasks/gen.js"}}',
    )
    _write(
        tmp_path,
        "README.md",
        """
        Run the evals:

        ```bash
        bun run src/evals/run.ts --sample 10
        ```

        The old tools/legacy.ts script was removed. See [the list](tools/linked.ts).

        ```
        cat tools/catted.ts
        ```
        """,
    )
    _write(
        tmp_path,
        "src/index.ts",
        """
        import { join } from 'node:path';

        export function register(hooksDir: string, outDir: string) {
          return {
            command: `node ${join(hooksDir, 'session-start.js')}`,
            report: join(outDir, 'report.js'),
            note: 'see archived-hook.js for history',
          };
        }
        """,
    )
    _write(
        tmp_path,
        "tasks/gen.js",
        """
        const path = require('path');
        const shared = require(path.join(__dirname, '..', 'lib', 'shared.js'));
        const input = path.join(__dirname, '..', 'tools', 'input.ts');
        const root = path.resolve(__dirname, '..');
        const entry = path.join(root, 'src/bundle.ts');
        // path.join(__dirname, '..', 'lib', 'commented.js')
        const label = ['lib', 'joined.js'].join('/');
        const fake = { join: (...parts) => parts.join('-') };
        shared.run(input, entry, label, fake.join(__dirname, '..', 'lib', 'fake.js'));
        """,
    )
    _write(tmp_path, "lib/shared.js", "module.exports = { run() {} };\n")
    _write(
        tmp_path,
        "hooks/session-start.js",
        "const { out } = require('./hook-utils.js');\n\nout();\n",
    )
    _write(tmp_path, "hooks/hook-utils.js", "module.exports = { out() {} };\n")
    for relative in (
        "src/evals/run.ts",
        "src/bundle.ts",
        "tools/input.ts",
        "tools/legacy.ts",
        "tools/linked.ts",
        "tools/catted.ts",
        "lib/commented.js",
        "lib/joined.js",
        "lib/fake.js",
        "hooks/archived-hook.js",
        "hooks/report.js",
    ):
        _write(tmp_path, relative, "console.log('script');\n")

    files = _unused_files(_scan(tmp_path), tmp_path)

    assert not files & {
        "src/evals/run.ts",
        "src/bundle.ts",
        "tools/input.ts",
        "lib/shared.js",
        "hooks/session-start.js",
        "hooks/hook-utils.js",
    }
    assert {
        "tools/legacy.ts",
        "tools/linked.ts",
        "tools/catted.ts",
        "lib/commented.js",
        "lib/joined.js",
        "lib/fake.js",
        "hooks/archived-hook.js",
        "hooks/report.js",
    } <= files


def test_platform_siblings_load_only_in_react_native_projects(tmp_path):
    _write(
        tmp_path,
        "native/package.json",
        '{"name": "native", "private": true, "main": "App.tsx", '
        '"dependencies": {"react-native": "0.74.0"}}',
    )
    _write(
        tmp_path,
        "native/App.tsx",
        """
        import { useScale } from './hooks/useScale';
        import { Button } from './ui/Button';

        export default function App() {
          return Button(useScale());
        }
        """,
    )
    _write(
        tmp_path,
        "plain/package.json",
        '{"name": "plain", "private": true, "main": "App.ts"}',
    )
    _write(
        tmp_path,
        "plain/App.ts",
        "import { useScale } from './hooks/useScale';\n\n"
        "export const value = useScale();\n",
    )
    for project in ("native", "plain"):
        for name in ("useScale.ts", "useScale.web.ts", "lonely.web.ts"):
            _write(
                tmp_path,
                f"{project}/hooks/{name}",
                "export function useScale(): number {\n  return 1;\n}\n",
            )
    for name in ("Button.ios.tsx", "Button.android.tsx"):
        _write(
            tmp_path,
            f"native/ui/{name}",
            "export function Button(scale: number) {\n  return scale;\n}\n",
        )

    result = _scan(tmp_path)
    files = _unused_files(result, tmp_path)

    assert not files & {
        "native/hooks/useScale.web.ts",
        "native/ui/Button.ios.tsx",
        "native/ui/Button.android.tsx",
    }
    assert {
        "native/hooks/lonely.web.ts",
        "plain/hooks/useScale.web.ts",
        "plain/hooks/lonely.web.ts",
    } <= files
    assert ("native/hooks/useScale.web.ts", "useScale") not in _unused(
        result, "unused_functions", tmp_path
    )


def test_default_export_reexported_by_name_from_the_entry_is_public(tmp_path):
    _write(
        tmp_path,
        "package.json",
        '{"name": "lib", "version": "1.0.0", "main": "lib/index.js", '
        '"types": "lib/index.d.ts"}',
    )
    _write(
        tmp_path,
        "src/index.ts",
        "export { default as useTimeout } from './useTimeout';\n"
        "export { default as useEnsured, ensuredForward } from './useEnsured';\n",
    )
    _write(
        tmp_path,
        "src/useTimeout.ts",
        """
        export default function useTimeout(ms: number = 0): number {
          return ms;
        }

        function unusedLocal(): number {
          return 2;
        }
        """,
    )
    _write(
        tmp_path,
        "src/useEnsured.ts",
        """
        export default function useEnsured<T>(ref: { current: T }): { current: T } {
          return ref;
        }

        export function ensuredForward<T>(component: T): T {
          useEnsured({ current: component });
          return component;
        }
        """,
    )

    result = _scan(tmp_path)
    functions = _unused(result, "unused_functions", tmp_path)

    assert ("src/useTimeout.ts", "useTimeout") not in functions
    assert ("src/useTimeout.ts", "unusedLocal") in functions
    assert not [
        item
        for item in result.get("unused_exports", [])
        if item["name"] == "useEnsured"
    ]


def test_source_reexport_does_not_read_the_local_import_binding(tmp_path):
    _write(
        tmp_path,
        "package.json",
        '{"name": "app", "private": true, "main": "src/index.ts"}',
    )
    _write(
        tmp_path,
        "src/index.ts",
        "import { tool, DESCRIPTION, LIMIT } from './tools';\n\n"
        "console.log(tool(), DESCRIPTION, LIMIT);\n",
    )
    _write(
        tmp_path,
        "src/tools.ts",
        """
        import { DESCRIPTION, LIMIT, helper } from './constants';

        export { DESCRIPTION } from './constants';
        export { LIMIT };

        export function tool() {
          return helper();
        }
        """,
    )
    _write(
        tmp_path,
        "src/constants.ts",
        """
        export const DESCRIPTION = 'd';
        export const LIMIT = 3;
        export function helper() {
          return 1;
        }
        """,
    )

    result = _scan(tmp_path)
    imports = _unused(result, "unused_imports", tmp_path)

    assert ("src/tools.ts", "DESCRIPTION") in imports
    assert ("src/tools.ts", "LIMIT") not in imports
    assert ("src/tools.ts", "helper") not in imports
    assert ("src/constants.ts", "DESCRIPTION") not in _unused(
        result, "unused_variables", tmp_path
    )
