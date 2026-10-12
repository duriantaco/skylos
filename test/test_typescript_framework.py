import pytest

from skylos.visitors.languages.typescript import scan_typescript_file


def _scan(tmp_path, filename, code):
    p = tmp_path / filename
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(code, encoding="utf-8")
    result = scan_typescript_file(str(p))
    defs = result[0]
    fw = result[5]  # framework_flags slot
    return defs, fw


def _decorated_names(defs, fw):
    return {d.name for d in defs if d.line in fw.framework_decorated_lines}


def test_page_default_export_function(tmp_path):
    code = 'import React from "react";\nexport default function Page() { return <div/>; }\n'
    defs, fw = _scan(tmp_path, "page.tsx", code)
    assert "Page" in _decorated_names(defs, fw)


def test_layout_default_export(tmp_path):
    code = 'import React from "react";\nexport default function RootLayout({ children }) { return <html>{children}</html>; }\n'
    defs, fw = _scan(tmp_path, "layout.tsx", code)
    assert "RootLayout" in _decorated_names(defs, fw)


def test_loading_default_export(tmp_path):
    code = 'import React from "react";\nexport default function Loading() { return <p>Loading...</p>; }\n'
    defs, fw = _scan(tmp_path, "loading.tsx", code)
    assert "Loading" in _decorated_names(defs, fw)


def test_error_default_export(tmp_path):
    code = """\
"use client";
export default function ErrorPage({ error }) { return <p>{error.message}</p>; }
"""
    defs, fw = _scan(tmp_path, "error.tsx", code)
    assert "ErrorPage" in _decorated_names(defs, fw)


def test_not_found_default_export(tmp_path):
    code = "export default function NotFound() { return <h1>404</h1>; }\n"
    defs, fw = _scan(tmp_path, "not-found.tsx", code)
    assert "NotFound" in _decorated_names(defs, fw)


def test_template_default_export(tmp_path):
    code = (
        "export default function Template({ children }) { return <>{children}</>; }\n"
    )
    defs, fw = _scan(tmp_path, "template.tsx", code)
    assert "Template" in _decorated_names(defs, fw)


def test_pages_router_default_export_without_next_import(tmp_path):
    code = "export default function HomePage() { return <main>home</main>; }\n"
    defs, fw = _scan(tmp_path, "pages/index.tsx", code)
    assert "HomePage" in _decorated_names(defs, fw)


def test_pages_router_js_default_export_without_next_import(tmp_path):
    code = "export default function HomePage() { return <main>home</main>; }\n"
    defs, fw = _scan(tmp_path, "pages/index.js", code)
    assert "HomePage" in _decorated_names(defs, fw)


def test_pages_api_default_export_without_next_import(tmp_path):
    code = "export default function handler(req, res) { res.status(200).json({ ok: true }); }\n"
    defs, fw = _scan(tmp_path, "pages/api/users.ts", code)
    assert "handler" in _decorated_names(defs, fw)


def test_pages_api_js_default_export_without_next_import(tmp_path):
    code = "export default function handler(req, res) { res.status(200).json({ ok: true }); }\n"
    defs, fw = _scan(tmp_path, "pages/api/users.js", code)
    assert "handler" in _decorated_names(defs, fw)


def test_default_export_via_identifier(tmp_path):
    code = """\
import React from "react";
function MyPage() { return <div/>; }
export default MyPage;
"""
    defs, fw = _scan(tmp_path, "page.tsx", code)
    assert "MyPage" in _decorated_names(defs, fw)


def test_page_jsx_default_export_identifier(tmp_path):
    code = """\
function MyPage() { return <div/>; }
export default MyPage;
"""
    defs, fw = _scan(tmp_path, "page.jsx", code)
    assert "MyPage" in _decorated_names(defs, fw)


def test_route_handler_get_post(tmp_path):
    code = """\
import { NextResponse } from "next/server";
export async function GET(request) { return NextResponse.json({}); }
export async function POST(request) { return NextResponse.json({}); }
"""
    defs, fw = _scan(tmp_path, "route.ts", code)
    names = _decorated_names(defs, fw)
    assert "GET" in names
    assert "POST" in names


def test_route_handler_arrow(tmp_path):
    code = """\
import { NextResponse } from "next/server";
export const DELETE = async (req) => { return NextResponse.json({}); };
"""
    defs, fw = _scan(tmp_path, "route.ts", code)
    assert "DELETE" in _decorated_names(defs, fw)


def test_middleware_exports(tmp_path):
    code = """\
import { NextResponse } from "next/server";
export function middleware(request) { return NextResponse.next(); }
export const config = { matcher: ["/api/:path*"] };
"""
    defs, fw = _scan(tmp_path, "middleware.ts", code)
    names = _decorated_names(defs, fw)
    assert "middleware" in names
    assert "config" in names


def test_instrumentation_exports(tmp_path):
    code = """\
export async function register() { /* init */ }
export function onRequestError(error) { console.error(error); }
"""
    defs, fw = _scan(tmp_path, "instrumentation.ts", code)
    names = _decorated_names(defs, fw)
    assert "register" in names
    assert "onRequestError" in names


def test_proxy_exports_without_next_import(tmp_path):
    code = """\
export function proxy(request) { return Response.redirect(new URL("/", request.url)); }
export const config = { matcher: ["/((?!api|_next/static).*)"] };
"""
    defs, fw = _scan(tmp_path, "proxy.ts", code)
    names = _decorated_names(defs, fw)
    assert "proxy" in names
    assert "config" in names


def test_route_segment_exports_without_next_import(tmp_path):
    code = """\
export const runtime = "edge";
export const maxDuration = 30;
export async function GET() { return Response.json({ ok: true }); }
"""
    defs, fw = _scan(tmp_path, "route.ts", code)
    names = _decorated_names(defs, fw)
    assert "runtime" in names
    assert "maxDuration" in names
    assert "GET" in names


def test_global_not_found_metadata_without_next_import(tmp_path):
    code = """\
export const metadata = { title: "Missing" };
export default function GlobalNotFound() {
    return <html><body>Not found</body></html>;
}
"""
    defs, fw = _scan(tmp_path, "global-not-found.tsx", code)
    names = _decorated_names(defs, fw)
    assert "metadata" in names
    assert "GlobalNotFound" in names


def test_pages_router_data_exports_without_next_import(tmp_path):
    code = """\
export async function getServerSideProps() {
    return { props: {} };
}
export default function Page() { return <div/>; }
"""
    defs, fw = _scan(tmp_path, "pages/index.tsx", code)
    names = _decorated_names(defs, fw)
    assert "getServerSideProps" in names
    assert "Page" in names


def test_getServerSideProps(tmp_path):
    code = """\
import React from "react";
import { GetServerSideProps } from "next";
export const getServerSideProps: GetServerSideProps = async (ctx) => {
    return { props: {} };
};
export default function Page({ data }) { return <div/>; }
"""
    defs, fw = _scan(tmp_path, "page.tsx", code)
    names = _decorated_names(defs, fw)
    assert "getServerSideProps" in names
    assert "Page" in names


def test_generateMetadata(tmp_path):
    code = """\
import type { Metadata } from "next";
export async function generateMetadata(): Promise<Metadata> { return { title: "Home" }; }
export default function Page() { return <div/>; }
"""
    defs, fw = _scan(tmp_path, "page.tsx", code)
    names = _decorated_names(defs, fw)
    assert "generateMetadata" in names


def test_generateStaticParams(tmp_path):
    code = """\
import { db } from "next";
export async function generateStaticParams() { return [{ id: "1" }]; }
export default function Page({ params }) { return <div/>; }
"""
    defs, fw = _scan(tmp_path, "page.tsx", code)
    assert "generateStaticParams" in _decorated_names(defs, fw)


def test_route_segment_config(tmp_path):
    code = """\
import React from "next";
export const dynamic = "force-dynamic";
export const revalidate = 60;
export const experimental_ppr = true;
export default function Page() { return <div/>; }
"""
    defs, fw = _scan(tmp_path, "page.tsx", code)
    names = _decorated_names(defs, fw)
    assert "dynamic" in names
    assert "revalidate" in names
    assert "experimental_ppr" in names


def test_metadata_export(tmp_path):
    code = """\
import type { Metadata } from "next";
export const metadata: Metadata = { title: "App" };
export default function Layout({ children }) { return <html>{children}</html>; }
"""
    defs, fw = _scan(tmp_path, "layout.tsx", code)
    assert "metadata" in _decorated_names(defs, fw)


def test_viewport_export_without_next_import(tmp_path):
    code = """\
export const viewport = { themeColor: "black" };
export default function Layout({ children }) { return <html>{children}</html>; }
"""
    defs, fw = _scan(tmp_path, "layout.tsx", code)
    names = _decorated_names(defs, fw)
    assert "viewport" in names
    assert "Layout" in names


def test_generateViewport_without_next_import(tmp_path):
    code = """\
export function generateViewport() { return { themeColor: "black" }; }
export default function Layout({ children }) { return <html>{children}</html>; }
"""
    defs, fw = _scan(tmp_path, "layout.tsx", code)
    names = _decorated_names(defs, fw)
    assert "generateViewport" in names
    assert "Layout" in names


def test_react_memo(tmp_path):
    code = """\
import React, { memo } from "react";
function Inner() { return <div/>; }
export const Memoized = memo(Inner);
"""
    defs, fw = _scan(tmp_path, "component.tsx", code)
    assert "Memoized" in _decorated_names(defs, fw)


def test_react_memo_dot(tmp_path):
    code = """\
import React from "react";
function Inner() { return <div/>; }
export const Memoized = React.memo(Inner);
"""
    defs, fw = _scan(tmp_path, "component.tsx", code)
    assert "Memoized" in _decorated_names(defs, fw)


def test_forwardRef(tmp_path):
    code = """\
import React, { forwardRef } from "react";
export const MyInput = forwardRef((props, ref) => { return <input ref={ref}/>; });
"""
    defs, fw = _scan(tmp_path, "component.tsx", code)
    assert "MyInput" in _decorated_names(defs, fw)


def test_exported_custom_hook_function(tmp_path):
    code = """\
import { useState } from "react";
export function useCounter() { const [c, setC] = useState(0); return c; }
"""
    defs, fw = _scan(tmp_path, "hooks.ts", code)
    assert "useCounter" in _decorated_names(defs, fw)


def test_exported_custom_hook_arrow(tmp_path):
    code = """\
import { useEffect } from "react";
export const useMyEffect = () => { useEffect(() => {}, []); };
"""
    defs, fw = _scan(tmp_path, "hooks.ts", code)
    assert "useMyEffect" in _decorated_names(defs, fw)


def test_non_exported_hook_not_marked(tmp_path):
    code = """\
import { useState } from "react";
function useInternal() { return useState(0); }
export function usePublic() { return useInternal(); }
"""
    defs, fw = _scan(tmp_path, "hooks.ts", code)
    names = _decorated_names(defs, fw)
    assert "usePublic" in names
    assert "useInternal" not in names


def test_plain_ts_file_no_framework(tmp_path):
    code = """\
export function helperFn() { return 42; }
export const config = { key: "value" };
"""
    defs, fw = _scan(tmp_path, "utils.ts", code)
    assert len(fw.framework_decorated_lines) == 0
    assert len(fw.detected_frameworks) == 0


def test_vscode_pseudoterminal_contract_callbacks(tmp_path):
    code = """\
import * as vscode from "vscode";

class BuildTerminal implements vscode.Pseudoterminal {
    open(dimensions: vscode.TerminalDimensions | undefined): void {}
    close(): void {}
    staleHelper(): void {}
}
"""
    defs, fw = _scan(tmp_path, "terminal.ts", code)
    names = _decorated_names(defs, fw)

    assert "BuildTerminal.open" in names
    assert "BuildTerminal.close" in names
    assert "BuildTerminal.staleHelper" not in names


def test_vscode_pseudoterminal_contract_import_bindings(tmp_path):
    cases = [
        (
            'import type { Pseudoterminal } from "vscode";',
            "Pseudoterminal",
        ),
        (
            'import type { Pseudoterminal as TerminalContract } from "vscode";',
            "TerminalContract",
        ),
        (
            'import type * as editorApi from "vscode";',
            "editorApi.Pseudoterminal",
        ),
        (
            'import editorApi from "vscode";',
            "editorApi.Pseudoterminal",
        ),
        (
            'import editorApi = require("vscode");',
            "editorApi.Pseudoterminal",
        ),
    ]

    for index, (import_statement, contract_name) in enumerate(cases):
        code = f"""\
{import_statement}

class BuildTerminal implements {contract_name} {{
    open(): void {{}}
    close(): void {{}}
    staleHelper(): void {{}}
}}
"""
        defs, fw = _scan(tmp_path, f"terminal-{index}.ts", code)
        names = _decorated_names(defs, fw)

        assert "BuildTerminal.open" in names
        assert "BuildTerminal.close" in names
        assert "BuildTerminal.staleHelper" not in names


def test_vscode_provider_contract_callbacks(tmp_path):
    contracts = {
        "CodeLensProvider": {"provideCodeLenses", "resolveCodeLens"},
        "DocumentLinkProvider": {"provideDocumentLinks", "resolveDocumentLink"},
        "FileSystemProvider": {
            "copy",
            "createDirectory",
            "delete",
            "readDirectory",
            "readFile",
            "rename",
            "stat",
            "watch",
            "writeFile",
        },
        "TaskProvider": {"provideTasks", "resolveTask"},
        "TextDocumentContentProvider": {"provideTextDocumentContent"},
        "TreeDataProvider": {
            "getChildren",
            "getParent",
            "getTreeItem",
            "resolveTreeItem",
        },
        "TreeDragAndDropController": {"handleDrag", "handleDrop"},
    }

    for index, (contract_name, callback_names) in enumerate(contracts.items()):
        methods = "\n".join(
            f"    {callback_name}(): void {{}}" for callback_name in callback_names
        )
        code = f"""\
import type {{ {contract_name} }} from "vscode";

class Provider implements {contract_name} {{
{methods}
    staleHelper(): void {{}}
}}
"""
        defs, fw = _scan(tmp_path, f"provider-{index}.ts", code)
        names = _decorated_names(defs, fw)

        assert {f"Provider.{name}" for name in callback_names} <= names
        assert "Provider.staleHelper" not in names


def test_plain_open_and_close_methods_are_not_framework_callbacks(tmp_path):
    code = """\
import * as vscode from "vscode";

interface Pseudoterminal {}

class FileHandle implements Pseudoterminal {
    open(): void {}
    close(): void {}
}
"""
    defs, fw = _scan(tmp_path, "file-handle.ts", code)

    assert _decorated_names(defs, fw) == set()


def test_non_convention_file_with_next_import(tmp_path):
    code = """\
import { useRouter } from "next/navigation";
export function helperFn() { return 42; }
export function getServerSideProps() { return {}; }
"""
    defs, fw = _scan(tmp_path, "helpers.ts", code)
    assert "getServerSideProps" in _decorated_names(defs, fw)
    assert "helperFn" not in _decorated_names(defs, fw)


def test_framework_detection_next(tmp_path):
    code = 'import Link from "next/link";\nexport default function Page() { return <div/>; }\n'
    _, fw = _scan(tmp_path, "page.tsx", code)
    assert "next" in fw.detected_frameworks


def test_framework_detection_react(tmp_path):
    code = 'import React from "react";\nfunction App() { return <div/>; }\n'
    _, fw = _scan(tmp_path, "app.tsx", code)
    assert "react" in fw.detected_frameworks


def test_no_framework_plain_ts(tmp_path):
    code = "export function add(a: number, b: number) { return a + b; }\n"
    _, fw = _scan(tmp_path, "math.ts", code)
    assert len(fw.detected_frameworks) == 0


STORY_CODE = """\
import type {Meta, StoryObj} from "@storybook/react";
import {Calendar} from "./index";

const meta: Meta<typeof Calendar> = {component: Calendar};
export default meta;
type Story = StoryObj<typeof Calendar>;

export const WeeksInMonth: Story = {
  render: (args) => <Calendar {...args} />,
};

export function Disabled() {
  return <Calendar isDisabled />;
}

const helper = 1;
"""


def test_storybook_csf_exports_are_framework_used(tmp_path):
    # agent-pr-bench real-33: Storybook imports every named story export.
    defs, fw = _scan(tmp_path, "calendar.stories.tsx", STORY_CODE)
    names = _decorated_names(defs, fw)
    assert {"WeeksInMonth", "Disabled"} <= names
    assert "helper" not in names


def test_same_exports_outside_story_file_are_not_marked(tmp_path):
    defs, fw = _scan(tmp_path, "calendar.tsx", STORY_CODE)
    assert "WeeksInMonth" not in _decorated_names(defs, fw)


# Next.js metadata routes, project-gated conventions and tool config files.
# vercel/commerce reported app/robots.ts, app/sitemap.ts and every
# opengraph-image.tsx as dead at 100% confidence.

NEXT_PACKAGE_JSON = '{"dependencies": {"next": "15.0.0", "react": "19.0.0"}}'


def _next_project(tmp_path):
    (tmp_path / "package.json").write_text(NEXT_PACKAGE_JSON, encoding="utf-8")  # skylos: ignore[SKY-D324] pytest tmp_path fixture
    return tmp_path


METADATA_ROUTE_CASES = [
    ("app/robots.ts", "export default function robots() { return {}; }\n", "robots"),
    (
        "app/sitemap.ts",
        "export default async function sitemap() { return []; }\n",
        "sitemap",
    ),
    (
        "app/manifest.ts",
        "export default function manifest() { return {}; }\n",
        "manifest",
    ),
    ("app/icon.tsx", "export default function Icon() { return null; }\n", "Icon"),
    (
        "src/app/icon2.tsx",
        "export default function Icon2() { return null; }\n",
        "Icon2",
    ),
    (
        "app/apple-icon.tsx",
        "export default function AppleIcon() { return null; }\n",
        "AppleIcon",
    ),
    (
        "app/shop/[slug]/opengraph-image.tsx",
        "export default async function Image() { return null; }\n",
        "Image",
    ),
    (
        "app/twitter-image.jsx",
        "const TwitterImage = () => null;\nexport default TwitterImage;\n",
        "TwitterImage",
    ),
]


@pytest.mark.parametrize(("relative", "code", "name"), METADATA_ROUTE_CASES)
def test_nextjs_metadata_route_default_export_is_framework_root(
    tmp_path, relative, code, name
):
    defs, fw = _scan(_next_project(tmp_path), relative, code)
    assert name in _decorated_names(defs, fw)


@pytest.mark.parametrize(("relative", "code", "name"), METADATA_ROUTE_CASES)
def test_metadata_route_names_outside_nextjs_project_are_not_marked(
    tmp_path, relative, code, name
):
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"react": "19.0.0"}}', encoding="utf-8"
    )
    defs, fw = _scan(tmp_path, relative, code)
    assert name not in _decorated_names(defs, fw)


def test_nextjs_metadata_route_outside_app_dir_is_not_marked(tmp_path):
    defs, fw = _scan(
        _next_project(tmp_path),
        "lib/robots.ts",
        "export default function robots() { return {}; }\n",
    )
    assert "robots" not in _decorated_names(defs, fw)


def test_nextjs_metadata_image_named_exports_are_framework_roots(tmp_path):
    code = """\
export const alt = "Shop";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";
export const runtime = "edge";
export function generateImageMetadata() { return [{ id: "a" }]; }
export function unusedImageHelper() { return 1; }
export default async function Image() { return null; }
"""
    defs, fw = _scan(_next_project(tmp_path), "app/opengraph-image.tsx", code)
    names = _decorated_names(defs, fw)
    assert {
        "alt",
        "size",
        "contentType",
        "runtime",
        "generateImageMetadata",
        "Image",
    } <= names
    assert "unusedImageHelper" not in names


def test_nextjs_sitemap_and_robots_keep_only_their_own_exports(tmp_path):
    project = _next_project(tmp_path)
    sitemap_defs, sitemap_fw = _scan(
        project,
        "app/sitemap.ts",
        "export async function generateSitemaps() { return [{ id: 0 }]; }\n"
        "export const alt = 'not an image';\n"
        "export default async function sitemap() { return []; }\n",
    )
    sitemap_names = _decorated_names(sitemap_defs, sitemap_fw)
    assert {"generateSitemaps", "sitemap"} <= sitemap_names
    assert "alt" not in sitemap_names

    robots_defs, robots_fw = _scan(
        project,
        "app/robots.ts",
        "export function generateSitemaps() { return []; }\n"
        "export default function robots() { return {}; }\n",
    )
    robots_names = _decorated_names(robots_defs, robots_fw)
    assert "robots" in robots_names
    assert "generateSitemaps" not in robots_names


def test_nextjs_page_keeps_convention_exports_but_not_helpers(tmp_path):
    code = """\
export async function generateStaticParams() { return []; }
export const revalidate = 60;
export function unusedPageHelper() { return 1; }
export default function BlogPage() { return null; }
"""
    defs, fw = _scan(_next_project(tmp_path), "app/blog/[slug]/page.tsx", code)
    names = _decorated_names(defs, fw)
    assert {"generateStaticParams", "revalidate", "BlogPage"} <= names
    assert "unusedPageHelper" not in names


def test_nextjs_detected_from_next_config_without_package_dependency(tmp_path):
    (tmp_path / "next.config.mjs").write_text("export default {};\n", encoding="utf-8")
    defs, fw = _scan(
        tmp_path, "app/robots.js", "export default function robots() { return {}; }\n"
    )
    assert "robots" in _decorated_names(defs, fw)


def test_nextjs_monorepo_app_uses_its_own_project_root(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"devDependencies": {"next": "15.0.0"}}', encoding="utf-8"
    )
    web = tmp_path / "apps" / "web"
    web.mkdir(parents=True)
    (web / "package.json").write_text(NEXT_PACKAGE_JSON, encoding="utf-8")
    defs, fw = _scan(
        tmp_path,
        "apps/web/app/robots.ts",
        "export default function robots() { return {}; }\n",
    )
    assert "robots" in _decorated_names(defs, fw)

    # Relative to the only Next.js root, a package's own app/ dir is not the
    # App Router, so its icon.tsx is ordinary code.
    defs, fw = _scan(
        tmp_path,
        "packages/ui/app/icon.tsx",
        "export default function Icon() { return null; }\n",
    )
    assert "Icon" not in _decorated_names(defs, fw)


def test_nextjs_pages_router_config_and_get_initial_props(tmp_path):
    project = _next_project(tmp_path)
    api_defs, api_fw = _scan(
        project,
        "pages/api/upload.ts",
        "export const config = { api: { bodyParser: false } };\n"
        "export default function handler(req, res) { res.end(); }\n",
    )
    assert {"config", "handler"} <= _decorated_names(api_defs, api_fw)

    app_defs, app_fw = _scan(
        project,
        "pages/_app.tsx",
        "export function reportWebVitals(metric) { console.log(metric); }\n"
        "export async function getInitialProps() { return {}; }\n"
        "export default function MyApp() { return null; }\n",
    )
    assert {"reportWebVitals", "getInitialProps", "MyApp"} <= _decorated_names(
        app_defs, app_fw
    )


def test_pages_config_export_outside_nextjs_project_is_not_marked(tmp_path):
    defs, fw = _scan(
        tmp_path,
        "pages/api/upload.ts",
        "export const config = { api: { bodyParser: false } };\n",
    )
    assert "config" not in _decorated_names(defs, fw)


def test_nextjs_root_files_keep_their_hook_exports(tmp_path):
    project = _next_project(tmp_path)
    mdx_defs, mdx_fw = _scan(
        project,
        "mdx-components.tsx",
        "export function useMDXComponents(components) { return components; }\n",
    )
    assert "useMDXComponents" in _decorated_names(mdx_defs, mdx_fw)

    client_defs, client_fw = _scan(
        project,
        "src/instrumentation-client.ts",
        "export function onRouterTransitionStart(url) { console.log(url); }\n",
    )
    assert "onRouterTransitionStart" in _decorated_names(client_defs, client_fw)


@pytest.mark.parametrize(
    "filename",
    ["next.config.mjs", "next.config.ts", "postcss.config.mjs", "vite.config.ts"],
)
def test_tool_config_default_export_identifier_is_framework_root(tmp_path, filename):
    # create-next-app writes `const nextConfig = {...}; export default nextConfig;`
    defs, fw = _scan(
        tmp_path, filename, "const config = { a: 1 };\nexport default config;\n"
    )
    assert "config" in _decorated_names(defs, fw)


def test_default_export_identifier_in_ordinary_file_is_not_framework_root(tmp_path):
    defs, fw = _scan(
        tmp_path,
        "lib/settings.ts",
        "const config = { a: 1 };\nexport default config;\n",
    )
    assert "config" not in _decorated_names(defs, fw)
