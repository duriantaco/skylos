from skylos.visitors.languages.typescript import scan_typescript_file


def _scan(tmp_path, filename, code):
    p = tmp_path / filename
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


def test_default_export_via_identifier(tmp_path):
    code = """\
import React from "react";
function MyPage() { return <div/>; }
export default MyPage;
"""
    defs, fw = _scan(tmp_path, "page.tsx", code)
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
export default function Page() { return <div/>; }
"""
    defs, fw = _scan(tmp_path, "page.tsx", code)
    names = _decorated_names(defs, fw)
    assert "dynamic" in names
    assert "revalidate" in names


def test_metadata_export(tmp_path):
    code = """\
import type { Metadata } from "next";
export const metadata: Metadata = { title: "App" };
export default function Layout({ children }) { return <html>{children}</html>; }
"""
    defs, fw = _scan(tmp_path, "layout.tsx", code)
    assert "metadata" in _decorated_names(defs, fw)


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


def test_non_convention_file_with_next_import(tmp_path):
    code = """\
import { useRouter } from "next/navigation";
export function helperFn() { return 42; }
export function getServerSideProps() { return {}; }
"""
    defs, fw = _scan(tmp_path, "helpers.ts", code)
    # getServerSideProps should still be marked because "next" is detected
    assert "getServerSideProps" in _decorated_names(defs, fw)
    # helperFn should NOT be marked
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
