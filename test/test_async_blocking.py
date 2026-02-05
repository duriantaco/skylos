import ast
from skylos.rules.quality.async_blocking import AsyncBlockingRule


def get_findings(code):
    tree = ast.parse(code)
    rule = AsyncBlockingRule()
    context = {"filename": "test.py"}
    findings = []
    for node in ast.walk(tree):
        result = rule.visit_node(node, context)
        if result:
            findings.extend(result)
    return findings


class TestAsyncBlockingRule:
    def test_time_sleep_in_async(self):
        code = """
import time
async def foo():
    time.sleep(1)
"""
        findings = get_findings(code)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-Q401"
        assert findings[0]["name"] == "time.sleep"

    def test_from_import_sleep(self):
        code = """
from time import sleep
async def foo():
    sleep(1)
"""
        findings = get_findings(code)
        assert len(findings) == 1
        assert findings[0]["name"] == "time.sleep"

    def test_requests_get_in_async(self):
        code = """
import requests
async def foo():
    requests.get("http://example.com")
"""
        findings = get_findings(code)
        assert len(findings) == 1
        assert findings[0]["name"] == "requests.get"

    def test_requests_aliased(self):
        code = """
import requests as r
async def foo():
    r.get("http://example.com")
"""
        findings = get_findings(code)
        assert len(findings) == 1
        assert findings[0]["name"] == "requests.get"

    def test_subprocess_run_in_async(self):
        code = """
import subprocess
async def foo():
    subprocess.run(["ls"])
"""
        findings = get_findings(code)
        assert len(findings) == 1
        assert findings[0]["name"] == "subprocess.run"

    def test_os_system_in_async(self):
        code = """
import os
async def foo():
    os.system("ls")
"""
        findings = get_findings(code)
        assert len(findings) == 1
        assert findings[0]["name"] == "os.system"

    def test_multiple_blocking_calls(self):
        code = """
import time
import requests
async def foo():
    time.sleep(1)
    requests.get("http://example.com")
    time.sleep(2)
"""
        findings = get_findings(code)
        assert len(findings) == 3

    def test_nested_async_function(self):
        code = """
import time
async def outer():
    async def inner():
        time.sleep(1)
    await inner()
"""
        findings = get_findings(code)
        assert len(findings) == 1

    def test_async_class_method(self):
        code = """
import time
class MyService:
    async def fetch(self):
        time.sleep(1)
"""
        findings = get_findings(code)
        assert len(findings) == 1

    # === SHOULD NOT FLAG ===

    def test_sync_function_ok(self):
        code = """
import time
def foo():
    time.sleep(1)
"""
        findings = get_findings(code)
        assert len(findings) == 0

    def test_sync_inner_function_ok(self):
        code = """
import time
async def outer():
    def inner():
        time.sleep(1)
    inner()
"""
        findings = get_findings(code)
        assert len(findings) == 0

    def test_lambda_inside_async_ok(self):
        code = """
import time
async def foo():
    f = lambda: time.sleep(1)
    f()
"""
        findings = get_findings(code)
        assert len(findings) == 0

    def test_asyncio_sleep_ok(self):
        code = """
import asyncio
async def foo():
    await asyncio.sleep(1)
"""
        findings = get_findings(code)
        assert len(findings) == 0

    def test_httpx_ok(self):
        code = """
import httpx
async def foo():
    async with httpx.AsyncClient() as client:
        await client.get("http://example.com")
"""
        findings = get_findings(code)
        assert len(findings) == 0

    def test_sync_class_method_ok(self):
        code = """
import time
class MyService:
    def fetch(self):
        time.sleep(1)
"""
        findings = get_findings(code)
        assert len(findings) == 0