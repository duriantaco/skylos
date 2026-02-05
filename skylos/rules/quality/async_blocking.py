import ast
from pathlib import Path
from skylos.rules.base import SkylosRule

RULE_ID = "SKY-Q401"

BLOCKING_CALLS = {
    "time.sleep": "Use 'await asyncio.sleep()' instead",
    "requests.get": "Use 'httpx' or 'aiohttp' instead",
    "requests.post": "Use 'httpx' or 'aiohttp' instead",
    "requests.put": "Use 'httpx' or 'aiohttp' instead",
    "requests.delete": "Use 'httpx' or 'aiohttp' instead",
    "requests.patch": "Use 'httpx' or 'aiohttp' instead",
    "requests.head": "Use 'httpx' or 'aiohttp' instead",
    "requests.request": "Use 'httpx' or 'aiohttp' instead",
    "urllib.request.urlopen": "Use 'httpx' or 'aiohttp' instead",
    "subprocess.run": "Use 'asyncio.create_subprocess_exec()' instead",
    "subprocess.call": "Use 'asyncio.create_subprocess_exec()' instead",
    "subprocess.check_output": "Use 'asyncio.create_subprocess_exec()' instead",
    "subprocess.check_call": "Use 'asyncio.create_subprocess_exec()' instead",
    "os.system": "Use 'asyncio.create_subprocess_exec()' instead",
}


class AsyncBlockingRule(SkylosRule):
    rule_id = RULE_ID
    name = "Async Blocking Calls"

    def __init__(self):
        self._import_aliases = {}
        self._async_ranges = []
        self._sync_ranges = []

    def visit_node(self, node, context):
        filename = context.get("filename", "")

        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    local_name = alias.asname
                else:
                    local_name = alias.name
                self._import_aliases[local_name] = alias.name
            return None

        if isinstance(node, ast.ImportFrom):
            if node.module:
                for alias in node.names:
                    if alias.asname:
                        local_name = alias.asname
                    else:
                        local_name = alias.name
                    full_name = f"{node.module}.{alias.name}"
                    self._import_aliases[local_name] = full_name
            return None

        if isinstance(node, ast.AsyncFunctionDef):
            start = node.lineno
            end = getattr(node, "end_lineno", None) or start
            self._async_ranges.append((start, end, node.name))
            return None

        if isinstance(node, (ast.FunctionDef, ast.Lambda)):
            start = node.lineno
            end = getattr(node, "end_lineno", None) or start
            self._sync_ranges.append((start, end))
            return None

        if not isinstance(node, ast.Call):
            return None

        async_func_name = self._get_async_context(node.lineno)
        if not async_func_name:
            return None

        call_name = self._resolve_call_name(node)
        if not call_name or call_name not in BLOCKING_CALLS:
            return None

        suggestion = BLOCKING_CALLS[call_name]

        return [
            {
                "rule_id": self.rule_id,
                "kind": "async",
                "severity": "HIGH",
                "type": "call",
                "name": call_name,
                "simple_name": call_name.split(".")[-1],
                "value": "blocking",
                "threshold": 0,
                "message": f"Blocking call '{call_name}' in async function '{async_func_name}'. {suggestion}",
                "file": filename,
                "basename": Path(filename).name,
                "line": node.lineno,
                "col": node.col_offset,
            }
        ]

    def _get_async_context(self, line):
        innermost_start = -1
        innermost = None

        for start, end, name in self._async_ranges:
            if start <= line <= end and start > innermost_start:
                innermost_start = start
                innermost = ("async", name)

        for start, end in self._sync_ranges:
            if start <= line <= end and start > innermost_start:
                innermost_start = start
                innermost = ("sync", None)

        if innermost and innermost[0] == "async":
            return innermost[1]
        return None

    def _resolve_call_name(self, node):
        func = node.func

        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name):
                module_name = func.value.id
                func_name = func.attr

                if module_name in self._import_aliases:
                    resolved_module = self._import_aliases[module_name]
                    return f"{resolved_module}.{func_name}"

                return f"{module_name}.{func_name}"

        elif isinstance(func, ast.Name):
            func_name = func.id

            if func_name in self._import_aliases:
                return self._import_aliases[func_name]

        return None
