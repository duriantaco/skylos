import ast
import re
from pathlib import Path


class CodeChunk:
    def __init__(
        self,
        content,
        start_line,
        end_line,
        chunk_type,
        name,
        imports,
        class_context,
        file_path,
    ):
        self.content = content
        self.start_line = start_line
        self.end_line = end_line
        self.chunk_type = chunk_type
        self.name = name
        self.imports = imports
        self.class_context = class_context
        self.file_path = file_path

    def get_full_context(self):
        parts = []
        if self.imports:
            parts.append(f"# Imports\n{self.imports}")
        if self.class_context:
            parts.append(f"# Class context\n{self.class_context}")
        parts.append(
            f"# {self.chunk_type.title()}: {self.name} (lines {self.start_line}-{self.end_line})"
        )
        parts.append(self.content)
        return "\n\n".join(parts)

    def with_line_numbers(self):
        lines = self.content.splitlines()
        numbered = []
        for i, line in enumerate(lines, self.start_line):
            numbered.append(f"{i:4d} | {line}")
        return "\n".join(numbered)


class ASTChunker:
    def __init__(
        self,
        max_chunk_tokens=2000,
        overlap_lines=5,
        include_imports=True,
        include_class_context=True,
    ):
        self.max_chunk_chars = max_chunk_tokens * 4
        self.overlap_lines = overlap_lines
        self.include_imports = include_imports
        self.include_class_context = include_class_context

    def chunk_file(self, source, file_path=""):
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return self._fallback_chunk(source, file_path)

        lines = source.splitlines()
        imports = self._extract_imports(tree, lines)
        chunks = []

        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                chunk = self._create_function_chunk(node, lines, imports, file_path)
                chunks.append(chunk)

            elif isinstance(node, ast.ClassDef):
                class_chunk = self._create_class_chunk(node, lines, imports, file_path)

                class_size = len(class_chunk.content)
                if class_size <= self.max_chunk_chars:
                    chunks.append(class_chunk)
                else:
                    class_context = self._get_class_header(node, lines)
                    for item in node.body:
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            method_chunk = self._create_method_chunk(
                                item,
                                lines,
                                imports,
                                file_path,
                                class_name=node.name,
                                class_context=class_context,
                            )
                            chunks.append(method_chunk)

        if not chunks:
            chunks.append(
                CodeChunk(
                    content=source,
                    start_line=1,
                    end_line=len(lines),
                    chunk_type="module",
                    name=Path(file_path).stem if file_path else "module",
                    imports=imports,
                    class_context=None,
                    file_path=file_path,
                )
            )

        chunks = self._split_large_chunks(chunks)

        return chunks

    def _extract_imports(self, tree, lines):
        import_lines = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                start = node.lineno - 1
                end = getattr(node, "end_lineno", node.lineno)
                import_lines.extend(lines[start:end])
        return "\n".join(import_lines)

    def _create_function_chunk(self, node, lines, imports, file_path):
        start = node.lineno - 1
        end = getattr(node, "end_lineno", node.lineno + 10)

        if node.decorator_list:
            start = min(d.lineno - 1 for d in node.decorator_list)

        content = "\n".join(lines[start:end])

        return CodeChunk(
            content=content,
            start_line=start + 1,
            end_line=end,
            chunk_type="function",
            name=node.name,
            imports=imports if self.include_imports else "",
            class_context=None,
            file_path=file_path,
        )

    def _create_class_chunk(self, node, lines, imports, file_path):
        start = node.lineno - 1
        end = getattr(node, "end_lineno", node.lineno + 20)

        if node.decorator_list:
            start = min(d.lineno - 1 for d in node.decorator_list)

        content = "\n".join(lines[start:end])

        return CodeChunk(
            content=content,
            start_line=start + 1,
            end_line=end,
            chunk_type="class",
            name=node.name,
            imports=imports if self.include_imports else "",
            class_context=None,
            file_path=file_path,
        )

    def _create_method_chunk(
        self, node, lines, imports, file_path, class_name, class_context
    ):
        start = node.lineno - 1
        end = getattr(node, "end_lineno", node.lineno + 10)

        if node.decorator_list:
            start = min(d.lineno - 1 for d in node.decorator_list)

        content = "\n".join(lines[start:end])

        name = class_name + "." + node.name

        imports_out = ""
        if self.include_imports:
            imports_out = imports

        class_ctx_out = None
        if self.include_class_context:
            class_ctx_out = class_context

        return CodeChunk(
            content=content,
            start_line=start + 1,
            end_line=end,
            chunk_type="method",
            name=name,
            imports=imports_out,
            class_context=class_ctx_out,
            file_path=file_path,
        )

    def _get_class_header(self, node, lines):
        start = node.lineno - 1

        if node.decorator_list:
            start = min(d.lineno - 1 for d in node.decorator_list)

        header_end = node.lineno
        for item in node.body:
            if isinstance(item, ast.Expr) and isinstance(item.value, ast.Constant):
                header_end = getattr(item, "end_lineno", item.lineno)
            else:
                break

        return "\n".join(lines[start:header_end])

    def _split_large_chunks(self, chunks):
        result = []
        for chunk in chunks:
            if len(chunk.content) <= self.max_chunk_chars:
                result.append(chunk)
            else:
                sub_chunks = self._split_by_blocks(chunk)
                result.extend(sub_chunks)
        return result

    def _split_by_blocks(self, chunk):
        lines = chunk.content.splitlines()
        chunk_lines = self.max_chunk_chars // 60

        sub_chunks = []
        i = 0
        while i < len(lines):
            end = min(i + chunk_lines, len(lines))

            if end < len(lines):
                for j in range(end, max(i + chunk_lines // 2, i), -1):
                    if not lines[j].strip() or lines[j].strip().startswith(
                        ("#", "def ", "class ")
                    ):
                        end = j
                        break

            sub_content = "\n".join(lines[i:end])
            sub_chunks.append(
                CodeChunk(
                    content=sub_content,
                    start_line=chunk.start_line + i,
                    end_line=chunk.start_line + end - 1,
                    chunk_type=f"{chunk.chunk_type}_part",
                    name=f"{chunk.name}_part{len(sub_chunks) + 1}",
                    imports=chunk.imports,
                    class_context=chunk.class_context,
                    file_path=chunk.file_path,
                )
            )

            i = end - self.overlap_lines
            if i <= 0 or end >= len(lines):
                break

        if sub_chunks:
            return sub_chunks
        return [chunk]

    def _fallback_chunk(self, source, file_path):
        lines = source.splitlines()
        chunk_lines = self.max_chunk_chars // 60

        import_re = re.compile(r"^(?:from\s+\S+\s+)?import\s+.+$")

        imports_list = []
        for line in lines[:50]:
            if import_re.match(line.strip()):
                imports_list.append(line)

        imports = "\n".join(imports_list)

        chunks = []
        i = 0
        while i < len(lines):
            end = min(i + chunk_lines, len(lines))
            content = "\n".join(lines[i:end])

            chunks.append(
                CodeChunk(
                    content=content,
                    start_line=i + 1,
                    end_line=end,
                    chunk_type="block",
                    name=f"block_{len(chunks) + 1}",
                    imports=imports,
                    class_context=None,
                    file_path=file_path,
                )
            )

            i = end - self.overlap_lines
            if i <= 0:
                break

        return (
            chunks
            if chunks
            else [
                CodeChunk(
                    content=source,
                    start_line=1,
                    end_line=len(lines),
                    chunk_type="module",
                    name="module",
                    imports=imports,
                    class_context=None,
                    file_path=file_path,
                )
            ]
        )


class ContextBuilder:
    def __init__(self, max_context_tokens=8000):
        self.max_context_tokens = max_context_tokens
        self.chunker = ASTChunker(max_chunk_tokens=max_context_tokens // 2)

    def chunk_file(self, source, file_path=""):
        return self.chunker.chunk_file(source, file_path)

    def build_analysis_context(
        self, source_or_chunk, file_path=None, defs_map=None, include_imports=True
    ):
        if isinstance(source_or_chunk, CodeChunk):
            return self._build_chunk_context(source_or_chunk, defs_map)

        source = source_or_chunk
        file_path = file_path or ""

        lines = source.splitlines()

        name = "module"
        if file_path:
            name = Path(file_path).stem

        imports = ""
        if include_imports:
            imports = self._extract_imports_str(source)

        chunk = CodeChunk(
            content=source,
            start_line=1,
            end_line=len(lines),
            chunk_type="module",
            name=name,
            imports=imports,
            class_context=None,
            file_path=file_path,
        )
        return self._build_chunk_context(chunk, defs_map)

    def _extract_imports_str(self, source):
        try:
            tree = ast.parse(source)
            lines = source.splitlines()
            import_lines = []
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    start = node.lineno - 1
                    end = getattr(node, "end_lineno", node.lineno)
                    import_lines.extend(lines[start:end])
            return "\n".join(import_lines)
        except:
            return ""

    def _build_chunk_context(self, chunk, defs_map=None):
        parts = []

        parts.append(f"=== FILE: {chunk.file_path} ===")
        parts.append(
            f"Analyzing: {chunk.chunk_type} '{chunk.name}' (lines {chunk.start_line}-{chunk.end_line})"
        )

        if chunk.imports:
            parts.append(f"\n[IMPORTS]\n{chunk.imports}")

        if chunk.class_context:
            parts.append(f"\n[CLASS CONTEXT]\n{chunk.class_context}")

        if defs_map:
            deps = self._find_dependencies(chunk.content, defs_map, chunk.file_path)
            if deps:
                parts.append(f"\n[EXTERNAL DEPENDENCIES]\n{deps}")

        parts.append(f"\n[CODE]\n{chunk.with_line_numbers()}")

        return "\n".join(parts)

    def build_fix_context(
        self, source, file_path, issue_line, issue_message, defs_map=None
    ):
        lines = source.splitlines()

        chunks = self.chunker.chunk_file(source, file_path)
        target_chunk = None
        for chunk in chunks:
            if chunk.start_line <= issue_line <= chunk.end_line:
                target_chunk = chunk
                break

        if target_chunk:
            context = self.build_analysis_context(target_chunk, defs_map)
        else:
            start = max(0, issue_line - 20)
            end = min(len(lines), issue_line + 20)

            numbered = []
            for i in range(start + 1, end + 1):
                num = str(i).rjust(4)
                numbered.append(num + " | " + lines[i - 1])

            context = "[CODE]\n" + "\n".join(numbered)

        return f"=== FIX CONTEXT ===\n[ISSUE] Line {issue_line}: {issue_message}\n\n{context}"

    def _find_dependencies(self, content, defs_map, current_file):
        used_names = set(re.findall(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b", content))

        deps = []
        for name, info in defs_map.items():
            if isinstance(info, dict):
                def_name = info.get("name", name)
                def_type = info.get("type", "unknown")
                def_file = str(info.get("file", ""))
            else:
                def_name = getattr(info, "name", name)
                def_type = getattr(info, "type", "unknown")
                def_file = str(getattr(info, "filename", ""))

            if def_name in used_names and def_file:
                source = (
                    "this file" if def_file == current_file else Path(def_file).name
                )
                deps.append(f"  - {def_name} ({def_type}) from {source}")

        return "\n".join(deps[:50])

    def _build_project_index(self, defs_map, max_items=150):
        if not defs_map:
            return ""

        index = []
        for name, info in defs_map.items():
            if isinstance(info, dict):
                def_name = info.get("name", name)
                def_type = info.get("type", "unknown")
                def_file = str(info.get("file", ""))
            else:
                def_name = getattr(info, "name", name)
                def_type = getattr(info, "type", "unknown")
                def_file = str(getattr(info, "filename", ""))

            short_file = Path(def_file).name if def_file else "?"
            index.append(f"  - {def_name} ({def_type}) [{short_file}]")

        if len(index) > max_items:
            index = index[:max_items]
            index.append(f"  ... and {len(defs_map) - max_items} more")

        return "\n".join(index)


class FewShotExamples:
    SECURITY = """
[EXAMPLE 1: SQL Injection]
Code:
  42 | query = f"SELECT * FROM users WHERE id = {user_id}"
  43 | cursor.execute(query)

Finding:
{"line": 42, "severity": "critical", "type": "security",
 "message": "SQL injection: user input in query string",
 "fix": "Use parameterized query: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"}

[EXAMPLE 2: Hardcoded Secret]
Code:
  15 | API_KEY = "sk-live-abc123secret"

Finding:
{"line": 15, "severity": "critical", "type": "security",
 "message": "Hardcoded API key exposed",
 "fix": "Use environment variable: os.getenv('API_KEY')"}
"""

    DEAD_CODE = """
[EXAMPLE 1: Unused Import]
Code:
   5 | import json  # never used in file

Finding:
{"line": 5, "severity": "low", "type": "dead_code",
 "message": "Unused import: json",
 "confidence": "high"}

[EXAMPLE 2: Unused Function]
Code:
  20 | def old_helper(x):  # no calls anywhere
  21 |     return x * 2

Finding:
{"line": 20, "severity": "medium", "type": "dead_code",
 "message": "Unused function: old_helper",
 "confidence": "medium"}
"""

    QUALITY = """
[EXAMPLE 1: Deep Nesting]
Code:
  10 | def process(data):
  11 |     if data:
  12 |         if data.valid:
  13 |             if data.type == 'A':
  14 |                 if data.status:  # 4 levels deep

Finding:
{"line": 10, "severity": "medium", "type": "quality",
 "message": "Excessive nesting (4 levels)",
 "fix": "Use early returns or extract helper functions"}

[EXAMPLE 2: Silent Exception]
Code:
  30 | try:
  31 |     risky_operation()
  32 | except:
  33 |     pass

Finding:
{"line": 32, "severity": "high", "type": "quality",
 "message": "Bare except swallows all errors silently",
 "fix": "Catch specific exceptions, log or handle appropriately"}
"""

    @classmethod
    def get(cls, types):
        examples = []
        if "security" in types:
            examples.append(cls.SECURITY)
        if "dead_code" in types:
            examples.append(cls.DEAD_CODE)
        if "quality" in types:
            examples.append(cls.QUALITY)
        return "\n".join(examples) if examples else cls.SECURITY + cls.QUALITY
