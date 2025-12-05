import os
import re
from skylos.adapters import get_adapter


class Fixer:
    def __init__(self, api_key=None, model="gpt-4.1"):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.model = model

        try:
            self.adapter = get_adapter(model, self.api_key)
        except Exception as e:
            self.adapter = None
            self.init_error = str(e)

    def _add_line_numbers(self, source_code):
        lines = source_code.splitlines()
        numbered_lines = []
        for i, line in enumerate(lines, start=1):
            # format eg: "  10 | import os"
            numbered_lines.append(f"{i:4d} | {line}")
        return "\n".join(numbered_lines)

    def _get_relevant_context(self, source_code, defs_map):
        used_names = set(re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", source_code))
        relevant_tools = []

        for name, d in defs_map.items():
            if isinstance(d, dict):
                dname = d.get("name")
                dtype = d.get("type")
            else:
                dname = getattr(d, "name", name)
                dtype = getattr(d, "type", None)

            if dname in used_names:
                relevant_tools.append(f"- {dname} ({dtype})")

        if not relevant_tools:
            return "No internal dependencies detected."
        return "\n".join(relevant_tools[:100])

    def generate_prompt(self, source_code, error_line, error_msg, defs_map):
        lines = source_code.splitlines()
        start = max(0, error_line - 10)
        end = min(len(lines), error_line + 10)
        snippet = "\n".join(
            [f"{i + 1}: {line}" for i, line in enumerate(lines) if start <= i <= end]
        )

        tools_str = self._get_relevant_context(source_code, defs_map)

        prompt = f"""
You are an expert Python developer. Fix this specific error.

ERROR: Line {error_line}: {error_msg}
CODE:
```python
{snippet}

CONTEXT (These things exist): {tools_str}

OUTPUT FORMAT: ---PROBLEM--- (Summary) ---CHANGE--- (Summary) ---CODE--- (Fixed code block only) 
"""
        return prompt

    def audit_file(self, source_code, defs_map):
        if not self.adapter:
            return f"Error: {getattr(self, 'init_error', 'Adapter not initialized')}"

        tools_str = self._get_relevant_context(source_code, defs_map)
        numbered_code = self._add_line_numbers(source_code)

        prompt = f"""
You are Skylos AI, an advanced code auditor. Your job is to catch issues that the Static Analyzer (AST) might have missed. You are an INDEPENDENT pair of eyes.
SOURCE CODE (Line numbers provided on left):
```text
{numbered_code}
```

VERIFIED REPO CONTEXT (These functions/classes definitely exist): {tools_str}

INSTRUCTIONS - HUNT FOR THESE SPECIFIC FAILURES. THIS IS A CHALLENGE:

1. DEAD CODE: Are there imports, functions, or variables that look unused?

2. SECRETS:HARDCODED SECRETS (CRITICAL): Are there any hardcoded secrets (API keys, passwords, tokens):

    -> LOOK INSIDE arguments: os.getenv("VAR", "password123") is a LEAK. Flag "password123".
    -> LOOK INSIDE variables: key = "sk-..." is a LEAK.
    -> LOOK INSIDE comments: # pass: admin is a LEAK.

3. DANGEROUS CODE: Security risks (eval, sql injection, hardcoded secrets, shell=True).

4. VIBE CODING / HALLUCINATIONS: Is it calling a function that is NOT in the 'Verified Repo Context' and NOT a standard Python library?

5. QUALITY: Is the logic confusing? Are there bare exceptions? Infinite loops?

OUTPUT FORMAT: If the code is perfect, output: " No issues found." If you find issues, list them strictly like this:

[DEAD CODE] Line X: Description [SECURITY] Line X: Description [SECRETS] Line X: Description [HALLUCINATION] Line X: Description [QUALITY] Line X: Description 
"""

        instructions = "You are a strict code auditor."
        return self.adapter.complete(instructions, prompt)

    def fix_bug(self, source_code, error_line, error_msg, defs_map):
        if not self.adapter:
            return {
                "error": f"Error: {getattr(self, 'init_error', 'Adapter not initialized')}"
            }

        prompt = self.generate_prompt(source_code, error_line, error_msg, defs_map)
        instructions = "You are a strict code repair agent. Output only code."

        try:
            raw_text = self.adapter.complete(instructions, prompt)
            problem = "Issue detected"
            change = "Applied fix"
            code = raw_text

            if (
                "---PROBLEM---" in raw_text
                and "---CHANGE---" in raw_text
                and "---CODE---" in raw_text
            ):
                parts = raw_text.split("---CHANGE---")
                problem_part = parts[0].replace("---PROBLEM---", "").strip()
                rest = parts[1]
                code_parts = rest.split("---CODE---")
                change = code_parts[0].strip()
                code = code_parts[1].strip()
                problem = problem_part

            code = code.replace("```python", "").replace("```", "").strip()
            return {"code": code, "problem": problem, "change": change}

        except Exception as e:
            return {"error": f"Error calling OpenAI: {str(e)}"}
