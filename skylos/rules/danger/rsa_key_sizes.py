"""Identify the RSA size operand in OpenSSL command arguments."""

import ast

_VECTOR_RUNNERS = {
    f"subprocess.{name}"
    for name in ("run", "Popen", "call", "check_call", "check_output")
}

_OPENSSL = {"openssl", "/usr/bin/openssl", "/usr/local/bin/openssl"}


def _text(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def openssl_size_operand(call, name):
    """Return genrsa's positional numbits operand for a direct, shell-free argv."""
    if name not in _VECTOR_RUNNERS and (
        len(call.args) < 3 or _text(call.args[0]) not in _OPENSSL
    ):
        return None
    kwargs = {kw.arg: kw.value for kw in call.keywords}
    if (
        None in kwargs
        or "executable" in kwargs
        or "shell" in kwargs
        and not (
            isinstance(kwargs["shell"], ast.Constant) and kwargs["shell"].value is False
        )
    ):
        return None
    if name in _VECTOR_RUNNERS:
        if len(call.args) > 1 or (call.args and "args" in kwargs):
            return None
        vector = call.args[0] if call.args else kwargs.get("args")
        if not isinstance(vector, (ast.List, ast.Tuple)):
            return None
        argv = vector.elts
    else:
        argv = call.args
    if len(argv) < 3 or any(isinstance(arg, ast.Starred) for arg in argv):
        return None
    if _text(argv[0]) not in _OPENSSL:
        return None
    if _text(argv[1]) != "genrsa":
        return None
    i = 2
    while i < len(argv) - 1:
        flag = _text(argv[i])
        if flag in {"-out", "-passout", "-rand", "-writerand"}:
            i += 2
        elif flag in {
            "-3",
            "-F4",
            "-f4",
            "-verbose",
            "-traditional",
            "-aes128",
            "-aes192",
            "-aes256",
            "-des3",
        }:
            i += 1
        else:
            return None
    return argv[i] if i == len(argv) - 1 else None
