import ast
from pathlib import Path

source = Path(__file__).with_name("models.py")


def load_model():
    tree = ast.parse(source.read_text())
    module = ast.Module(body=[tree.body[0]], type_ignores=[])
    namespace = {}
    exec(compile(module, str(source), "exec"), namespace)


def after_load(observer):
    observer()
