#!/usr/bin/env python3
import pytest
import ast
from unittest.mock import Mock, patch

from skylos.visitors.framework_aware import (
    FrameworkAwareVisitor,
    detect_framework_usage,
    FRAMEWORK_DECORATORS,
    FRAMEWORK_FUNCTIONS,
    FRAMEWORK_IMPORTS,
)


class TestFrameworkAwareVisitor:
    def test_init_default(self):
        v = FrameworkAwareVisitor()
        assert v.is_framework_file is False
        assert v.framework_decorated_lines == set()
        assert v.detected_frameworks == set()

    def test_flask_import_detection(self):
        code = """
import flask
from flask import Flask, request
"""
        tree = ast.parse(code)
        v = FrameworkAwareVisitor()
        v.visit(tree)
        v.finalize()
        assert v.is_framework_file is True
        assert "flask" in v.detected_frameworks

    def test_fastapi_import_detection(self):
        code = """
from fastapi import FastAPI
import fastapi
"""
        tree = ast.parse(code)
        v = FrameworkAwareVisitor()
        v.visit(tree)
        v.finalize()
        assert v.is_framework_file is True
        assert "fastapi" in v.detected_frameworks

    def test_django_import_detection(self):
        code = """
from django.http import HttpResponse
from django.views import View
"""
        tree = ast.parse(code)
        v = FrameworkAwareVisitor()
        v.visit(tree)
        v.finalize()
        assert v.is_framework_file is True
        assert "django" in v.detected_frameworks

    def test_flask_route_decorator_detection(self):
        code = """
@app.route('/api/users')
def get_users():
    return []

@app.post('/api/users')
def create_user():
    return {}
"""
        tree = ast.parse(code)
        v = FrameworkAwareVisitor()
        v.visit(tree)
        v.finalize()
        assert v.is_framework_file is True
        assert 3 in v.framework_decorated_lines
        assert 7 in v.framework_decorated_lines

    def test_fastapi_router_decorator_detection(self):
        code = """
@router.get('/items')
async def read_items():
    return []

@router.post('/items')
async def create_item():
    return {}
"""
        tree = ast.parse(code)
        v = FrameworkAwareVisitor()
        v.visit(tree)
        v.finalize()
        assert v.is_framework_file is True
        assert 3 in v.framework_decorated_lines
        assert 7 in v.framework_decorated_lines

    def test_django_decorator_detection(self):
        code = """
@login_required
def protected_view(request):
    return HttpResponse("Protected")

@permission_required('auth.add_user')
def admin_view(request):
    return HttpResponse("Admin")
"""
        tree = ast.parse(code)
        v = FrameworkAwareVisitor()
        v.visit(tree)
        v.finalize()
        assert v.is_framework_file is True
        assert 3 in v.framework_decorated_lines
        assert 7 in v.framework_decorated_lines

    def test_django_view_class_detection(self):
        code = """
from django import views

class UserView(View):
    def get(self, request):
        return HttpResponse("GET")

class UserViewSet(ViewSet):
    def list(self, request):
        return Response([])
"""
        tree = ast.parse(code)
        v = FrameworkAwareVisitor()
        v.visit(tree)
        v.finalize()
        assert v.is_framework_file is True
        assert 5 in v.framework_decorated_lines
        assert 9 in v.framework_decorated_lines

    def test_framework_functions_not_detected_in_non_framework_file(self):
        code = """
def save(self):
    pass

def get(self):
    pass
"""
        tree = ast.parse(code)
        v = FrameworkAwareVisitor()
        v.visit(tree)
        v.finalize()
        assert v.is_framework_file is False
        assert v.framework_decorated_lines == set()

    def test_multiple_decorators(self):
        code = """
@app.route('/users')
@login_required
@cache.cached(timeout=60)
def get_users():
    return []
"""
        tree = ast.parse(code)
        v = FrameworkAwareVisitor()
        v.visit(tree)
        v.finalize()
        assert v.is_framework_file is True
        assert 5 in v.framework_decorated_lines

    def test_complex_decorator_patterns(self):
        code = """
@app.route('/api/v1/users/<int:user_id>', methods=['GET', 'POST'])
def user_endpoint(user_id):
    return {}

@router.get('/items/{item_id}')
async def get_item(item_id: int):
    return {}
"""
        tree = ast.parse(code)
        v = FrameworkAwareVisitor()
        v.visit(tree)
        v.finalize()
        assert v.is_framework_file is True
        assert 3 in v.framework_decorated_lines
        assert 7 in v.framework_decorated_lines

    def test_flask_add_url_rule_marks_view_func(self):
        code = """
from flask import Flask
app = Flask(__name__)

def list_users():
    return []

app.add_url_rule("/users", view_func=list_users)
"""
        tree = ast.parse(code)
        v = FrameworkAwareVisitor()
        v.visit(tree)
        v.finalize()
        assert v.is_framework_file is True
        assert 5 in v.framework_decorated_lines

    def test_flask_add_url_rule_marks_method_view(self):
        code = """
from flask import Flask
from flask.views import MethodView
app = Flask(__name__)

class UserView(MethodView):
    def get(self):
        return []

app.add_url_rule("/users", view_func=UserView.as_view("users"))
"""
        tree = ast.parse(code)
        v = FrameworkAwareVisitor()
        v.visit(tree)
        v.finalize()
        assert v.is_framework_file is True
        assert 6 in v.framework_decorated_lines
        assert 7 in v.framework_decorated_lines

    def test_fastapi_add_api_route_marks_endpoint(self):
        code = """
from fastapi import FastAPI
app = FastAPI()

async def read_items():
    return []

app.add_api_route("/items", read_items, methods=["GET"])
"""
        tree = ast.parse(code)
        v = FrameworkAwareVisitor()
        v.visit(tree)
        v.finalize()
        assert v.is_framework_file is True
        assert 5 in v.framework_decorated_lines

    def test_starlette_add_route_marks_endpoint(self):
        code = """
from starlette.applications import Starlette
app = Starlette()

async def homepage(request):
    return None

app.add_route("/", endpoint=homepage, methods=["GET"])
"""
        tree = ast.parse(code)
        v = FrameworkAwareVisitor()
        v.visit(tree)
        v.finalize()
        assert v.is_framework_file is True
        assert 5 in v.framework_decorated_lines

    def test_starlette_add_websocket_route_marks_endpoint(self):
        code = """
from starlette.applications import Starlette
app = Starlette()

async def ws_endpoint(websocket):
    return None

app.add_websocket_route("/ws", endpoint=ws_endpoint)
"""
        tree = ast.parse(code)
        v = FrameworkAwareVisitor()
        v.visit(tree)
        v.finalize()
        assert v.is_framework_file is True
        assert 5 in v.framework_decorated_lines

    def test_sanic_register_listener_marks_callback(self):
        code = """
from sanic import Sanic
app = Sanic("demo")

async def setup_db(app, loop):
    return None

app.register_listener(setup_db, "before_server_start")
"""
        tree = ast.parse(code)
        v = FrameworkAwareVisitor()
        v.visit(tree)
        v.finalize()
        assert v.is_framework_file is True
        assert 5 in v.framework_decorated_lines

    def test_sanic_register_middleware_marks_callback(self):
        code = """
from sanic import Sanic
app = Sanic("demo")

async def auth_middleware(request):
    return None

app.register_middleware(auth_middleware, "request")
"""
        tree = ast.parse(code)
        v = FrameworkAwareVisitor()
        v.visit(tree)
        v.finalize()
        assert v.is_framework_file is True
        assert 5 in v.framework_decorated_lines

    def test_sqlalchemy_listens_for_curried_marks_callback(self):
        code = """
from sqlalchemy import event

class Engine:
    pass

def on_connect(dbapi_connection, connection_record):
    return None

event.listens_for(Engine, "connect")(on_connect)
"""
        tree = ast.parse(code)
        v = FrameworkAwareVisitor()
        v.visit(tree)
        v.finalize()
        assert v.is_framework_file is True
        assert 7 in v.framework_decorated_lines

    def test_pytest_hookimpl_marks_plugin_hook(self):
        code = """
import pytest

class Plugin:
    @pytest.hookimpl(optionalhook=True)
    def pytest_testnodedown(self, node, error):
        return None
"""
        tree = ast.parse(code)
        v = FrameworkAwareVisitor()
        v.visit(tree)
        v.finalize()
        assert v.is_framework_file is True
        assert 6 in v.framework_decorated_lines

    def test_direct_hookimpl_marks_plugin_hook(self):
        code = """
from pluggy import hookimpl

class Plugin:
    @hookimpl
    def pytest_addoption(self, parser):
        return None
"""
        tree = ast.parse(code)
        v = FrameworkAwareVisitor()
        v.visit(tree)
        v.finalize()
        assert v.is_framework_file is True
        assert 6 in v.framework_decorated_lines

    def test_pytest_import_marks_pytest_framework(self):
        code = """
import pytest

class Plugin:
    def pytest_sessionfinish(self, session, exitstatus):
        return None
"""
        tree = ast.parse(code)
        v = FrameworkAwareVisitor()
        v.visit(tree)
        v.finalize()
        assert v.is_framework_file is True
        assert "pytest" in v.detected_frameworks

    def test_pluggy_import_marks_pluggy_framework(self):
        code = """
import pluggy

class Plugin:
    def pytest_addoption(self, parser):
        return None
"""
        tree = ast.parse(code)
        v = FrameworkAwareVisitor()
        v.visit(tree)
        v.finalize()
        assert v.is_framework_file is True
        assert "pluggy" in v.detected_frameworks

    @patch("skylos.visitors.framework_aware.Path")
    def test_file_content_framework_detection(self, mock_path):
        mock_file = Mock()
        mock_file.read_text.return_value = (
            "from flask import Flask\napp = Flask(__name__)"
        )
        mock_path.return_value = mock_file
        v = FrameworkAwareVisitor(filename="test.py")
        v.finalize()
        assert v.is_framework_file is True
        assert "flask" in v.detected_frameworks

    @patch("skylos.visitors.framework_aware.Path")
    def test_file_content_framework_detection_ignores_strings(self, mock_path):
        mock_file = Mock()
        mock_file.read_text.return_value = (
            'pattern = r"(?:from django|import django|from flask|import fastapi)"'
        )
        mock_path.return_value = mock_file
        v = FrameworkAwareVisitor(filename="test.py")
        v.finalize()
        assert v.is_framework_file is False
        assert v.detected_frameworks == set()

    def test_normalize_decorator_name(self):
        v = FrameworkAwareVisitor()
        node = ast.parse("@decorator\ndef func(): pass").body[0].decorator_list[0]
        assert v._normalize_decorator(node) == "@decorator"
        node = ast.parse("@app.route\ndef func(): pass").body[0].decorator_list[0]
        assert v._normalize_decorator(node) == "@app.route"

    def test_depends_marks_dependency_and_flags_framework_file(self):
        code = """
from fastapi import Depends

def dep():
    return 1

@router.get("/")
def foo(x: int = Depends(dep)):
    return {}
"""
        tree = ast.parse(code)
        v = FrameworkAwareVisitor()
        v.visit(tree)
        v.finalize()
        assert v.is_framework_file is True
        assert 4 in v.framework_decorated_lines

    def test_fastapi_annotated_depends_marks_dependency(self):
        code = """
from typing import Annotated
from fastapi import Depends, FastAPI

app = FastAPI()

def common_parameters():
    return {}

@app.get("/items/")
def read_items(commons: Annotated[dict, Depends(common_parameters)]):
    return commons
"""
        tree = ast.parse(code)
        v = FrameworkAwareVisitor()
        v.visit(tree)
        v.finalize()
        assert v.is_framework_file is True
        assert v.func_defs["common_parameters"] in v.framework_decorated_lines

    def test_fastapi_dependency_kwargs_mark_dependencies(self):
        code = """
from fastapi import APIRouter, Depends, FastAPI

def global_dep():
    return None

def router_dep():
    return None

def include_dep():
    return None

def route_dep():
    return None

app = FastAPI(dependencies=[Depends(global_dep)])
router = APIRouter(dependencies=[Depends(router_dep)])
app.include_router(router, dependencies=[Depends(include_dep)])

@router.get("/items/", dependencies=[Depends(route_dep)])
def read_items():
    return []
"""
        tree = ast.parse(code)
        v = FrameworkAwareVisitor()
        v.visit(tree)
        v.finalize()
        assert v.is_framework_file is True
        for name in ("global_dep", "router_dep", "include_dep", "route_dep"):
            assert v.func_defs[name] in v.framework_decorated_lines

    def test_fastapi_dependency_alias_marks_only_when_used(self):
        code = """
from typing import Annotated
from fastapi import Depends, FastAPI

app = FastAPI()

def used_dep():
    return None

def unused_dep():
    return None

UsedDep = Annotated[dict, Depends(used_dep)]
UnusedDep = Annotated[dict, Depends(unused_dep)]

@app.get("/items/")
def read_items(commons: UsedDep):
    return commons
"""
        tree = ast.parse(code)
        v = FrameworkAwareVisitor()
        v.visit(tree)
        v.finalize()
        assert v.func_defs["used_dep"] in v.framework_decorated_lines
        assert v.func_defs["unused_dep"] not in v.framework_decorated_lines

    def test_fastapi_dependency_alias_from_annassign_marks_only_when_used(self):
        code = """
from typing import Annotated, TypeAlias
from fastapi import Depends, FastAPI

app = FastAPI()

def used_dep():
    return None

def unused_dep():
    return None

UsedDep: TypeAlias = Annotated[dict, Depends(used_dep)]
UnusedDep: TypeAlias = Annotated[dict, Depends(unused_dep)]

@app.get("/items/")
def read_items(commons: UsedDep):
    return commons
"""
        tree = ast.parse(code)
        v = FrameworkAwareVisitor()
        v.visit(tree)
        v.finalize()
        assert v.func_defs["used_dep"] in v.framework_decorated_lines
        assert v.func_defs["unused_dep"] not in v.framework_decorated_lines

    def test_fastapi_dependency_import_aliases_mark_dependencies(self):
        code = """
from typing_extensions import Annotated as A
from fastapi import APIRouter as Router, Depends as Dep, FastAPI as App, Security as Sec

app = App()
router = Router()

def app_dep():
    return None

def router_dep():
    return None

def security_dep():
    return None

def keyword_dep():
    return None

app = App(dependencies=[Dep(app_dep)])
router = Router(dependencies=[Dep(router_dep)])

@router.get("/items/")
def read_items(
    auth: A[dict, Sec(security_dep)],
    item: A[dict, Dep(dependency=keyword_dep)],
):
    return item
"""
        tree = ast.parse(code)
        v = FrameworkAwareVisitor()
        v.visit(tree)
        v.finalize()
        for name in ("app_dep", "router_dep", "security_dep", "keyword_dep"):
            assert v.func_defs[name] in v.framework_decorated_lines

    def test_fastapi_class_dependency_shortcut_marks_class(self):
        code = """
from typing import Annotated
from fastapi import Depends, FastAPI

app = FastAPI()

class CommonQueryParams:
    def __init__(self):
        pass

@app.get("/items/")
def read_items(commons: Annotated[CommonQueryParams, Depends()]):
    return commons
"""
        tree = ast.parse(code)
        v = FrameworkAwareVisitor()
        v.visit(tree)
        v.finalize()
        assert (
            v.class_defs["CommonQueryParams"].lineno in v.framework_decorated_lines
        )

    def test_fastapi_lifespan_and_constructor_callbacks_mark_handlers(self):
        code = """
from contextlib import asynccontextmanager
from fastapi import FastAPI

@asynccontextmanager
async def lifespan(app):
    yield

def startup():
    return None

def shutdown():
    return None

def handle_error(request, exc):
    return None

app = FastAPI(
    lifespan=lifespan,
    on_startup=[startup],
    on_shutdown=[shutdown],
    exception_handlers={Exception: handle_error},
)
"""
        tree = ast.parse(code)
        v = FrameworkAwareVisitor()
        v.visit(tree)
        v.finalize()
        for name in ("lifespan", "startup", "shutdown", "handle_error"):
            assert v.func_defs[name] in v.framework_decorated_lines

    def test_fastapi_imperative_websocket_and_exception_handlers_mark_callbacks(self):
        code = """
from fastapi import FastAPI

app = FastAPI()

async def websocket_endpoint(websocket):
    pass

async def unicorn_exception_handler(request, exc):
    pass

app.add_api_websocket_route("/ws", websocket_endpoint)
app.add_exception_handler(Exception, unicorn_exception_handler)
"""
        tree = ast.parse(code)
        v = FrameworkAwareVisitor()
        v.visit(tree)
        v.finalize()
        assert v.func_defs["websocket_endpoint"] in v.framework_decorated_lines
        assert v.func_defs["unicorn_exception_handler"] in v.framework_decorated_lines

    def test_typed_model_in_route_marks_model_definition(self):
        code = """
from pydantic import BaseModel

class In(BaseModel):
    x: int

@router.post("/")
def calc(req: In):
    return 1
"""
        tree = ast.parse(code)
        v = FrameworkAwareVisitor()
        v.visit(tree)
        v.finalize()
        assert v.is_framework_file is True
        assert 4 in v.framework_decorated_lines


class TestDetectFrameworkUsage:
    def test_decorated_endpoint_confidence_is_zero(self):
        d = Mock()
        d.line = 10
        d.simple_name = "get_users"
        d.type = "function"
        v = FrameworkAwareVisitor()
        v.framework_decorated_lines = {10}
        v.is_framework_file = True
        assert detect_framework_usage(d, visitor=v) == 0

    def test_undecorated_function_in_framework_file_returns_none(self):
        d = Mock()
        d.line = 15
        d.simple_name = "helper_function"
        d.type = "function"
        v = Mock()
        v.framework_decorated_lines = set()
        v.is_framework_file = True
        assert detect_framework_usage(d, visitor=v) is None

    def test_private_function_in_framework_file_returns_none(self):
        d = Mock()
        d.line = 20
        d.simple_name = "_private_function"
        d.type = "function"
        v = Mock()
        v.framework_decorated_lines = set()
        v.is_framework_file = True
        assert detect_framework_usage(d, visitor=v) is None

    def test_non_framework_file_returns_none(self):
        d = Mock()
        d.line = 25
        d.simple_name = "regular_function"
        d.type = "function"
        v = Mock()
        v.framework_decorated_lines = set()
        v.is_framework_file = False
        assert detect_framework_usage(d, visitor=v) is None

    def test_no_visitor_returns_none(self):
        d = Mock()
        assert detect_framework_usage(d, visitor=None) is None

    def test_non_function_in_framework_file_returns_none(self):
        d = Mock()
        d.line = 30
        d.simple_name = "my_variable"
        d.type = "variable"
        v = Mock()
        v.framework_decorated_lines = set()
        v.is_framework_file = True
        assert detect_framework_usage(d, visitor=v) is None


class TestFrameworkPatterns:
    def test_framework_decorators_list(self):
        assert "@*.route" in FRAMEWORK_DECORATORS
        assert "@*.get" in FRAMEWORK_DECORATORS
        assert "@login_required" in FRAMEWORK_DECORATORS

    def test_framework_functions_list(self):
        assert "get" in FRAMEWORK_FUNCTIONS
        assert "post" in FRAMEWORK_FUNCTIONS
        assert "*_queryset" in FRAMEWORK_FUNCTIONS
        assert "get_context_data" in FRAMEWORK_FUNCTIONS

    def test_framework_imports_set(self):
        assert "flask" in FRAMEWORK_IMPORTS
        assert "django" in FRAMEWORK_IMPORTS
        assert "fastapi" in FRAMEWORK_IMPORTS
        assert "pydantic" in FRAMEWORK_IMPORTS


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
