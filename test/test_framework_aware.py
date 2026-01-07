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
    def test_decorated_endpoint_confidence_is_one(self):
        d = Mock()
        d.line = 10
        d.simple_name = "get_users"
        d.type = "function"
        v = Mock()
        v.framework_decorated_lines = {10}
        v.is_framework_file = True
        assert detect_framework_usage(d, visitor=v) == 1

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
