#!/usr/bin/env python3
import pytest
import ast
from pathlib import Path
from unittest.mock import Mock, patch
import fnmatch

try:
    from skylos.framework_aware import (
        FrameworkAwareVisitor, 
        detect_framework_usage,
        FRAMEWORK_DECORATORS,
        FRAMEWORK_FUNCTIONS,
        FRAMEWORK_IMPORTS
    )
except ImportError:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from skylos.framework_aware import (
        FrameworkAwareVisitor, 
        detect_framework_usage,
        FRAMEWORK_DECORATORS,
        FRAMEWORK_FUNCTIONS,
        FRAMEWORK_IMPORTS
    )

class TestFrameworkAwareVisitor:
    
    def test_init_default(self):
        """Test default initialization"""
        visitor = FrameworkAwareVisitor()
        assert visitor.is_framework_file == False
        assert visitor.framework_decorated_lines == set()
        assert visitor.detected_frameworks == set()
    
    def test_flask_import_detection(self):
        """Test Flask import detection"""
        code = """
import flask
from flask import Flask, request
"""
        tree = ast.parse(code)
        visitor = FrameworkAwareVisitor()
        visitor.visit(tree)
        
        assert visitor.is_framework_file == True
        assert 'flask' in visitor.detected_frameworks
    
    def test_fastapi_import_detection(self):
        """Test FastAPI import detection"""
        code = """
from fastapi import FastAPI
import fastapi
"""
        tree = ast.parse(code)
        visitor = FrameworkAwareVisitor()
        visitor.visit(tree)
        
        assert visitor.is_framework_file == True
        assert 'fastapi' in visitor.detected_frameworks
    
    def test_django_import_detection(self):
        """Test Django import detection"""
        code = """
from django.http import HttpResponse
from django.views import View
"""
        tree = ast.parse(code)
        visitor = FrameworkAwareVisitor()
        visitor.visit(tree)
        
        assert visitor.is_framework_file == True
        assert 'django' in visitor.detected_frameworks
    
    def test_flask_route_decorator_detection(self):
        """Test Flask route decorator detection"""
        code = """
@app.route('/api/users')
def get_users():
    return []

@app.post('/api/users')
def create_user():
    return {}
"""
        tree = ast.parse(code)
        visitor = FrameworkAwareVisitor()
        visitor.visit(tree)
        
        assert visitor.is_framework_file == True
        assert 3 in visitor.framework_decorated_lines  # get_users function
        assert 7 in visitor.framework_decorated_lines  # create_user function
    
    def test_fastapi_router_decorator_detection(self):
        """Test FastAPI router decorator detection"""
        code = """
@router.get('/items')
async def read_items():
    return []

@router.post('/items')
async def create_item():
    return {}
"""
        tree = ast.parse(code)
        visitor = FrameworkAwareVisitor()
        visitor.visit(tree)
        
        assert visitor.is_framework_file == True
        assert 3 in visitor.framework_decorated_lines
        assert 7 in visitor.framework_decorated_lines
    
    def test_django_decorator_detection(self):
        """Test Django decorator detection"""
        code = """
@login_required
def protected_view(request):
    return HttpResponse("Protected")

@permission_required('auth.add_user')
def admin_view(request):
    return HttpResponse("Admin")
"""
        tree = ast.parse(code)
        visitor = FrameworkAwareVisitor()
        visitor.visit(tree)
        
        assert visitor.is_framework_file == True
        assert 3 in visitor.framework_decorated_lines
        assert 7 in visitor.framework_decorated_lines
    
    def test_celery_task_decorator_detection(self):
        """Test Celery task decorator detection"""
        code = """
@task
def background_task():
    return "done"

@shared_task
def shared_background_task():
    return "shared done"
"""
        tree = ast.parse(code)
        visitor = FrameworkAwareVisitor()
        visitor.visit(tree)
        
        assert visitor.is_framework_file == True
        assert 3 in visitor.framework_decorated_lines
        assert 7 in visitor.framework_decorated_lines
    
    def test_django_view_class_detection(self):
        """Test Django view class detection"""
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
        visitor = FrameworkAwareVisitor()
        visitor.visit(tree)
        
        assert visitor.is_framework_file == True
        assert 4 in visitor.framework_decorated_lines
        assert 8 in visitor.framework_decorated_lines
    
    def test_django_model_methods_in_framework_file(self):
        code = """
from django.db import models

class User(models.Model):
    name = models.CharField(max_length=100)
    
    def save(self, *args, **kwargs):
        # custom save logic
        super().save(*args, **kwargs)
    
    def delete(self, *args, **kwargs):
        # custom delete logic
        super().delete(*args, **kwargs)
"""
        tree = ast.parse(code)
        visitor = FrameworkAwareVisitor()
        visitor.visit(tree)
        
        assert visitor.is_framework_file == True
        assert 7 in visitor.framework_decorated_lines  # save method
        assert 11 in visitor.framework_decorated_lines  # delete method
    
    def test_framework_functions_not_detected_in_non_framework_file(self):
        code = """
def save(self):
    # regular save method, not Django
    pass

def get(self):
    # regular get method, not Django view
    pass
"""
        tree = ast.parse(code)
        visitor = FrameworkAwareVisitor()
        visitor.visit(tree)
        
        assert visitor.is_framework_file == False
        assert visitor.framework_decorated_lines == set()
    
    def test_multiple_decorators(self):
        """Test function with multiple decorators"""
        code = """
@app.route('/users')
@login_required
@cache.cached(timeout=60)
def get_users():
    return []
"""
        tree = ast.parse(code)
        visitor = FrameworkAwareVisitor()
        visitor.visit(tree)
        
        assert visitor.is_framework_file == True
        assert 5 in visitor.framework_decorated_lines
    
    def test_complex_decorator_patterns(self):
        """Test complex decorator patterns"""
        code = """
@app.route('/api/v1/users/<int:user_id>', methods=['GET', 'POST'])
def user_endpoint(user_id):
    return {}

@router.get('/items/{item_id}')
async def get_item(item_id: int):
    return {}
"""
        tree = ast.parse(code)
        visitor = FrameworkAwareVisitor()
        visitor.visit(tree)
        
        assert visitor.is_framework_file == True
        assert 3 in visitor.framework_decorated_lines
        assert 7 in visitor.framework_decorated_lines
    
    @patch('skylos.framework_aware.Path')
    def test_file_content_framework_detection(self, mock_path):
        """Test framework detection from file content"""
        mock_file = Mock()
        mock_file.read_text.return_value = "from flask import Flask\napp = Flask(__name__)"
        mock_path.return_value = mock_file
        
        visitor = FrameworkAwareVisitor(filename="test.py")
        
        assert visitor.is_framework_file == True
        assert 'flask' in visitor.detected_frameworks
    
    def test_normalize_decorator_name(self):
        visitor = FrameworkAwareVisitor()
        
        node = ast.parse("@decorator\ndef func(): pass").body[0].decorator_list[0]
        result = visitor._normalize_decorator(node)
        assert result == "@decorator"
        
        node = ast.parse("@app.route\ndef func(): pass").body[0].decorator_list[0]
        result = visitor._normalize_decorator(node)
        assert result == "@app.route"

class TestDetectFrameworkUsage:
    
    def test_framework_decorated_function_low_confidence(self):
        mock_def = Mock()
        mock_def.line = 10
        mock_def.simple_name = "get_users"
        mock_def.type = "function"
        
        mock_visitor = Mock()
        mock_visitor.framework_decorated_lines = {10}
        mock_visitor.is_framework_file = True
        
        confidence = detect_framework_usage(mock_def, visitor=mock_visitor)
        assert confidence == 20
    
    def test_framework_file_function_medium_confidence(self):
        mock_def = Mock()
        mock_def.line = 15
        mock_def.simple_name = "helper_function"
        mock_def.type = "function"
        
        mock_visitor = Mock()
        mock_visitor.framework_decorated_lines = set()
        mock_visitor.is_framework_file = True
        
        confidence = detect_framework_usage(mock_def, visitor=mock_visitor)
        assert confidence == 40
    
    def test_private_function_in_framework_file_no_confidence(self):
        mock_def = Mock()
        mock_def.line = 20
        mock_def.simple_name = "_private_function"
        mock_def.type = "function"
        
        mock_visitor = Mock()
        mock_visitor.framework_decorated_lines = set()
        mock_visitor.is_framework_file = True
        
        confidence = detect_framework_usage(mock_def, visitor=mock_visitor)
        assert confidence is None
    
    def test_non_framework_file_no_confidence(self):
        mock_def = Mock()
        mock_def.line = 25
        mock_def.simple_name = "regular_function"
        mock_def.type = "function"
        
        mock_visitor = Mock()
        mock_visitor.framework_decorated_lines = set()
        mock_visitor.is_framework_file = False
        
        confidence = detect_framework_usage(mock_def, visitor=mock_visitor)
        assert confidence is None
    
    def test_no_visitor_returns_none(self):
        mock_def = Mock()
        confidence = detect_framework_usage(mock_def, visitor=None)
        assert confidence is None
    
    def test_non_function_in_framework_file_no_confidence(self):
        mock_def = Mock()
        mock_def.line = 30
        mock_def.simple_name = "my_variable"
        mock_def.type = "variable"
        
        mock_visitor = Mock()
        mock_visitor.framework_decorated_lines = set()
        mock_visitor.is_framework_file = True
        
        confidence = detect_framework_usage(mock_def, visitor=mock_visitor)
        assert confidence is None


class TestFrameworkPatterns:
    
    def test_framework_decorators_list(self):
        """Test that FRAMEWORK_DECORATORS contains expected patterns"""
        assert "@app.route" in FRAMEWORK_DECORATORS
        assert "@router.get" in FRAMEWORK_DECORATORS
        assert "@login_required" in FRAMEWORK_DECORATORS
        assert "@task" in FRAMEWORK_DECORATORS
        assert "@validator" in FRAMEWORK_DECORATORS
    
    def test_framework_functions_list(self):
        """Test that FRAMEWORK_FUNCTIONS contains expected patterns"""
        assert "get" in FRAMEWORK_FUNCTIONS
        assert "post" in FRAMEWORK_FUNCTIONS
        assert "save" in FRAMEWORK_FUNCTIONS
        assert "*_queryset" in FRAMEWORK_FUNCTIONS
        assert "get_context_data" in FRAMEWORK_FUNCTIONS
    
    def test_framework_imports_set(self):
        """Test that FRAMEWORK_IMPORTS contains expected frameworks"""
        assert 'flask' in FRAMEWORK_IMPORTS
        assert 'django' in FRAMEWORK_IMPORTS
        assert 'fastapi' in FRAMEWORK_IMPORTS
        assert 'celery' in FRAMEWORK_IMPORTS
        assert 'pydantic' in FRAMEWORK_IMPORTS


if __name__ == "__main__":
    pytest.main([__file__, "-v"])