import ast
import fnmatch
from pathlib import Path

FRAMEWORK_DECORATORS = [
    # flask
    "@app.route", "@app.get", "@app.post", "@app.put", "@app.delete", 
    "@app.patch", "@app.before_request", "@app.after_request",
    "@app.errorhandler", "@app.teardown_*",
    
    # fastapi  
    "@router.get", "@router.post", "@router.put", "@router.delete",
    "@router.patch", "@router.head", "@router.options",
    "@router.trace", "@router.websocket",
    
    # django
    "@*_required", "@login_required", "@permission_required", 
    "@user_passes_test", "@staff_member_required",
    
    # pydantic 
    "@validator", "@field_validator", "@model_validator", "@root_validator",
    
    # celery patterns
    "@task", "@shared_task", "@periodic_task", "@celery_task",
    
    # generic ones
    "@route", "@get", "@post", "@put", "@delete", "@patch",
    "@middleware", "@depends", "@inject"
]

FRAMEWORK_FUNCTIONS = [
    # django view methods
    "get", "post", "put", "patch", "delete", "head", "options", "trace",
    "*_queryset", "get_queryset", "get_object", "get_context_data",
    "*_form", "form_valid", "form_invalid", "get_form_*",
    
    # django model methods
    "save", "delete", "clean", "full_clean", "*_delete", "*_save",
    
    # generic API endpoints
    "create_*", "update_*", "delete_*", "list_*", "retrieve_*",
    "handle_*", "process_*", "*_handler", "*_view"
]

FRAMEWORK_IMPORTS = {
    'flask', 'fastapi', 'django', 'pydantic', 'celery', 'starlette', 
    'sanic', 'tornado', 'pyramid', 'bottle', 'cherrypy', 'web2py',
    'falcon', 'hug', 'responder', 'quart', 'hypercorn', 'uvicorn'
}

class FrameworkAwareVisitor:
    
    def __init__(self, filename=None):
        self.is_framework_file = False
        self.framework_decorated_lines = set()
        self.detected_frameworks = set()
        
        if filename:
            self._check_framework_imports_in_file(filename)

    def visit(self, node):
        method = 'visit_' + node.__class__.__name__
        visitor = getattr(self, method, self.generic_visit)
        return visitor(node)

    def generic_visit(self, node):
        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        self.visit(item)
            elif isinstance(value, ast.AST):
                self.visit(value)

    def visit_Import(self, node):
        for alias in node.names:
            if any(fw in alias.name.lower() for fw in FRAMEWORK_IMPORTS):
                self.is_framework_file = True
                self.detected_frameworks.add(alias.name.split('.')[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            module_name = node.module.split('.')[0].lower()

            if module_name in FRAMEWORK_IMPORTS:
                self.is_framework_file = True
                self.detected_frameworks.add(module_name)

        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        for deco in node.decorator_list:
            decorator_str = self._normalize_decorator(deco)

            if self._matches_framework_pattern(decorator_str, FRAMEWORK_DECORATORS):
                self.framework_decorated_lines.add(node.lineno)
                self.is_framework_file = True
        
        if self._matches_framework_pattern(node.name, FRAMEWORK_FUNCTIONS):
            if self.is_framework_file:  
                self.framework_decorated_lines.add(node.lineno)
        
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def visit_ClassDef(self, node):
        for base in node.bases:
            if isinstance(base, ast.Name):
                if any(pattern in base.id.lower() for pattern in ['view', 'viewset', 'api', 'handler']):
                    if self.is_framework_file:
                        self.framework_decorated_lines.add(node.lineno)
        
        self.generic_visit(node)

    def _normalize_decorator(self, decorator_node):
        if isinstance(decorator_node, ast.Name):
            return f"@{decorator_node.id}"
        
        elif isinstance(decorator_node, ast.Attribute):
            if isinstance(decorator_node.value, ast.Name):
                return f"@{decorator_node.value.id}.{decorator_node.attr}"
            
            else:
                return f"@{decorator_node.attr}"
            
        elif isinstance(decorator_node, ast.Call):
            return self._normalize_decorator(decorator_node.func)
        
        return "@unknown"

    def _matches_framework_pattern(self, text, patterns):
        text_clean = text.lstrip('@')
        return any(fnmatch.fnmatch(text_clean, pattern.lstrip('@')) for pattern in patterns)

    def _check_framework_imports_in_file(self, filename):
        try:
            content = Path(filename).read_text(encoding='utf-8')
            for framework in FRAMEWORK_IMPORTS:
                if (f'import {framework}' in content or 
                    f'from {framework}' in content):
                    self.is_framework_file = True
                    self.detected_frameworks.add(framework)
                    break
        except:
            pass

def detect_framework_usage(definition, visitor=None):
    if not visitor:
        return None
    
    # very low confidence - likely framework magic
    if definition.line in visitor.framework_decorated_lines:
        return 20  
    
    # framework file but no direct markers
    if visitor.is_framework_file:
        if (not definition.simple_name.startswith('_') and 
            definition.type in ('function', 'method')):
            return 40 
    
    return None