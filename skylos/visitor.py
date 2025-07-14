#!/usr/bin/env python3
import ast
from pathlib import Path
import os 
import re, logging, traceback
DBG = bool(int(os.getenv("SKYLOS_DEBUG", "0")))
log = logging.getLogger("Skylos")


PYTHON_BUILTINS={"print", "len", "str", "int", "float", "list", "dict", "set", "tuple", "range", "open", 
                 "super", "object", "type", "enumerate", "zip", "map", "filter", "sorted", "sum", "min", 
                "next", "iter", "bytes", "bytearray", "format", "round", "abs", "complex", "hash", "id", "bool", "callable", 
                "getattr", "max", "all", "any", "setattr", "hasattr", "isinstance", "globals", "locals", 
                "vars", "dir" ,"property", "classmethod", "staticmethod"}
DYNAMIC_PATTERNS={"getattr", "globals", "eval", "exec"}

class Definition:
    
    def __init__(self, name, t, filename, line):
        self.name = name
        self.type = t
        self.filename = filename
        self.line = line
        self.simple_name = name.split('.')[-1]
        self.confidence = 100
        self.references = 0
        self.is_exported = False
        self.in_init = "__init__.py" in str(filename)
    
    def to_dict(self):
        if self.type == "method" and "." in self.name:
            parts = self.name.split(".")
            if len(parts) >= 3:
                output_name = ".".join(parts[-2:])
            else:
                output_name = self.name
        else:
            output_name = self.simple_name
            
        return{
            "name": output_name,
            "full_name": self.name,
            "simple_name": self.simple_name,
            "type": self.type,
            "file": str(self.filename),
            "basename": Path(self.filename).name,
            "line": self.line,
            "confidence": self.confidence,
            "references": self.references
        }

class Visitor(ast.NodeVisitor):
    def __init__(self,mod,file):
        self.mod= mod
        self.file= file
        self.defs= []
        self.refs= []
        self.cls= None
        self.alias= {}
        self.dyn= set()
        self.exports= set()
        self.current_function_scope= []
        self.current_function_params= []

    def add_def(self, name, t, line):
        if name not in {d.name for d in self.defs}:
            self.defs.append(Definition(name, t, self.file, line))

    def add_ref(self, name):
        self.refs.append((name, self.file))

    def qual(self, name):
        if name in self.alias:
            return self.alias[name]
        if name in PYTHON_BUILTINS:
            return name
        return f"{self.mod}.{name}" if self.mod else name

    def visit_annotation(self, node):
        if node is not None:
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                self.visit_string_annotation(node.value)
            elif hasattr(node, 's') and isinstance(node.s, str):
                self.visit_string_annotation(node.s)
            else:
                self.visit(node)

    def visit_string_annotation(self, annotation_str):
        if not isinstance(annotation_str, str):
            return

        if DBG:
            log.debug(f"parsing annotation: {annotation_str}")


        try:
            parsed = ast.parse(annotation_str, mode="eval")
            self.visit(parsed.body)
        except:
            if DBG:
                if DBG: log.debug("annotation parse failed")
            
            for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", annotation_str):
                self.add_ref(tok)

    def visit_Import(self, node):
        for a in node.names:
            full= a.name
            self.alias[a.asname or a.name.split(".")[-1]]= full
            self.add_def(full,"import",node.lineno)

    def visit_ImportFrom(self, node):
        if node.module is None:
            return
        for a in node.names:
            if a.name == "*":
                continue
            base = node.module
            if node.level:
                parts = self.mod.split(".")
                base = ".".join(parts[:-node.level]) + (f".{node.module}" if node.module else "")
            
            full = f"{base}.{a.name}"
            if a.asname:
                self.alias[a.asname] = full
                self.add_def(full, "import", node.lineno)
            else:
                self.alias[a.name] = full
                self.add_def(full, "import", node.lineno)
            
    def visit_arguments(self, args):
        for arg in args.args:
            self.visit_annotation(arg.annotation)
        for arg in args.posonlyargs:
            self.visit_annotation(arg.annotation)
            
        for arg in args.kwonlyargs:
            self.visit_annotation(arg.annotation)
        if args.vararg:
            self.visit_annotation(args.vararg.annotation)
        if args.kwarg:
            self.visit_annotation(args.kwarg.annotation)
        for default in args.defaults:
            self.visit(default)
        for default in args.kw_defaults:
            if default:
                self.visit(default)

    def visit_FunctionDef(self,node):
        outer_scope_prefix = '.'.join(self.current_function_scope) + '.' if self.current_function_scope else ''
        
        if self.cls:
            name_parts= [self.mod, self.cls, outer_scope_prefix + node.name]
        else:
            name_parts= [self.mod, outer_scope_prefix + node.name]
        
        qualified_name= ".".join(filter(None, name_parts))

        self.add_def(qualified_name,"method"if self.cls else"function",node.lineno)
        
        self.current_function_scope.append(node.name)
        
        old_params = self.current_function_params
        self.current_function_params = []
        
        for d_node in node.decorator_list:
            self.visit(d_node)
        
        for arg in node.args.args:
            param_name = f"{qualified_name}.{arg.arg}"
            self.add_def(param_name, "parameter", node.lineno)
            self.current_function_params.append((arg.arg, param_name))
        
        self.visit_arguments(node.args)
        self.visit_annotation(node.returns)
        
        for stmt in node.body:
            self.visit(stmt)
            
        self.current_function_scope.pop()
        self.current_function_params = old_params
        
    visit_AsyncFunctionDef= visit_FunctionDef

    def visit_ClassDef(self, node):
        cname =f"{self.mod}.{node.name}"
        self.add_def(cname, "class",node.lineno)
        
        for base in node.bases:
            self.visit(base)
        for keyword in node.keywords:
            self.visit(keyword.value)
        for decorator in node.decorator_list:
            self.visit(decorator)
        
        prev= self.cls

        self.cls= node.name
        for b in node.body:
            self.visit(b)

        self.cls= prev

    def visit_AnnAssign(self, node):
        self.visit_annotation(node.annotation)
        if node.value:
            self.visit(node.value)
        self.visit(node.target)

    def visit_AugAssign(self, node):
        self.visit(node.target)
        self.visit(node.value)

    def visit_Subscript(self, node):
        self.visit(node.value)
        self.visit(node.slice)

    def visit_Slice(self, node):
        if node.lower:
            self.visit(node.lower)
        if node.upper:
            self.visit(node.upper)
        if node.step:
            self.visit(node.step)

    def visit_Assign(self, node):
        def process_target_for_def(target_node):
            if isinstance(target_node, ast.Name):
                name_simple = target_node.id
                if name_simple == "__all__" and not self.current_function_scope and not self.cls:
                    return

                scope_parts = [self.mod]

                if self.cls:
                    scope_parts.append(self.cls)

                if self.current_function_scope:
                    scope_parts.extend(self.current_function_scope)
                
                prefix = '.'.join(filter(None, scope_parts))
                var_name = f"{prefix}.{name_simple}" if prefix else name_simple

                self.add_def(var_name, "variable", target_node.lineno)

            elif isinstance(target_node, (ast.Tuple, ast.List)):
                for elt in target_node.elts:
                    process_target_for_def(elt)

        for t in node.targets:
            process_target_for_def(t)
        
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "__all__":
                if isinstance(node.value, (ast.List, ast.Tuple)):
                    for elt in node.value.elts:
                        value = None
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            value = elt.value
                        elif hasattr(elt, 's') and isinstance(elt.s, str):
                            value = elt.s
                            
                        if value is not None:
                            export_name = f"{self.mod}.{value}" if self.mod else value
                            self.add_ref(export_name)
                            self.add_ref(value) 
        
        self.generic_visit(node)

    def visit_Call(self, node):
        self.generic_visit(node)
        
        if isinstance(node.func, ast.Name) and node.func.id in ("getattr", "hasattr") and len(node.args) >= 2:
            if isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
                attr_name = node.args[1].value
                self.add_ref(attr_name)
                
                if isinstance(node.args[0], ast.Name):
                    module_name = node.args[0].id
                    if module_name != "self": 
                        qualified_name = f"{self.qual(module_name)}.{attr_name}"
                        self.add_ref(qualified_name)
            
            elif isinstance(node.args[0], ast.Name):
                target_name = node.args[0].id
                if target_name != "self":
                    self.dyn.add(self.mod.split(".")[0] if self.mod else "")
        
        elif isinstance(node.func, ast.Name) and node.func.id == "globals":
            parent = getattr(node, 'parent', None)
            if (isinstance(parent, ast.Subscript) and 
                isinstance(parent.slice, ast.Constant) and 
                isinstance(parent.slice.value, str)):
                func_name = parent.slice.value
                self.add_ref(func_name)
                self.add_ref(f"{self.mod}.{func_name}")
        
        elif isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
            self.dyn.add(self.mod.split(".")[0] if self.mod else "")

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Load):
            for param_name, param_full_name in self.current_function_params:
                if node.id == param_name:
                    self.add_ref(param_full_name)
                    break

            else:
                # not parameter, handle normally
                qualified = self.qual(node.id)
                self.add_ref(qualified)
                if node.id in DYNAMIC_PATTERNS:
                    self.dyn.add(self.mod.split(".")[0])

    def visit_Attribute(self, node):
        self.generic_visit(node)
        if isinstance(node.ctx, ast.Load) and isinstance(node.value, ast.Name):
            if node.value.id in [param_name for param_name, _ in self.current_function_params]:
                # mark parameter as referenced
                for param_name, param_full_name in self.current_function_params:
                    if node.value.id == param_name:
                        self.add_ref(param_full_name)
                        break

            self.add_ref(f"{self.qual(node.value.id)}.{node.attr}")

    def visit_keyword(self, node):
        self.visit(node.value)

    def visit_withitem(self, node):
        self.visit(node.context_expr)
        if node.optional_vars:
            self.visit(node.optional_vars)

    def visit_ExceptHandler(self, node):
        if node.type:
            self.visit(node.type)
        for stmt in node.body:
            self.visit(stmt)

    def generic_visit(self, node):
        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        item.parent = node
                        self.visit(item)
            elif isinstance(value, ast.AST):
                value.parent = node
                self.visit(value)