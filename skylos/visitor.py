#!/usr/bin/env python3
import ast,re
from pathlib import Path

PYTHON_BUILTINS={"print","len","str","int","float","list","dict","set","tuple","range","open","super","object","type","enumerate","zip","map","filter","sorted","reversed","sum","min","max","all","any","next","iter","repr","chr","ord","bytes","bytearray","memoryview","format","round","abs","pow","divmod","complex","hash","id","bool","callable","getattr","setattr","delattr","hasattr","isinstance","issubclass","globals","locals","vars","dir","property","classmethod","staticmethod"}
DYNAMIC_PATTERNS={"getattr","globals","eval","exec"}

class Definition:
    __slots__ = ('name', 'type', 'filename', 'line', 'simple_name', 'confidence', 'references', 'is_exported', 'in_init')
    
    def __init__(self, n, t, f, l):
        self.name = n
        self.type = t
        self.filename = f
        self.line = l
        self.simple_name = n.split('.')[-1]
        self.confidence = 100
        self.references = 0
        self.is_exported = False
        self.in_init = "__init__.py" in str(f)
    
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
        self.mod=mod
        self.file=file
        self.defs=[]
        self.refs=[]
        self.cls=None
        self.alias={}
        self.dyn=set()
        self.exports=set()
        self.current_function_scope = []

    def add_def(self,n,t,l):
        if n not in{d.name for d in self.defs}:self.defs.append(Definition(n,t,self.file,l))

    def add_ref(self,n):self.refs.append((n,self.file))

    def qual(self,n):
        if n in self.alias:return self.alias[n]
        if n in PYTHON_BUILTINS:return n
        return f"{self.mod}.{n}"if self.mod else n

    def visit_annotation(self, node):
        if node is not None:
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                self.visit_string_annotation(node.value)
            elif hasattr(node, 's') and isinstance(node.s, str):
                self.visit_string_annotation(node.s)
            else:
                self.visit(node)

    def visit_string_annotation(self, annotation_str):
        try:
            parsed = ast.parse(annotation_str, mode='eval')
            self.visit(parsed.body)
        except:
            pass

    def visit_Import(self,node):
        for a in node.names:
            full=a.name
            self.alias[a.asname or a.name.split(".")[-1]]=full
            self.add_def(full,"import",node.lineno)

    def visit_ImportFrom(self,node):
        if node.module is None:return
        for a in node.names:
            if a.name=="*":continue
            base=node.module
            if node.level:
                parts=self.mod.split(".")
                base=".".join(parts[:-node.level])+(f".{node.module}"if node.module else"")
            full=f"{base}.{a.name}"
            self.alias[a.asname or a.name]=full
            self.add_def(full,"import",node.lineno)

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
            name_parts = [self.mod, self.cls, outer_scope_prefix + node.name]
        else:
            name_parts = [self.mod, outer_scope_prefix + node.name]
        
        qualified_name = ".".join(filter(None, name_parts))

        self.add_def(qualified_name,"method"if self.cls else"function",node.lineno)
        
        self.current_function_scope.append(node.name)
        
        for d_node in node.decorator_list:
            self.visit(d_node)
        
        self.visit_arguments(node.args)
        self.visit_annotation(node.returns)
        
        for stmt in node.body:
            self.visit(stmt)
        self.current_function_scope.pop()
        
    visit_AsyncFunctionDef=visit_FunctionDef

    def visit_ClassDef(self,node):
        cname=f"{self.mod}.{node.name}"
        self.add_def(cname,"class",node.lineno)
        
        for base in node.bases:
            self.visit(base)
        for keyword in node.keywords:
            self.visit(keyword.value)
        for decorator in node.decorator_list:
            self.visit(decorator)
        
        prev=self.cls;self.cls=node.name
        for b in node.body:self.visit(b)
        self.cls=prev

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
                            full_name = f"{self.mod}.{value}"
                            self.add_ref(full_name)
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
        
        elif isinstance(node.func, ast.Name) and node.func.id == "globals":
            parent = getattr(node, 'parent', None)
            if (isinstance(parent, ast.Subscript) and 
                isinstance(parent.slice, ast.Constant) and 
                isinstance(parent.slice.value, str)):
                func_name = parent.slice.value
                self.add_ref(func_name)
                self.add_ref(f"{self.mod}.{func_name}")

    def visit_Name(self,node):
        if isinstance(node.ctx,ast.Load):
            self.add_ref(self.qual(node.id))
            if node.id in DYNAMIC_PATTERNS:self.dyn.add(self.mod.split(".")[0])

    def visit_Attribute(self,node):
        self.generic_visit(node)
        if isinstance(node.ctx,ast.Load)and isinstance(node.value,ast.Name):
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