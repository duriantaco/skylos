#!/usr/bin/env python3
import ast,sys,json,logging,re
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
import multiprocessing
from collections import defaultdict

logging.basicConfig(level=logging.INFO,format='%(asctime)s - %(levelname)s - %(message)s')
logger=logging.getLogger('Skylos')

MAGIC_METHODS={f"__{n}__"for n in["init","new","call","getattr","getattribute","enter","exit","str","repr","hash","eq","ne","lt","gt","le","ge","iter","next","contains","len","getitem","setitem","delitem","iadd","isub","imul","itruediv","ifloordiv","imod","ipow","ilshift","irshift","iand","ixor","ior","round","format","dir","abs","complex","int","float","bool","bytes","reduce","await","aiter","anext","add","sub","mul","truediv","floordiv","mod","divmod","pow","lshift","rshift","and","or","xor","radd","rsub","rmul","rtruediv","rfloordiv","rmod","rdivmod","rpow","rlshift","rrshift","rand","ror","rxor"]}
PYTHON_BUILTINS={"print","len","str","int","float","list","dict","set","tuple","range","open","super","object","type","enumerate","zip","map","filter","sorted","reversed","sum","min","max","all","any","next","iter","repr","chr","ord","bytes","bytearray","memoryview","format","round","abs","pow","divmod","complex","hash","id","bool","callable","getattr","setattr","delattr","hasattr","isinstance","issubclass","globals","locals","vars","dir","property","classmethod","staticmethod"}
DYNAMIC_PATTERNS={"getattr","globals","eval","exec"}
AUTO_CALLED={"__init__","__enter__","__exit__"}

TEST_BASE_CLASSES = {"TestCase", "AsyncioTestCase", "unittest.TestCase", "unittest.AsyncioTestCase"}
TEST_METHOD_PATTERN = re.compile(r"^test_\w+$")

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

class Skylos:

    def __init__(self):
        self.defs={}
        self.refs=[]
        self.dynamic=set()
        self.exports=defaultdict(set)

    def _module(self,root,f):
        p=list(f.relative_to(root).parts)
        if p[-1].endswith(".py"):p[-1]=p[-1][:-3]
        if p[-1]=="__init__":p.pop()
        return".".join(p)
    
    def _mark_exports(self):
        for name, d in self.defs.items():
            if d.in_init and not d.simple_name.startswith('_'):
                d.is_exported = True
        
        for mod, export_names in self.exports.items():
            for name in export_names:
                full_name = f"{mod}.{name}"
                if full_name in self.defs:
                    self.defs[full_name].is_exported = True
                
                for def_name, def_obj in self.defs.items():
                    if def_name.startswith(f"{mod}.") and def_obj.simple_name == name:
                        def_obj.is_exported = True

    def _mark_refs(self):
        import_to_original = {}
        for name, def_obj in self.defs.items():
            if def_obj.type == "import":
                import_name = name.split('.')[-1]
                
                for def_name, orig_def in self.defs.items():
                    if (orig_def.type != "import" and 
                        orig_def.simple_name == import_name and
                        def_name != name):
                        import_to_original[name] = def_name
                        break

        simple_name_lookup = defaultdict(list)
        for d in self.defs.values():
            simple_name_lookup[d.simple_name].append(d)
        
        for ref, file in self.refs:
            if ref in self.defs:
                self.defs[ref].references += 1
                
                if ref in import_to_original:
                    original = import_to_original[ref]
                    self.defs[original].references += 1
                continue
            
            simple = ref.split('.')[-1]
            matches = simple_name_lookup.get(simple, [])
            for d in matches:
                d.references += 1
            
    def _apply_heuristics(self):

        class_methods=defaultdict(list)
        for d in self.defs.values():
            if d.type in("method","function") and"." in d.name:
                cls=d.name.rsplit(".",1)[0]
                if cls in self.defs and self.defs[cls].type=="class":
                    class_methods[cls].append(d)

        for cls,methods in class_methods.items():
            if self.defs[cls].references>0:
                for m in methods:
                    if m.simple_name in AUTO_CALLED:m.references+=1
                    
        for d in self.defs.values():
            if d.simple_name in MAGIC_METHODS or d.simple_name.startswith("__")and d.simple_name.endswith("__"):d.confidence=0
            if not d.simple_name.startswith("_")and d.type in("function","method","class"):d.confidence=min(d.confidence,90)
            if d.in_init and d.type in("function","class"):d.confidence=min(d.confidence,85)
            if d.name.split(".")[0] in self.dynamic:d.confidence=min(d.confidence,50)

    def analyze(self, path, thr=60):
        p = Path(path).resolve()
        files = [p] if p.is_file() else list(p.glob("**/*.py"))
        root = p.parent if p.is_file() else p
        
        modmap = {}
        for f in files:
            modmap[f] = self._module(root, f)
        
        for file in files:
            mod = modmap[file]
            defs, refs, dyn, exports = proc_file(file, mod)
            
            for d in defs: 
                self.defs[d.name] = d
            self.refs.extend(refs)
            self.dynamic.update(dyn)
            self.exports[mod].update(exports)
        
        self._mark_refs()
        self._apply_heuristics()
        self._mark_exports()
        
        print("\nDEBUG - FINAL REFERENCE COUNTS:")
        for name, d in self.defs.items():
            print(f"  {d.type} '{name}': {d.references} refs, exported: {d.is_exported}, confidence: {d.confidence}")
            
        thr = max(0, thr)
        print(f"\nDEBUG - ITEMS BELOW THRESHOLD ({thr}):")

        unused = []
        for d in self.defs.values():
            if d.references == 0 and not d.is_exported and d.confidence >= thr:
                unused.append(d.to_dict())
        
        result = {"unused_functions": [], "unused_imports": [], "unused_classes": []}
        for u in unused:
            if u["type"] in ("function", "method"):
                result["unused_functions"].append(u)
            elif u["type"] == "import":
                result["unused_imports"].append(u)
            elif u["type"] == "class": 
                result["unused_classes"].append(u)
                
        return json.dumps(result, indent=2)

def proc_file(file_or_args, mod=None):
    if mod is None and isinstance(file_or_args, tuple):
        file, mod = file_or_args 
    else:
        file = file_or_args 

    try:
        tree = ast.parse(Path(file).read_text(encoding="utf-8"))
        v = Visitor(mod, file)
        v.visit(tree)
        return v.defs, v.refs, v.dyn, v.exports
    except Exception as e:
        logger.error(f"{file}: {e}")
        return [], [], set(), set()

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
        for stmt in node.body:
            self.visit(stmt)
        self.current_function_scope.pop()
        
    visit_AsyncFunctionDef=visit_FunctionDef


    def visit_ClassDef(self,node):
        cname=f"{self.mod}.{node.name}"
        self.add_def(cname,"class",node.lineno)
        prev=self.cls;self.cls=node.name
        for b in node.body:self.visit(b)
        self.cls=prev

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
        
        elif (isinstance(node.func, ast.Attribute) and 
            node.func.attr == "format" and 
            isinstance(node.func.value, ast.Constant) and 
            isinstance(node.func.value.value, str)):
            fmt = node.func.value.value
            if any(isinstance(k.arg, str) and k.arg is None for k in node.keywords):
                for _, n, _, _ in re.findall(r'\{([^}:!]+)', fmt):
                    if n:
                        self.add_ref(self.qual(n))

    def visit_Name(self,node):
        if isinstance(node.ctx,ast.Load):
            self.add_ref(self.qual(node.id))
            if node.id in DYNAMIC_PATTERNS:self.dyn.add(self.mod.split(".")[0])

    def visit_Attribute(self,node):
        self.generic_visit(node)
        if isinstance(node.ctx,ast.Load)and isinstance(node.value,ast.Name):
            self.add_ref(f"{self.qual(node.value.id)}.{node.attr}")

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

def analyze(path,conf=60):return Skylos().analyze(path,conf)

if __name__=="__main__":
    if len(sys.argv)>1:
        p=sys.argv[1];c=int(sys.argv[2])if len(sys.argv)>2 else 60
        print(analyze(p,c))
    else:
        print("Usage: python Skylos.py <path> [confidence_threshold]")