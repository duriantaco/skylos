#!/usr/bin/env python3
import ast,sys,json,logging,re
from pathlib import Path
from collections import defaultdict
from skylos.visitor import Visitor

logging.basicConfig(level=logging.INFO,format='%(asctime)s - %(levelname)s - %(message)s')
logger=logging.getLogger('Skylos')

AUTO_CALLED={"__init__","__enter__","__exit__"}
TEST_BASE_CLASSES = {"TestCase", "AsyncioTestCase", "unittest.TestCase", "unittest.AsyncioTestCase"}
TEST_METHOD_PATTERN = re.compile(r"^test_\w+$")
MAGIC_METHODS={f"__{n}__"for n in["init","new","call","getattr","getattribute","enter","exit","str","repr","hash","eq","ne","lt","gt","le","ge","iter","next","contains","len","getitem","setitem","delitem","iadd","isub","imul","itruediv","ifloordiv","imod","ipow","ilshift","irshift","iand","ixor","ior","round","format","dir","abs","complex","int","float","bool","bytes","reduce","await","aiter","anext","add","sub","mul","truediv","floordiv","mod","divmod","pow","lshift","rshift","and","or","xor","radd","rsub","rmul","rtruediv","rfloordiv","rmod","rdivmod","rpow","rlshift","rrshift","rand","ror","rxor"]}

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
                for def_name, def_obj in self.defs.items():
                    if (def_name.startswith(f"{mod}.") and 
                        def_obj.simple_name == name and
                        def_obj.type != "import"):
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
    
    def _get_base_classes(self, class_name):
        """Get base classes for a given class name"""
        if class_name not in self.defs:
            return []
        
        class_def = self.defs[class_name]
        
        if hasattr(class_def, 'base_classes'):
            return class_def.base_classes
        
        return []
            
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
        
        for d in self.defs.values():
            if d.type == "method" and TEST_METHOD_PATTERN.match(d.simple_name):
                # check if its in a class that inherits from a test base class
                class_name = d.name.rsplit(".", 1)[0]
                class_simple_name = class_name.split(".")[-1]
                # class name suggests it's a test class, ignore test methods
                if "Test" in class_simple_name or class_simple_name.endswith("TestCase"):
                    d.confidence = 0

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
        
        # for name, d in self.defs.items():
        #     print(f"  {d.type} '{name}': {d.references} refs, exported: {d.is_exported}, confidence: {d.confidence}")
            
        thr = max(0, thr)

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

def analyze(path,conf=60):return Skylos().analyze(path,conf)

if __name__=="__main__":
    if len(sys.argv)>1:
        p=sys.argv[1];c=int(sys.argv[2])if len(sys.argv)>2 else 60
        print(analyze(p,c))
    else:
        print("Usage: python Skylos.py <path> [confidence_threshold]")