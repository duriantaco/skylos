import importlib.metadata, skylos, pathlib, importlib.util
import os
from pathlib import Path


print(skylos.__file__)                        
print(importlib.metadata.version("skylos")) 
print(pathlib.Path(skylos.__file__).stat().st_mtime)
print("Extension path:", skylos._core.__file__)
print("Built:", pathlib.Path(skylos._core.__file__).stat().st_mtime)


os.environ["RUST_LOG"] = "debug"
root = Path(__file__).parent / "sample_project"
print("Result:", skylos.analyze(str(root)))