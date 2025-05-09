import json
import pathlib
import tempfile
import skylos

def test_method_calls():
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = pathlib.Path(temp_dir)
        
        with open(temp_path / "method_calls.py", "w") as f:
            f.write("""
class MyClass:
    def used_method(self):
        return "I'm used"
        
    def unused_method(self):
        return "I'm not used"

obj = MyClass()
obj.used_method()
            """)
        
        result = json.loads(skylos.analyze(str(temp_path)))
        names = {d["name"] for d in result}
        
        assert "method_calls.MyClass.used_method" not in names
        assert any("unused_method" in name for name in names)