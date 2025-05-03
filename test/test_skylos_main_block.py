import json
import pathlib
import tempfile
import skylos

def test_main_block_detection():
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = pathlib.Path(temp_dir)
        
        with open(temp_path / "main_block.py", "w") as f:
            f.write("""
def called_from_main():
    return "I'm called from main"
    
def not_called():
    return "I'm not called"

if __name__ == "__main__":
    # This function is called in the main block
    called_from_main()
            """)
        
        result = json.loads(skylos.analyze(str(temp_path)))
        names = {d["name"] for d in result}
        
        assert "main_block.called_from_main" not in names
        assert "main_block.not_called" in names