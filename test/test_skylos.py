import json
import skylos
import os

def main():
    project_path = "path/to/test_project"
    
    if not os.path.exists(project_path):
        print(f"Error: {project_path} does not exist")
        return
    
    print(f"Analyzing Python project: {project_path}")
    try:
        result_json = skylos.analyze(project_path)
        result = json.loads(result_json)
        
        print(f"\nFound {len(result)} unreachable functions:")
        for func in result:
            print(f"- {func['name']} at {func['file']}:{func['line']}")
    except Exception as e:
        print(f"Error analyzing project: {e}")

if __name__ == "__main__":
    main()