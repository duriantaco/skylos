import argparse
import json
import sys
import skylos

def main():
    parser = argparse.ArgumentParser(
        description="Detect unreachable functions in Python projects"
    )
    parser.add_argument(
        "path", help="Path to the Python project to analyze"
    )
    parser.add_argument(
        "--json", action="store_true", 
        help="Output raw JSON instead of formatted text"
    )
    parser.add_argument(
        "--output", "-o", type=str,
        help="Write output to file instead of stdout"
    )
    
    args = parser.parse_args()
    
    try:
        result_json = skylos.analyze(args.path)
        result = json.loads(result_json)
        
        output_file = open(args.output, 'w') if args.output else sys.stdout
        
        try:
            if args.json:
                print(result_json, file=output_file)
            else:
                print(f"Found {len(result)} unreachable functions:", file=output_file)
                for func in result:
                    print(f"- {func['name']} at {func['file']}:{func['line']}", 
                          file=output_file)
        finally:
            if args.output:
                output_file.close()
                
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()