import argparse
import json
import sys
import os

import skylos


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Detect unreachable functions in a Python project"
    )
    parser.add_argument("path", help="Path to the Python project to analyze")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON instead of formatted text",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        help="Write output to file instead of stdout",
    )

    args = parser.parse_args()

    result_json = skylos.analyze(args.path)
    result = json.loads(result_json)

    out = open(args.output, "w") if args.output else sys.stdout
    try:
        if args.json:
            print(result_json, file=out)
        else:
            print(f"Found {len(result)} unreachable functions:", file=out)
            for item in result:
                print(
                    f"- {item['name']}  ({item['file']}:{item['line']})",
                    file=out,
                )
    finally:
        if args.output:
            out.close()


if __name__ == "__main__":
    main()
