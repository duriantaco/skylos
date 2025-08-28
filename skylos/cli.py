import argparse
import json
import sys
import logging
from skylos.constants import parse_exclude_folders, DEFAULT_EXCLUDE_FOLDERS
from skylos.server import start_server
from skylos.analyzer import analyze as run_analyze
from skylos.codemods import (
    remove_unused_import_cst,
    remove_unused_function_cst,
)
import pathlib
import skylos

try:
    import inquirer
    INTERACTIVE_AVAILABLE = True
except ImportError:
    INTERACTIVE_AVAILABLE = False

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'
    GRAY = '\033[90m'

class CleanFormatter(logging.Formatter):
    def format(self, record):
        return record.getMessage()

def setup_logger(output_file=None):
    logger = logging.getLogger('skylos')
    logger.setLevel(logging.INFO)
    
    logger.handlers.clear()
    
    formatter = CleanFormatter()
    
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    if output_file:
        file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler = logging.FileHandler(output_file)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    logger.propagate = False
    
    return logger

def remove_unused_import(file_path, import_name, line_number):
    path = pathlib.Path(file_path)
    try:
        src = path.read_text(encoding="utf-8")
        new_code, changed = remove_unused_import_cst(src, import_name, line_number)
        if not changed:
            return False
        path.write_text(new_code, encoding="utf-8")
        return True
    except Exception as e:
        logging.error(f"Failed to remove import {import_name} from {file_path}: {e}")
        return False

def remove_unused_function(file_path, function_name, line_number):
    path = pathlib.Path(file_path)
    try:
        src = path.read_text(encoding="utf-8")
        new_code, changed = remove_unused_function_cst(src, function_name, line_number)
        if not changed:
            return False
        path.write_text(new_code, encoding="utf-8")
        return True
    except Exception as e:
        logging.error(f"Failed to remove function {function_name} from {file_path}: {e}")
        return False

def interactive_selection(logger, unused_functions, unused_imports):
    if not INTERACTIVE_AVAILABLE:
        logger.error("Interactive mode requires 'inquirer' package. Install with: pip install inquirer")
        return [], []
    
    selected_functions = []
    selected_imports = []
    
    if unused_functions:
        logger.info(f"\n{Colors.CYAN}{Colors.BOLD}Select unused functions to remove (hit spacebar to select):{Colors.RESET}")
        
        function_choices = []

        for item in unused_functions:
            choice_text = f"{item['name']} ({item['file']}:{item['line']})"
            function_choices.append((choice_text, item))
        
        questions = [
            inquirer.Checkbox('functions',
                            message="Select functions to remove",
                            choices=function_choices,
                            )
        ]
        
        answers = inquirer.prompt(questions)
        if answers:
            selected_functions = answers['functions']
    
    if unused_imports:
        logger.info(f"\n{Colors.MAGENTA}{Colors.BOLD}Select unused imports to remove (hit spacebar to select):{Colors.RESET}")
        
        import_choices = []

        for item in unused_imports:
            choice_text = f"{item['name']} ({item['file']}:{item['line']})"
            import_choices.append((choice_text, item))
        
        questions = [
            inquirer.Checkbox('imports',
                            message="Select imports to remove",
                            choices=import_choices,
                            )
        ]
        
        answers = inquirer.prompt(questions)
        if answers:
            selected_imports = answers['imports']
    
    return selected_functions, selected_imports

def print_badge(dead_code_count: int, logger):
    logger.info(f"\n{Colors.GRAY}{'─' * 50}{Colors.RESET}")
    
    if dead_code_count == 0:
        logger.info(f" Your code is 100% dead code free! Add this badge to your README:")
        logger.info("```markdown")
        logger.info("![Dead Code Free](https://img.shields.io/badge/Dead_Code-Free-brightgreen?logo=moleculer&logoColor=white)")
        logger.info("```")
    else:
        logger.info(f"Found {dead_code_count} dead code items. Add this badge to your README:")
        logger.info("```markdown")  
        logger.info(f"![Dead Code: {dead_code_count}](https://img.shields.io/badge/Dead_Code-{dead_code_count}_detected-orange?logo=codacy&logoColor=red)")
        logger.info("```")

def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'run':
        try:
            start_server()
            return
        except ImportError:
            print(f"{Colors.RED}Error: Flask is required {Colors.RESET}")
            print(f"{Colors.YELLOW}Install with: pip install flask flask-cors{Colors.RESET}")
            sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Detect unreachable functions and unused imports in a Python project"
    )
    parser.add_argument("path", help="Path to the Python project")

    parser.add_argument(
        "--version",
        action="version", 
        version=f"skylos {skylos.__version__}",
        help="Show version and exit"
    )
    
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        help="Write output to file",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose"
    )
    parser.add_argument(
        "--confidence",
        "-c",
        type=int,
        default=60,
        help="Confidence threshold (0-100). Lower values include more items. Default: 60"
    )
    parser.add_argument(
        "--interactive", "-i",
        action="store_true",
        help="Select items to remove"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be removed"
    )
    
    parser.add_argument(
        "--exclude-folder",
        action="append",
        dest="exclude_folders",
        help="Exclude a folder from analysis (can be used multiple times). "
             "By default, common folders like __pycache__, .git, venv are excluded. "
             "Use --no-default-excludes to disable default exclusions."
    )
    
    parser.add_argument(
        "--include-folder", 
        action="append",
        dest="include_folders",
        help="Force include a folder that would otherwise be excluded "
             "(overrides both default and custom exclusions). "
             "Example: --include-folder venv"
    )
    
    parser.add_argument(
        "--no-default-excludes",
        action="store_true",
        help="Don't exclude default folders (__pycache__, .git, venv, etc.). "
             "Only exclude folders with --exclude-folder."
    )
    
    parser.add_argument(
        "--list-default-excludes",
        action="store_true", 
        help="List the default excluded folders and exit."
    )

    args = parser.parse_args()

    if args.list_default_excludes:
        print("Default excluded folders:")
        for folder in sorted(DEFAULT_EXCLUDE_FOLDERS):
            print(f"  {folder}")
        print(f"\nTotal: {len(DEFAULT_EXCLUDE_FOLDERS)} folders")
        print("\nUse --no-default-excludes to disable these exclusions")
        print("Use --include-folder <folder> to force include specific folders")
        return
    
    logger = setup_logger(args.output)
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug(f"Analyzing path: {args.path}")
        
        if args.exclude_folders:
            logger.debug(f"Excluding folders: {args.exclude_folders}")

    use_defaults = not args.no_default_excludes
    final_exclude_folders = parse_exclude_folders(
        user_exclude_folders=args.exclude_folders,
        use_defaults=use_defaults,
        include_folders=args.include_folders
    )
    
    if not args.json:
        if final_exclude_folders:
            logger.info(f"{Colors.YELLOW}📁 Excluding: {', '.join(sorted(final_exclude_folders))}{Colors.RESET}")
        else:
            logger.info(f"{Colors.GREEN}📁 No folders excluded{Colors.RESET}")

    try:
        result_json = run_analyze(args.path, conf=args.confidence, exclude_folders=list(final_exclude_folders))
        result = json.loads(result_json)

    except Exception as e:
        logger.error(f"Error during analysis: {e}")
        sys.exit(1)

    if args.json:
        logger.info(result_json)
        return

    unused_functions = result.get("unused_functions", [])
    unused_imports = result.get("unused_imports", [])
    unused_parameters = result.get("unused_parameters", [])
    unused_variables = result.get("unused_variables", [])
    unused_classes = result.get("unused_classes", [])
    
    logger.info(f"{Colors.CYAN}{Colors.BOLD} Python Static Analysis Results{Colors.RESET}")
    logger.info(f"{Colors.CYAN}{'=' * 35}{Colors.RESET}")
    
    logger.info(f"\n{Colors.BOLD}Summary:{Colors.RESET}")
    logger.info(f" * Unreachable functions: {Colors.YELLOW}{len(unused_functions)}{Colors.RESET}")
    logger.info(f" * Unused imports: {Colors.YELLOW}{len(unused_imports)}{Colors.RESET}")
    logger.info(f" * Unused parameters: {Colors.YELLOW}{len(unused_parameters)}{Colors.RESET}")
    logger.info(f" * Unused variables: {Colors.YELLOW}{len(unused_variables)}{Colors.RESET}")
    logger.info(f" * Unused classes: {Colors.YELLOW}{len(unused_classes)}{Colors.RESET}")

    if args.interactive and (unused_functions or unused_imports):
        logger.info(f"\n{Colors.BOLD}Interactive Mode:{Colors.RESET}")
        selected_functions, selected_imports = interactive_selection(logger, unused_functions, unused_imports)
        
        if selected_functions or selected_imports:
            logger.info(f"\n{Colors.BOLD}Selected items to remove:{Colors.RESET}")
            
            if selected_functions:
                logger.info(f"  Functions: {len(selected_functions)}")
                for func in selected_functions:
                    logger.info(f"    - {func['name']} ({func['file']}:{func['line']})")
            
            if selected_imports:
                logger.info(f"  Imports: {len(selected_imports)}")
                for imp in selected_imports:
                    logger.info(f"    - {imp['name']} ({imp['file']}:{imp['line']})")
            
            if not args.dry_run:
                questions = [
                    inquirer.Confirm('confirm',
                                   message="Are you sure you want to remove these items?",
                                   default=False)
                ]
                answers = inquirer.prompt(questions)
                
                if answers and answers['confirm']:
                    logger.info(f"\n{Colors.YELLOW}Removing selected items...{Colors.RESET}")
                    
                    for func in selected_functions:
                        success = remove_unused_function(func['file'], func['name'], func['line'])
                        if success:
                            logger.info(f"  {Colors.GREEN} {Colors.RESET} Removed function: {func['name']}")
                        else:
                            logger.error(f"  {Colors.RED} x {Colors.RESET} Failed to remove: {func['name']}")
                    
                    for imp in selected_imports:
                        success = remove_unused_import(imp['file'], imp['name'], imp['line'])
                        if success:
                            logger.info(f"  {Colors.GREEN} {Colors.RESET} Removed import: {imp['name']}")
                        else:
                            logger.error(f"  {Colors.RED} x {Colors.RESET} Failed to remove: {imp['name']}")
                    
                    logger.info(f"\n{Colors.GREEN}Cleanup complete!{Colors.RESET}")
                else:
                    logger.info(f"\n{Colors.YELLOW}Operation cancelled.{Colors.RESET}")
            else:
                logger.info(f"\n{Colors.YELLOW}Dry run - no files were modified.{Colors.RESET}")
        else:
            logger.info(f"\n{Colors.BLUE}No items selected.{Colors.RESET}")
    
    else:
        if unused_functions:
            logger.info(f"\n{Colors.RED}{Colors.BOLD} - Unreachable Functions{Colors.RESET}")
            logger.info(f"{Colors.RED}{'=' * 23}{Colors.RESET}")
            for i, item in enumerate(unused_functions, 1):
                logger.info(f"{Colors.GRAY}{i:2d}. {Colors.RESET}{Colors.RED}{item['name']}{Colors.RESET}")
                logger.info(f"    {Colors.GRAY}└─ {item['file']}:{item['line']}{Colors.RESET}")
        else:
            logger.info(f"\n{Colors.GREEN} All functions are reachable!{Colors.RESET}")
        
        if unused_imports:
            logger.info(f"\n{Colors.MAGENTA}{Colors.BOLD} - Unused Imports{Colors.RESET}")
            logger.info(f"{Colors.MAGENTA}{'=' * 16}{Colors.RESET}")
            for i, item in enumerate(unused_imports, 1):
                logger.info(f"{Colors.GRAY}{i:2d}. {Colors.RESET}{Colors.MAGENTA}{item['name']}{Colors.RESET}")
                logger.info(f"    {Colors.GRAY}└─ {item['file']}:{item['line']}{Colors.RESET}")
        else:
            logger.info(f"\n{Colors.GREEN}✓ All imports are being used!{Colors.RESET}")
        
        if unused_parameters:
            logger.info(f"\n{Colors.BLUE}{Colors.BOLD} - Unused Parameters{Colors.RESET}")
            logger.info(f"{Colors.BLUE}{'=' * 18}{Colors.RESET}")
            for i, item in enumerate(unused_parameters, 1):
                logger.info(f"{Colors.GRAY}{i:2d}. {Colors.RESET}{Colors.BLUE}{item['name']}{Colors.RESET}")
                logger.info(f"    {Colors.GRAY}└─ {item['file']}:{item['line']}{Colors.RESET}")
        else:
            logger.info(f"\n{Colors.GREEN}✓ All parameters are being used!{Colors.RESET}")
        
        if unused_variables:
            logger.info(f"\n{Colors.YELLOW}{Colors.BOLD} - Unused Variables{Colors.RESET}")
            logger.info(f"{Colors.YELLOW}{'=' * 18}{Colors.RESET}")
            for i, item in enumerate(unused_variables, 1):
                logger.info(f"{Colors.GRAY}{i:2d}. {Colors.RESET}{Colors.YELLOW}{item['name']}{Colors.RESET}")
                logger.info(f"    {Colors.GRAY}└─ {item['file']}:{item['line']}{Colors.RESET}")
        else:
            logger.info(f"\n{Colors.GREEN}✓ All variables are being used!{Colors.RESET}")
                
        if unused_classes:
            logger.info(f"\n{Colors.YELLOW}{Colors.BOLD} - Unused Classes{Colors.RESET}")
            logger.info(f"{Colors.YELLOW}{'=' * 18}{Colors.RESET}")
            for i, item in enumerate(unused_classes, 1):
                logger.info(f"{Colors.GRAY}{i:2d}. {Colors.RESET}{Colors.YELLOW}{item['name']}{Colors.RESET}")
                logger.info(f"    {Colors.GRAY}└─ {item['file']}:{item['line']}{Colors.RESET}")
        else:
            logger.info(f"\n{Colors.GREEN}✓ All classes are being used!{Colors.RESET}")

        dead_code_count = len(unused_functions) + len(unused_imports) + len(unused_variables) + len(unused_classes) + len(unused_parameters)

        print_badge(dead_code_count, logger)

        if unused_functions or unused_imports:
            logger.info(f"\n{Colors.BOLD}Next steps:{Colors.RESET}")
            logger.info(f" * Use --select specific items to remove")
            logger.info(f" * Use --dry-run to preview changes")
            logger.info(f" * Use --exclude-folder to skip directories")

if __name__ == "__main__":
    main()