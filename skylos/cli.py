import argparse
import json
import sys
import logging
import ast
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
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    GRAY = '\033[90m'

class CleanFormatter(logging.Formatter):
    """Custom formatter that removes timestamps and log levels for clean output"""
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

def remove_unused_import(file_path: str, import_name: str, line_number: int) -> bool:
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
        
        line_idx = line_number - 1
        original_line = lines[line_idx].strip()
        
        if original_line.startswith(f'import {import_name}'):
            lines[line_idx] = ''
        elif original_line.startswith('import ') and f' {import_name}' in original_line:
            parts = original_line.split(' ', 1)[1].split(',')
            new_parts = [p.strip() for p in parts if p.strip() != import_name]
            if new_parts:
                lines[line_idx] = f'import {", ".join(new_parts)}\n'
            else:
                lines[line_idx] = ''
        elif original_line.startswith('from ') and import_name in original_line:
            if f'import {import_name}' in original_line and ',' not in original_line:
                lines[line_idx] = ''
            else:
                parts = original_line.split('import ', 1)[1].split(',')
                new_parts = [p.strip() for p in parts if p.strip() != import_name]
                if new_parts:
                    prefix = original_line.split(' import ')[0]
                    lines[line_idx] = f'{prefix} import {", ".join(new_parts)}\n'
                else:
                    lines[line_idx] = ''
        
        with open(file_path, 'w') as f:
            f.writelines(lines)
        
        return True
    except Exception as e:
        logging.error(f"Failed to remove import {import_name} from {file_path}: {e}")
        return False

def remove_unused_function(file_path: str, function_name: str, line_number: int) -> bool:
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        
        tree = ast.parse(content)
        
        lines = content.splitlines()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if (node.name in function_name and 
                    node.lineno == line_number):
                    
                    start_line = node.lineno - 1
                    
                    if node.decorator_list:
                        start_line = node.decorator_list[0].lineno - 1
                    
                    end_line = len(lines)
                    base_indent = len(lines[start_line]) - len(lines[start_line].lstrip())
                    
                    for i in range(node.end_lineno, len(lines)):
                        if lines[i].strip() == '':
                            continue
                        current_indent = len(lines[i]) - len(lines[i].lstrip())
                        if current_indent <= base_indent and lines[i].strip():
                            end_line = i
                            break
                    
                    while end_line < len(lines) and lines[end_line].strip() == '':
                        end_line += 1
                    
                    new_lines = lines[:start_line] + lines[end_line:]
                    
                    with open(file_path, 'w') as f:
                        f.write('\n'.join(new_lines) + '\n')
                    
                    return True
        
        return False
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
        logger.info(f"\n{Colors.CYAN}{Colors.BOLD}Select unused functions to remove:{Colors.RESET}")
        
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
        logger.info(f"\n{Colors.MAGENTA}{Colors.BOLD}Select unused imports to remove:{Colors.RESET}")
        
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
    """Print appropriate badge based on dead code count"""
    logger.info(f"\n{Colors.GRAY}{'─' * 50}{Colors.RESET}")
    
    if dead_code_count == 0:
        logger.info(f"✨ Your code is 100% dead code free! Add this badge to your README:")
        logger.info("```markdown")
        logger.info("![Dead Code Free](https://img.shields.io/badge/Dead_Code-Free-brightgreen?logo=moleculer&logoColor=white)")
        logger.info("```")
    else:
        logger.info(f"Found {dead_code_count} dead code items. Add this badge to your README:")
        logger.info("```markdown")  
        logger.info(f"![Dead Code: {dead_code_count}](https://img.shields.io/badge/Dead_Code-{dead_code_count}_detected-orange?logo=codacy&logoColor=red)")
        logger.info("```")

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Detect unreachable functions and unused imports in a Python project"
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
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--interactive", "-i",
        action="store_true",
        help="Interactively select items to remove (requires inquirer)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be removed without actually modifying files"
    )

    args = parser.parse_args()
    logger = setup_logger(args.output)
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug(f"Analyzing path: {args.path}")

    try:
        result_json = skylos.analyze(args.path)
        result = json.loads(result_json)
    except Exception as e:
        logger.error(f"Error during analysis: {e}")
        sys.exit(1)

    if args.json:
        logger.info(result_json)
        return

    unused_functions = result.get("unused_functions", [])
    unused_imports = result.get("unused_imports", [])
    
    logger.info(f"{Colors.CYAN}{Colors.BOLD}🔍 Python Static Analysis Results{Colors.RESET}")
    logger.info(f"{Colors.CYAN}{'=' * 35}{Colors.RESET}")
    
    logger.info(f"\n{Colors.BOLD}Summary:{Colors.RESET}")
    logger.info(f"  • Unreachable functions: {Colors.YELLOW}{len(unused_functions)}{Colors.RESET}")
    logger.info(f"  • Unused imports: {Colors.YELLOW}{len(unused_imports)}{Colors.RESET}")
    
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
                            logger.info(f"  {Colors.GREEN}✓{Colors.RESET} Removed function: {func['name']}")
                        else:
                            logger.error(f"  {Colors.RED}✗{Colors.RESET} Failed to remove: {func['name']}")
                    
                    for imp in selected_imports:
                        success = remove_unused_import(imp['file'], imp['name'], imp['line'])
                        if success:
                            logger.info(f"  {Colors.GREEN}✓{Colors.RESET} Removed import: {imp['name']}")
                        else:
                            logger.error(f"  {Colors.RED}✗{Colors.RESET} Failed to remove: {imp['name']}")
                    
                    logger.info(f"\n{Colors.GREEN}Cleanup complete!{Colors.RESET}")
                else:
                    logger.info(f"\n{Colors.YELLOW}Operation cancelled.{Colors.RESET}")
            else:
                logger.info(f"\n{Colors.YELLOW}Dry run - no files were modified.{Colors.RESET}")
        else:
            logger.info(f"\n{Colors.BLUE}No items selected.{Colors.RESET}")
    
    else:
        if unused_functions:
            logger.info(f"\n{Colors.RED}{Colors.BOLD}📦 Unreachable Functions{Colors.RESET}")
            logger.info(f"{Colors.RED}{'=' * 23}{Colors.RESET}")
            for i, item in enumerate(unused_functions, 1):
                logger.info(f"{Colors.GRAY}{i:2d}. {Colors.RESET}{Colors.RED}{item['name']}{Colors.RESET}")
                logger.info(f"    {Colors.GRAY}└─ {item['file']}:{item['line']}{Colors.RESET}")
        else:
            logger.info(f"\n{Colors.GREEN}✓ All functions are reachable!{Colors.RESET}")
        
        if unused_imports:
            logger.info(f"\n{Colors.MAGENTA}{Colors.BOLD}📥 Unused Imports{Colors.RESET}")
            logger.info(f"{Colors.MAGENTA}{'=' * 16}{Colors.RESET}")
            for i, item in enumerate(unused_imports, 1):
                logger.info(f"{Colors.GRAY}{i:2d}. {Colors.RESET}{Colors.MAGENTA}{item['name']}{Colors.RESET}")
                logger.info(f"    {Colors.GRAY}└─ {item['file']}:{item['line']}{Colors.RESET}")
        else:
            logger.info(f"\n{Colors.GREEN}✓ All imports are being used!{Colors.RESET}")
        
        dead_code_count = len(unused_functions) + len(unused_imports)
        print_badge(dead_code_count, logger)

        if unused_functions or unused_imports:
            logger.info(f"\n{Colors.BOLD}Next steps:{Colors.RESET}")
            logger.info(f"  • Use --interactive to select specific items to remove")
            logger.info(f"  • Use --dry-run to preview changes before applying them")

if __name__ == "__main__":
    main()