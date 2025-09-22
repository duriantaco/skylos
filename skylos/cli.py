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
    comment_out_unused_import_cst,
    comment_out_unused_function_cst, 
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
    
    console_handler = logging.StreamHandler(sys.stderr)
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
    
def comment_out_unused_import(file_path, import_name, line_number, marker="SKYLOS DEADCODE"):
    path = pathlib.Path(file_path)
    try:
        src = path.read_text(encoding="utf-8")
        new_code, changed = comment_out_unused_import_cst(src, import_name, line_number, marker=marker)
        if not changed:
            return False
        path.write_text(new_code, encoding="utf-8")
        return True
    except Exception as e:
        logging.error(f"Failed to comment out import {import_name} from {file_path}: {e}")
        return False

def comment_out_unused_function(file_path, function_name, line_number, marker="SKYLOS DEADCODE"):
    path = pathlib.Path(file_path)
    try:
        src = path.read_text(encoding="utf-8")
        new_code, changed = comment_out_unused_function_cst(src, function_name, line_number, marker=marker)
        if not changed:
            return False
        path.write_text(new_code, encoding="utf-8")
        return True
    except Exception as e:
        logging.error(f"Failed to comment out function {function_name} from {file_path}: {e}")
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
        logger.info(f"\n{Colors.MAGENTA}{Colors.BOLD}Select unused imports to act on (hit spacebar to select):{Colors.RESET}")
        
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
        "--table",
        action="store_true",
        help="Show findings in table"
    )

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
        "--comment-out",
        action="store_true",
        help="Comment out selected dead code instead of deleting it",
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

    parser.add_argument("--secrets", action="store_true",
                   help="Scan for API keys. Off by default.")
    
    parser.add_argument("--danger", action="store_true",
                   help="Scan for security issues. Off by default.")
    
    args = parser.parse_args()

    if args.list_default_excludes:
        print("Default excluded folders:")
        for folder in sorted(DEFAULT_EXCLUDE_FOLDERS):
            print(f" {folder}")
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
        result_json = run_analyze(args.path, conf=args.confidence, enable_secrets=bool(args.secrets), 
                                  enable_danger=bool(args.danger), exclude_folders=list(final_exclude_folders))

        if args.json:
            print(result_json)
            return

        result = json.loads(result_json)

    except Exception as e:
        logger.error(f"Error during analysis: {e}")
        sys.exit(1)
    
    if args.table:
        ELLIPSIS = "…"

        def clip(text, max_length):
            if not text:
                text = ""
            
            if len(text) <= max_length:
                return text
            
            truncated_end = max(0, max_length - 1)
            return text[:truncated_end] + ELLIPSIS

        def severity_color(severity):
            severity_upper = (severity or "").upper()
            
            if severity_upper in ("HIGH", "CRITICAL"):
                return Colors.RED
            elif severity_upper == "MEDIUM":
                return Colors.YELLOW
            else:
                return Colors.GRAY

        print(f"\n{Colors.CYAN}{Colors.BOLD}Unused {Colors.RESET}")
        print(f"{Colors.CYAN}{'='*18}{Colors.RESET}")

        print(f"{Colors.BOLD}{'kind':9} {'name':28} {'where'}{Colors.RESET}")
        print(f"{'-'*9} {'-'*28} {'-'*36}")
        
        unused_categories = [
            ("unused_functions", "function"),
            ("unused_imports", "import"),
            ("unused_classes", "class"),
            ("unused_variables", "variable"),
            ("unused_parameters", "parameter"),
        ]

        for bucket, kind in unused_categories:
            items = result.get(bucket, [])
            for item in items:
                name = item.get("name") or item.get("simple_name") or ""
                file_path = item.get('file', '?')
                line_num = item.get('line', item.get('lineno', '?'))
                where = f"{file_path}:{line_num}"
                
                clipped_name = clip(name, 28)
                clipped_where = clip(where, 36)
                print(f"{kind:9} {clipped_name:28} {clipped_where}")

        secrets = result.get("secrets", []) or []
        if secrets:
            print(f"\n{Colors.RED}{Colors.BOLD}Secrets{Colors.RESET}")
            print(f"{Colors.RED}{'=' * 7}{Colors.RESET}")
            print(f"{Colors.BOLD}{'provider':12} {'message':22} {'preview':24} {'where'}{Colors.RESET}")
            print(f"{'-' * 12} {'-' * 22} {'-' * 24} {'-' * 36}")
            
            for secret in secrets[:100]:
                provider = clip(secret.get("provider") or "generic", 12)
                message = clip(secret.get("message") or "Secret detected", 22)
                preview = clip(secret.get("preview") or "****", 24)
                
                file_path = secret.get('file', '?')
                line_num = secret.get('line', '?')
                location = f"{file_path}:{line_num}"
                clipped_location = clip(location, 36)
                
                print(f"{Colors.MAGENTA}{provider:12}{Colors.RESET} {message:22} {preview:24} {clipped_location}")

            
        security_issues = result.get("danger", [])
        if security_issues:
            print(f"\n{Colors.RED}{Colors.BOLD}Security issues{Colors.RESET}")
            print(f"{Colors.RED}{'=' * 15}{Colors.RESET}")
            print(f"{Colors.BOLD}{'rule_id':10} {'sev':5} {'message':38} {'where'}{Colors.RESET}")
            print(f"{'-' * 10} {'-' * 5} {'-' * 38} {'-' * 36}")
            
            for issue in security_issues[:100]:
                rule_id = clip(issue.get("rule_id") or "", 10)
                severity = (issue.get("severity") or "").upper()
                message = clip(issue.get("message") or "", 38)
                
                file_path = issue.get('file', '?')
                line_num = issue.get('line', '?')
                location = f"{file_path}:{line_num}"
                clipped_location = clip(location, 36)
                
                severity_color_code = severity_color(severity)
                clipped_severity = clip(severity, 5)
                
                print(f"{rule_id:10} {severity_color_code}{clipped_severity:5}{Colors.RESET} {message:38} {clipped_location}")

        summ = result.get("analysis_summary", {})
        unused_keys = [
            "unused_functions",
            "unused_imports", 
            "unused_classes",
            "unused_variables",
            "unused_parameters"
        ]

        total_unused = 0
        for k in unused_keys:
            total_unused += len(result.get(k, []))
  
        print(f"\n{Colors.BOLD}Summary{Colors.RESET}")

        print("=======")
        print(f"files analyzed : {summ.get('total_files','?')}")
        print(f"unused items   : {total_unused}")
        if "secrets_count" in summ:
            print(f"secrets        : {summ['secrets_count']}")
        if "dangerous_count" in summ:
            print(f"security issues: {summ['dangerous_count']}")
        return

    if args.json:
        lg = logging.getLogger('skylos')
        for h in list(lg.handlers):
            if isinstance(h, logging.StreamHandler):
                lg.removeHandler(h)
        print(result_json)
        return
    
    result = json.loads(result_json)

    unused_functions = result.get("unused_functions", [])
    unused_imports = result.get("unused_imports", [])
    unused_parameters = result.get("unused_parameters", [])
    unused_variables = result.get("unused_variables", [])
    unused_classes = result.get("unused_classes", [])
    secrets_findings = result.get("secrets", [])
    danger_findings = result.get("danger", [])
    
    logger.info(f"{Colors.CYAN}{Colors.BOLD} Python Static Analysis Results{Colors.RESET}")
    logger.info(f"{Colors.CYAN}{'=' * 35}{Colors.RESET}")
    
    logger.info(f"\n{Colors.BOLD}Summary:{Colors.RESET}")
    logger.info(f" * Unreachable functions: {Colors.YELLOW}{len(unused_functions)}{Colors.RESET}")
    logger.info(f" * Unused imports: {Colors.YELLOW}{len(unused_imports)}{Colors.RESET}")
    logger.info(f" * Unused parameters: {Colors.YELLOW}{len(unused_parameters)}{Colors.RESET}")
    logger.info(f" * Unused variables: {Colors.YELLOW}{len(unused_variables)}{Colors.RESET}")
    logger.info(f" * Unused classes: {Colors.YELLOW}{len(unused_classes)}{Colors.RESET}")
    if secrets_findings:
        logger.info(f" * Secrets: {Colors.RED}{len(secrets_findings)}{Colors.RESET}")
    if danger_findings:
        logger.info(f" * Security issues: {Colors.RED}{len(danger_findings)}{Colors.RESET}")

    if args.interactive and (unused_functions or unused_imports):
        logger.info(f"\n{Colors.BOLD}Interactive Mode:{Colors.RESET}")
        selected_functions, selected_imports = interactive_selection(logger, unused_functions, unused_imports)
        
        if selected_functions or selected_imports:
            logger.info(f"\n{Colors.BOLD}Selected items to process:{Colors.RESET}")
            
            if selected_functions:
                logger.info(f" Functions: {len(selected_functions)}")
                for func in selected_functions:
                    logger.info(f"  - {func['name']} ({func['file']}: {func['line']})")
            
            if selected_imports:
                logger.info(f" Imports: {len(selected_imports)}")
                for imp in selected_imports:
                    logger.info(f"  - {imp['name']} ({imp['file']}: {imp['line']})")
            
            if not args.dry_run:
                if args.comment_out:
                    confirm_verb = "comment out"
                else:
                    confirm_verb = "remove"

                questions = [
                    inquirer.Confirm('confirm',
                                   message="Are you sure you want to process these items?",
                                   default=False)
                ]
                answers = inquirer.prompt(questions)
                
                if answers and answers['confirm']:
                    action = "Commenting out" if args.comment_out else "Removing"
                    logger.info(f"\n{Colors.YELLOW}{action} selected items...{Colors.RESET}")

                    action_func = comment_out_unused_function if args.comment_out else remove_unused_function
                    if args.comment_out:
                        action_past = "Commented out"
                        action_verb = "comment out"
                    else:
                        action_past = "Removed"
                        action_verb = "remove"

                    for func in selected_functions:
                        success = action_func(func['file'], func['name'], func['line'])
                        
                        if success:
                            logger.info(f"  {Colors.GREEN} ✓ {Colors.RESET} {action_past} function: {func['name']}")
                        else:
                            logger.error(f"  {Colors.RED} x {Colors.RESET} Failed to {action_verb}: {func['name']}")
                            
                    import_func = comment_out_unused_import if args.comment_out else remove_unused_import
                    if args.comment_out:
                        action_past = "Commented out"
                        action_verb = "comment out"
                    else:
                        action_past = "Removed"
                        action_verb = "remove"

                    for imp in selected_imports:
                        success = import_func(imp['file'], imp['name'], imp['line'])
                        
                        if success:
                            logger.info(f"  {Colors.GREEN} ✓ {Colors.RESET} {action_past} import: {imp['name']}")
                        else:
                            logger.error(f"  {Colors.RED} x {Colors.RESET} Failed to {action_verb}: {imp['name']}")
                            
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

        if secrets_findings:
            logger.info(f"\n{Colors.RED}{Colors.BOLD} - Secrets{Colors.RESET}")
            logger.info(f"{Colors.RED}{'=' * 9}{Colors.RESET}")
            for i, s in enumerate(secrets_findings[:20], 1):
                provider = s.get("provider", "generic")
                where = f"{s.get('file','?')}:{s.get('line','?')}"
                prev = s.get("preview", "****")
                msg = s.get("message", "Secret detected")
                logger.info(f"{Colors.GRAY}{i:2d}. {Colors.RESET}{msg} [{provider}] {Colors.GRAY}({where}){Colors.RESET} -> {prev}")
        
        if danger_findings:
            logger.info(f"\n{Colors.RED}{Colors.BOLD} - Security Issues{Colors.RESET}")
            logger.info(f"{Colors.RED}{'=' * 16}{Colors.RESET}")
            for i, d in enumerate(danger_findings[:20], 1):
                rule_id = d.get("rule_id", "unknown_rule")
                severity = d.get("severity", "UNKNOWN").upper()
                message = d.get("message", "Issue detected")
                file = d.get("file", "?")
                line = d.get("line", "?")
                logger.info(f"{Colors.GRAY}{i:2d}. {Colors.RESET}{message} [{rule_id}] {Colors.GRAY}({file}:{line}){Colors.RESET} Severity: {severity}")

        dead_code_count = len(unused_functions) + len(unused_imports) + len(unused_variables) + len(unused_classes) + len(unused_parameters)

        print_badge(dead_code_count, logger)

        if unused_functions or unused_imports:
            logger.info(f"\n{Colors.BOLD}Next steps:{Colors.RESET}")
            logger.info(f" * Use --select specific items to remove")
            logger.info(f" * Use --dry-run to preview changes")
            logger.info(f" * Use --exclude-folder to skip directories")

if __name__ == "__main__":
    main()