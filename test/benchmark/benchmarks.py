#!/usr/bin/env python3
"""
Simple benchmark script for Skylos vs other Python static analysis tools.
Automatically installs missing tools.
"""

import json
import time
import subprocess
import sys
from pathlib import Path

# Colors for pretty output
class c:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def check_and_install_tool(tool_name, package_name=None):
    """Check if a tool is installed, install if missing"""
    package_name = package_name or tool_name
    
    # Check if tool exists
    try:
        subprocess.run([tool_name, '--version'], capture_output=True, check=True)
        print(f"  {c.GREEN}✓{c.RESET} {tool_name} already installed")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"  {c.YELLOW}Installing {tool_name}...{c.RESET}")
        try:
            subprocess.run([sys.executable, '-m', 'pip', 'install', package_name], check=True)
            print(f"  {c.GREEN}✓{c.RESET} {tool_name} installed successfully")
            return True
        except subprocess.CalledProcessError:
            print(f"  {c.RED}✗{c.RESET} Failed to install {tool_name}")
            return False

def install_all_tools():
    """Install all benchmark tools"""
    print(f"{c.BOLD}Checking and installing benchmark tools...{c.RESET}")
    
    tools = [
        ('vulture', None),
        ('flake8', None),
        ('pylint', None),
        ('autoflake', None),
        ('dead', 'dead')  # dead might need explicit package name
    ]
    
    success_count = 0
    for tool, package in tools:
        if check_and_install_tool(tool, package):
            success_count += 1
    
    print(f"\n{success_count}/{len(tools)} tools successfully installed/verified")
    return success_count

def run_skylos(project_path):
    """Run Skylos analysis"""
    print(f"\n{c.BOLD}Running Skylos...{c.RESET}")
    start = time.time()
    try:
        import skylos
        result = json.loads(skylos.analyze(str(project_path)))
        elapsed = time.time() - start
        
        functions = len(result.get('unused_functions', []))
        imports = len(result.get('unused_imports', []))
        total = functions + imports
        
        print(f"  Time: {elapsed:.3f}s")
        print(f"  Unused functions: {functions}")
        print(f"  Unused imports: {imports}")
        print(f"  Total issues: {total}")
        return elapsed, total, functions, imports
    except Exception as e:
        print(f"  {c.RED}Error: {e}{c.RESET}")
        return 0, 0, 0, 0

def run_vulture(project_path, min_confidence=60):
    """Run Vulture analysis with adjustable confidence level"""
    print(f"\n{c.BOLD}Running Vulture (confidence: {min_confidence}%)...{c.RESET}")
    start = time.time()
    try:
        cmd = ['vulture', str(project_path), f'--min-confidence={min_confidence}']
        result = subprocess.run(cmd, capture_output=True, text=True)
        elapsed = time.time() - start
        
        # Count issues in output
        functions = result.stdout.count('unused function')
        imports = result.stdout.count('unused import')
        total = functions + imports
        
        print(f"  Time: {elapsed:.3f}s")
        print(f"  Unused functions: {functions}")
        print(f"  Unused imports: {imports}")
        print(f"  Total issues: {total}")
        return elapsed, total, functions, imports
    except FileNotFoundError:
        print(f"  {c.RED}Vulture not found - skipping{c.RESET}")
        return 0, 0, 0, 0
    except Exception as e:
        print(f"  {c.RED}Error: {e}{c.RESET}")
        return 0, 0, 0, 0

def run_flake8(project_path):
    """Run Flake8 analysis (unused imports only)"""
    print(f"\n{c.BOLD}Running Flake8...{c.RESET}")
    start = time.time()
    try:
        cmd = ['flake8', '--select=F401', str(project_path)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        elapsed = time.time() - start
        
        # Count unused imports (F401)
        imports = result.stdout.count('F401')
        
        print(f"  Time: {elapsed:.3f}s")
        print(f"  Unused functions: 0 (not supported)")
        print(f"  Unused imports: {imports}")
        print(f"  Total issues: {imports}")
        return elapsed, imports, 0, imports
    except FileNotFoundError:
        print(f"  {c.RED}Flake8 not found - skipping{c.RESET}")
        return 0, 0, 0, 0
    except Exception as e:
        print(f"  {c.RED}Error: {e}{c.RESET}")
        return 0, 0, 0, 0

def run_pylint(project_path):
    """Run Pylint analysis"""
    print(f"\n{c.BOLD}Running Pylint...{c.RESET}")
    start = time.time()
    try:
        cmd = ['pylint', '--disable=all', '--enable=unused-import,unused-variable', str(project_path)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        elapsed = time.time() - start
        
        # Count issues
        imports = result.stdout.count('unused-import')
        variables = result.stdout.count('unused-variable')
        
        print(f"  Time: {elapsed:.3f}s")
        print(f"  Unused functions: {variables} (as variables)")
        print(f"  Unused imports: {imports}")
        print(f"  Total issues: {variables + imports}")
        return elapsed, variables + imports, variables, imports
    except FileNotFoundError:
        print(f"  {c.RED}Pylint not found - skipping{c.RESET}")
        return 0, 0, 0, 0
    except Exception as e:
        print(f"  {c.RED}Error: {e}{c.RESET}")
        return 0, 0, 0, 0

def run_dead(project_path):
    """Run dead analysis"""
    print(f"\n{c.BOLD}Running dead...{c.RESET}")
    start = time.time()
    try:
        cmd = ['dead', str(project_path)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        elapsed = time.time() - start
        
        # Count functions (dead focuses on functions)
        functions = len([line for line in result.stdout.splitlines() if line.strip() and not line.startswith('#')])
        
        print(f"  Time: {elapsed:.3f}s")
        print(f"  Unused functions: {functions}")
        print(f"  Unused imports: 0 (not supported)")
        print(f"  Total issues: {functions}")
        return elapsed, functions, functions, 0
    except FileNotFoundError:
        print(f"  {c.RED}dead not found - skipping{c.RESET}")
        return 0, 0, 0, 0
    except Exception as e:
        print(f"  {c.RED}Error: {e}{c.RESET}")
        return 0, 0, 0, 0

def main():
    # Find the sample project
    script_dir = Path(__file__).parent.parent.parent
    sample_project = script_dir / 'test' / 'sample_project'
    
    if not sample_project.exists():
        print(f"{c.RED}Error: sample_project not found at {sample_project}{c.RESET}")
        print("Make sure you're running this from the Skylos repository root")
        return
    
    print(f"{c.BOLD}Skylos Benchmark Suite{c.RESET}")
    print(f"Testing against: {sample_project}")
    print("="*50)
    
    # Auto-install tools
    install_all_tools()
    print("="*50)
    
    # Run benchmarks
    results = {}
    tools = {
        'Skylos': run_skylos,
        'Vulture (100%)': lambda p: run_vulture(p, 90),  # almost sure it's dead code
        'Vulture (60%)': lambda p: run_vulture(p, 60),
        'Vulture (0%)': lambda p: run_vulture(p, 0),      # everything suspicious
        'Flake8': run_flake8,
        'Pylint': run_pylint,
        'Dead': run_dead
    }
    for name, func in tools.items():
        elapsed, total, functions, imports = func(sample_project)
        results[name] = {
            'time': elapsed,
            'total': total,
            'functions': functions,
            'imports': imports
        }
    
    # Summary table
    print(f"\n{c.BOLD}Summary{c.RESET}")
    print("="*70)
    print(f"{'Tool':<10} {'Time (s)':<10} {'Functions':<12} {'Imports':<10} {'Total':<8}")
    print("-"*70)
    
    for name, data in results.items():
        print(f"{name:<10} {data['time']:<10.3f} {data['functions']:<12} {data['imports']:<10} {data['total']:<8}")
    
    print("-"*70)
    
    # Speed comparison
    active_tools = {name: data for name, data in results.items() if data['time'] > 0}
    if active_tools:
        skylos_time = results['Skylos']['time']
        fastest = min(r['time'] for r in active_tools.values())
        slowest = max(r['time'] for r in active_tools.values())
        
        print(f"\n{c.BOLD}Speed Analysis:{c.RESET}")
        print(f"  Fastest: {fastest:.3f}s")
        print(f"  Slowest: {slowest:.3f}s")
        print(f"  Skylos: {skylos_time:.3f}s ({skylos_time/fastest:.1f}x vs fastest)")
        
        # Detection analysis
        skylos_total = results['Skylos']['total']
        max_total = max(r['total'] for r in active_tools.values())
        
        print(f"\n{c.BOLD}Detection Analysis:{c.RESET}")
        print(f"  Most issues found: {max_total}")
        print(f"  Skylos found: {skylos_total} ({skylos_total/max_total*100:.1f}% coverage)")
        
        # Show which tools found issues
        print(f"\n{c.BOLD}Tools by detection coverage:{c.RESET}")
        for name, data in sorted(active_tools.items(), key=lambda x: x[1]['total'], reverse=True):
            if data['total'] > 0:
                percent = (data['total'] / max_total) * 100
                print(f"  {name}: {data['total']} issues ({percent:.1f}%)")

if __name__ == '__main__':
    main()