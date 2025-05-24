#!/usr/bin/env python3
import subprocess
import sys
import os
import json
import time
from pathlib import Path
import re
import shutil
import argparse
import pandas as pd

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

def check_tool_exists(tool_name):
    return shutil.which(tool_name) is not None

def install_tool(tool_name):
    if check_tool_exists(tool_name):
        print(f"✅ {tool_name} is already installed")
        return True
        
    print(f"Installing {tool_name}...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", tool_name], check=True)
        print(f"✅ {tool_name} installed successfully")
        return True
    except subprocess.SubprocessError as e:
        print(f"⚠️ Error installing {tool_name}: {e}")
        return False

def load_ground_truth(test_dir):
    ground_truth_items = []
    
    for gt_file in Path(test_dir).glob("**/ground_truth.json"):
        try:
            with open(gt_file, 'r') as f:
                data = json.load(f)
                
            test_case_dir = gt_file.parent
            
            for file_name, file_data in data["files"].items():
                for item in file_data.get("dead_items", []):
                    full_path = test_case_dir / file_name
                    ground_truth_items.append({
                        "type": item["type"],
                        "name": item["name"],
                        "simple_name": extract_simple_name(item["name"]),
                        "file": str(full_path),
                        "basename": file_name,
                        "line": item.get("line_start", 0),
                        "category": data.get("category", "unknown")
                    })
        except Exception as e:
            print(f"Error loading {gt_file}: {e}")
    
    return ground_truth_items

def extract_simple_name(full_name):
    if '.' in full_name:
        return full_name.split('.')[-1]
    return full_name

def run_vulture(test_dir, confidence=60):
    try:
        installed = install_tool("vulture")
        if not installed:
            return {"tool": f"Vulture ({confidence}%)", "items": [], "time": 0}
        
        print(f"Running Vulture with {confidence}% confidence...")
        start_time = time.time()
        output = subprocess.run(["vulture", "--min-confidence", str(confidence), test_dir], 
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE, 
                                universal_newlines=True)
        
        detected_items = []
        for line in output.stdout.splitlines():
            if ':' not in line:
                continue
                
            match = re.match(r'(.+?):(\d+): (.+?) \'(.+?)\' (.+)', line)
            if match:
                file_path, line_num, item_type, name, _ = match.groups()
                
                if "unused function" in item_type:
                    item_type = "function"
                elif "unused method" in item_type:
                    item_type = "method"
                elif "unused class" in item_type:
                    item_type = "class"
                elif "unused import" in item_type:
                    item_type = "import"
                elif "unused variable" in item_type:
                    item_type = "variable"
                else:
                    continue
                
                detected_items.append({
                    "type": item_type,
                    "name": name,
                    "simple_name": extract_simple_name(name),
                    "file": file_path,
                    "basename": Path(file_path).name,
                    "line": int(line_num)
                })
        
        elapsed_time = time.time() - start_time
        return {
            "tool": f"Vulture ({confidence}%)",
            "items": detected_items,
            "time": elapsed_time,
            "capabilities": ["function", "method", "class", "import", "variable"]
        }
    except Exception as e:
        print(f"Error running Vulture: {e}")
        return {"tool": f"Vulture ({confidence}%)", "items": [], "time": 0, "capabilities": []}

def run_skylos_local(test_dir):
    """Run the locally installed development version of Skylos"""
    try:
        start_time = time.time()
        
        try:
            import skylos
        except ImportError as e:
            print(f"Error importing local skylos: {e}")
            return {"tool": "Skylos (Local Dev)", "items": [], "time": 0, "capabilities": []}
        
        try:
            result_json = skylos.analyze(test_dir)
            data = json.loads(result_json)
            
            detected_items = []
            
            for item in data.get("unused_functions", []):
                name = item["name"]
                
                if "." in name:
                    parts = name.split(".")
                    
                    if len(parts) >= 2 and parts[-2][0].isupper():
                        item_type = "method"
                        clean_name = f"{parts[-2]}.{parts[-1]}"
                    elif any(p[0].isupper() for p in parts[:-1]):
                        item_type = "function" 
                        clean_name = parts[-1]
                    else:
                        item_type = "function"
                        clean_name = name
                else:
                    clean_name = name
                    item_type = "function"
                
                detected_items.append({
                    "type": item_type,
                    "name": clean_name,
                    "simple_name": extract_simple_name(clean_name),
                    "file": item["file"],
                    "basename": Path(item["file"]).name,
                    "line": item["line"]
                })
            
            for item in data.get("unused_imports", []):
                name = item["name"].strip()
                name = re.sub(r'^[\(\s]+|[\)\s]+$', '', name)
                name = re.sub(r'#.*$', '', name).strip()
                
                detected_items.append({
                    "type": "import",
                    "name": name,
                    "simple_name": extract_simple_name(name),
                    "file": item["file"],
                    "basename": Path(item["file"]).name,
                    "line": item["line"]
                })
                
            for item in data.get("unused_classes", []):
                detected_items.append({
                    "type": "class",
                    "name": item["name"],
                    "simple_name": extract_simple_name(item["name"]),
                    "file": item["file"],
                    "basename": Path(item["file"]).name,
                    "line": item["line"]
                })
                        
            elapsed_time = time.time() - start_time
            return {
                "tool": "Skylos (Local Dev)",
                "items": detected_items,
                "time": elapsed_time,
                "capabilities": ["function", "method", "class", "import"]
            }
            
        except Exception as e:
            print(f"Analysis error with local Skylos: {e}")
            # import traceback
            # traceback.print_exc()
            return {"tool": "Skylos (Local Dev)", "items": [], "time": 0, "capabilities": []}
    except Exception as e:
        print(f"Error running local Skylos: {e}")
        return {"tool": "Skylos (Local Dev)", "items": [], "time": 0, "capabilities": []}

def run_flake8(test_dir):
    try:
        installed = install_tool("flake8")
        if not installed:
            return {"tool": "Flake8", "items": [], "time": 0, "capabilities": []}
        
        print(f"Running Flake8...")
        start_time = time.time()
        output = subprocess.run(["flake8", "--select=F401", test_dir], 
                              stdout=subprocess.PIPE, 
                              stderr=subprocess.PIPE, 
                              universal_newlines=True)
        
        detected_items = []
        for line in output.stdout.splitlines():
            if ':' not in line:
                continue
                
            match = re.match(r'(.+?):(\d+):\d+: F401 \'(.+?)\' imported but unused', line)
            if match:
                file_path, line_num, name = match.groups()
                
                detected_items.append({
                    "type": "import",
                    "name": name,
                    "simple_name": extract_simple_name(name),
                    "file": file_path,
                    "basename": Path(file_path).name,
                    "line": int(line_num)
                })
        
        elapsed_time = time.time() - start_time
        return {
            "tool": "Flake8",
            "items": detected_items,
            "time": elapsed_time,
            "capabilities": ["import"]
        }
    except Exception as e:
        print(f"Error running Flake8: {e}")
        return {"tool": "Flake8", "items": [], "time": 0, "capabilities": []}

def run_pylint(test_dir):
    try:
        installed = install_tool("pylint")
        if not installed:
            return {"tool": "Pylint", "items": [], "time": 0, "capabilities": []}
        
        print(f"Running Pylint...")
        start_time = time.time()
        cmd = ["pylint", "--disable=all", "--enable=unused-import,unused-variable,unused-argument", test_dir]
        output = subprocess.run(cmd, 
                              stdout=subprocess.PIPE, 
                              stderr=subprocess.PIPE, 
                              universal_newlines=True)
        
        detected_items = []
        for line in output.stdout.splitlines():
            if ':' not in line:
                continue
                
            match = re.match(r'(.+?):(\d+):.*: (Unused import|Unused variable|Unused argument) (.+)', line)
            if match:
                file_path, line_num, warning_type, name = match.groups()
                
                if "import" in warning_type:
                    item_type = "import"
                elif "variable" in warning_type:
                    item_type = "variable"
                elif "argument" in warning_type:
                    item_type = "variable"
                else:
                    continue
                    
                name = name.strip()
                if "'" in name:
                    name = name.split("'")[1]
                
                detected_items.append({
                    "type": item_type,
                    "name": name,
                    "simple_name": extract_simple_name(name),
                    "file": file_path,
                    "basename": Path(file_path).name,
                    "line": int(line_num)
                })
        
        elapsed_time = time.time() - start_time
        return {
            "tool": "Pylint",
            "items": detected_items,
            "time": elapsed_time,
            "capabilities": ["import", "variable"]
        }
    except Exception as e:
        print(f"Error running Pylint: {e}")
        return {"tool": "Pylint", "items": [], "time": 0, "capabilities": []}
        
def run_ruff(test_dir):
    try:
        installed = install_tool("ruff")
        if not installed:
            return {"tool": "Ruff", "items": [], "time": 0, "capabilities": []}
        
        print(f"Running Ruff...")
        start_time = time.time()
        command = ["ruff", "check", "--select=F401,F811,F841,F504,F505", "--verbose", test_dir]
        print(f"Running command: {' '.join(command)}")
        
        output = subprocess.run(command,
                              stdout=subprocess.PIPE, 
                              stderr=subprocess.PIPE, 
                              universal_newlines=True)
        
        detected_items = []
        for line in output.stdout.splitlines():
            if ':' not in line or line.startswith(' ') or line.startswith('='):
                continue
                
            match = re.match(r'(.+?):(\d+):\d+: (F\d+)(?:\s+\[\*\])?\s+(.+)', line)
            if match:
                file_path, line_num, code, message = match.groups()
                
                if code == "F401":
                    name_match = re.search(r'`(.+?)`', message)
                    if name_match:
                        name = name_match.group(1)
                        detected_items.append({
                            "type": "import",
                            "name": name,
                            "simple_name": extract_simple_name(name),
                            "file": file_path,
                            "basename": Path(file_path).name,
                            "line": int(line_num)
                        })
                elif code == "F841":
                    name_match = re.search(r'`(.+?)`', message)
                    if name_match:
                        name = name_match.group(1)
                        detected_items.append({
                            "type": "variable",
                            "name": name,
                            "simple_name": extract_simple_name(name),
                            "file": file_path,
                            "basename": Path(file_path).name,
                            "line": int(line_num)
                        })
                elif code == "F811":
                    name_match = re.search(r'`(.+?)`', message)
                    if name_match:
                        name = name_match.group(1)
                        detected_items.append({
                            "type": "function",
                            "name": name,
                            "simple_name": extract_simple_name(name),
                            "file": file_path,
                            "basename": Path(file_path).name,
                            "line": int(line_num)
                        })
                elif code in ("F504", "F505"):
                    detected_items.append({
                        "type": "unreachable",
                        "name": f"unreachable code at line {line_num}",
                        "simple_name": "unreachable",
                        "file": file_path,
                        "basename": Path(file_path).name,
                        "line": int(line_num)
                    })
        
        print(f"Ruff found {len(detected_items)} items")
        
        elapsed_time = time.time() - start_time
        return {
            "tool": "Ruff",
            "items": detected_items,
            "time": elapsed_time,
            "capabilities": ["import", "function", "variable", "unreachable"]
        }
    except Exception as e:
        print(f"Error running Ruff: {e}")
        import traceback
        traceback.print_exc()
        return {"tool": "Ruff", "items": [], "time": 0, "capabilities": []}

def calculate_metrics(detected_items, ground_truth_items):
    """Calculate metrics using normalized item names and types"""
    detected_set = {(normalize_item(item), item["type"]) for item in detected_items}
    ground_truth_set = {(normalize_item(item), item["type"]) for item in ground_truth_items}
    
    true_positives = detected_set.intersection(ground_truth_set)
    false_positives = detected_set - ground_truth_set
    false_negatives = ground_truth_set - detected_set
    
    precision = len(true_positives) / max(len(detected_set), 1)
    recall = len(true_positives) / max(len(ground_truth_set), 1)
    f1_score = 2 * precision * recall / max(precision + recall, 1e-10)
    
    return {
        "true_positives": len(true_positives),
        "false_positives": len(false_positives),
        "false_negatives": len(false_negatives),
        "precision": precision,
        "recall": recall,
        "f1_score": f1_score
    }

def calculate_metrics_by_type(detected_items, ground_truth_items, capabilities):
    metrics_by_type = {}
    
    for item_type in capabilities:
        type_detected = [i for i in detected_items if i["type"] == item_type]
        type_ground_truth = [i for i in ground_truth_items if i["type"] == item_type]
        
        if type_ground_truth:
            metrics_by_type[item_type] = calculate_metrics(type_detected, type_ground_truth)
        else:
            metrics_by_type[item_type] = {
                "true_positives": 0,
                "false_positives": len(type_detected),
                "false_negatives": 0,
                "precision": 0.0,
                "recall": 0.0,
                "f1_score": 0.0
            }
    
    return metrics_by_type

def normalize_item(item):
    """Normalize an item name for better comparison"""
    if isinstance(item, str):
        return item
    
    name = item.get("name", "")
    
    if item.get("type") == "method" and "." in name:
        parts = name.split(".")
        if len(parts) > 2:
            return ".".join(parts[-2:])
        return name
    
    if "." in name:
        return name.split(".")[-1]
    
    return name

def run_benchmarks(test_dir, output_dir=None):
    
    ground_truth_items = load_ground_truth(test_dir)
    
    tools = [
        run_skylos_local(test_dir),
        run_vulture(test_dir, 0),
        run_vulture(test_dir, 60),
        run_flake8(test_dir),
        run_pylint(test_dir),
        run_ruff(test_dir),
    ]
    
    results = []
    metrics_by_type = {}
    
    for tool_result in tools:
        tool_name = tool_result["tool"]
        items = tool_result["items"]
        time_taken = tool_result["time"]
        capabilities = tool_result["capabilities"]
            
        if tool_result is None:
            print(f"Error: Tool returned None instead of results dictionary")
            continue 

        overall_metrics = calculate_metrics(items, ground_truth_items)
        type_metrics = calculate_metrics_by_type(items, ground_truth_items, capabilities)
        
        metrics_by_type[tool_name] = type_metrics
        
        result = {
            "tool": tool_name,
            "time": time_taken,
            "item_count": len(items),
            "overall": overall_metrics,
            "by_type": type_metrics,
            "capabilities": capabilities
        }
        results.append(result)
    
    print_results(results, ground_truth_items)


    if output_dir:
        output_dir_path = Path(output_dir)
        output_dir_path.mkdir(exist_ok=True)
        generate_charts(results, ground_truth_items, output_dir_path)
    
    return results

def print_results(results, ground_truth_items):
    print("\n")
    print(f"{Colors.BOLD}Benchmark Results Summary{Colors.END}")
    print("=" * 80)
    
    print(f"{Colors.BOLD}Overall Performance (All Dead Code Types Combined){Colors.END}")
    print("-" * 80)
    print(f"{'Tool':<20} {'Time (s)':<10} {'Items':<8} {'TP':<5} {'FP':<5} {'FN':<5} {'Precision':<10} {'Recall':<10} {'F1 Score':<10}")
    print("-" * 80)
    
    for result in results:
        tool = result["tool"]
        time_taken = result["time"]
        item_count = result["item_count"]
        overall = result["overall"]
        
        print(f"{tool:<20} {time_taken:<10.3f} {item_count:<8} {overall['true_positives']:<5} "
              f"{overall['false_positives']:<5} {overall['false_negatives']:<5} {overall['precision']:<10.4f} "
              f"{overall['recall']:<10.4f} {overall['f1_score']:<10.4f}")
    
    print("\n")
    print(f"{Colors.BOLD}Performance by Dead Code Type (Fair Comparison){Colors.END}")
    
    types = set()
    for result in results:
        types.update(result["capabilities"])
    
    for dead_code_type in sorted(types):
        type_gt = [i for i in ground_truth_items if i["type"] == dead_code_type]
        if not type_gt:
            continue
            
        print(f"\n{Colors.BOLD}Type: {dead_code_type} (Ground Truth: {len(type_gt)} items){Colors.END}")
        print("-" * 80)
        print(f"{'Tool':<20} {'TP':<5} {'FP':<5} {'FN':<5} {'Precision':<10} {'Recall':<10} {'F1 Score':<10}")
        print("-" * 80)
        
        for result in results:
            if dead_code_type not in result["capabilities"]:
                continue
                
            tool = result["tool"]
            by_type = result["by_type"]
            
            if dead_code_type in by_type:
                metrics = by_type[dead_code_type]
                print(f"{tool:<20} {metrics['true_positives']:<5} {metrics['false_positives']:<5} "
                    f"{metrics['false_negatives']:<5} {metrics['precision']:<10.4f} "
                    f"{metrics['recall']:<10.4f} {metrics['f1_score']:<10.4f}")
            else:
                print(f"{tool:<20} {'N/A':<5} {'N/A':<5} {'N/A':<5} {'N/A':<10} {'N/A':<10} {'N/A':<10}")

def generate_charts(results, ground_truth_items, output_dir):
    types = set()
    for result in results:
        types.update(result["capabilities"])
    
    data = []
    for dead_code_type in sorted(types):
        type_gt = [i for i in ground_truth_items if i["type"] == dead_code_type]
        if not type_gt:
            continue
            
        for result in results:
            if dead_code_type not in result["capabilities"]:
                continue
                
            tool = result["tool"]
            by_type = result["by_type"]
            
            if dead_code_type in by_type:
                metrics = by_type[dead_code_type]
                data.append({
                    "Tool": tool,
                    "Type": dead_code_type,
                    "Precision": metrics["precision"],
                    "Recall": metrics["recall"],
                    "F1": metrics["f1_score"],
                    "True Positives": metrics["true_positives"],
                    "False Positives": metrics["false_positives"],
                    "Time": result["time"]
                })
    
    df = pd.DataFrame(data)
    
def main():
    parser = argparse.ArgumentParser(description="Fair Dead Code Detection Benchmark")
    parser.add_argument("test_dir", nargs="?", default="cases", help="Directory containing test cases")
    parser.add_argument("--output", "-o", help="Directory to output charts and reports")
    args = parser.parse_args()
    
    print(f"{Colors.BOLD}Fair Dead Code Detection Benchmark{Colors.END}")
    print(f"{Colors.BOLD}==============================={Colors.END}")
    
    run_benchmarks(args.test_dir, args.output)

if __name__ == "__main__":
    main()