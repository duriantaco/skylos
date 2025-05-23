#!/usr/bin/env python3
import sys
import json
import subprocess
import re
from pathlib import Path

def load_ground_truth(path):
    """Load the ground truth data from a ground_truth.json file with the Skylos test structure"""
    try:
        with open(path, 'r') as f:
            data = json.load(f)
            
            dead_items = []
            if "files" in data and "code.py" in data["files"]:
                if "dead_items" in data["files"]["code.py"]:
                    return data["files"]["code.py"]["dead_items"]
            
            return []
    except Exception as e:
        print(f"Error loading ground truth from {path}: {e}")
        return []

def run_skylos_on_file(code_file, skylos_path):
    try:
        cmd = [sys.executable, skylos_path, str(code_file)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"Error running Skylos subprocess: {result.stderr}")
            return {}
        
        json_start = result.stdout.find('{')
        if json_start > -1:
            json_str = result.stdout[json_start:]
            try:
                return json.loads(json_str)
            except json.JSONDecodeError:
                print(f"Error parsing Skylos JSON output")
                return {}
        else:
            print(f"Could not find JSON in output")
            return {}
    except Exception as e:
        print(f"Error running Skylos: {e}")
        return {}

def run_vulture_on_file(code_file, confidence=0):
    try:
        cmd = ["vulture", str(code_file), f"--min-confidence={confidence}"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        items = []
        pattern = r"([^:]+):(\d+): (\w+) '([^']+)' is never used"
        
        for line in result.stdout.splitlines():
            match = re.search(pattern, line)
            if match:
                filename, lineno, item_type, name = match.groups()
                
                if item_type == "unused variable":
                    continue
                elif item_type == "unused import":
                    normalized_type = "import"
                elif item_type == "unused class":
                    normalized_type = "class"
                elif item_type == "unused function":
                    if "." in name:
                        normalized_type = "method"
                    else:
                        normalized_type = "function"
                elif item_type == "unused method":
                    normalized_type = "method"
                elif item_type == "unused property":
                    normalized_type = "method" 
                else:
                    normalized_type = item_type.replace("unused ", "")
                
                if normalized_type == "method" and "." in name:
                    items.append({
                        "name": name,
                        "type": normalized_type,
                        "file": filename,
                        "line": int(lineno)
                    })
                else:
                    items.append({
                        "name": name,
                        "type": normalized_type,
                        "file": filename,
                        "line": int(lineno)
                    })
        
        return items
    except Exception as e:
        print(f"Error running Vulture on {code_file}: {e}")
        return []

def normalize_item(item):
    if isinstance(item, str):
        return item
    
    name = item.get("name", "")
    
    if item.get("type") == "method" and "." in name:
        parts = name.split(".")
        if len(parts) > 2:
            return ".".join(parts[-2:])
        return name
    
    # for other types, just get the last part
    if "." in name:
        return name.split(".")[-1]
    
    return name

def get_skylos_results_as_list(skylos_results):
    """Convert Skylos JSON results to a flat list of items"""
    result = []
    
    for item in skylos_results.get("unused_functions", []):
        # try to determine if its a method or function based on name
        if "." in item["name"]:
            item_type = "method"
        else:
            item_type = "function"
        
        result.append({
            "name": item["name"],
            "type": item_type,
            "file": item.get("file", ""),
            "line": item.get("line", 0)
        })
    
    for item in skylos_results.get("unused_imports", []):
        result.append({
            "name": item["name"],
            "type": "import",
            "file": item.get("file", ""),
            "line": item.get("line", 0)
        })
    
    for item in skylos_results.get("unused_classes", []):
        result.append({
            "name": item["name"],
            "type": "class",
            "file": item.get("file", ""),
            "line": item.get("line", 0)
        })
    
    return result

def find_test_cases(test_dir):
    """Find all test cases in the directory structure"""
    test_cases = []
    
    for path in Path(test_dir).rglob("ground_truth.json"):
        code_file = path.parent / "code.py"
        if code_file.exists():
            test_cases.append({
                "name": path.parent.name,
                "code_file": code_file,
                "ground_truth_file": path
            })
    
    return test_cases

def compare_results(skylos_results, vulture_results, ground_truth, test_case):
    """Compare tool results with ground truth for a single test case"""
    gt_normalized = set()
    for item in ground_truth:
        if isinstance(item, dict):
            gt_normalized.add((normalize_item(item), item.get("type")))
    
    skylos_flat = get_skylos_results_as_list(skylos_results)
    skylos_normalized = set()
    for item in skylos_flat:
        skylos_normalized.add((normalize_item(item), item.get("type")))
    
    vulture_normalized = set()
    for item in vulture_results:
        vulture_normalized.add((normalize_item(item), item.get("type")))
    
    skylos_tp = skylos_normalized.intersection(gt_normalized)
    skylos_fp = skylos_normalized - gt_normalized
    skylos_fn = gt_normalized - skylos_normalized
    
    vulture_tp = vulture_normalized.intersection(gt_normalized)
    vulture_fp = vulture_normalized - gt_normalized
    vulture_fn = gt_normalized - vulture_normalized
    
    vulture_only_tp = vulture_tp - skylos_tp
    
    skylos_only_tp = skylos_tp - vulture_tp
    
    return {
        "name": test_case["name"],
        "ground_truth_count": len(gt_normalized),
        "skylos": {
            "tp": skylos_tp,
            "fp": skylos_fp,
            "fn": skylos_fn,
            "tp_count": len(skylos_tp),
            "fp_count": len(skylos_fp),
            "fn_count": len(skylos_fn),
            "precision": len(skylos_tp) / len(skylos_normalized) if skylos_normalized else 0,
            "recall": len(skylos_tp) / len(gt_normalized) if gt_normalized else 0,
        },
        "vulture": {
            "tp": vulture_tp,
            "fp": vulture_fp,
            "fn": vulture_fn, 
            "tp_count": len(vulture_tp),
            "fp_count": len(vulture_fp),
            "fn_count": len(vulture_fn),
            "precision": len(vulture_tp) / len(vulture_normalized) if vulture_normalized else 0,
            "recall": len(vulture_tp) / len(gt_normalized) if gt_normalized else 0,
        },
        "vulture_only_tp": vulture_only_tp,
        "skylos_only_tp": skylos_only_tp
    }

def print_test_result(result):
    """Print results for a single test case"""
    print(f"\n=== Test Case: {result['name']} ===")
    print(f"Ground Truth: {result['ground_truth_count']} items")
    
    print("\nSkylos Results:")
    print(f"  True Positives: {result['skylos']['tp_count']}")
    print(f"  False Positives: {result['skylos']['fp_count']}")
    print(f"  False Negatives: {result['skylos']['fn_count']}")
    print(f"  Precision: {result['skylos']['precision']:.4f}")
    print(f"  Recall: {result['skylos']['recall']:.4f}")
    
    print("\nVulture Results:")
    print(f"  True Positives: {result['vulture']['tp_count']}")
    print(f"  False Positives: {result['vulture']['fp_count']}")
    print(f"  False Negatives: {result['vulture']['fn_count']}")
    print(f"  Precision: {result['vulture']['precision']:.4f}")
    print(f"  Recall: {result['vulture']['recall']:.4f}")
    
    if result['skylos']['fp_count'] > 0:
        print("\nSkylos False Positives (items Skylos flags that should be used):")
        for item in result['skylos']['fp']:
            print(f"  - {item[0]} ({item[1]})")
    
    if result['skylos']['fn_count'] > 0:
        print("\nSkylos False Negatives (items Skylos misses that should be flagged):")
        for item in result['skylos']['fn']:
            print(f"  - {item[0]} ({item[1]})")
    
    if result['vulture_only_tp']:
        print("\nVulture-only True Positives (What Vulture catches correctly but Skylos misses):")
        for item in result['vulture_only_tp']:
            print(f"  - {item[0]} ({item[1]})")
    
    if result['skylos_only_tp']:
        print("\nSkylos-only True Positives (What Skylos catches correctly but Vulture misses):")
        for item in result['skylos_only_tp']:
            print(f"  - {item[0]} ({item[1]})")

def main():
    if len(sys.argv) < 3:
        print("Usage: python analyze_test_cases.py <skylos_path> <test_cases_dir>")
        return
    
    skylos_path = sys.argv[1]
    test_dir = sys.argv[2]
    
    print(f"Finding test cases in {test_dir}...")
    test_cases = find_test_cases(test_dir)
    print(f"Found {len(test_cases)} test cases.")
    
    total_results = {
        "test_cases": len(test_cases),
        "ground_truth_total": 0,
        "skylos": {
            "tp_total": 0,
            "fp_total": 0,
            "fn_total": 0,
            "precision_avg": 0,
            "recall_avg": 0
        },
        "vulture": {
            "tp_total": 0,
            "fp_total": 0,
            "fn_total": 0,
            "precision_avg": 0,
            "recall_avg": 0
        },
        "problem_cases": []
    }
    
    test_results = []
    for test_case in test_cases:
        print(f"\nProcessing test case: {test_case['name']}...")
        
        ground_truth = load_ground_truth(test_case["ground_truth_file"])
        total_results["ground_truth_total"] += len(ground_truth)
        
        skylos_results = run_skylos_on_file(test_case["code_file"], skylos_path)
        
        vulture_results = run_vulture_on_file(test_case["code_file"])
        
        result = compare_results(skylos_results, vulture_results, ground_truth, test_case)
        test_results.append(result)
        
        total_results["skylos"]["tp_total"] += result["skylos"]["tp_count"]
        total_results["skylos"]["fp_total"] += result["skylos"]["fp_count"]
        total_results["skylos"]["fn_total"] += result["skylos"]["fn_count"]
        total_results["skylos"]["precision_avg"] += result["skylos"]["precision"]
        total_results["skylos"]["recall_avg"] += result["skylos"]["recall"]
        
        total_results["vulture"]["tp_total"] += result["vulture"]["tp_count"]
        total_results["vulture"]["fp_total"] += result["vulture"]["fp_count"] 
        total_results["vulture"]["fn_total"] += result["vulture"]["fn_count"]
        total_results["vulture"]["precision_avg"] += result["vulture"]["precision"]
        total_results["vulture"]["recall_avg"] += result["vulture"]["recall"]
        
        if result["skylos"]["fp_count"] > 0 or result["skylos"]["fn_count"] > 0:
            total_results["problem_cases"].append({
                "name": test_case["name"],
                "fp": result["skylos"]["fp_count"],
                "fn": result["skylos"]["fn_count"]
            })
        
        print_test_result(result)
    
    if test_cases:
        total_results["skylos"]["precision_avg"] /= len(test_cases)
        total_results["skylos"]["recall_avg"] /= len(test_cases)
        total_results["vulture"]["precision_avg"] /= len(test_cases)
        total_results["vulture"]["recall_avg"] /= len(test_cases)
    
    print("\n=== OVERALL SUMMARY ===")
    print(f"Total Test Cases: {total_results['test_cases']}")
    print(f"Total Ground Truth Items: {total_results['ground_truth_total']}")
    
    print("\nSkylos Overall Results:")
    print(f"  Total True Positives: {total_results['skylos']['tp_total']}")
    print(f"  Total False Positives: {total_results['skylos']['fp_total']}")
    print(f"  Total False Negatives: {total_results['skylos']['fn_total']}")
    print(f"  Average Precision: {total_results['skylos']['precision_avg']:.4f}")
    print(f"  Average Recall: {total_results['skylos']['recall_avg']:.4f}")
    
    print("\nVulture Overall Results:")
    print(f"  Total True Positives: {total_results['vulture']['tp_total']}")
    print(f"  Total False Positives: {total_results['vulture']['fp_total']}")
    print(f"  Total False Negatives: {total_results['vulture']['fn_total']}")
    print(f"  Average Precision: {total_results['vulture']['precision_avg']:.4f}")
    print(f"  Average Recall: {total_results['vulture']['recall_avg']:.4f}")
    
    if total_results["problem_cases"]:
        print("\nProblem Test Cases (with Skylos FP or FN):")
        sorted_problems = sorted(total_results["problem_cases"], 
                                key=lambda x: x["fp"] + x["fn"], 
                                reverse=True)
        for case in sorted_problems:
            print(f"  - {case['name']} (FP: {case['fp']}, FN: {case['fn']})")
        
        print("\nRecommendation: Fix these specific test cases to improve Skylos performance.")

if __name__ == "__main__":
    main()