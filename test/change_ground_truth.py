import json
import argparse
from pathlib import Path
import os

def update_item_names_in_file_data(file_data, file_module_fqn, dry_run=False):
    """
    Updates 'name' fields in dead_items and live_items to be fully qualified.
    Returns True if any changes were made, False otherwise.
    """
    changed = False
    for item_list_key in ["dead_items", "live_items"]:
        items = file_data.get(item_list_key, [])
        for item in items:
            original_name = item.get("name")
            item_type = item.get("type")

            if not original_name or not item_type:
                continue

            expected_fqn_prefix = file_module_fqn + "."
            
            if not original_name.startswith(expected_fqn_prefix):
                new_name = expected_fqn_prefix + original_name
                if not dry_run:
                    item["name"] = new_name
                print(f"    - Type '{item_type}', Name: '{original_name}' -> '{new_name}'")
                changed = True
            else:
                print(f"    - Type '{item_type}', Name: '{original_name}' (already qualified, skipped)")
    return changed

def process_ground_truth_file(gt_file_path, root_test_dir_abs, dry_run=False):

    print(f"\nProcessing: {gt_file_path}")
    try:
        with open(gt_file_path, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"  Error: Could not decode JSON from {gt_file_path}. Skipping. ({e})")
        return
    except Exception as e:
        print(f"  Error reading {gt_file_path}. Skipping. ({e})")
        return

    gt_file_dir_abs = gt_file_path.parent
    made_any_changes_in_json = False

    for code_filename_key, file_data in data.get("files", {}).items():
        if not code_filename_key.endswith(".py"):
            print(f"  Skipping non-Python file entry: {code_filename_key}")
            continue

      
        try:
            relative_dir_of_code_file = gt_file_dir_abs.relative_to(root_test_dir_abs)
        except ValueError:
            print(f"  Error: Cannot determine relative path for {gt_file_dir_abs} from {root_test_dir_abs}. Skipping file entries.")
            continue
            
        module_parts = list(relative_dir_of_code_file.parts)
        
        code_file_stem = Path(code_filename_key).stem
        module_parts.append(code_file_stem)
        
        file_module_fqn = ".".join(part for part in module_parts if part) 

        print(f"  Processing entries for '{code_filename_key}' (module FQN base: {file_module_fqn})")
        if update_item_names_in_file_data(file_data, file_module_fqn, dry_run):
            made_any_changes_in_json = True

    if made_any_changes_in_json and not dry_run:
        try:
            with open(gt_file_path, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"  Successfully updated and saved {gt_file_path}")
        except Exception as e:
            print(f"  Error writing updated JSON to {gt_file_path}: {e}")
    elif dry_run and made_any_changes_in_json:
        print(f"  Dry run: Changes would be made to {gt_file_path}")
    elif not made_any_changes_in_json:
        print(f"  No changes needed for {gt_file_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Update 'name' fields in ground_truth.json files to be Fully Qualified Names (FQNs)."
    )
    parser.add_argument(
        "test_dir",
        type=str,
        help="The root directory containing test cases and ground_truth.json files (e.g., 'cases')."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be changed without actually modifying files."
    )
    args = parser.parse_args()

    root_test_dir = Path(args.test_dir)
    if not root_test_dir.is_dir():
        print(f"Error: The specified test directory '{args.test_dir}' does not exist or is not a directory.")
        return

    root_test_dir_abs = root_test_dir.resolve()
    print(f"Starting FQN update process for ground_truth.json files in: {root_test_dir_abs}")
    if args.dry_run:
        print("DRY RUN MODE: No files will be modified.")

    gt_files_found = list(root_test_dir_abs.rglob("ground_truth.json"))

    if not gt_files_found:
        print("No 'ground_truth.json' files found in the specified directory.")
        return

    for gt_file_path_abs in gt_files_found:
        process_ground_truth_file(gt_file_path_abs, root_test_dir_abs, args.dry_run)

    print("\nProcess finished.")
    if args.dry_run:
        print("DRY RUN COMPLETED. No files were changed.")
    else:
        print("Updates completed. Please review the changes.")

if __name__ == "__main__":
    main()
