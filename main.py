"""ASM Tool - Asset Scanning and Management."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from controller.workflow import run_full_scan, run_nuclei_scan
from database.db_manager import (
    get_default_scan_targets,
    get_scan_result_json,
    initialize_database,
    list_scans,
    save_scan_results,
)
from modules.utils import (
    validate_target,
    create_data_directories,
    save_results_json,
)


def print_header(title: str) -> None:
    """Print a formatted header."""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def print_error(message: str) -> None:
    """Print an error message."""
    print(f"\n[ERROR] {message}", file=sys.stderr)


def print_info(message: str) -> None:
    """Print an informational message."""
    print(f"\n[INFO] {message}")


def print_menu() -> None:
    print_header("ASM Tool - Asset Scanning and Management")
    print("\nThis tool supports the following operations:")
    print("  1. Default Scanning")
    print("  2. CVE Scanning")
    print("  3. View scan history")
    print("  4. Exit")


def prompt_target() -> str | None:
    target = input("\nEnter target domain or IP address: ").strip()
    if not target:
        print_error("Target cannot be empty.")
        return None

    is_valid, target_type = validate_target(target)
    if not is_valid:
        print_error(f"Invalid target format: {target}")
        print("Please provide a valid domain (e.g., example.com), IP address (e.g., 192.168.1.0), or host:port (e.g., 127.0.0.1:8080)")
        return None

    print_info(f"Target type: {target_type.upper()}")
    return target


def format_filename_segment(value: str) -> str:
    sanitized = value
    for invalid in [".", "/", "\\", ",", ";", ":", "?", "*", '"', "<", ">", "|"]:
        sanitized = sanitized.replace(invalid, "_")
    return sanitized


def list_template_files() -> list[Path]:
    """Return a sorted list of template file Paths under the `templates/` folder."""
    p = Path("templates")
    if not p.exists() or not p.is_dir():
        return []
    files = sorted([f for f in p.glob("*.yaml")] + [f for f in p.glob("*.yml")])
    return files


def save_and_report_scan(conn, results: dict, scan_label: str, target_name: str) -> None:
    print_header("Saving Results")
    try:
        scan_id = save_scan_results(conn, results, scan_label)
        print_info(f"Results saved to DB: scan_id={scan_id}")
    except Exception as exc:
        print_error(f"Failed to save results to database: {exc}")

    try:
        filename = f"scan_{scan_label}_{format_filename_segment(target_name)}_{results['timestamp']}"
        filepath = save_results_json(results, filename)
        print_info(f"Results saved to: {filepath}")
    except Exception as exc:
        print_error(f"Failed to save results: {exc}")


def print_scan_summary(results: dict, scan_label: str) -> None:
    print_header("Summary")
    if scan_label == "default_scanning":
        print(f"\nSubfinder:  {results['subfinder']['status'].upper()}")
        if results['subfinder']['status'] == 'success':
            print(f"  - Found {len(results['subfinder']['results'])} subdomain(s)")

        print(f"\nNaabu:      {results['naabu']['status'].upper()}")
        if results['naabu']['status'] == 'success':
            print(f"  - Found {len(results['naabu']['results'])} open port(s)")

        print(f"\nNmap:       {results['nmap']['status'].upper()}")
        if results['nmap']['status'] == 'success':
            print(f"  - Analyzed {len(results['nmap']['results'])} service(s)")
    else:
        print(f"\nCVE Scan:   {results['nuclei']['status'].upper()}")
        if results['nuclei']['status'] == 'success':
            print(f"  - Found {len(results['nuclei']['results'])} finding(s)")

    print("\n" + "=" * 70)
    print("Scan complete!")
    print("=" * 70 + "\n")


def choose_previous_default_scan(conn) -> int | None:
    scans = list_scans(conn, "default_scanning")
    if not scans:
        print_info("No Default Scanning history found.")
        return None

    print_header("Default Scanning History")
    for row in scans:
        print(f"ID {row['id']}: {row['created_at']} | {row['target']}")

    selection = input("\nEnter scan ID to reuse or press Enter to cancel: ").strip()
    if not selection:
        return None

    if not selection.isdigit():
        print_error("Scan ID must be a number.")
        return None

    return int(selection)


def choose_targets_from_scan(conn, scan_id: int) -> list[str] | None:
    targets = get_default_scan_targets(conn, scan_id)
    if not targets:
        print_error("No targets were found for the selected Default scan.")
        return None

    if len(targets) == 1:
        print_info(f"Found one target: {targets[0]}")
        return targets

    print_header("Available Hosts from Default Scanning")
    for idx, host in enumerate(targets, start=1):
        print(f"  {idx}. {host}")

    use_all = input("\nScan all hosts from this result? [Y/n]: ").strip().lower()
    if use_all in {"", "y", "yes"}:
        return targets

    selection = input("Enter host numbers separated by commas: ").strip()
    if not selection:
        print_error("No hosts selected.")
        return None

    indices = [item.strip() for item in selection.split(",") if item.strip().isdigit()]
    chosen = []
    for index in indices:
        idx = int(index) - 1
        if 0 <= idx < len(targets):
            chosen.append(targets[idx])

    if not chosen:
        print_error("No valid hosts selected.")
        return None

    return chosen


def run_default_scanning(conn) -> None:
    target = prompt_target()
    if not target:
        return

    results = run_full_scan(target)
    save_and_report_scan(conn, results, "default_scanning", target)
    print_scan_summary(results, "default_scanning")


def run_cve_scanning(conn) -> None:
    reuse_choice = input("\nReuse a previous Default Scanning result? [Y/n]: ").strip().lower()
    selected_targets = None
    target_name = ""

    if reuse_choice in {"", "y", "yes"}:
        scan_id = choose_previous_default_scan(conn)
        if scan_id is not None:
            selected_targets = choose_targets_from_scan(conn, scan_id)
            if selected_targets:
                target_name = ",".join(selected_targets)

    if selected_targets is None:
        target = prompt_target()
        if not target:
            return
        selected_targets = target
        target_name = target

    templates_input = input("Enter Nuclei template path or leave blank to choose from templates folder: ").strip()
    templates = None

    if templates_input:
        templates = templates_input
    else:
        files = list_template_files()
        if files:
            print_header("Available Nuclei Templates")
            for idx, f in enumerate(files, start=1):
                print(f"  {idx}. {f.name}")

            selection = input("\nSelect template number (comma-separated for multiple), 0 for all templates, or press Enter to use all: ").strip()
            if selection == "":
                templates = None
            elif selection == "0":
                templates = None
            else:
                nums = [s.strip() for s in selection.split(",") if s.strip().isdigit()]
                chosen = []
                for n in nums:
                    idx = int(n) - 1
                    if 0 <= idx < len(files):
                        chosen.append(str(files[idx]))
                if chosen:
                    templates = ",".join(chosen) if len(chosen) > 1 else chosen[0]
                else:
                    print_info("No valid templates selected; using all templates.")
                    templates = None
        else:
            print_info("No templates found in templates/ folder. You can provide a path manually.")
            templates = None

    results = run_nuclei_scan(selected_targets, templates)
    save_and_report_scan(conn, results, "cve_scanning", target_name)
    print_scan_summary(results, "cve_scanning")


def view_scan_history(conn) -> None:
    scans = list_scans(conn)
    if not scans:
        print_info("No scan history found.")
        return

    print_header("Scan History")
    for row in scans:
        print(f"ID {row['id']}: {row['created_at']} | {row['scan_label']} | {row['target']}")

    selection = input("\nEnter scan ID to view details or press Enter to return: ").strip()
    if not selection:
        return

    if not selection.isdigit():
        print_error("Scan ID must be a number.")
        return

    scan_id = int(selection)
    results = get_scan_result_json(conn, scan_id)
    if not results:
        print_error("No details available for selected scan.")
        return

    print_header(f"Scan Details: ID {scan_id}")
    print(json.dumps(results, indent=2, ensure_ascii=False))


def main() -> None:
    create_data_directories()
    conn = initialize_database()

    try:
        while True:
            print_menu()
            choice = input("\nSelect option [1-4]: ").strip()

            if choice == "1":
                run_default_scanning(conn)
            elif choice == "2":
                run_cve_scanning(conn)
            elif choice == "3":
                view_scan_history(conn)
            elif choice == "4":
                print_info("Exiting program.")
                break
            else:
                print_error("Invalid selection. Please choose 1, 2, 3, or 4.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()

