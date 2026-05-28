"""ASM workflow controller for scan orchestration."""

from __future__ import annotations

import sys

from scanner.naabu_scan import (
    NaabuExecutionError,
    NaabuNotInstalledError,
    run_naabu,
)
from scanner.nmap_scan import (
    NmapExecutionError,
    NmapNotInstalledError,
    run_nmap,
)
from scanner.nuclei_scan import (
    NucleiExecutionError,
    NucleiNotInstalledError,
    run_nuclei,
)
from scanner.subfinder_scan import (
    SubfinderExecutionError,
    SubfinderNotInstalledError,
    run_subfinder,
)
from modules.utils import (
    validate_target,
    save_results_json,
    get_timestamp,
    format_subdomain_output,
    format_naabu_output,
    format_nmap_output,
    format_nuclei_output,
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


def run_full_scan(target: str) -> dict:
    """Run the Default Scanning sequence."""
    results = {
        "timestamp": get_timestamp(),
        "target": target,
        "subfinder": {"status": "pending", "results": []},
        "naabu": {"status": "pending", "results": []},
        "nmap": {"status": "pending", "results": []},
    }

    print_header("STEP 1: Subdomain Discovery (Subfinder)")
    try:
        print_info(f"Scanning subdomains for: {target}")
        subfinder_out = run_subfinder(target)
        subdomains = subfinder_out.get("parsed", [])

        print(format_subdomain_output(subdomains, target))
        # Also print raw output for debugging / fidelity
        raw = subfinder_out.get("raw", "")
        err = subfinder_out.get("stderr", "")
        print_header("RAW: Subfinder stdout")
        if raw:
            print(raw)
        else:
            print("(no stdout captured)")
        if err:
            print_header("RAW: Subfinder stderr")
            print(err)

        results["subfinder"]["status"] = "success"
        results["subfinder"]["results"] = subdomains
        results["subfinder"]["raw"] = subfinder_out.get("raw", "")
        if not subdomains:
            print_info("No subdomains found. Using original target for port scanning.")
            subdomains = [target]

    except SubfinderNotInstalledError as exc:
        print_error(str(exc))
        results["subfinder"]["status"] = "error"
        results["subfinder"]["error"] = str(exc)
        return results
    except SubfinderExecutionError as exc:
        print_error(str(exc))
        results["subfinder"]["status"] = "error"
        results["subfinder"]["error"] = str(exc)
        return results
    except ValueError as exc:
        print_error(f"Invalid input: {exc}")
        results["subfinder"]["status"] = "error"
        results["subfinder"]["error"] = str(exc)
        return results

    print_header("STEP 2: Port Scanning (Naabu)")
    try:
        print_info(f"Scanning open ports on {len(subdomains)} host(s)")
        naabu_out = run_naabu(subdomains)
        naabu_results = naabu_out.get("parsed", [])

        print(format_naabu_output(naabu_results))
        raw = naabu_out.get("raw", "")
        err = naabu_out.get("stderr", "")
        print_header("RAW: Naabu stdout")
        if raw:
            print(raw)
        else:
            print("(no stdout captured)")
        if err:
            print_header("RAW: Naabu stderr")
            print(err)

        results["naabu"]["status"] = "success"
        results["naabu"]["results"] = naabu_results
        results["naabu"]["raw"] = naabu_out.get("raw", "")

        if not naabu_results:
            print_info("No open ports found. Skipping service detection.")
            return results

    except NaabuNotInstalledError as exc:
        print_error(str(exc))
        results["naabu"]["status"] = "error"
        results["naabu"]["error"] = str(exc)
        return results
    except NaabuExecutionError as exc:
        print_error(str(exc))
        results["naabu"]["status"] = "error"
        results["naabu"]["error"] = str(exc)
        return results
    except ValueError as exc:
        print_error(f"Invalid input: {exc}")
        results["naabu"]["status"] = "error"
        results["naabu"]["error"] = str(exc)
        return results

    print_header("STEP 3: Service & OS Detection (Nmap)")
    try:
        # Group ports by host for nmap
        from collections import defaultdict
        host_ports = defaultdict(set)
        for result in naabu_results:
            host = result['host']
            port = result['port']
            host_ports[host].add(port)
        
        # Build targets list: ["host:port1,port2", ...]
        targets = []
        for host, ports in sorted(host_ports.items()):
            port_str = ",".join(str(p) for p in sorted(ports))
            targets.append(f"{host}:{port_str}")

        print_info(f"Analyzing {len(host_ports)} host(s) with {sum(len(p) for p in host_ports.values())} port(s)")
        print_info("This may take several minutes, please wait...")

        nmap_out = run_nmap(targets)
        nmap_results = nmap_out.get("parsed", [])

        print(format_nmap_output(nmap_results))
        raw = nmap_out.get("raw", "")
        err = nmap_out.get("stderr", "")
        print_header("RAW: Nmap stdout")
        if raw:
            print(raw)
        else:
            print("(no stdout captured)")
        if err:
            print_header("RAW: Nmap stderr")
            print(err)

        results["nmap"]["status"] = "success"
        results["nmap"]["results"] = nmap_results
        results["nmap"]["raw"] = nmap_out.get("raw", "")

    except NmapNotInstalledError as exc:
        print_error(str(exc))
        results["nmap"]["status"] = "error"
        results["nmap"]["error"] = str(exc)
    except NmapExecutionError as exc:
        print_error(str(exc))
        results["nmap"]["status"] = "error"
        results["nmap"]["error"] = str(exc)
    except ValueError as exc:
        print_error(f"Invalid input: {exc}")
        results["nmap"]["status"] = "error"
        results["nmap"]["error"] = str(exc)

    return results


def run_nuclei_scan(target: str, templates: str | None = None) -> dict:
    """Run the Nuclei vulnerability scan workflow."""
    results = {
        "timestamp": get_timestamp(),
        "target": target,
        "nuclei": {"status": "pending", "results": []},
    }

    print_header("STEP 1: Vulnerability Detection (Nuclei)")
    try:
        print_info(f"Scanning target with Nuclei: {target}")
        nuclei_out = run_nuclei(target, templates)
        nuclei_results = nuclei_out.get("parsed", [])

        print(format_nuclei_output(nuclei_results))
        raw = nuclei_out.get("raw", "")
        err = nuclei_out.get("stderr", "")
        print_header("RAW: Nuclei stdout")
        if raw:
            print(raw)
        else:
            print("(no stdout captured)")
        if err:
            print_header("RAW: Nuclei stderr")
            print(err)

        results["nuclei"]["status"] = "success"
        results["nuclei"]["results"] = nuclei_results
        results["nuclei"]["raw"] = nuclei_out.get("raw", "")
    except NucleiNotInstalledError as exc:
        print_error(str(exc))
        results["nuclei"]["status"] = "error"
        results["nuclei"]["error"] = str(exc)
    except NucleiExecutionError as exc:
        print_error(str(exc))
        results["nuclei"]["status"] = "error"
        results["nuclei"]["error"] = str(exc)
    except ValueError as exc:
        print_error(f"Invalid input: {exc}")
        results["nuclei"]["status"] = "error"
        results["nuclei"]["error"] = str(exc)

    return results
