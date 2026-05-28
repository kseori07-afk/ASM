"""Utility functions for ASM tool."""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path


def validate_target(target: str) -> tuple[bool, str]:
    """
    Validate if input is a valid domain, IP address, or host:port target.

    Args:
        target: Input string to validate.

    Returns:
        Tuple (is_valid, type) where type is 'domain', 'ip', 'domain_with_port', 'ip_with_port', or 'unknown'.
    """
    target = target.strip()
    if not target:
        return False, "unknown"

    host = target
    port = None
    if ":" in target and target.count(":") == 1:
        possible_host, possible_port = target.rsplit(":", 1)
        if possible_port.isdigit():
            port_value = int(possible_port)
            if 1 <= port_value <= 65535:
                host = possible_host
                port = port_value
            else:
                return False, "unknown"
        else:
            return False, "unknown"

    if _is_ip_address(host):
        return True, "ip_with_port" if port is not None else "ip"

    if _is_domain(host):
        return True, "domain_with_port" if port is not None else "domain"

    return False, "unknown"


def _is_ip_address(value: str) -> bool:
    """Validate a dotted-quad IPv4 address."""
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if not re.match(ip_pattern, value):
        return False

    return all(0 <= int(part) <= 255 for part in value.split("."))


def _is_domain(value: str) -> bool:
    """Validate a domain name without protocol or path."""
    domain_pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
    return bool(re.match(domain_pattern, value))


def create_data_directories() -> None:
    """Create necessary data directories if they don't exist."""
    directories = [
        "data",
        "data/json",
        "data/logs",
        "data/reports",
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)


def get_timestamp() -> str:
    """Get current timestamp in format YYYYMMDD_HHMMSS."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def save_results_json(
    results: dict,
    filename: str | None = None,
) -> str:
    """
    Save results to JSON file in data/json/ directory.
    
    Args:
        results: Dictionary containing scan results.
        filename: Optional custom filename (without extension). 
                 If not provided, uses timestamp.
    
    Returns:
        Path to saved file.
    """
    create_data_directories()
    
    if filename is None:
        filename = f"scan_results_{get_timestamp()}"
    
    filepath = Path("data/json") / f"{filename}.json"
    
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    return str(filepath)


def format_table(
    headers: list[str],
    rows: list[list[str]],
    col_widths: list[int] | None = None,
) -> str:
    """
    Format data as a pretty table for terminal output.
    
    Args:
        headers: List of column headers.
        rows: List of rows, each row is a list of strings.
        col_widths: Optional list of column widths. If not provided, auto-calculate.
    
    Returns:
        Formatted table as string.
    """
    if not headers or not rows:
        return ""
    
    # Auto-calculate column widths if not provided
    if col_widths is None:
        col_widths = []
        for i, header in enumerate(headers):
            max_width = len(header)
            for row in rows:
                if i < len(row):
                    max_width = max(max_width, len(str(row[i])))
            col_widths.append(max_width)
    
    # Build separator line
    separator = "+" + "+".join("-" * (width + 2) for width in col_widths) + "+"
    
    # Build header
    header_cells = []
    for i, header in enumerate(headers):
        header_cells.append(f" {header:<{col_widths[i]}} ")
    header_line = "|" + "|".join(header_cells) + "|"
    
    # Build rows
    body_lines = []
    for row in rows:
        row_cells = []
        for i, cell in enumerate(row):
            cell_str = str(cell) if cell is not None else ""
            row_cells.append(f" {cell_str:<{col_widths[i]}} ")
        body_lines.append("|" + "|".join(row_cells) + "|")
    
    # Combine all parts
    output = [separator, header_line, separator]
    output.extend(body_lines)
    output.append(separator)
    
    return "\n".join(output)


def format_subdomain_output(subdomains: list[str], domain: str) -> str:
    """Format subdomain results for terminal output."""
    output = f"\n{'='*60}\n"
    output += f"SUBFINDER RESULTS: {domain}\n"
    output += f"{'='*60}\n"
    output += f"Found: {len(subdomains)} subdomain(s)\n\n"
    
    if subdomains:
        for idx, subdomain in enumerate(subdomains, start=1):
            output += f"{idx:3}. {subdomain}\n"
    else:
        output += "No subdomains found.\n"
    
    return output


def format_naabu_output(results: list[dict]) -> str:
    """Format Naabu port scan results for terminal output."""
    output = f"\n{'='*60}\n"
    output += "NAABU RESULTS: Open Ports\n"
    output += f"{'='*60}\n"
    
    if not results:
        output += "No open ports found.\n"
        return output
    
    # Group by host
    hosts_dict = {}
    for result in results:
        host = result["host"]
        port = result["port"]
        protocol = result.get("protocol", "tcp")
        
        if host not in hosts_dict:
            hosts_dict[host] = []
        hosts_dict[host].append(f"{port}/{protocol}")
    
    output += f"Found: {len(results)} open port(s)\n\n"
    
    for host, ports in sorted(hosts_dict.items()):
        output += f"{host}:\n"
        for port in sorted(ports, key=lambda x: int(x.split("/")[0])):
            output += f"  - {port}\n"
    
    return output


def format_nmap_output(results: list[dict]) -> str:
    """Format Nmap service/OS detection results for terminal output."""
    output = f"\n{'='*60}\n"
    output += "NMAP RESULTS: Service & OS Detection\n"
    output += f"{'='*60}\n"
    
    if not results:
        output += "No results found.\n"
        return output
    
    output += f"Found: {len(results)} service(s)\n\n"
    
    # Group by host
    hosts_dict = {}
    for result in results:
        host = result["host"]
        if host not in hosts_dict:
            hosts_dict[host] = {
                "services": [],
                "os": result.get("os", "Unknown"),
            }
        hosts_dict[host]["services"].append({
            "port": result["port"],
            "service": result["service"],
            "version": result.get("version", ""),
            "state": result.get("state", "unknown"),
        })
    
    for host, data in sorted(hosts_dict.items()):
        output += f"\nHost: {host}\n"
        output += f"OS: {data['os']}\n"
        output += "Services:\n"
        for svc in sorted(data["services"], key=lambda x: x["port"]):
            port = svc["port"]
            service = svc["service"]
            version = svc["version"]
            state = svc["state"]
            
            version_str = f" ({version})" if version else ""
            output += f"  - {port}/{service}{version_str} [{state}]\n"
    
    return output


def format_nuclei_output(results: list[dict]) -> str:
    """Format Nuclei vulnerability scan results for terminal output."""
    output = f"\n{'='*60}\n"
    output += "NUCLEI RESULTS: Vulnerability Findings\n"
    output += f"{'='*60}\n"
    
    if not results:
        output += "No findings detected.\n"
        return output
    
    output += f"Found: {len(results)} finding(s)\n\n"
    
    for idx, finding in enumerate(results, start=1):
        host = finding.get("host") or finding.get("ip") or "Unknown"
        port = finding.get("port")
        template_id = finding.get("template_id", "unknown")
        name = finding.get("name", "unknown")
        severity = finding.get("severity", "unknown")
        matched = finding.get("matched", "")
        matched_at = finding.get("matched_at", "")
        references = finding.get("reference", [])
        
        output += f"{idx:3}. [{severity.upper()}] {template_id} - {name}\n"
        output += f"     Host: {host}\n"
        if port is not None:
            output += f"     Port: {port}\n"
        if matched:
            output += f"     Matched: {matched}\n"
        if matched_at:
            output += f"     Time: {matched_at}\n"
        if references:
            output += f"     References: {', '.join(references)}\n"
        output += "\n"
    
    return output
