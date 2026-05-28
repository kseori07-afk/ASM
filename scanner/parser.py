"""Parsing helpers for scanner outputs."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from json import JSONDecodeError


class SubfinderParseError(Exception):
    """Raised when Subfinder output cannot be parsed safely."""


class NaabuParseError(Exception):
    """Raised when Naabu output cannot be parsed safely."""


class NmapParseError(Exception):
    """Raised when Nmap output cannot be parsed safely."""


class NucleiParseError(Exception):
    """Raised when Nuclei output cannot be parsed safely."""


def parse_subfinder_output(raw_output: str) -> list[str]:
    """Convert Subfinder NDJSON output into a list of discovered subdomains."""
    subdomains: list[str] = []

    for line_number, line in enumerate(raw_output.splitlines(), start=1):
        stripped_line = line.strip()
        if not stripped_line:
            continue

        try:
            payload = json.loads(stripped_line)
        except JSONDecodeError as exc:
            raise SubfinderParseError(
                f"Subfinder JSON parse failed at line {line_number}: {exc.msg}"
            ) from exc

        host = payload.get("host")
        if not isinstance(host, str) or not host.strip():
            raise SubfinderParseError(
                f"Subfinder output line {line_number} does not contain a valid 'host' field."
            )

        subdomains.append(host.strip())

    return list(dict.fromkeys(subdomains))


def parse_nuclei_output(raw_output: str) -> list[dict]:
    """
    Parse Nuclei JSON output into a list of findings.
    """
    findings: list[dict] = []

    for line_number, line in enumerate(raw_output.splitlines(), start=1):
        stripped_line = line.strip()
        if not stripped_line:
            continue

        try:
            payload = json.loads(stripped_line)
        except JSONDecodeError as exc:
            raise NucleiParseError(
                f"Nuclei JSON parse failed at line {line_number}: {exc.msg}"
            ) from exc

        if not isinstance(payload, dict):
            raise NucleiParseError(
                f"Nuclei output line {line_number}: JSON object expected."
            )

        info = payload.get("info", {})
        if not isinstance(info, dict):
            info = {}

        host = payload.get("host") or payload.get("matched") or payload.get("matched-at")
        template_id = payload.get("template-id") or payload.get("template")

        findings.append({
            "host": host or "",
            "ip": payload.get("ip", ""),
            "port": payload.get("port"),
            "template_id": template_id or "unknown",
            "name": info.get("name", template_id or "unknown"),
            "severity": info.get("severity", "unknown"),
            "matched": payload.get("matched", ""),
            "matched_at": payload.get("matched-at", ""),
            "description": info.get("description", ""),
            "reference": info.get("reference", []),
            "extra": payload.get("extracted-results", []),
        })

    return findings


def parse_naabu_output(raw_output: str) -> list[dict]:
    """
    Convert Naabu NDJSON output into a list of discovered open ports.
    
    Args:
        raw_output: Naabu JSON output (NDJSON format).
    
    Returns:
        List of dictionaries with keys: host, port, protocol
        Example: [{"host": "example.com", "port": 80, "protocol": "tcp"}, ...]
    """
    results: list[dict] = []

    for line_number, line in enumerate(raw_output.splitlines(), start=1):
        stripped_line = line.strip()
        if not stripped_line:
            continue

        try:
            payload = json.loads(stripped_line)
        except JSONDecodeError as exc:
            raise NaabuParseError(
                f"Naabu JSON parse failed at line {line_number}: {exc.msg}"
            ) from exc

        host = payload.get("host")
        if not isinstance(host, str) or not host.strip():
            host = payload.get("ip")

        port = payload.get("port")
        
        if not isinstance(host, str) or not host.strip():
            raise NaabuParseError(
                f"Naabu output line {line_number}: missing or invalid 'host'/'ip' field."
            )
        
        if isinstance(port, str) and port.isdigit():
            port = int(port)
        
        if not isinstance(port, int) or port <= 0 or port > 65535:
            raise NaabuParseError(
                f"Naabu output line {line_number}: invalid port number '{port}'."
            )
        
        results.append({
            "host": host.strip(),
            "port": port,
            "protocol": str(payload.get("protocol", "tcp")).lower(),
        })

    return results


def parse_nmap_output(xml_file: str) -> list[dict]:
    """
    Parse Nmap XML output to extract host, port, service, version, and OS information.
    
    Args:
        xml_file: Path to Nmap XML output file.
    
    Returns:
        List of dictionaries with keys: host, port, service, version, os, state
        Example: [
            {
                "host": "192.168.1.1",
                "port": 80,
                "service": "http",
                "version": "Apache 2.4.41",
                "os": "Linux 4.15 - 5.6",
                "state": "open"
            },
            ...
        ]
    """
    results: list[dict] = []
    
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except ET.ParseError as exc:
        raise NmapParseError(f"Failed to parse Nmap XML file: {exc}") from exc
    except FileNotFoundError as exc:
        raise NmapParseError(f"Nmap XML file not found: {xml_file}") from exc
    
    # Extract OS information
    os_info = {}
    for host_elem in root.findall("host"):
        host_addr = host_elem.find("address")
        if host_addr is not None:
            addr = host_addr.get("addr")
            # Try to get OS from osmatch
            osmatch = host_elem.find("os/osmatch")
            if osmatch is not None:
                os_name = osmatch.get("name", "Unknown OS")
                os_info[addr] = os_name
    
    # Extract port and service information
    for host_elem in root.findall("host"):
        # Get host address
        host_addr_elem = host_elem.find("address")
        if host_addr_elem is None:
            continue
        
        host_addr = host_addr_elem.get("addr")
        if not host_addr:
            continue
        
        # Also try to get hostname if available
        hostnames_elem = host_elem.find("hostnames/hostname")
        if hostnames_elem is not None:
            hostname = hostnames_elem.get("name")
            if hostname:
                host_addr = hostname
        
        # Extract ports
        ports_elem = host_elem.find("ports")
        if ports_elem is None:
            continue
        
        for port_elem in ports_elem.findall("port"):
            port_num = port_elem.get("protocol")
            port_id = port_elem.get("portid")
            
            if not port_id:
                continue
            
            try:
                port = int(port_id)
            except ValueError:
                continue
            
            # Get port state
            state_elem = port_elem.find("state")
            state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"
            
            # Skip closed/filtered ports
            if state not in ("open", "open|filtered"):
                continue
            
            # Get service information
            service_elem = port_elem.find("service")
            service_name = "unknown"
            service_version = ""
            
            if service_elem is not None:
                service_name = service_elem.get("name", "unknown")
                product = service_elem.get("product")
                version = service_elem.get("version")
                
                if product:
                    service_version = product
                    if version:
                        service_version += f" {version}"
                elif version:
                    service_version = version
            
            results.append({
                "host": host_addr,
                "port": port,
                "service": service_name,
                "version": service_version,
                "os": os_info.get(host_addr, "Unknown"),
                "state": state,
            })
    
    return results
