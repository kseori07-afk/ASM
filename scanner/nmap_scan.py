"""Nmap service and OS detection module."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from scanner.parser import NmapParseError, parse_nmap_output


class NmapError(Exception):
    """Base exception for Nmap execution failures."""


class NmapNotInstalledError(NmapError):
    """Raised when the Nmap binary is unavailable."""


class NmapExecutionError(NmapError):
    """Raised when Nmap exits with an error."""


def run_nmap(targets: list[str]) -> dict:
    """
    Run Nmap for service and OS detection on given targets.
    
    Args:
        targets: List of targets in format "host:port" or "host:port1,port2".
                Example: ["example.com:80", "192.168.1.1:80,443", ...]
    
    Returns:
        Dict with keys: 'parsed' -> list[dict], 'raw' -> stdout text, 'stderr' -> stderr text
        Each dict in 'parsed': {host, port, service, version, os, state}
    
    Raises:
        ValueError: If targets list is empty.
        NmapNotInstalledError: If Nmap is not installed or not in PATH.
        NmapExecutionError: If Nmap execution fails.
    """
    if not targets:
        raise ValueError("Targets list must not be empty.")
    
    # Clean and validate targets, parse host:port format
    host_ports = {}  # {host: [port1, port2, ...]}
    for target in targets:
        target = target.strip()
        if not target or ':' not in target:
            raise ValueError(f"Invalid target format: {target}. Expected 'host:port' or 'host:port1,port2'")
        
        host, port_str = target.rsplit(':', 1)
        host = host.strip()
        port_str = port_str.strip()
        
        if not host:
            raise ValueError(f"Invalid target: {target}. Host cannot be empty.")
        
        if not port_str:
            raise ValueError(f"Invalid target: {target}. Port cannot be empty.")
        
        # Parse ports (may be comma-separated)
        ports = []
        for port_part in port_str.split(','):
            port_part = port_part.strip()
            try:
                port = int(port_part)
                if port <= 0 or port > 65535:
                    raise ValueError(f"Port out of range: {port}")
                ports.append(port)
            except ValueError as e:
                raise ValueError(f"Invalid port in {target}: {port_part}") from e
        
        if host not in host_ports:
            host_ports[host] = []
        host_ports[host].extend(ports)
    
    # Create temporary XML output file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as temp_file:
        xml_output_path = temp_file.name
    
    try:
        # Build command: nmap -sV -O -p ports -oX output.xml -oN - --privileged host1 host2 ...
        # Collect unique ports
        all_ports = set()
        for ports in host_ports.values():
            all_ports.update(ports)
        port_str = ",".join(str(p) for p in sorted(all_ports))
        
        hosts = list(host_ports.keys())
        
        command = [
            "nmap",
            "-sV",           # Service version detection
            "-O",            # OS detection
            "-p", port_str,  # Specify ports
            "-oX", xml_output_path,  # XML output
            "-oN", "-",      # Normal format output to stdout
            "--privileged",  # Required for OS detection (may need sudo on Linux)
        ] + hosts
        
        try:
            completed_process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=600,  # 10 minute timeout
            )
        except FileNotFoundError as exc:
            raise NmapNotInstalledError(
                "Nmap is not installed or not available in PATH."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise NmapExecutionError(
                f"Nmap execution timed out (10 minutes): {exc}"
            ) from exc
        except OSError as exc:
            raise NmapExecutionError(
                f"Failed to start Nmap: {exc}"
            ) from exc
        
        raw_stdout = completed_process.stdout or ""
        raw_stderr = completed_process.stderr or ""

        if completed_process.returncode not in (0, 1):  # 0 = success, 1 = no hosts up
            stderr = raw_stderr.strip() or "No stderr output."
            raise NmapExecutionError(
                f"Nmap exited with code {completed_process.returncode}: {stderr}"
            )

        # Parse XML output
        try:
            results = parse_nmap_output(xml_output_path)
            return {"parsed": results, "raw": raw_stdout, "stderr": raw_stderr}
        except NmapParseError as exc:
            raise NmapExecutionError(f"Failed to parse Nmap output: {exc}") from exc
    
    finally:
        # Clean up temporary XML file
        try:
            Path(xml_output_path).unlink(missing_ok=True)
        except Exception:
            pass
