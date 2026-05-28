"""Naabu port scanning module."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from scanner.parser import NaabuParseError, parse_naabu_output


class NaabuError(Exception):
    """Base exception for Naabu execution failures."""


class NaabuNotInstalledError(NaabuError):
    """Raised when the Naabu binary is unavailable."""


class NaabuExecutionError(NaabuError):
    """Raised when Naabu exits with an error."""


def run_naabu(hosts: list[str]) -> dict:
    """
    Run Naabu for a list of hosts and return parsed open ports.
    
    Args:
        hosts: List of hostnames or IP addresses to scan.
    
    Returns:
        List of dictionaries containing host, port, and protocol information.
        Example: [{"host": "example.com", "port": 80, "protocol": "tcp"}, ...]
    
    Raises:
        ValueError: If hosts list is empty.
        NaabuNotInstalledError: If Naabu is not installed or not in PATH.
        NaabuExecutionError: If Naabu execution fails.
    """
    if not hosts:
        raise ValueError("Hosts list must not be empty.")
    
    # Clean and validate hosts
    cleaned_hosts = [host.strip() for host in hosts if host.strip()]
    if not cleaned_hosts:
        raise ValueError("All hosts are empty.")
    
    # Create temporary hosts file
    with tempfile.NamedTemporaryFile(
        mode='w',
        suffix='.txt',
        delete=False,
        encoding='utf-8'
    ) as temp_file:
        for host in cleaned_hosts:
            temp_file.write(f"{host}\n")
        hosts_file_path = temp_file.name
    
    try:
        # Build command: naabu -l hosts.txt -top-ports 1000 -json -silent
        command = [
            "naabu",
            "-l", hosts_file_path,
            "-top-ports", "1000",
            "-json",
            "-silent",  # Minimal output
        ]
        
        try:
            completed_process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=600,  # 10 minute timeout
            )
        except FileNotFoundError as exc:
            raise NaabuNotInstalledError(
                "Naabu is not installed or not available in PATH."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise NaabuExecutionError(
                f"Naabu execution timed out (10 minutes): {exc}"
            ) from exc
        except OSError as exc:
            raise NaabuExecutionError(
                f"Failed to start Naabu: {exc}"
            ) from exc
        
        raw_stdout = completed_process.stdout or ""
        raw_stderr = completed_process.stderr or ""

        if completed_process.returncode != 0:
            stderr = raw_stderr.strip() or "No stderr output."
            raise NaabuExecutionError(
                f"Naabu exited with code {completed_process.returncode}: {stderr}"
            )

        try:
            parsed = parse_naabu_output(raw_stdout)
            return {"parsed": parsed, "raw": raw_stdout, "stderr": raw_stderr}
        except NaabuParseError as exc:
            raise NaabuExecutionError(f"Failed to parse Naabu output: {exc}") from exc
    
    finally:
        # Clean up temporary hosts file
        try:
            Path(hosts_file_path).unlink(missing_ok=True)
        except Exception:
            pass
