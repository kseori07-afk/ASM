"""Subfinder execution module."""

from __future__ import annotations

import subprocess

from scanner.parser import SubfinderParseError, parse_subfinder_output


class SubfinderError(Exception):
    """Base exception for Subfinder execution failures."""


class SubfinderNotInstalledError(SubfinderError):
    """Raised when the Subfinder binary is unavailable."""


class SubfinderExecutionError(SubfinderError):
    """Raised when Subfinder exits with an error."""


def run_subfinder(domain: str) -> dict:
    """Run Subfinder for a single domain and return parsed subdomains and raw output.

    Returns a dict with keys: 'parsed' -> list[str], 'raw' -> stdout text, 'stderr' -> stderr text
    """
    cleaned_domain = domain.strip()
    if not cleaned_domain:
        raise ValueError("Domain must not be empty.")

    command = ["subfinder", "-d", cleaned_domain, "-json"]

    try:
        completed_process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise SubfinderNotInstalledError(
            "Subfinder is not installed or not available in PATH."
        ) from exc
    except OSError as exc:
        raise SubfinderExecutionError(
            f"Failed to start Subfinder: {exc}"
        ) from exc

    raw_stdout = completed_process.stdout or ""
    raw_stderr = completed_process.stderr or ""

    if completed_process.returncode != 0:
        stderr = raw_stderr.strip() or "No stderr output."
        raise SubfinderExecutionError(
            f"Subfinder exited with code {completed_process.returncode}: {stderr}"
        )

    try:
        parsed = parse_subfinder_output(raw_stdout)
        return {"parsed": parsed, "raw": raw_stdout, "stderr": raw_stderr}
    except SubfinderParseError as exc:
        raise SubfinderExecutionError(f"Failed to parse Subfinder output: {exc}") from exc
