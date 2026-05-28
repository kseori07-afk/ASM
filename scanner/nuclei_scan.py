"""Nuclei vulnerability scanning module."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from scanner.parser import NucleiParseError, parse_nuclei_output


class NucleiError(Exception):
    """Base exception for Nuclei execution failures."""


class NucleiNotInstalledError(NucleiError):
    """Raised when the Nuclei binary is unavailable."""


class NucleiExecutionError(NucleiError):
    """Raised when Nuclei exits with an error."""


def run_nuclei(target: str | list[str], templates: str | None = None) -> dict:
    """
    Run Nuclei against one or more targets and return parsed findings.

    Args:
        target: Target domain/IP or list of targets.
        templates: Optional Nuclei template path or comma-separated template IDs.

    Returns:
        List of dictionaries containing vulnerability findings.
    """
    if isinstance(target, str):
        cleaned_targets = [target.strip()]
    else:
        cleaned_targets = [item.strip() for item in target if isinstance(item, str) and item.strip()]

    cleaned_targets = [item for item in cleaned_targets if item]
    if not cleaned_targets:
        raise ValueError("Target must not be empty.")

    templates_arg = None
    if templates:
        # Allow comma-separated list of template file paths
        if "," in templates:
            parts = [p.strip() for p in templates.split(",") if p.strip()]
            missing = [p for p in parts if not Path(p).exists()]
            if missing:
                raise ValueError(f"Nuclei template path(s) do not exist: {', '.join(missing)}")
            templates_arg = ",".join(parts)
        else:
            pth = Path(templates)
            if not pth.exists():
                raise ValueError(f"Nuclei template path does not exist: {templates}")
            templates_arg = str(pth)

    temporary_file_path = None
    if len(cleaned_targets) == 1:
        target_args = ["-target", cleaned_targets[0]]
    else:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as temp_file:
            for entry in cleaned_targets:
                temp_file.write(f"{entry}\n")
            temporary_file_path = temp_file.name

        target_args = ["-l", temporary_file_path]

    command_base = ["nuclei", "-silent", "-no-color"]
    if templates_arg is not None:
        command_base.extend(["-t", templates_arg])

    # Try flags that produce JSONL on stdout first
    stdout_flags = ["-j", "-jsonl"]
    file_flags = ["-je", "-json-export", "-jle", "-jsonl-export"]

    completed_process = None
    output_text = None

    # Try stdout JSON flags
    for flag in stdout_flags:
        candidate_command = command_base + [flag] + target_args
        try:
            completed_process = subprocess.run(
                candidate_command,
                capture_output=True,
                text=True,
                check=False,
                timeout=900,
            )
        except FileNotFoundError as exc:
            raise NucleiNotInstalledError(
                "Nuclei is not installed or not available in PATH."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise NucleiExecutionError(
                f"Nuclei execution timed out (15 minutes): {exc}"
            ) from exc
        except OSError as exc:
            raise NucleiExecutionError(
                f"Failed to start Nuclei: {exc}"
            ) from exc

        if completed_process.returncode in (0, 1):
            output_text = completed_process.stdout
            break

        stderr = completed_process.stderr.strip().lower()
        if "flag provided but not defined" in stderr or "unknown flag" in stderr:
            # try next flag
            continue
        # unexpected error, stop trying
        break

    # If stdout flags didn't work, try file-export flags
    if output_text is None:
        for flag in file_flags:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as out_file:
                out_path = out_file.name

            candidate_command = command_base + [flag, out_path] + target_args
            try:
                completed_process = subprocess.run(
                    candidate_command,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=900,
                )
            except FileNotFoundError as exc:
                raise NucleiNotInstalledError(
                    "Nuclei is not installed or not available in PATH."
                ) from exc
            except subprocess.TimeoutExpired as exc:
                raise NucleiExecutionError(
                    f"Nuclei execution timed out (15 minutes): {exc}"
                ) from exc
            except OSError as exc:
                raise NucleiExecutionError(
                    f"Failed to start Nuclei: {exc}"
                ) from exc

            if completed_process.returncode in (0, 1):
                try:
                    with open(out_path, "r", encoding="utf-8") as fh:
                        output_text = fh.read()
                except Exception:
                    output_text = None
                finally:
                    try:
                        Path(out_path).unlink(missing_ok=True)
                    except Exception:
                        pass
                break

            # cleanup file
            try:
                Path(out_path).unlink(missing_ok=True)
            except Exception:
                pass

    if completed_process is None:
        raise NucleiExecutionError("Failed to execute Nuclei.")

    raw_stdout = (output_text or completed_process.stdout) or ""
    raw_stderr = completed_process.stderr or ""

    if raw_stdout == "" and completed_process.returncode not in (0, 1):
        stderr = raw_stderr.strip()
        stdout = completed_process.stdout.strip()
        details = stderr or stdout or "No stderr or stdout output."
        raise NucleiExecutionError(
            f"Nuclei exited with code {completed_process.returncode}: {details}"
        )

    try:
        parsed = parse_nuclei_output(raw_stdout)
        return {"parsed": parsed, "raw": raw_stdout, "stderr": raw_stderr}
    except NucleiParseError as exc:
        raise NucleiExecutionError(f"Failed to parse Nuclei output: {exc}") from exc
