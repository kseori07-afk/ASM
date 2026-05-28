"""SQLite database manager for ASM scan history."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path

DEFAULT_DB_PATH = Path("data/results.db")
SCHEMA_FILE = Path(__file__).resolve().parent / "schema.sql"


def initialize_database(db_path: str | Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(db_path))
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON;")
    create_tables(connection)
    return connection


def create_tables(connection: sqlite3.Connection) -> None:
    if not SCHEMA_FILE.exists():
        raise FileNotFoundError(f"Database schema file not found: {SCHEMA_FILE}")

    with SCHEMA_FILE.open("r", encoding="utf-8") as handle:
        connection.executescript(handle.read())


def save_scan_results(
    connection: sqlite3.Connection,
    results: dict,
    scan_label: str,
) -> int:
    """Save scan results and details into the database."""
    status = _get_overall_status(results, scan_label)
    cursor = connection.cursor()
    cursor.execute(
        "INSERT INTO scans (timestamp, target, scan_label, status, raw_results, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (
            results.get("timestamp", datetime.now().strftime("%Y%m%d_%H%M%S")),
            results.get("target", ""),
            scan_label,
            status,
            json.dumps(results, ensure_ascii=False),
            datetime.now().isoformat(),
        ),
    )
    scan_id = cursor.lastrowid

    if scan_label == "default_scanning":
        _save_subdomains(cursor, scan_id, results.get("subfinder", {}).get("results", []))
        _save_ports(cursor, scan_id, results.get("naabu", {}).get("results", []))
        _save_nmap_services(cursor, scan_id, results.get("nmap", {}).get("results", []))
    elif scan_label == "cve_scanning":
        _save_nuclei_findings(cursor, scan_id, results.get("nuclei", {}).get("results", []))
    else:
        _save_nuclei_findings(cursor, scan_id, results.get("nuclei", {}).get("results", []))

    connection.commit()
    return scan_id


def list_scans(connection: sqlite3.Connection, scan_label: str | None = None) -> list[sqlite3.Row]:
    cursor = connection.cursor()
    if scan_label:
        cursor.execute(
            "SELECT id, timestamp, target, scan_label, status, created_at FROM scans WHERE scan_label = ? ORDER BY id DESC",
            (scan_label,),
        )
    else:
        cursor.execute(
            "SELECT id, timestamp, target, scan_label, status, created_at FROM scans ORDER BY id DESC"
        )
    return cursor.fetchall()


def get_default_scan_targets(connection: sqlite3.Connection, scan_id: int) -> list[str]:
    cursor = connection.cursor()
    cursor.execute(
        "SELECT host, port FROM ports WHERE scan_id = ? ORDER BY host, port",
        (scan_id,),
    )
    port_targets = [f"{row['host']}:{row['port']}" for row in cursor.fetchall()]

    cursor.execute(
        "SELECT host FROM subdomains WHERE scan_id = ? ORDER BY id",
        (scan_id,),
    )
    hosts = [row[0] for row in cursor.fetchall()]

    if port_targets:
        combined_targets = []
        for target in port_targets + hosts:
            if target not in combined_targets:
                combined_targets.append(target)
        return combined_targets

    if hosts:
        return hosts

    cursor.execute(
        "SELECT target FROM scans WHERE id = ? AND scan_label = 'default_scanning'",
        (scan_id,),
    )
    row = cursor.fetchone()
    if row and row[0]:
        return [row[0]]
    return []


def get_scan_result_json(connection: sqlite3.Connection, scan_id: int) -> dict:
    cursor = connection.cursor()
    cursor.execute(
        "SELECT raw_results FROM scans WHERE id = ?",
        (scan_id,),
    )
    row = cursor.fetchone()
    if row is None or row[0] is None:
        return {}
    try:
        return json.loads(row[0])
    except json.JSONDecodeError:
        return {}


def _get_overall_status(results: dict, scan_label: str) -> str:
    """Return scan completion status (always 'completed')."""
    return "completed"


def _save_subdomains(cursor: sqlite3.Cursor, scan_id: int, subdomains: list[str]) -> None:
    cursor.executemany(
        "INSERT INTO subdomains (scan_id, host) VALUES (?, ?)",
        [(scan_id, subdomain) for subdomain in subdomains if isinstance(subdomain, str) and subdomain.strip()],
    )


def _save_ports(cursor: sqlite3.Cursor, scan_id: int, naabu_results: list[dict]) -> None:
    cursor.executemany(
        "INSERT INTO ports (scan_id, host, port, protocol) VALUES (?, ?, ?, ?)",
        [
            (
                scan_id,
                result.get("host", ""),
                result.get("port"),
                result.get("protocol", "tcp"),
            )
            for result in naabu_results
            if isinstance(result, dict)
        ],
    )


def _save_nmap_services(cursor: sqlite3.Cursor, scan_id: int, nmap_results: list[dict]) -> None:
    cursor.executemany(
        "INSERT INTO nmap_services (scan_id, host, port, service, version, os, state) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
            (
                scan_id,
                result.get("host", ""),
                result.get("port"),
                result.get("service", "unknown"),
                result.get("version", ""),
                result.get("os", "Unknown"),
                result.get("state", "unknown"),
            )
            for result in nmap_results
            if isinstance(result, dict)
        ],
    )


def _save_nuclei_findings(cursor: sqlite3.Cursor, scan_id: int, nuclei_results: list[dict]) -> None:
    cursor.executemany(
        "INSERT INTO nuclei_findings (scan_id, host, port, template_id, name, severity, matched, matched_at, description, reference_json, extra_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (
                scan_id,
                result.get("host", ""),
                result.get("port"),
                result.get("template_id", "unknown"),
                result.get("name", "unknown"),
                result.get("severity", "unknown"),
                result.get("matched", ""),
                result.get("matched_at", ""),
                result.get("description", ""),
                json.dumps(result.get("reference", []), ensure_ascii=False),
                json.dumps(result.get("extra", []), ensure_ascii=False),
            )
            for result in nuclei_results
            if isinstance(result, dict)
        ],
    )
