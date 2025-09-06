"""Simple SQLite persistence layer for the AlyanaGlobal Device Guard backend.

This module provides helper functions to initialise the database, create and
retrieve devices, store allow‑list domains and record blocked attempts.
It uses the built‑in ``sqlite3`` module to avoid external dependencies.

The schema is intentionally minimalist for Phase 1 and can be evolved in
future phases.  All functions are safe to call from FastAPI request handlers
because the SQLite connection is configured with ``check_same_thread=False``.
"""

from __future__ import annotations

import os
import sqlite3
import uuid
import secrets
from datetime import datetime
from typing import Iterable, List, Optional


# Determine a path for the database file.  It lives alongside this module
# in the ``backend`` directory to keep the repository self‑contained.
DATA_DIR = os.path.dirname(os.path.dirname(__file__))
DB_PATH = os.path.join(DATA_DIR, "data.sqlite3")

# Create a single global connection.  SQLite allows concurrent reads
# and serialises writes internally.  ``check_same_thread=False`` allows
# the connection to be shared across FastAPI worker threads.
conn = sqlite3.connect(DB_PATH, check_same_thread=False)
conn.row_factory = sqlite3.Row


def init_db() -> None:
    """Initialise the database if it has not been created yet.

    This function creates the core tables and seeds initial data for
    allow‑list domains and an enrolment key.  It is idempotent and safe
    to call multiple times.
    """
    with conn:
        # Devices table: each device gets a UUID and a bearer token.  The
        # ``status`` column controls whether a device is allowed to fetch
        # policies.  Valid values are ``pending`` or ``active``.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                tenant_id INTEGER DEFAULT 1,
                hostname TEXT,
                user_hint TEXT,
                token TEXT UNIQUE,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL,
                last_seen_at TEXT
            )
            """
        )

        # Allow‑list domains.  Each domain_pattern can include wildcards
        # (e.g. ``*.google.com``).  All rows belong to tenant_id=1 for
        # Phase 1; multi‑tenant support can be added later.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS allowlist_domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id INTEGER DEFAULT 1,
                domain_pattern TEXT NOT NULL,
                notes TEXT
            )
            """
        )

        # Logs table.  Stores blocked domain events from devices.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id INTEGER DEFAULT 1,
                device_id TEXT,
                ts TEXT NOT NULL,
                attempted_domain TEXT NOT NULL,
                verdict TEXT NOT NULL,
                src_user TEXT,
                src_process TEXT,
                src_ip TEXT
            )
            """
        )

        # Enrolment keys table.  Keys can have optional expiry or usage
        # limits; Phase 1 uses a single perpetual key.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS enrollment_keys (
                key TEXT PRIMARY KEY,
                tenant_id INTEGER DEFAULT 1,
                expires_at TEXT,
                max_uses INTEGER,
                uses INTEGER DEFAULT 0
            )
            """
        )

        # Seed a default enrolment key if none exists.  In a real system
        # these keys would be managed via an admin interface.
        cur = conn.execute(
            "SELECT COUNT(1) FROM enrollment_keys WHERE key = ?", ("default",)
        )
        if cur.fetchone()[0] == 0:
            conn.execute(
                "INSERT INTO enrollment_keys (key, tenant_id) VALUES (?, 1)",
                ("default",),
            )

        # Seed default allow‑list patterns if the table is empty.  These
        # entries represent the domains required for Phase 1.  Additional
        # entries can be added via the admin interface in later phases.
        cur = conn.execute("SELECT COUNT(1) FROM allowlist_domains")
        if cur.fetchone()[0] == 0:
            default_domains = [
                ("classera.com", "LMS"),
                ("*.google.com", "Google base"),
                ("gstatic.com", "Google static"),
                ("googleapis.com", "Google APIs"),
                ("meet.google.com", "Google Meet"),
                ("blueride.com", "Transport"),
            ]
            conn.executemany(
                "INSERT INTO allowlist_domains (domain_pattern, notes) VALUES (?, ?)",
                default_domains,
            )


def validate_enrollment_key(key: str) -> bool:
    """Return True if ``key`` is a known enrolment key and has not expired.

    Phase 1 supports a single static key; expiry and usage limits are not
    enforced.
    """
    if not key:
        return False
    cur = conn.execute(
        "SELECT key FROM enrollment_keys WHERE key = ?",
        (key,),
    )
    return cur.fetchone() is not None


def create_device(hostname: str, user_hint: str) -> tuple[str, str]:
    """Create a new pending device and return ``(device_id, token)``.

    Each device is assigned a random UUID for the identifier and a
    cryptographically secure random token.  The token is stored in
    plaintext for Phase 1 but should be hashed in future phases.
    """
    device_id = str(uuid.uuid4())
    token = secrets.token_hex(32)
    now = datetime.utcnow().isoformat() + "Z"
    with conn:
        conn.execute(
            """
            INSERT INTO devices (id, hostname, user_hint, token, status, created_at)
            VALUES (?, ?, ?, ?, 'pending', ?)
            """,
            (device_id, hostname, user_hint, token, now),
        )
    return device_id, token


def get_device_by_token(token: str) -> Optional[sqlite3.Row]:
    """Return the device record matching ``token`` or ``None`` if not found."""
    if not token:
        return None
    cur = conn.execute(
        "SELECT * FROM devices WHERE token = ?",
        (token,),
    )
    return cur.fetchone()


def activate_device(device_id: str) -> None:
    """Set the status of ``device_id`` to ``active``."""
    with conn:
        conn.execute(
            "UPDATE devices SET status = 'active' WHERE id = ?",
            (device_id,),
        )


def get_allowlist_domains() -> List[str]:
    """Return a list of domain patterns for the default tenant."""
    cur = conn.execute(
        "SELECT domain_pattern FROM allowlist_domains WHERE tenant_id = 1"
    )
    return [row["domain_pattern"] for row in cur.fetchall()]


def insert_logs(device_id: str, events: Iterable[dict]) -> None:
    """Insert a batch of log events for a device.

    Each event dictionary should contain the keys ``ts``, ``domain``,
    ``verdict``, ``src_user``, ``src_process`` and ``src_ip``.  Missing
    keys are inserted as NULL.
    """
    rows = []
    for ev in events:
        # If a timestamp is provided but is falsy (e.g. ``None``), use the current time
        ts = ev.get("ts") or (datetime.utcnow().isoformat() + "Z")
        domain = ev.get("domain") or ev.get("attempted_domain")
        verdict = ev.get("verdict", "blocked")
        src_user = ev.get("src_user")
        src_process = ev.get("src_process")
        src_ip = ev.get("src_ip")
        rows.append(
            (
                ts,
                domain,
                verdict,
                src_user,
                src_process,
                src_ip,
                device_id,
            )
        )
    with conn:
        conn.executemany(
            """
            INSERT INTO logs (ts, attempted_domain, verdict, src_user, src_process, src_ip, device_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )