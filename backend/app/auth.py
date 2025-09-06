"""Simple bearer token authentication for the AlyanaGlobal backend."""

from __future__ import annotations

from fastapi import Header, HTTPException, status
from typing import Optional
from datetime import datetime

from . import db


async def get_current_device(
    authorization: Optional[str] = Header(None),
) -> db.sqlite3.Row:
    """Extract the bearer token from the Authorization header and return
    the associated device record.

    Raises ``HTTPException`` with status 401 if the token is missing or
    invalid.  Updates the ``last_seen_at`` column on every successful call.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header",
        )
    token = authorization.split(" ", 1)[1].strip()
    device = db.get_device_by_token(token)
    if device is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid bearer token",
        )
    # Update last_seen_at asynchronously (no commit conflict risk)
    now = datetime.utcnow().isoformat() + "Z"
    with db.conn:
        db.conn.execute(
            "UPDATE devices SET last_seen_at = ? WHERE id = ?", (now, device["id"])
        )
    return device