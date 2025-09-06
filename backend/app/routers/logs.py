"""Router for receiving blocked domain events from agents."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from ..auth import get_current_device
from .. import db
from ..models import LogsRequest, LogsResponse


router = APIRouter()


@router.post("/logs", response_model=LogsResponse)
async def post_logs(
    payload: LogsRequest, device=Depends(get_current_device)
) -> LogsResponse:
    """Record a batch of blocked domain events.

    The ``device`` dependency ensures that the bearer token is valid.
    Optionally cross‑check that the device ID in the payload matches
    the authenticated device.
    """
    if payload.device_id != device["id"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Device ID does not match bearer token",
        )
    # Convert each Pydantic model to a plain dict.  Pydantic 2 uses
    # ``model.model_dump()``, but we call ``dict()`` for simplicity.
    events = [ev.dict() for ev in payload.events]
    db.insert_logs(device_id=device["id"], events=events)
    return LogsResponse(ok=True)