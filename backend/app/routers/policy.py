"""Router for delivering device policies."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from ..auth import get_current_device
from .. import db
from ..models import PolicyResponse, PendingResponse


router = APIRouter()


@router.get("/policy", response_model=PolicyResponse | PendingResponse)
async def get_policy(device=Depends(get_current_device)):
    """Return the domain allow‑list for an active device.

    If the device is not yet active (still ``pending``) the response
    will signal that the agent should continue to block all domains.
    """
    if device["status"] != "active":
        return PendingResponse()
    domains = db.get_allowlist_domains()
    return PolicyResponse(
        device_id=device["id"],
        mode="allowlist",
        domains=domains,
        refresh_minutes=5,
    )