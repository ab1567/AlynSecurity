"""Router for device enrolment."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from .. import db
from ..models import EnrollmentRequest, EnrollmentResponse


router = APIRouter()


@router.post("/enroll", response_model=EnrollmentResponse)
async def enroll_device(payload: EnrollmentRequest) -> EnrollmentResponse:
    """Create a new device record and return a bearer token.

    The enrolment key in the request must match an entry in the
    ``enrollment_keys`` table.  The device will be created in
    ``pending`` status until an administrator approves it in a later
    phase.
    """
    if not db.validate_enrollment_key(payload.enrollment_key):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid enrolment key",
        )
    device_id, token = db.create_device(
        hostname=payload.hostname, user_hint=payload.user_hint or ""
    )
    return EnrollmentResponse(
        status="pending", device_id=device_id, device_token=token
    )