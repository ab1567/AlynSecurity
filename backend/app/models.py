"""Pydantic request and response models for the FastAPI backend."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class EnrollmentRequest(BaseModel):
    """Request body for the device enrolment endpoint."""

    hostname: str = Field(..., description="Hostname or identifier of the device")
    user_hint: Optional[str] = Field(
        None,
        description="Optional hint identifying the user or department associated with the device",
    )
    enrollment_key: str = Field(..., description="Pre‑shared key required to enroll a device")


class EnrollmentResponse(BaseModel):
    """Response for a successful enrolment request."""

    status: str = Field(..., description="Status of the device ('pending' until approved)")
    device_id: str = Field(..., description="UUID assigned to the device")
    device_token: str = Field(..., description="Bearer token used for future API requests")


class PolicyResponse(BaseModel):
    """Response returned by the policy endpoint for an active device."""

    device_id: str = Field(..., description="UUID of the device")
    mode: str = Field(..., description="Policy mode; Phase 1 always returns 'allowlist'")
    domains: List[str] = Field(..., description="List of domain patterns allowed for this device")
    refresh_minutes: int = Field(
        5,
        description="Interval at which the agent should refresh the policy",
    )
    # Additional fields can be added in later phases (e.g. DNS settings)


class PendingResponse(BaseModel):
    """Response returned by the policy endpoint when device is not active."""

    status: str = Field(
        "pending",
        description="Indicates that the device is waiting for administrator approval",
    )


class LogEvent(BaseModel):
    """Individual event within a log batch."""

    ts: Optional[str] = Field(
        None,
        description="Timestamp in ISO 8601 format; defaults to current time if omitted",
    )
    domain: str = Field(..., description="The domain that was requested")
    verdict: Optional[str] = Field(
        "blocked", description="Outcome; Phase 1 always uses 'blocked' for denied domains"
    )
    src_user: Optional[str] = Field(
        None,
        description="Username under which the request was made",
    )
    src_process: Optional[str] = Field(
        None,
        description="Process that initiated the request, if known",
    )
    src_ip: Optional[str] = Field(
        None,
        description="IP address of the client application on the device",
    )


class LogsRequest(BaseModel):
    """Request body for posting a batch of log events."""

    device_id: str = Field(..., description="UUID of the device generating the logs")
    events: List[LogEvent] = Field(
        ..., description="List of blocked events to record"
    )


class LogsResponse(BaseModel):
    """Response returned after successfully recording a batch of logs."""

    ok: bool = Field(True, description="Indicates whether the logs were recorded successfully")