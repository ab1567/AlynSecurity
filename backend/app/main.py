"""FastAPI application entry point for the AlyanaGlobal Device Guard backend."""

from __future__ import annotations

from fastapi import FastAPI

from . import db
from .routers import enroll, policy, logs

# Instantiate the FastAPI application.  Descriptive metadata helps with
# documentation generation and discovery when serving the OpenAPI schema.
app = FastAPI(
    title="AlyanaGlobal Device Guard API",
    version="1.0.0",
    description=(
        "API endpoints for enrolling devices, delivering allow‑list policies and "
        "recording blocked domain attempts.  Phase 1 of the Device Guard backend."
    ),
)


@app.on_event("startup")
def on_startup() -> None:
    """Initialise the database on application startup."""
    db.init_db()


# Mount API routers under a common prefix.  All endpoints live under
# `/api/v1` to accommodate future versioning.
app.include_router(enroll.router, prefix="/api/v1", tags=["enroll"])
app.include_router(policy.router, prefix="/api/v1", tags=["policy"])
app.include_router(logs.router, prefix="/api/v1", tags=["logs"])