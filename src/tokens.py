"""
AgentPassport — Token System.

Generates scoped capability tokens with server-side validation.
Format: agentpassport_<random_hex>
Claims are stored server-side in Supabase; the token is an opaque
reference that the agent presents. Verification queries the database.

Supports: issuance, verification, revocation, expiry.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from src import db
from models.schemas import TokenVerifyResponse


TOKEN_PREFIX = "agentpassport_"


def generate_token_id() -> str:
    """Generate a unique opaque token ID."""
    random_part = secrets.token_hex(24)  # 48 hex chars = 192 bits
    return f"{TOKEN_PREFIX}{random_part}"


def compute_token_expiry(duration_seconds: int) -> datetime:
    """Compute expiry timestamp from duration."""
    return datetime.now(timezone.utc) + timedelta(seconds=duration_seconds)


async def issue_token(
    capability: dict,
    narrowed_max_spend: Optional[int] = None,
    narrowed_duration: Optional[int] = None,
) -> dict:
    """
    Issue a scoped capability token from an approved capability request.
    Stores the token record in Supabase and returns the full record.
    """
    token_id = generate_token_id()
    max_spend = narrowed_max_spend if narrowed_max_spend else capability["max_spend"]
    duration = narrowed_duration if narrowed_duration else capability["duration_seconds"]
    expires_at = compute_token_expiry(duration)

    token_data = {
        "id": token_id,
        "capability_id": str(capability["id"]),
        "agent_id": capability["agent_id"],
        "scope": capability["scope"],
        "max_spend": max_spend,
        "spent_so_far": 0,
        "allowed_merchants": capability.get("allowed_merchants", []),
        "allowed_categories": capability.get("allowed_categories", []),
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": expires_at.isoformat(),
        "revoked": False,
        "metadata": capability.get("metadata", {}),
    }

    record = await db.create_token(token_data)
    return record


async def verify_token(token_id: str) -> TokenVerifyResponse:
    """
    Verify a capability token. Checks:
      - Token exists in DB
      - Not revoked
      - Not expired
    Returns TokenVerifyResponse with all details.
    """
    record = await db.get_token(token_id)

    if not record:
        return TokenVerifyResponse(
            valid=False,
            token_id=token_id,
            agent_id="",
            scope="",
            max_spend=0,
            spent_so_far=0,
            remaining=0,
            allowed_merchants=[],
            allowed_categories=[],
            expires_at=datetime.now(timezone.utc),
            issued_at=datetime.now(timezone.utc),
            revoked=False,
            violations=["Token not found"],
        )

    violations = []
    now = datetime.now(timezone.utc)

    # Check revoked
    if record.get("revoked", False):
        violations.append("Token has been revoked")

    # Check expiry
    expires_at = record.get("expires_at")
    if expires_at:
        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        if now > expires_at:
            violations.append(f"Token expired at {expires_at.isoformat()}")

    valid = len(violations) == 0
    spent = record.get("spent_so_far", 0)
    max_spend = record.get("max_spend", 0)

    return TokenVerifyResponse(
        valid=valid,
        token_id=token_id,
        agent_id=record.get("agent_id", ""),
        scope=record.get("scope", ""),
        max_spend=max_spend,
        spent_so_far=spent,
        remaining=max(0, max_spend - spent),
        allowed_merchants=record.get("allowed_merchants", []),
        allowed_categories=record.get("allowed_categories", []),
        expires_at=expires_at if isinstance(expires_at, datetime) else datetime.now(timezone.utc),
        issued_at=record.get("issued_at", datetime.now(timezone.utc)),
        revoked=record.get("revoked", False),
        violations=violations,
    )


async def revoke_token(token_id: str) -> bool:
    """Revoke a capability token, preventing further use."""
    record = await db.get_token(token_id)
    if not record:
        return False
    await db.update_token(token_id, {"revoked": True})
    return True


async def record_spend(token_id: str, amount: int) -> bool:
    """Increment spent_so_far on a token after a successful transaction."""
    record = await db.get_token(token_id)
    if not record:
        return False
    new_spent = record.get("spent_so_far", 0) + amount
    await db.update_token(token_id, {"spent_so_far": new_spent})
    return True
