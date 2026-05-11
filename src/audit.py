"""
AgentPassport — Immutable Audit Trail.

Every action (requests, approvals, denials, transactions, verifications)
is logged with cryptographic chain-linking using SHA-256.

Each entry contains:
  - sha256_hash: SHA-256(prev_hash + action + details + timestamp + entry_index)
  - prev_hash: hash of the previous entry
  - This creates a tamper-evident chain

Query by agent, token, capability, action, or time range.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from src import db
from models.schemas import AuditAction


def compute_hash(
    prev_hash: Optional[str],
    action: str,
    details: dict,
    timestamp: str,
    entry_index: int,
) -> str:
    """Compute SHA-256 hash for an audit entry."""
    payload = json.dumps(
        {
            "prev_hash": prev_hash or "",
            "action": action,
            "details": details,
            "timestamp": timestamp,
            "entry_index": entry_index,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


async def append_entry(
    action: AuditAction,
    agent_id: Optional[str] = None,
    token_id: Optional[str] = None,
    capability_id: Optional[UUID] = None,
    transaction_id: Optional[UUID] = None,
    details: Optional[dict] = None,
) -> dict:
    """
    Append a new entry to the immutable audit trail.
    Links to the previous entry via SHA-256.
    """
    # Get latest entry for chain linking
    latest = await db.get_latest_audit_entry()
    prev_hash = latest["sha256_hash"] if latest else None
    entry_index = (latest["entry_index"] + 1) if latest else 0

    timestamp = datetime.now(timezone.utc).isoformat()

    sha256_hash = compute_hash(
        prev_hash=prev_hash,
        action=action.value if isinstance(action, AuditAction) else action,
        details=details or {},
        timestamp=timestamp,
        entry_index=entry_index,
    )

    entry_data = {
        "action": action.value if isinstance(action, AuditAction) else action,
        "agent_id": agent_id,
        "token_id": token_id,
        "capability_id": str(capability_id) if capability_id else None,
        "transaction_id": str(transaction_id) if transaction_id else None,
        "details": details or {},
        "sha256_hash": sha256_hash,
        "prev_hash": prev_hash,
    }

    record = await db.create_audit_entry(entry_data)
    return record


async def verify_chain() -> tuple[bool, list[dict]]:
    """
    Verify the integrity of the entire audit chain.
    Returns (valid, list_of_invalid_entries).
    """
    entries, _ = await db.query_audit_log(limit=10000, offset=0)

    if not entries:
        return True, []

    # Sort by entry_index ascending for chain verification
    entries_sorted = sorted(entries, key=lambda e: e.get("entry_index", 0))
    invalid = []
    prev_hash = None

    for i, entry in enumerate(entries_sorted):
        expected_prev = prev_hash
        actual_prev = entry.get("prev_hash")
        if expected_prev is not None and actual_prev != expected_prev:
            invalid.append(entry)

        # Recompute hash
        computed = compute_hash(
            prev_hash=actual_prev,
            action=entry["action"],
            details=entry.get("details", {}),
            timestamp=entry.get("created_at", ""),
            entry_index=entry.get("entry_index", i),
        )
        if computed != entry.get("sha256_hash"):
            if entry not in invalid:
                invalid.append(entry)

        prev_hash = entry.get("sha256_hash")

    return len(invalid) == 0, invalid


async def query_entries(
    agent_id: Optional[str] = None,
    token_id: Optional[str] = None,
    capability_id: Optional[str] = None,
    action: Optional[str] = None,
    from_time: Optional[str] = None,
    to_time: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict], int]:
    """Query the audit trail with filters."""
    return await db.query_audit_log(
        agent_id=agent_id,
        token_id=token_id,
        capability_id=capability_id,
        action=action,
        from_time=from_time,
        to_time=to_time,
        limit=limit,
        offset=offset,
    )
