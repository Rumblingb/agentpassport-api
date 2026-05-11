"""
AgentPassport API — Governed Payment Middleware for AI Agents.

Built on Stripe. AgentPassport governs who can spend, how much, on what,
and for how long. Stripe moves the money.

Run: uvicorn main:app --reload --port 8000
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from models.schemas import (
    ApproveRequest,
    AuditEntryResponse,
    AuditListResponse,
    AuditQuery,
    CapabilityRequest,
    CapabilityRequestResponse,
    CapabilityTokenResponse,
    DenyRequest,
    ErrorResponse,
    HealthResponse,
    TokenVerifyResponse,
    TransactionRequest,
    TransactionResponse,
)
from src import audit as audit_module
from src import db
from src import stripe as stripe_module
from src.guardrails import GuardrailContext, get_guardrails_engine
from src.tokens import issue_token, record_spend, revoke_token, verify_token

load_dotenv()


# ── Lifespan ──────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: bootstrap DB, init Stripe. Shutdown: clean up connections."""
    await db.bootstrap_db()
    stripe_module.init_stripe()
    yield
    # Cleanup handled by httpx client garbage collection


app = FastAPI(
    title="AgentPassport API",
    description="Governed payment middleware for AI agents. Built on Stripe.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Health ────────────────────────────────────────────────────────────────────


@app.get("/v1/health", response_model=HealthResponse, tags=["System"])
async def health():
    checks = {
        "supabase": "connected" if await db.get_rest_client() else "disconnected",
        "stripe": "configured" if os.getenv("STRIPE_API_KEY") else "not configured",
    }
    return HealthResponse(checks=checks)


# ── Capabilities ──────────────────────────────────────────────────────────────


@app.post(
    "/v1/capabilities/request",
    response_model=CapabilityRequestResponse,
    status_code=201,
    tags=["Capabilities"],
)
async def request_capability(req: CapabilityRequest):
    """
    Agent submits a capability request. Returns a request_id.
    The human approver must approve or deny via /v1/capabilities/approve or /deny.
    """
    capability_data = {
        "agent_id": req.agent_id,
        "scope": req.scope,
        "max_spend": req.max_spend,
        "allowed_merchants": req.allowed_merchants,
        "allowed_categories": req.allowed_categories,
        "duration_seconds": req.duration_seconds,
        "status": "pending",
        "metadata": req.metadata,
    }
    record = await db.create_capability(capability_data)

    # Audit: capability_requested
    await audit_module.append_entry(
        action="capability_requested",
        agent_id=req.agent_id,
        capability_id=UUID(record["id"]),
        details={
            "scope": req.scope,
            "max_spend": req.max_spend,
            "allowed_merchants": req.allowed_merchants,
            "allowed_categories": req.allowed_categories,
            "duration_seconds": req.duration_seconds,
        },
    )

    return CapabilityRequestResponse(
        request_id=UUID(record["id"]),
        agent_id=req.agent_id,
        scope=req.scope,
        max_spend=req.max_spend,
        allowed_merchants=req.allowed_merchants,
        allowed_categories=req.allowed_categories,
        expires_in_seconds=req.duration_seconds,
        created_at=record.get("created_at", datetime.now(timezone.utc)),
    )


@app.post(
    "/v1/capabilities/approve",
    response_model=CapabilityTokenResponse,
    tags=["Capabilities"],
)
async def approve_capability(req: ApproveRequest):
    """
    Human approves a pending capability request.
    Optionally narrows max_spend or duration.
    Returns a scoped capability token (agentpassport_xxx).
    """
    capability = await db.get_capability(req.request_id)
    if not capability:
        raise HTTPException(status_code=404, detail="Capability request not found")
    if capability["status"] != "pending":
        raise HTTPException(
            status_code=409,
            detail=f"Capability already {capability['status']}",
        )

    # Update capability status
    await db.update_capability(
        req.request_id,
        {
            "status": "approved",
            "approver_id": req.approver_id,
            "narrowed_max_spend": req.narrowed_max_spend,
            "narrowed_duration_seconds": req.narrowed_duration_seconds,
            "notes": req.notes,
        },
    )

    # Issue token
    token_record = await issue_token(
        capability=capability,
        narrowed_max_spend=req.narrowed_max_spend,
        narrowed_duration=req.narrowed_duration_seconds,
    )

    # Audit: capability_approved
    await audit_module.append_entry(
        action="capability_approved",
        agent_id=capability["agent_id"],
        capability_id=req.request_id,
        token_id=token_record["id"],
        details={
            "approver_id": req.approver_id,
            "original_max_spend": capability["max_spend"],
            "narrowed_max_spend": req.narrowed_max_spend,
            "narrowed_duration": req.narrowed_duration_seconds,
            "notes": req.notes,
        },
    )

    return CapabilityTokenResponse(
        token=token_record["id"],
        request_id=req.request_id,
        scope=token_record["scope"],
        max_spend=token_record["max_spend"],
        allowed_merchants=token_record.get("allowed_merchants", []),
        allowed_categories=token_record.get("allowed_categories", []),
        expires_at=token_record["expires_at"],
        issued_at=token_record["issued_at"],
    )


@app.post(
    "/v1/capabilities/deny",
    status_code=200,
    tags=["Capabilities"],
)
async def deny_capability(req: DenyRequest):
    """Human denies a pending capability request."""
    capability = await db.get_capability(req.request_id)
    if not capability:
        raise HTTPException(status_code=404, detail="Capability request not found")
    if capability["status"] != "pending":
        raise HTTPException(
            status_code=409,
            detail=f"Capability already {capability['status']}",
        )

    await db.update_capability(
        req.request_id,
        {
            "status": "denied",
            "approver_id": req.approver_id,
            "notes": req.reason,
        },
    )

    await audit_module.append_entry(
        action="capability_denied",
        agent_id=capability["agent_id"],
        capability_id=req.request_id,
        details={
            "approver_id": req.approver_id,
            "reason": req.reason,
        },
    )

    return {
        "request_id": str(req.request_id),
        "status": "denied",
        "reason": req.reason,
    }


# ── Token Verification ───────────────────────────────────────────────────────


@app.get(
    "/v1/capabilities/{token}",
    response_model=TokenVerifyResponse,
    tags=["Tokens"],
)
async def verify_capability_token(token: str):
    """
    Verify a capability token. Returns validity status, remaining budget,
    allowed merchants/categories, and any violations.
    """
    result = await verify_token(token)

    # Audit: token_verified
    if result.valid:
        await audit_module.append_entry(
            action="token_verified",
            agent_id=result.agent_id,
            token_id=token,
            details={"valid": True},
        )

    return result


@app.post(
    "/v1/capabilities/{token}/revoke",
    status_code=200,
    tags=["Tokens"],
)
async def revoke_capability_token(token: str, approver_id: str = Query(...)):
    """Revoke a capability token, preventing further use."""
    revoked = await revoke_token(token)
    if not revoked:
        raise HTTPException(status_code=404, detail="Token not found")

    token_record = await db.get_token(token)

    await audit_module.append_entry(
        action="capability_revoked",
        agent_id=token_record.get("agent_id") if token_record else None,
        token_id=token,
        details={"approver_id": approver_id},
    )

    return {"token": token, "status": "revoked"}


# ── Transactions ─────────────────────────────────────────────────────────────


@app.post(
    "/v1/transactions",
    response_model=TransactionResponse,
    status_code=201,
    tags=["Transactions"],
)
async def submit_transaction(req: TransactionRequest):
    """
    Agent submits a transaction for approval.
    All guardrails are evaluated before the transaction is recorded.
    """
    # Verify token
    token_verification = await verify_token(req.token)
    if not token_verification.valid:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "Token invalid",
                "violations": token_verification.violations,
            },
        )

    # Check token-request agent match
    if req.agent_id != token_verification.agent_id:
        raise HTTPException(
            status_code=403,
            detail="Agent ID does not match token owner",
        )

    # Idempotency check
    if req.idempotency_key:
        existing = await db.find_transaction_by_idempotency(req.idempotency_key)
        if existing:
            return TransactionResponse(
                transaction_id=UUID(existing["id"]),
                status=existing["status"],
                token_id=existing["token_id"],
                agent_id=existing["agent_id"],
                amount=existing["amount"],
                merchant=existing["merchant"],
                category=existing["category"],
                description=existing.get("description", ""),
                guardrail_checks=existing.get("guardrail_checks", {}),
                violation=existing.get("violation"),
                created_at=existing["created_at"],
                message="Idempotent replay — transaction already exists",
            )

    # Load token record for guardrail context
    token_record = await db.get_token(req.token)
    if not token_record:
        raise HTTPException(status_code=404, detail="Token record not found")

    # Evaluate guardrails
    engine = get_guardrails_engine()
    ctx = GuardrailContext(
        token=token_record,
        transaction_amount=req.amount,
        transaction_merchant=req.merchant,
        transaction_category=req.category,
        agent_id=req.agent_id,
        daily_spend=0,  # Could compute from DB for stricter limits
    )
    result = engine.evaluate(ctx)

    # Record transaction (even denied ones — for audit)
    txn_data = {
        "token_id": req.token,
        "agent_id": req.agent_id,
        "amount": req.amount,
        "merchant": req.merchant,
        "category": req.category,
        "description": req.description,
        "status": "approved" if result.allowed else "denied",
        "guardrail_checks": result.checks,
        "violation": result.violation.value if result.violation else None,
        "idempotency_key": req.idempotency_key,
        "metadata": req.metadata,
    }
    txn_record = await db.create_transaction(txn_data)

    # Audit
    await audit_module.append_entry(
        action="transaction_approved" if result.allowed else "transaction_denied",
        agent_id=req.agent_id,
        token_id=req.token,
        transaction_id=UUID(txn_record["id"]),
        details={
            "amount": req.amount,
            "merchant": req.merchant,
            "category": req.category,
            "guardrail_checks": result.checks,
            "violation": result.violation.value if result.violation else None,
        },
    )

    # If approved, update spent_so_far on token
    if result.allowed:
        await record_spend(req.token, req.amount)

    return TransactionResponse(
        transaction_id=UUID(txn_record["id"]),
        status=txn_record["status"],
        token_id=req.token,
        agent_id=req.agent_id,
        amount=req.amount,
        merchant=req.merchant,
        category=req.category,
        description=req.description,
        guardrail_checks=result.checks,
        violation=result.violation.value if result.violation else None,
        created_at=txn_record.get("created_at", datetime.now(timezone.utc)),
        message=result.message,
    )


# ── Audit ─────────────────────────────────────────────────────────────────────


@app.get("/v1/audit", response_model=AuditListResponse, tags=["Audit"])
async def query_audit_trail(
    agent_id: Optional[str] = Query(default=None),
    token_id: Optional[str] = Query(default=None),
    capability_id: Optional[str] = Query(default=None),
    action: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    """
    Query the immutable audit trail with optional filters.
    Includes chain integrity verification.
    """
    entries, total = await audit_module.query_entries(
        agent_id=agent_id,
        token_id=token_id,
        capability_id=capability_id,
        action=action,
        limit=limit,
        offset=offset,
    )

    # Verify chain integrity
    chain_valid, _invalid = await audit_module.verify_chain()

    mapped = [
        AuditEntryResponse(
            entry_id=UUID(e["id"]),
            entry_index=e.get("entry_index", 0),
            action=e["action"],
            agent_id=e.get("agent_id"),
            token_id=e.get("token_id"),
            capability_id=e.get("capability_id"),
            transaction_id=e.get("transaction_id"),
            details=e.get("details", {}),
            sha256_hash=e["sha256_hash"],
            prev_hash=e.get("prev_hash"),
            created_at=e.get("created_at", datetime.now(timezone.utc)),
        )
        for e in entries
    ]

    return AuditListResponse(
        entries=mapped,
        total=total if total else len(mapped),
        limit=limit,
        offset=offset,
        chain_valid=chain_valid,
    )


# ── Error Handlers ────────────────────────────────────────────────────────────


@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc: HTTPException):
    from fastapi.responses import JSONResponse
    detail = exc.detail
    if isinstance(detail, dict):
        return JSONResponse(status_code=exc.status_code, content=detail)
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": str(exc.detail)},
    )


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
