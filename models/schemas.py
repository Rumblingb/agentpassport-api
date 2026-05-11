"""
AgentPassport API — Pydantic schemas for requests and responses.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator


# ── Enums ────────────────────────────────────────────────────────────────────


class CapabilityStatus(str, Enum):
    pending = "pending"
    approved = "approved"
    denied = "denied"
    expired = "expired"
    revoked = "revoked"


class TransactionStatus(str, Enum):
    pending = "pending"
    approved = "approved"
    denied = "denied"
    completed = "completed"
    failed = "failed"


class AuditAction(str, Enum):
    capability_requested = "capability_requested"
    capability_approved = "capability_approved"
    capability_denied = "capability_denied"
    capability_expired = "capability_expired"
    capability_revoked = "capability_revoked"
    transaction_submitted = "transaction_submitted"
    transaction_approved = "transaction_approved"
    transaction_denied = "transaction_denied"
    transaction_completed = "transaction_completed"
    token_verified = "token_verified"


class GuardrailViolation(str, Enum):
    spend_limit_exceeded = "spend_limit_exceeded"
    daily_limit_exceeded = "daily_limit_exceeded"
    budget_cap_exceeded = "budget_cap_exceeded"
    merchant_not_allowed = "merchant_not_allowed"
    category_not_allowed = "category_not_allowed"
    token_expired = "token_expired"
    rate_limit_exceeded = "rate_limit_exceeded"
    scope_mismatch = "scope_mismatch"


# ── Request Schemas ───────────────────────────────────────────────────────────


class CapabilityRequest(BaseModel):
    """Agent requests a spending capability from a human approver."""

    agent_id: str = Field(..., min_length=1, max_length=128, description="Unique agent identifier")
    scope: str = Field(..., min_length=1, max_length=256, description="What the agent wants to do (e.g., 'purchase_flights')")
    max_spend: int = Field(..., gt=0, description="Maximum spend in cents (USD)")
    allowed_merchants: list[str] = Field(default_factory=list, description="List of allowed merchant IDs or patterns")
    allowed_categories: list[str] = Field(default_factory=list, description="List of allowed spending categories")
    duration_seconds: int = Field(default=3600, ge=60, le=86400, description="Token lifetime in seconds (1 min to 24 hrs)")
    metadata: dict = Field(default_factory=dict, description="Arbitrary metadata for audit trail")


class ApproveRequest(BaseModel):
    """Human approves a pending capability request, optionally narrowing scope."""

    request_id: UUID = Field(..., description="The capability request ID to approve")
    approver_id: str = Field(..., min_length=1, max_length=128, description="Who is approving")
    narrowed_max_spend: Optional[int] = Field(default=None, description="Override max spend (must be ≤ original)")
    narrowed_duration_seconds: Optional[int] = Field(default=None, ge=60, le=86400)
    notes: str = Field(default="", max_length=1024)


class DenyRequest(BaseModel):
    """Human denies a pending capability request."""

    request_id: UUID = Field(...)
    approver_id: str = Field(..., min_length=1, max_length=128)
    reason: str = Field(default="Denied by approver", max_length=1024)


class TransactionRequest(BaseModel):
    """Agent submits a transaction within an approved capability scope."""

    token: str = Field(..., min_length=1, description="Capability token (agentpassport_xxx)")
    agent_id: str = Field(..., min_length=1, max_length=128)
    amount: int = Field(..., gt=0, description="Transaction amount in cents (USD)")
    merchant: str = Field(..., min_length=1, max_length=256, description="Merchant identifier")
    category: str = Field(default="general", max_length=128)
    description: str = Field(default="", max_length=1024)
    idempotency_key: Optional[str] = Field(default=None, max_length=256, description="Client-supplied idempotency key")
    metadata: dict = Field(default_factory=dict)


class AuditQuery(BaseModel):
    """Query the immutable audit trail."""

    agent_id: Optional[str] = Field(default=None)
    token_id: Optional[str] = Field(default=None)
    capability_id: Optional[str] = Field(default=None)
    action: Optional[AuditAction] = Field(default=None)
    from_time: Optional[datetime] = Field(default=None)
    to_time: Optional[datetime] = Field(default=None)
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)


# ── Response Schemas ──────────────────────────────────────────────────────────


class CapabilityRequestResponse(BaseModel):
    """Returned to the agent after requesting a capability."""

    request_id: UUID
    agent_id: str
    status: CapabilityStatus = CapabilityStatus.pending
    scope: str
    max_spend: int
    allowed_merchants: list[str]
    allowed_categories: list[str]
    expires_in_seconds: int
    created_at: datetime
    message: str = "Capability request created. Awaiting human approval."


class CapabilityTokenResponse(BaseModel):
    """Returned after a capability is approved — contains the scoped token."""

    token: str = Field(..., description="Scoped capability token (agentpassport_xxx)")
    request_id: UUID
    status: CapabilityStatus = CapabilityStatus.approved
    scope: str
    max_spend: int
    allowed_merchants: list[str]
    allowed_categories: list[str]
    expires_at: datetime
    issued_at: datetime


class TokenVerifyResponse(BaseModel):
    """Result of verifying a capability token."""

    valid: bool
    token_id: str
    agent_id: str
    scope: str
    max_spend: int
    spent_so_far: int
    remaining: int
    allowed_merchants: list[str]
    allowed_categories: list[str]
    expires_at: datetime
    issued_at: datetime
    revoked: bool
    violations: list[str] = Field(default_factory=list)


class TransactionResponse(BaseModel):
    """Result of a transaction submission."""

    transaction_id: UUID
    status: TransactionStatus
    token_id: str
    agent_id: str
    amount: int
    merchant: str
    category: str
    description: str
    guardrail_checks: dict = Field(default_factory=dict)
    violation: Optional[str] = None
    created_at: datetime
    message: str


class AuditEntryResponse(BaseModel):
    """A single entry in the audit trail."""

    entry_id: UUID
    entry_index: int
    action: AuditAction
    agent_id: Optional[str] = None
    token_id: Optional[str] = None
    capability_id: Optional[str] = None
    transaction_id: Optional[str] = None
    details: dict = Field(default_factory=dict)
    sha256_hash: str
    prev_hash: Optional[str] = None
    created_at: datetime


class AuditListResponse(BaseModel):
    """Paginated audit trail results."""

    entries: list[AuditEntryResponse]
    total: int
    limit: int
    offset: int
    chain_valid: bool = Field(..., description="Whether all SHA-256 chain links are intact")


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = "ok"
    version: str = "0.1.0"
    service: str = "AgentPassport API"
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    checks: dict = Field(default_factory=dict)


class ErrorResponse(BaseModel):
    """Standard error response."""

    error: str
    detail: Optional[str] = None
    violation: Optional[GuardrailViolation] = None
    request_id: Optional[UUID] = None
