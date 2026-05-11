"""
AgentPassport — Guardrails Engine.

Enforces spending constraints on every transaction:
  - Per-transaction spend limit
  - Daily spend limit (configurable)
  - Total budget cap
  - Action/merchant/category allowlists
  - Token expiry checks
  - Rate limiting (transactions per hour/day)
  - Violation detection and structured error reporting
"""

from __future__ import annotations

import hashlib
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from models.schemas import GuardrailViolation


# ── In-memory rate limiter (sliding window) ───────────────────────────────────


@dataclass
class RateLimitWindow:
    """Tracks transaction count in a sliding window for rate limiting."""

    max_per_hour: int = 100
    max_per_day: int = 500
    _hourly: list[float] = field(default_factory=list)
    _daily: list[float] = field(default_factory=list)

    def _prune(self, now: float, window_sec: float, bucket: list[float]) -> list[float]:
        cutoff = now - window_sec
        return [t for t in bucket if t > cutoff]

    def check_and_record(self) -> Optional[GuardrailViolation]:
        now = time.time()
        self._hourly = self._prune(now, 3600, self._hourly)
        self._daily = self._prune(now, 86400, self._daily)

        if len(self._hourly) >= self.max_per_hour:
            return GuardrailViolation.rate_limit_exceeded
        if len(self._daily) >= self.max_per_day:
            return GuardrailViolation.rate_limit_exceeded

        self._hourly.append(now)
        self._daily.append(now)
        return None


# Global rate limiter per agent
_rate_limiters: dict[str, RateLimitWindow] = defaultdict(lambda: RateLimitWindow())


# ── Guardrail check context ───────────────────────────────────────────────────


@dataclass
class GuardrailContext:
    """All the data needed to evaluate guardrails for a transaction."""

    token: dict  # The token record from DB
    transaction_amount: int
    transaction_merchant: str
    transaction_category: str
    agent_id: str
    daily_spend: int = 0  # Total spent today under this token


@dataclass
class GuardrailResult:
    """Result of guardrail evaluation."""

    allowed: bool
    violation: Optional[GuardrailViolation] = None
    message: str = ""
    checks: dict = field(default_factory=dict)


# ── Guardrails Engine ─────────────────────────────────────────────────────────


class GuardrailsEngine:
    """Evaluates all guardrails for a proposed transaction."""

    def __init__(
        self,
        per_transaction_limit: Optional[int] = None,
        daily_limit: Optional[int] = None,
        budget_cap: Optional[int] = None,
    ):
        self.per_transaction_limit = per_transaction_limit  # If set, hard cap per txn
        self.daily_limit = daily_limit  # If set, max daily spend
        self.budget_cap = budget_cap  # If set, total budget cap

    def evaluate(self, ctx: GuardrailContext) -> GuardrailResult:
        checks = {}
        now = datetime.now(timezone.utc)

        # 1. Token expiry check
        expires_at = ctx.token.get("expires_at")
        if expires_at:
            if isinstance(expires_at, str):
                expires_at = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if now > expires_at:
                checks["expiry"] = False
                return GuardrailResult(
                    allowed=False,
                    violation=GuardrailViolation.token_expired,
                    message=f"Token expired at {expires_at.isoformat()}",
                    checks=checks,
                )
        checks["expiry"] = True

        # 2. Token revoked check
        if ctx.token.get("revoked", False):
            checks["revoked"] = False
            return GuardrailResult(
                allowed=False,
                violation=GuardrailViolation.token_expired,  # closest semantic match
                message="Token has been revoked",
                checks=checks,
            )
        checks["revoked"] = True

        # 3. Merchant allowlist
        allowed_merchants = ctx.token.get("allowed_merchants", [])
        if allowed_merchants and ctx.transaction_merchant not in allowed_merchants:
            checks["merchant"] = False
            return GuardrailResult(
                allowed=False,
                violation=GuardrailViolation.merchant_not_allowed,
                message=f"Merchant '{ctx.transaction_merchant}' not in allowlist",
                checks=checks,
            )
        checks["merchant"] = True

        # 4. Category allowlist
        allowed_categories = ctx.token.get("allowed_categories", [])
        if allowed_categories and ctx.transaction_category not in allowed_categories:
            checks["category"] = False
            return GuardrailResult(
                allowed=False,
                violation=GuardrailViolation.category_not_allowed,
                message=f"Category '{ctx.transaction_category}' not in allowlist",
                checks=checks,
            )
        checks["category"] = True

        # 5. Per-transaction limit (global config)
        if self.per_transaction_limit and ctx.transaction_amount > self.per_transaction_limit:
            checks["per_transaction_limit"] = False
            return GuardrailResult(
                allowed=False,
                violation=GuardrailViolation.spend_limit_exceeded,
                message=f"Transaction amount {ctx.transaction_amount} exceeds per-transaction limit {self.per_transaction_limit}",
                checks=checks,
            )
        checks["per_transaction_limit"] = True

        # 6. Token max_spend check
        token_max = ctx.token.get("max_spend", 0)
        spent_so_far = ctx.token.get("spent_so_far", 0)
        if spent_so_far + ctx.transaction_amount > token_max:
            checks["token_budget"] = False
            return GuardrailResult(
                allowed=False,
                violation=GuardrailViolation.spend_limit_exceeded,
                message=f"Transaction would exceed token budget: spent {spent_so_far} + {ctx.transaction_amount} > {token_max}",
                checks=checks,
            )
        checks["token_budget"] = True

        # 7. Daily limit check
        if self.daily_limit and ctx.daily_spend + ctx.transaction_amount > self.daily_limit:
            checks["daily_limit"] = False
            return GuardrailResult(
                allowed=False,
                violation=GuardrailViolation.daily_limit_exceeded,
                message=f"Transaction would exceed daily limit: {ctx.daily_spend} + {ctx.transaction_amount} > {self.daily_limit}",
                checks=checks,
            )
        checks["daily_limit"] = True

        # 8. Global budget cap
        if self.budget_cap and spent_so_far + ctx.transaction_amount > self.budget_cap:
            checks["budget_cap"] = False
            return GuardrailResult(
                allowed=False,
                violation=GuardrailViolation.budget_cap_exceeded,
                message=f"Transaction would exceed budget cap: {spent_so_far} + {ctx.transaction_amount} > {self.budget_cap}",
                checks=checks,
            )
        checks["budget_cap"] = True

        # 9. Rate limiting
        rl = _rate_limiters[ctx.agent_id]
        rl_violation = rl.check_and_record()
        if rl_violation:
            checks["rate_limit"] = False
            return GuardrailResult(
                allowed=False,
                violation=rl_violation,
                message="Rate limit exceeded — too many transactions",
                checks=checks,
            )
        checks["rate_limit"] = True

        # All checks passed
        return GuardrailResult(allowed=True, checks=checks, message="All guardrails passed")


# ── Singleton ─────────────────────────────────────────────────────────────────

_engine: Optional[GuardrailsEngine] = None


def get_guardrails_engine() -> GuardrailsEngine:
    global _engine
    if _engine is None:
        _engine = GuardrailsEngine(
            per_transaction_limit=None,  # No hard global limit
            daily_limit=None,  # Per-token budget handles this
            budget_cap=None,  # Per-token budget handles this
        )
    return _engine
