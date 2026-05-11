"""
AgentPassport — Stripe Integration (Placeholder).

Ready for Stripe Connect platform-model payments or direct payment method
token issuance. Currently wired as an async-ready stub that logs operations.

To activate:
  1. Set STRIPE_API_KEY in environment
  2. Implement create_payment_intent, confirm_payment, etc.
  3. Call from transaction endpoint after guardrails pass
"""

from __future__ import annotations

import os
from typing import Optional

import stripe


STRIPE_API_KEY = os.getenv("STRIPE_API_KEY", "")

_stripe_initialized = False


def init_stripe():
    global _stripe_initialized
    if STRIPE_API_KEY and not _stripe_initialized:
        stripe.api_key = STRIPE_API_KEY
        _stripe_initialized = True


async def create_payment_intent(
    amount: int,  # cents
    currency: str = "usd",
    merchant: str = "",
    metadata: Optional[dict] = None,
) -> dict:
    """Placeholder: Create a Stripe PaymentIntent."""
    init_stripe()
    if not STRIPE_API_KEY:
        return {
            "status": "stub",
            "message": "Stripe not configured — set STRIPE_API_KEY",
            "amount": amount,
            "currency": currency,
            "merchant": merchant,
        }

    try:
        intent = stripe.PaymentIntent.create(
            amount=amount,
            currency=currency,
            metadata={
                "merchant": merchant,
                **(metadata or {}),
            },
        )
        return {
            "id": intent.id,
            "status": intent.status,
            "client_secret": intent.client_secret,
            "amount": amount,
            "currency": currency,
        }
    except stripe.StripeError as e:
        return {
            "status": "error",
            "message": str(e),
            "amount": amount,
            "currency": currency,
        }


async def confirm_payment(payment_intent_id: str) -> dict:
    """Placeholder: Confirm a Stripe PaymentIntent."""
    init_stripe()
    if not STRIPE_API_KEY:
        return {"status": "stub", "message": "Stripe not configured"}

    try:
        intent = stripe.PaymentIntent.confirm(payment_intent_id)
        return {"id": intent.id, "status": intent.status}
    except stripe.StripeError as e:
        return {"status": "error", "message": str(e)}
