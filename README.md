# AgentPassport API

![Status](https://img.shields.io/badge/status-active-brightgreen)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-blue)
![Built on Stripe](https://img.shields.io/badge/built%20on-Stripe-635BFF)

**Governed payment middleware for AI agents. Built on Stripe.**

> Stripe moves the money. AgentPassport governs who can spend it.

## Why AgentPassport?

AI agents need to spend money — API credits, flights, SaaS subscriptions, compute. But giving an agent your credit card is terrifying. AgentPassport sits between your agent and Stripe, enforcing guardrails on every transaction before a cent moves:

- **Capability Vault** — Agent requests spending power; human approves with guardrails
- **Scoped Tokens** — Spend limits, merchant allowlists, time-based expiry built in
- **Immutable Audit** — Every action logged with SHA-256 chain linking
- **Nine-layer guardrails engine** — Budget caps, rate limits, category filters, revocation
- **Built on Stripe** — Leverages Stripe's payment rails, compliance, and global trust

## Architecture

```
AI Agent → AgentPassport API (governance layer) → Stripe (money movement)
                 ↑
          Human approves via API or dashboard
```

## Pricing

| Tier | Price | Transactions | Active Tokens |
|------|-------|-------------|---------------|
| Free | $0/mo | 50/day | 5 |
| Pro | **$19/mo** | 500/day | 50 |
| Enterprise | **$99/mo** | Unlimited | Unlimited + custom guardrails |

→ **[Subscribe Pro — $19/mo](https://buy.stripe.com/28E3cxflRabW1jqgvx1oI0s)**  
→ **[Subscribe Enterprise — $99/mo](https://buy.stripe.com/eVqfZjflRgAk1jqfrt1oI0t)**

## Prerequisites

- Python 3.10+
- [Stripe account](https://stripe.com) (live or test keys)
- [Supabase project](https://supabase.com) (for audit trail + token storage)

## Quick Start

```bash
# Clone and install
git clone https://github.com/Rumblingb/agentpassport-api
cd agentpassport-api
pip install -r requirements.txt

# Configure
cp .env.example .env   # fill in your keys (see below)

# Run
uvicorn main:app --reload --port 8000
```

API docs live at `http://localhost:8000/docs` (Swagger UI auto-generated).

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `STRIPE_SECRET_KEY` | ✅ | Stripe secret key (`sk_live_...` or `sk_test_...`) |
| `SUPABASE_URL` | ✅ | Your Supabase project URL |
| `SUPABASE_SERVICE_KEY` | ✅ | Supabase service role key |
| `API_SECRET` | ✅ | Secret for signing AgentPassport tokens |
| `ENVIRONMENT` | — | `production` or `development` (default: development) |

## API Reference

### Capabilities

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/capabilities/request` | Agent requests a spending capability |
| `POST` | `/v1/capabilities/approve` | Human approves and receives scoped token |
| `POST` | `/v1/capabilities/deny` | Human denies the request |
| `GET` | `/v1/capabilities/{token}` | Verify token validity and remaining budget |
| `POST` | `/v1/capabilities/{token}/revoke` | Revoke a token immediately |

### Transactions

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/transactions` | Agent submits a transaction (all guardrails enforced) |

### Audit

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/audit` | Query the immutable SHA-256 audit trail |

### System

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/health` | Health check |

## Integration Example

```python
import requests

BASE = "http://localhost:8000"

# 1. Agent requests capability
resp = requests.post(f"{BASE}/v1/capabilities/request", json={
    "agent_id": "travel-agent-01",
    "scope": "purchase_flights",
    "max_spend": 50000,          # $500.00 in cents
    "allowed_merchants": ["united", "delta", "southwest"],
    "allowed_categories": ["travel"],
    "duration_seconds": 3600     # 1-hour window
})
request_id = resp.json()["request_id"]

# 2. Human approves (optionally narrows scope)
resp = requests.post(f"{BASE}/v1/capabilities/approve", json={
    "request_id": request_id,
    "approver_id": "human-rajiv",
    "narrowed_max_spend": 30000  # Approve only $300
})
token = resp.json()["token"]     # agentpassport_abc123...

# 3. Agent spends within guardrails
resp = requests.post(f"{BASE}/v1/transactions", json={
    "token": token,
    "agent_id": "travel-agent-01",
    "amount": 25000,             # $250.00
    "merchant": "united",
    "category": "travel",
    "description": "SFO-JFK flight UA 123"
})
# 201 Created — approved

# 4. Overspend attempt is silently blocked
resp = requests.post(f"{BASE}/v1/transactions", json={
    "token": token,
    "agent_id": "travel-agent-01",
    "amount": 10000,             # Would push total over $300 cap
    "merchant": "delta",
    "category": "travel",
    "description": "Hotel"
})
# 201 Created, status: "denied" — budget cap exceeded
```

## Guardrails Engine

Nine checks run in sequence on every transaction:

1. **Token expiry** — Token must not be past its `duration_seconds` window
2. **Revocation** — Token must not have been explicitly revoked
3. **Merchant allowlist** — Merchant must appear in the approved list (if set)
4. **Category allowlist** — Category must be allowed (if set)
5. **Per-transaction limit** — Single amount must not exceed configured max
6. **Token budget** — Cumulative spend must not exceed `max_spend`
7. **Daily limit** — Daily spend must not exceed configured daily cap
8. **Absolute budget cap** — Hard ceiling regardless of other limits
9. **Rate limiting** — Transactions per hour/day must not exceed limits

## Deploy to Railway

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/new?template=https://github.com/Rumblingb/agentpassport-api)

Set the four required env vars in Railway's dashboard after deploy.

## License

MIT — [AgentPay Labs](https://rumblingb.github.io)
