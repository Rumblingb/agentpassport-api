# AgentPassport API

**Governed payment middleware for AI agents. Built on Stripe.**

> Stripe moves the money. AgentPassport governs who can spend it.

## What It Does

AI agents need to spend money — API credits, SaaS subscriptions, compute. But giving an agent your credit card is terrifying. AgentPassport sits between your agent and Stripe, enforcing guardrails on every transaction:

- **Capability Vault** — Agent requests spending power, human approves with guardrails
- **Scoped Tokens** — Spend limits, merchant allowlists, time-based expiry
- **Immutable Audit** — Every action logged with SHA-256 chain linking
- **Built on Stripe** — Leverages Stripe's payment rails, compliance, and trust

## Architecture

```
AI Agent → AgentPassport API (governance) → Stripe (money movement)
              ↑
         Human approves via API
```

## Quick Start

```bash
# Install
pip install -r requirements.txt

# Set environment
cp .env.example .env  # edit with your Supabase + Stripe keys

# Run
uvicorn main:app --reload --port 8000
```

API docs at `http://localhost:8000/docs`

## API

### Capabilities

| Method | Path | Description |
|--------|------|-------------|
| POST | `/v1/capabilities/request` | Agent requests a spending capability |
| POST | `/v1/capabilities/approve` | Human approves and gets scoped token |
| POST | `/v1/capabilities/deny` | Human denies the request |
| GET | `/v1/capabilities/{token}` | Verify token validity and remaining budget |
| POST | `/v1/capabilities/{token}/revoke` | Revoke a token immediately |

### Transactions

| Method | Path | Description |
|--------|------|-------------|
| POST | `/v1/transactions` | Agent submits a transaction (guardrails enforced) |

### Audit

| Method | Path | Description |
|--------|------|-------------|
| GET | `/v1/audit` | Query the immutable audit trail |

### System

| Method | Path | Description |
|--------|------|-------------|
| GET | `/v1/health` | Health check |

## Flow

```python
# 1. Agent requests capability
resp = requests.post("/v1/capabilities/request", json={
    "agent_id": "travel-agent-01",
    "scope": "purchase_flights",
    "max_spend": 50000,  # $500.00 in cents
    "allowed_merchants": ["united", "delta", "southwest"],
    "allowed_categories": ["travel"],
    "duration_seconds": 3600  # 1 hour
})
request_id = resp.json()["request_id"]

# 2. Human approves (optionally narrows scope)
resp = requests.post("/v1/capabilities/approve", json={
    "request_id": request_id,
    "approver_id": "human-rajiv",
    "narrowed_max_spend": 30000  # Narrow to $300
})
token = resp.json()["token"]  # agentpassport_abc123...

# 3. Agent spends within guardrails
resp = requests.post("/v1/transactions", json={
    "token": token,
    "agent_id": "travel-agent-01",
    "amount": 25000,  # $250.00
    "merchant": "united",
    "category": "travel",
    "description": "SFO→JFK flight UA 123"
})
# → 201 Created: approved (within guardrails)

# 4. Agent tries to overspend
resp = requests.post("/v1/transactions", json={
    "token": token,
    "agent_id": "travel-agent-01",
    "amount": 10000,  # $100 (would exceed $300 cap)
    "merchant": "delta",
    "category": "travel",
    "description": "Hotel booking"
})
# → 201 Created, status: "denied" — budget cap exceeded
```

## Guardrails Engine

Nine checks on every transaction:
1. **Token expiry** — Token must not be expired
2. **Revocation** — Token must not be revoked
3. **Merchant allowlist** — Merchant must be in allowed list (if configured)
4. **Category allowlist** — Category must be allowed (if configured)
5. **Per-transaction limit** — Amount must not exceed configured max
6. **Token budget** — Total spend must not exceed token max_spend
7. **Daily limit** — Daily spend must not exceed configured limit
8. **Budget cap** — Total must not exceed absolute cap
9. **Rate limiting** — Transactions per hour/day must not exceed limits

## Pricing

| Tier | Price | Limits |
|------|-------|--------|
| Free | $0/mo | 50 transactions/day, 5 active tokens |
| Pro | $19/mo | 500 transactions/day, 50 active tokens |
| Enterprise | $99/mo | Unlimited, custom guardrails, priority support |

→ [Subscribe on Stripe](https://buy.stripe.com/agentpassport)

## Deploy

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/new?template=https://github.com/Rumblingb/agentpassport-api)

## License

MIT — AgentPay Labs
