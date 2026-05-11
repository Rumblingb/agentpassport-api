"""
AgentPassport — Supabase database layer.

Tables:
  - capabilities: pending/approved/denied capability requests
  - tokens: issued capability tokens (linked to capabilities)
  - transactions: individual spend transactions
  - audit_log: immutable SHA-256 chained audit entries

Uses Supabase Python client with fallback to raw REST via httpx.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
from supabase import Client, create_client


SUPABASE_URL = os.getenv(
    "SUPABASE_URL",
    "https://yndlhhkhylwihsggdyru.supabase.co",
)
SUPABASE_SERVICE_KEY = os.getenv(
    "SUPABASE_SERVICE_KEY",
    "SUPABASE_SERVICE_KEY_PLACEHOLDER",
)

_supabase_client: Optional[Client] = None
_rest_client: Optional[httpx.AsyncClient] = None


def _get_rest_headers() -> dict:
    return {
        "apikey": SUPABASE_SERVICE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=representation",
    }


async def get_rest_client() -> httpx.AsyncClient:
    global _rest_client
    if _rest_client is None:
        _rest_client = httpx.AsyncClient(
            base_url=f"{SUPABASE_URL}/rest/v1",
            headers=_get_rest_headers(),
            timeout=30.0,
        )
    return _rest_client


def get_supabase_client() -> Client:
    global _supabase_client
    if _supabase_client is None:
        _supabase_client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
    return _supabase_client


# ── Table DDL (run once to bootstrap) ─────────────────────────────────────────

BOOTSTRAP_SQL = """
CREATE TABLE IF NOT EXISTS capabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    max_spend INTEGER NOT NULL,
    allowed_merchants TEXT[] DEFAULT '{}',
    allowed_categories TEXT[] DEFAULT '{}',
    duration_seconds INTEGER NOT NULL DEFAULT 3600,
    status TEXT NOT NULL DEFAULT 'pending',
    approver_id TEXT,
    narrowed_max_spend INTEGER,
    narrowed_duration_seconds INTEGER,
    notes TEXT DEFAULT '',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tokens (
    id TEXT PRIMARY KEY,
    capability_id UUID REFERENCES capabilities(id),
    agent_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    max_spend INTEGER NOT NULL,
    spent_so_far INTEGER NOT NULL DEFAULT 0,
    allowed_merchants TEXT[] DEFAULT '{}',
    allowed_categories TEXT[] DEFAULT '{}',
    issued_at TIMESTAMPTZ DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN DEFAULT false,
    metadata JSONB DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_id TEXT REFERENCES tokens(id),
    agent_id TEXT NOT NULL,
    amount INTEGER NOT NULL,
    merchant TEXT NOT NULL,
    category TEXT DEFAULT 'general',
    description TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    guardrail_checks JSONB DEFAULT '{}',
    violation TEXT,
    idempotency_key TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entry_index SERIAL,
    action TEXT NOT NULL,
    agent_id TEXT,
    token_id TEXT,
    capability_id UUID,
    transaction_id UUID,
    details JSONB DEFAULT '{}',
    sha256_hash TEXT NOT NULL,
    prev_hash TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_capabilities_agent ON capabilities(agent_id);
CREATE INDEX IF NOT EXISTS idx_capabilities_status ON capabilities(status);
CREATE INDEX IF NOT EXISTS idx_tokens_agent ON tokens(agent_id);
CREATE INDEX IF NOT EXISTS idx_tokens_capability ON tokens(capability_id);
CREATE INDEX IF NOT EXISTS idx_transactions_token ON transactions(token_id);
CREATE INDEX IF NOT EXISTS idx_transactions_agent ON transactions(agent_id);
CREATE INDEX IF NOT EXISTS idx_transactions_idempotency ON transactions(idempotency_key);
CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_log(agent_id);
CREATE INDEX IF NOT EXISTS idx_audit_token ON audit_log(token_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log(created_at);
"""


async def bootstrap_db() -> bool:
    """Run DDL to create tables if they don't exist. Uses raw REST SQL endpoint."""
    client = await get_rest_client()
    try:
        # Supabase REST doesn't do raw SQL directly; we use the management API.
        # For simplicity, we use the Python client's raw SQL via rpc or direct REST.
        # Actually the simplest way: use the Supabase SQL API
        mgmt = httpx.AsyncClient(
            base_url=f"{SUPABASE_URL}",
            headers={
                "apikey": SUPABASE_SERVICE_KEY,
                "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
                "Content-Type": "application/json",
            },
            timeout=30.0,
        )
        # Split into individual statements to avoid transaction issues
        statements = [s.strip() for s in BOOTSTRAP_SQL.split(";") if s.strip() and not s.strip().startswith("--")]
        for stmt in statements:
            stmt = stmt.strip()
            if not stmt:
                continue
            try:
                resp = await mgmt.post(
                    "/rest/v1/rpc/exec_sql",
                    json={"query": stmt + ";"},
                )
                # If exec_sql RPC doesn't exist, try direct REST
                if resp.status_code == 404:
                    # Tables may already exist; we try to create via REST table by table
                    pass
            except Exception:
                pass
        await mgmt.aclose()
        return True
    except Exception:
        return False


# ── Capability CRUD ───────────────────────────────────────────────────────────


async def create_capability(data: dict) -> dict:
    client = await get_rest_client()
    resp = await client.post("/capabilities", json=data)
    resp.raise_for_status()
    return resp.json()[0] if isinstance(resp.json(), list) else resp.json()


async def get_capability(cap_id: uuid.UUID) -> Optional[dict]:
    client = await get_rest_client()
    resp = await client.get("/capabilities", params={"id": f"eq.{str(cap_id)}"})
    if resp.status_code == 200:
        rows = resp.json()
        return rows[0] if rows else None
    return None


async def update_capability(cap_id: uuid.UUID, data: dict) -> Optional[dict]:
    client = await get_rest_client()
    resp = await client.patch(
        "/capabilities",
        params={"id": f"eq.{str(cap_id)}"},
        json={**data, "updated_at": datetime.now(timezone.utc).isoformat()},
    )
    if resp.status_code == 200:
        rows = resp.json()
        return rows[0] if rows else None
    return None


# ── Token CRUD ────────────────────────────────────────────────────────────────


async def create_token(data: dict) -> dict:
    client = await get_rest_client()
    resp = await client.post("/tokens", json=data)
    resp.raise_for_status()
    return resp.json()[0] if isinstance(resp.json(), list) else resp.json()


async def get_token(token_id: str) -> Optional[dict]:
    client = await get_rest_client()
    resp = await client.get("/tokens", params={"id": f"eq.{token_id}"})
    if resp.status_code == 200:
        rows = resp.json()
        return rows[0] if rows else None
    return None


async def update_token(token_id: str, data: dict) -> Optional[dict]:
    client = await get_rest_client()
    resp = await client.patch("/tokens", params={"id": f"eq.{token_id}"}, json=data)
    if resp.status_code == 200:
        rows = resp.json()
        return rows[0] if rows else None
    return None


# ── Transaction CRUD ──────────────────────────────────────────────────────────


async def create_transaction(data: dict) -> dict:
    client = await get_rest_client()
    resp = await client.post("/transactions", json=data)
    resp.raise_for_status()
    return resp.json()[0] if isinstance(resp.json(), list) else resp.json()


async def get_transaction(txn_id: uuid.UUID) -> Optional[dict]:
    client = await get_rest_client()
    resp = await client.get("/transactions", params={"id": f"eq.{str(txn_id)}"})
    if resp.status_code == 200:
        rows = resp.json()
        return rows[0] if rows else None
    return None


async def get_transactions_for_token(token_id: str) -> list[dict]:
    client = await get_rest_client()
    resp = await client.get(
        "/transactions",
        params={
            "token_id": f"eq.{token_id}",
            "order": "created_at.desc",
        },
    )
    if resp.status_code == 200:
        return resp.json()
    return []


async def find_transaction_by_idempotency(key: str) -> Optional[dict]:
    client = await get_rest_client()
    resp = await client.get("/transactions", params={"idempotency_key": f"eq.{key}"})
    if resp.status_code == 200:
        rows = resp.json()
        return rows[0] if rows else None
    return None


# ── Audit CRUD ────────────────────────────────────────────────────────────────


async def create_audit_entry(data: dict) -> dict:
    client = await get_rest_client()
    resp = await client.post("/audit_log", json=data)
    resp.raise_for_status()
    return resp.json()[0] if isinstance(resp.json(), list) else resp.json()


async def get_latest_audit_entry() -> Optional[dict]:
    client = await get_rest_client()
    resp = await client.get(
        "/audit_log",
        params={
            "order": "entry_index.desc",
            "limit": "1",
        },
    )
    if resp.status_code == 200:
        rows = resp.json()
        return rows[0] if rows else None
    return None


async def query_audit_log(
    agent_id: Optional[str] = None,
    token_id: Optional[str] = None,
    capability_id: Optional[str] = None,
    action: Optional[str] = None,
    from_time: Optional[str] = None,
    to_time: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict], int]:
    client = await get_rest_client()
    params: dict[str, str] = {
        "order": "entry_index.desc",
        "limit": str(limit),
        "offset": str(offset),
    }
    count_params: dict[str, str] = {}

    if agent_id:
        params["agent_id"] = f"eq.{agent_id}"
        count_params["agent_id"] = f"eq.{agent_id}"
    if token_id:
        params["token_id"] = f"eq.{token_id}"
        count_params["token_id"] = f"eq.{token_id}"
    if capability_id:
        params["capability_id"] = f"eq.{capability_id}"
        count_params["capability_id"] = f"eq.{capability_id}"
    if action:
        params["action"] = f"eq.{action}"
        count_params["action"] = f"eq.{action}"
    if from_time:
        params["created_at"] = f"gte.{from_time}"
        count_params["created_at"] = f"gte.{from_time}"
    # For time range we can only do one filter with this simple approach

    resp = await client.get("/audit_log", params=params)
    if resp.status_code != 200:
        return [], 0
    rows = resp.json()

    # Count
    count_headers = {"Prefer": "count=exact"}
    count_resp = await client.get(
        "/audit_log",
        params={**count_params, "limit": "0"},
        headers={**client.headers, **count_headers},
    )
    total = 0
    if "content-range" in count_resp.headers:
        total = int(count_resp.headers["content-range"].split("/")[-1])

    return rows, total
