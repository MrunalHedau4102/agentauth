"""
Example 2 — Scope Enforcement
===============================
Demonstrates @require_scope, ScopeManager, and trust-level hierarchy.

Run:
    python -m examples.scope_enforcement
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from agentauth import (
    ScopeManager,
    EphemeralTokenVault,
    set_current_token,
    clear_current_token,
    require_scope,
)
from agentauth.db import Base
from agentauth.exceptions import (
    ScopeNotGrantedError,
    TrustLevelInsufficientError,
    PermissionDeniedError,
)


def main():
    # ── Setup ────────────────────────────────────────────────────────────
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()

    vault = EphemeralTokenVault(
        secret_key="my-production-secret-key-min-32-chars",
        session=session,
    )
    sm = ScopeManager(session)
    print("✅ Setup complete\n")

    # ── Define protected functions ────────────────────────────────────────

    @require_scope("db:read", trust_level="low")
    def read_users():
        return [{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}]

    @require_scope("db:write", trust_level="medium")
    def create_user(name: str):
        return {"id": 99, "name": name, "created": True}

    @require_scope("db:delete", trust_level="high")
    def delete_user(user_id: int):
        return {"deleted": True, "user_id": user_id}

    @require_scope("email:send", trust_level="low")
    async def send_email(to: str, subject: str):
        return {"sent": True, "to": to}

    print("🛡️  Protected functions defined\n")

    # ── Grant scopes to test agent ────────────────────────────────────────
    sm.grant_scope("agent-1", "db:read",    trust_level_required="low")
    sm.grant_scope("agent-1", "db:write",   trust_level_required="medium")
    sm.grant_scope("agent-1", "db:delete",  trust_level_required="high")
    sm.grant_scope("agent-1", "email:send", trust_level_required="low")
    print("🔑 Scopes granted\n")

    # ── Test 1: Full access with high trust token ─────────────────────────
    print("─" * 50)
    print("Test 1: High trust token — all operations allowed")
    print("─" * 50)

    token = vault.issue(
        agent_id="agent-1",
        scopes=["db:read", "db:write", "db:delete", "email:send"],
        trust_level="high",
        ttl_seconds=60,
    )
    ctx = set_current_token(vault.verify(token))
    try:
        users = read_users()
        print(f"  ✅ read_users()      → {len(users)} users")

        user = create_user("Charlie")
        print(f"  ✅ create_user()     → {user}")

        result = delete_user(1)
        print(f"  ✅ delete_user(1)    → {result}")
    finally:
        clear_current_token(ctx)

    # ── Test 2: Read-only token blocked on write ──────────────────────────
    print("\n" + "─" * 50)
    print("Test 2: Low trust / read-only token — writes blocked")
    print("─" * 50)

    token = vault.issue(
        agent_id="agent-1",
        scopes=["db:read"],
        trust_level="low",
        ttl_seconds=60,
    )
    ctx = set_current_token(vault.verify(token))
    try:
        users = read_users()
        print(f"  ✅ read_users()   → {len(users)} users")

        try:
            create_user("Dave")
        except ScopeNotGrantedError as e:
            print(f"  ❌ create_user()  → ScopeNotGrantedError: {e}")

        try:
            delete_user(2)
        except ScopeNotGrantedError as e:
            print(f"  ❌ delete_user()  → ScopeNotGrantedError: {e}")
    finally:
        clear_current_token(ctx)

    # ── Test 3: Scope present but trust level too low ─────────────────────
    print("\n" + "─" * 50)
    print("Test 3: Has db:delete scope but trust=medium (needs high)")
    print("─" * 50)

    token = vault.issue(
        agent_id="agent-1",
        scopes=["db:delete"],
        trust_level="medium",
        ttl_seconds=60,
    )
    ctx = set_current_token(vault.verify(token))
    try:
        delete_user(3)
    except TrustLevelInsufficientError as e:
        print(f"  ❌ delete_user()  → TrustLevelInsufficientError: {e}")
    finally:
        clear_current_token(ctx)

    # ── Test 4: No token set ──────────────────────────────────────────────
    print("\n" + "─" * 50)
    print("Test 4: No token in context")
    print("─" * 50)

    try:
        read_users()
    except PermissionDeniedError as e:
        print(f"  ❌ read_users()   → PermissionDeniedError: {e}")

    # ── List granted scopes ───────────────────────────────────────────────
    print("\n📋 All scopes for agent-1:")
    for scope in sm.list_scopes("agent-1"):
        print(f"   {scope['scope']:15s} (trust_required: {scope['trust_level_required']})")

    # ── Revoke a scope ────────────────────────────────────────────────────
    revoked = sm.revoke_scope("agent-1", "db:delete")
    print(f"\n🗑️  Revoked db:delete → {revoked}")
    print(f"   Remaining scopes: {len(sm.list_scopes('agent-1'))}")

    session.close()
    print("\n✅ scope_enforcement complete")


if __name__ == "__main__":
    main()
