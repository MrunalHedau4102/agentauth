"""
Example 1 — Basic Setup
========================
Register an agent, issue a token, verify it, and log audit events.

Run:
    python -m examples.basic_setup
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from agentauth import (
    AgentIdentity,
    AgentRegistry,
    EphemeralTokenVault,
    AuditLogger,
)
from agentauth.db import Base
from agentauth.exceptions import TokenExpiredError


def main():
    # ── 1. Database setup ───────────────────────────────────────────────
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    print("✅ Database initialised\n")

    # ── 2. Generate cryptographic key pair ──────────────────────────────
    private_key, public_key = AgentIdentity.generate_keypair("ed25519")
    print(f"🔑 Ed25519 key pair generated")
    print(f"   Public key (first 60 chars): {public_key[:60]}...\n")

    # ── 3. Create and register agent ────────────────────────────────────
    agent = AgentIdentity(
        agent_id="gpt4-assistant-001",
        display_name="GPT-4 Assistant",
        owner="my-company",
        public_key=public_key,
        private_key=private_key,
        scopes_requested=["db:read", "email:send"],
    )

    registry = AgentRegistry(session)
    registered = registry.register_agent(agent)

    print(f"📋 Agent registered")
    print(f"   agent_id    : {registered['agent_id']}")
    print(f"   trust_level : {registered['trust_level']}")
    print(f"   owner       : {registered['owner']}")
    print(f"   is_revoked  : {registered['is_revoked']}\n")

    # ── 4. Elevate trust level ──────────────────────────────────────────
    updated = registry.trust_agent("gpt4-assistant-001", "verified")
    print(f"⭐ Trust level updated → {updated['trust_level']}\n")

    # ── 5. Issue ephemeral token ────────────────────────────────────────
    vault = EphemeralTokenVault(
        secret_key="my-production-secret-key-min-32-chars",
        session=session,
    )

    token = vault.issue(
        agent_id="gpt4-assistant-001",
        scopes=["db:read", "email:send"],
        ttl_seconds=300,
        trust_level="high",
    )

    print(f"🔐 Token issued")
    print(f"   First 40 chars : {token[:40]}...")
    print(f"   TTL            : 300 seconds\n")

    # ── 6. Verify token ─────────────────────────────────────────────────
    payload = vault.verify(token)
    print(f"✔️  Token verified")
    print(f"   agent_id    : {payload['agent_id']}")
    print(f"   scopes      : {payload['scopes']}")
    print(f"   trust_level : {payload['trust_level']}\n")

    # ── 7. Issue one-time-use token ─────────────────────────────────────
    ott = vault.issue(
        agent_id="gpt4-assistant-001",
        scopes=["db:read"],
        ttl_seconds=60,
        one_time_use=True,
    )
    vault.verify(ott)   # first use — succeeds
    print(f"🔂 One-time token: first use ✅")

    from agentauth.exceptions import InvalidTokenError
    try:
        vault.verify(ott)   # second use — must fail
    except InvalidTokenError as e:
        print(f"🔂 One-time token: second use ❌ ({e})\n")

    # ── 8. Audit logging ────────────────────────────────────────────────
    audit = AuditLogger(session)

    audit.log(
        event_type="agent_registered",
        agent_id="gpt4-assistant-001",
        outcome="success",
        metadata={"algorithm": "ed25519"},
    )
    audit.log(
        event_type="token_issued",
        agent_id="gpt4-assistant-001",
        outcome="success",
        scopes=["db:read", "email:send"],
        metadata={"ttl": 300},
    )

    events = audit.get_events(agent_id="gpt4-assistant-001")
    print(f"📊 Audit log ({len(events)} events)")
    for e in events:
        print(f"   [{e['event_type']:20s}] {e['outcome']:7s}")

    # ── 9. Chain verification ────────────────────────────────────────────
    print(f"\n🔗 Chain integrity: {'✅ VALID' if audit.verify_chain() else '❌ CORRUPTED'}")

    session.close()
    print("\n✅ basic_setup complete")


if __name__ == "__main__":
    main()
