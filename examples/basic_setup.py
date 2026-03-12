"""
Example 1: Basic Setup
======================
Demonstrates agent registration, token issuance, and basic verification.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from agentauth import (
    AgentIdentity,
    AgentRegistry,
    EphemeralTokenVault,
    AuditLogger,
)
from agentauth.db import Base


def main():
    # ============================================================
    # 1. Setup Database
    # ============================================================
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    print("✅ Database initialized\n")

    # ============================================================
    # 2. Create and Register an Agent
    # ============================================================
    print("📋 Registering agent...")
    
    agent = AgentIdentity(
        agent_id="agent-gpt4-001",
        display_name="GPT-4 Assistant",
        owner="OpenAI",
        scopes_requested=["knowledge:search", "tools:execute"]
    )

    # Generate cryptographic key pair
    private_key, public_key = AgentIdentity.generate_keypair("ed25519")
    agent.public_key = public_key
    agent.private_key = private_key

    registry = AgentRegistry(session)
    registered = registry.register_agent(agent)
    
    print(f"  Agent ID: {registered['agent_id']}")
    print(f"  Trust Level: {registered['trust_level']}")
    print(f"  Owner: {registered['owner']}\n")

    # ============================================================
    # 3. Issue an Ephemeral Token
    # ============================================================
    print("🔐 Issuing ephemeral token...")
    
    vault = EphemeralTokenVault(
        secret_key="test-secret-key-min-32-chars-long-1234567890",
        session=session
    )

    token = vault.issue(
        agent_id="agent-gpt4-001",
        scopes=["knowledge:search", "tools:execute"],
        ttl_seconds=300,  # 5 minutes
        trust_level="high"
    )

    print(f"  Token (first 30 chars): {token[:30]}...")
    print(f"  TTL: 300 seconds (5 minutes)")
    print(f"  Scopes: knowledge:search, tools:execute\n")

    # ============================================================
    # 4. Verify Token
    # ============================================================
    print("✔️  Verifying token...")
    
    try:
        payload = vault.verify(token)
        print(f"  Agent ID: {payload['agent_id']}")
        print(f"  Scopes: {payload['scopes']}")
        print(f"  Trust Level: {payload['trust_level']}")
        print(f"  Valid: ✅\n")
    except Exception as e:
        print(f"  Error: {e}\n")

    # ============================================================
    # 5. Log Audit Events
    # ============================================================
    print("📊 Logging audit events...")
    
    audit = AuditLogger(session)
    
    audit.log(
        event_type="agent_registered",
        agent_id="agent-gpt4-001",
        outcome="success",
        metadata={"algorithm": "ed25519"}
    )
    
    audit.log(
        event_type="token_issued",
        agent_id="agent-gpt4-001",
        outcome="success",
        scopes=["knowledge:search", "tools:execute"],
        metadata={"ttl": 300}
    )

    print(f"  Events logged: 2\n")

    # ============================================================
    # 6. Query Audit Events
    # ============================================================
    print("📈 Querying audit events...")
    
    events = audit.get_events(agent_id="agent-gpt4-001")
    
    for event in events:
        print(f"  [{event['event_type']:20s}] {event['outcome']:7s} - {event['timestamp']}")

    # ============================================================
    # 7. Verify Audit Chain
    # ============================================================
    print("\n🔗 Verifying audit chain integrity...")
    
    if audit.verify_chain():
        print("  Chain integrity: ✅ VALID\n")
    else:
        print("  Chain integrity: ❌ CORRUPTED\n")

    # ============================================================
    # 8. Update Agent Trust Level
    # ============================================================
    print("⭐ Updating agent trust level...")
    
    updated = registry.trust_agent("agent-gpt4-001", "trusted")
    print(f"  New trust level: {updated['trust_level']}\n")

    # ============================================================
    # Cleanup
    # ============================================================
    session.close()
    print("✅ Example completed successfully!")


if __name__ == "__main__":
    main()
