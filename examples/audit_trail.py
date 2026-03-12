"""
Example 4: Audit Trail & Chain Verification
=============================================
Demonstrates cryptographic audit logging and integrity verification.
"""

from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from agentauth import AuditLogger
from agentauth.db import Base
from agentauth.exceptions import AuditChainCorruptedError


def main():
    # ============================================================
    # 1. Setup Database
    # ============================================================
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    audit = AuditLogger(session)

    print("✅ Database initialized\n")

    # ============================================================
    # 2. Log Multiple Events
    # ============================================================
    print("📝 Logging authentication and authorization events...\n")

    events_to_log = [
        {
            "event_type": "agent_registered",
            "agent_id": "agent-claude-001",
            "outcome": "success",
            "metadata": {"algorithm": "ed25519"},
        },
        {
            "event_type": "token_issued",
            "agent_id": "agent-claude-001",
            "outcome": "success",
            "scopes": ["knowledge:search", "tools:execute"],
            "metadata": {"ttl": 300},
        },
        {
            "event_type": "scope_granted",
            "agent_id": "agent-claude-001",
            "outcome": "success",
            "scopes": ["database:read"],
            "metadata": {"scope": "database:read", "trust_level": "low"},
        },
        {
            "event_type": "token_used",
            "agent_id": "agent-claude-001",
            "outcome": "success",
            "scopes": ["knowledge:search"],
            "metadata": {"action": "search_knowledge_base"},
        },
        {
            "event_type": "scope_denied",
            "agent_id": "agent-claude-001",
            "outcome": "failure",
            "metadata": {"reason": "insufficient_trust_level", "scope": "database:delete"},
        },
    ]

    logged_events = []
    for i, event_data in enumerate(events_to_log):
        result = audit.log(**event_data)
        logged_events.append(result)
        print(f"  [{i+1}] {event_data['event_type']:20s} - {event_data['outcome']}")

    print()

    # ============================================================
    # 3. Display Event Details
    # ============================================================
    print("📋 First event details:")
    first = logged_events[0]
    print(f"  Event ID:       {first['event_id']}")
    print(f"  Type:           {first['event_type']}")
    print(f"  Agent:          {first['agent_id']}")
    print(f"  Outcome:        {first['outcome']}")
    print(f"  Entry Hash:     {first['entry_hash'][:16]}...")
    print(f"  Previous Hash:  {first['previous_hash']}\n")

    print("📋 Second event details:")
    second = logged_events[1]
    print(f"  Event ID:       {second['event_id']}")
    print(f"  Type:           {second['event_type']}")
    print(f"  Agent:          {second['agent_id']}")
    print(f"  Entry Hash:     {second['entry_hash'][:16]}...")
    print(f"  Previous Hash:  {second['previous_hash'][:16]}...")
    print(f"  Chain valid:    {second['previous_hash'] == first['entry_hash']} ✅\n")

    # ============================================================
    # 4. Verify Chain Integrity
    # ============================================================
    print("🔗 Verifying audit chain integrity...")

    try:
        is_valid = audit.verify_chain()
        if is_valid:
            print("  Chain status: ✅ VALID\n")
        else:
            print("  Chain status: ❌ INVALID\n")
    except AuditChainCorruptedError as e:
        print(f"  Chain status: ❌ CORRUPTED\n  Error: {e}\n")

    # ============================================================
    # 5. Query Events with Filters
    # ============================================================
    print("🔍 Querying events by agent...")

    events = audit.get_events(agent_id="agent-claude-001")
    print(f"  Total events for agent-claude-001: {len(events)}\n")

    print("  All events for this agent:")
    for e in events:
        print(f"    {e['timestamp']:30s} | {e['event_type']:20s} | {e['outcome']}")

    print()

    # ============================================================
    # 6. Query by Event Type
    # ============================================================
    print("🔍 Querying events by type (token_issued)...")

    token_events = audit.get_events(event_type="token_issued")
    print(f"  Found {len(token_events)} token_issued events\n")

    # ============================================================
    # 7. Query by Time Range
    # ============================================================
    print("🔍 Querying events by time range (future)...")

    future = datetime.now(timezone.utc) + timedelta(hours=1)
    future_events = audit.get_events(since=future)
    print(f"  Events in future: {len(future_events)} (should be 0)\n")

    # ============================================================
    # 8. Demonstrate Tamper Detection
    # ============================================================
    print("🚨 Demonstrating tamper detection...\n")

    from agentauth.db.models import AuditLogModel

    # Tamper with first entry
    first_entry = (
        session.query(AuditLogModel)
        .order_by(AuditLogModel.id.asc())
        .first()
    )

    original_hash = first_entry.entry_hash
    print(f"  Original hash:  {original_hash[:16]}...")

    # Simulate tampering by modifying the hash
    first_entry.entry_hash = "tampered_hash_0000000000000000000000000000000000000000"
    session.commit()
    print(f"  Tampered hash:  tampered_hash_00...")
    print()

    # Try to verify chain
    print("  Verifying chain with tampering...")
    try:
        audit.verify_chain()
        print("  Chain status: ✅ VALID (unexpected!)\n")
    except AuditChainCorruptedError as e:
        print(f"  Chain status: ❌ CORRUPTED (detected!)")
        print(f"  Error: {e}\n")

    # ============================================================
    # Cleanup
    # ============================================================
    session.close()
    print("✅ Example completed successfully!")


if __name__ == "__main__":
    main()
