"""
Example 4 — Audit Trail & Chain Verification
==============================================
Demonstrates hash-chained tamper-evident logging, querying, and tampering detection.

Run:
    python -m examples.audit_trail
"""

from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from agentauth import AuditLogger
from agentauth.db import Base
from agentauth.db.models import AuditLogModel
from agentauth.exceptions import AuditChainCorruptedError


def main():
    # ── Setup ────────────────────────────────────────────────────────────
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    audit = AuditLogger(session)
    print("✅ Database initialised\n")

    # ── Log a sequence of real-world events ──────────────────────────────
    print("📝 Logging events...\n")

    events = [
        dict(event_type="agent_registered",  agent_id="agent-gpt4",   outcome="success",
             metadata={"algorithm": "ed25519"}),
        dict(event_type="token_issued",      agent_id="agent-gpt4",   outcome="success",
             scopes=["db:read", "email:send"], metadata={"ttl": 300}),
        dict(event_type="token_used",        agent_id="agent-gpt4",   outcome="success",
             scopes=["db:read"], metadata={"action": "list_users"}),
        dict(event_type="scope_denied",      agent_id="agent-gpt4",   outcome="failure",
             metadata={"scope": "db:delete", "reason": "trust_level_insufficient"}),
        dict(event_type="suspicious_activity", agent_id="agent-gpt4", outcome="failure",
             metadata={"rule": "suspicious_phrase", "field": "query"}),
    ]

    logged = []
    for ev in events:
        result = audit.log(**ev)
        logged.append(result)
        print(f"  [{result['event_type']:22s}] {result['outcome']:7s}  "
              f"hash={result['entry_hash'][:12]}...")

    # ── Show chain linkage ────────────────────────────────────────────────
    print(f"\n🔗 Chain linkage:")
    print(f"   Entry 1 previous_hash : {logged[0]['previous_hash']} (genesis)")
    print(f"   Entry 2 previous_hash : {logged[1]['previous_hash'][:16]}...")
    print(f"   Chain link valid      : {logged[1]['previous_hash'] == logged[0]['entry_hash']} ✅")

    # ── Verify intact chain ───────────────────────────────────────────────
    print(f"\n🔗 Verifying chain integrity...")
    try:
        audit.verify_chain()
        print(f"   Status: ✅ VALID\n")
    except AuditChainCorruptedError as e:
        print(f"   Status: ❌ CORRUPTED — {e}\n")

    # ── Querying ──────────────────────────────────────────────────────────
    print("🔍 Querying events:")

    all_events = audit.get_events()
    print(f"   All events             : {len(all_events)}")

    agent_events = audit.get_events(agent_id="agent-gpt4")
    print(f"   agent-gpt4 events      : {len(agent_events)}")

    failures = audit.get_events(event_type="scope_denied")
    print(f"   scope_denied events    : {len(failures)}")

    suspicious = audit.get_events(event_type="suspicious_activity")
    print(f"   suspicious_activity    : {len(suspicious)}")

    future = datetime.now(timezone.utc) + timedelta(hours=1)
    future_events = audit.get_events(since=future)
    print(f"   Events in future       : {len(future_events)} (should be 0)")

    # ── Tamper detection demonstration ────────────────────────────────────
    print(f"\n🚨 Demonstrating tamper detection...")

    first = session.query(AuditLogModel).order_by(AuditLogModel.id.asc()).first()
    original_hash = first.entry_hash
    print(f"   Original hash  : {original_hash[:16]}...")

    # Simulate an attacker changing the outcome of the first entry
    first.outcome    = "success"   # Was "success" already — let's change event_type
    first.event_type = "login"     # Changed from "agent_registered"
    session.commit()
    print(f"   Tampered field : event_type changed to 'login'")

    try:
        audit.verify_chain()
        print(f"   Detection: ⚠️  NOT detected (unexpected)")
    except AuditChainCorruptedError as e:
        print(f"   Detection: ✅ Tamper detected!")
        print(f"   Error    : {e}")

    session.close()
    print("\n✅ audit_trail complete")


if __name__ == "__main__":
    main()
