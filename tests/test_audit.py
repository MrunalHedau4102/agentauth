"""Tests for cryptographic audit trail (AuditLogger)."""

import pytest
from agentauth.audit import AuditLogger
from agentauth.db.models import AuditLogModel
from agentauth.exceptions import AuditChainCorruptedError


class TestAuditLogger:
    """Test cases for AuditLogger."""

    def test_log_event(self, agentauth_session):
        """Log a single event and verify its contents."""
        audit = AuditLogger(agentauth_session)
        result = audit.log(
            event_type="login",
            agent_id="agent-1",
            user_id=42,
            outcome="success",
            ip_address="192.168.1.1",
            scopes=["db:read"],
            metadata={"extra": "info"},
        )
        assert result["event_type"] == "login"
        assert result["agent_id"] == "agent-1"
        assert result["user_id"] == 42
        assert result["outcome"] == "success"
        assert result["entry_hash"] is not None
        assert result["previous_hash"] is None  # first entry

    def test_log_chaining(self, agentauth_session):
        """Second entry's previous_hash must equal first entry's entry_hash."""
        audit = AuditLogger(agentauth_session)
        first = audit.log(event_type="login", outcome="success")
        second = audit.log(event_type="token_issued", outcome="success")

        assert second["previous_hash"] == first["entry_hash"]

    def test_verify_chain_valid(self, agentauth_session):
        """verify_chain returns True for an intact chain."""
        audit = AuditLogger(agentauth_session)
        audit.log(event_type="login", outcome="success")
        audit.log(event_type="token_issued", outcome="success")
        audit.log(event_type="scope_denied", outcome="failure")

        assert audit.verify_chain() is True

    def test_verify_chain_empty(self, agentauth_session):
        """verify_chain returns True for an empty log."""
        audit = AuditLogger(agentauth_session)
        assert audit.verify_chain() is True

    def test_verify_chain_tampered(self, agentauth_session):
        """verify_chain raises AuditChainCorruptedError if entry is tampered."""
        audit = AuditLogger(agentauth_session)
        audit.log(event_type="login", outcome="success")
        audit.log(event_type="token_issued", outcome="success")

        # Tamper with the first entry's hash
        first_entry = (
            agentauth_session.query(AuditLogModel)
            .order_by(AuditLogModel.id.asc())
            .first()
        )
        first_entry.entry_hash = "tampered_hash_value"
        agentauth_session.commit()

        with pytest.raises(AuditChainCorruptedError):
            audit.verify_chain()

    def test_get_events_filter_by_agent(self, agentauth_session):
        """Filter events by agent_id."""
        audit = AuditLogger(agentauth_session)
        audit.log(event_type="login", agent_id="agent-1", outcome="success")
        audit.log(event_type="login", agent_id="agent-2", outcome="success")
        audit.log(event_type="token_issued", agent_id="agent-1", outcome="success")

        events = audit.get_events(agent_id="agent-1")
        assert len(events) == 2
        assert all(e["agent_id"] == "agent-1" for e in events)

    def test_get_events_filter_by_event_type(self, agentauth_session):
        """Filter events by event_type."""
        audit = AuditLogger(agentauth_session)
        audit.log(event_type="login", outcome="success")
        audit.log(event_type="token_issued", outcome="success")
        audit.log(event_type="login", outcome="failure")

        events = audit.get_events(event_type="login")
        assert len(events) == 2

    def test_get_events_filter_by_since(self, agentauth_session):
        """Filter events by timestamp."""
        from datetime import datetime, timezone, timedelta

        audit = AuditLogger(agentauth_session)
        audit.log(event_type="login", outcome="success")

        future = datetime.now(timezone.utc) + timedelta(hours=1)
        events = audit.get_events(since=future)
        assert len(events) == 0

    def test_multiple_events_chain(self, agentauth_session):
        """Verify chain integrity across many events."""
        audit = AuditLogger(agentauth_session)
        for i in range(10):
            audit.log(
                event_type="login" if i % 2 == 0 else "token_issued",
                agent_id=f"agent-{i}",
                outcome="success",
            )
        assert audit.verify_chain() is True
