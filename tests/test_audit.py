"""
Tests for AuditLogger.

NOTE: audit.py uses a `timestamp_str` field on AuditLogModel for
deterministic hashing. If your AuditLogModel does not have this column,
add it — or store the ISO timestamp string as a separate column alongside
the DateTime column. The hash must be computed from the stored string,
not from a freshly computed datetime.isoformat(), to make verify_chain()
deterministic across sessions.

Coverage:
    - log() basic event
    - log() first entry has previous_hash=None
    - log() second entry chains to first
    - log() with all optional fields (user_id, ip_address, scopes, metadata)
    - log() returns dict with correct fields
    - verify_chain() empty log returns True
    - verify_chain() single entry
    - verify_chain() multiple entries
    - verify_chain() detects tampered entry_hash
    - verify_chain() detects tampered previous_hash
    - verify_chain() detects tampered event_type
    - get_events() no filters returns all
    - get_events() filter by agent_id
    - get_events() filter by event_type
    - get_events() filter by since
    - get_events() multiple filters combined
    - get_events() returns list of dicts
    - get_events() returns correct fields
    - 10-entry chain is valid
    - failure outcome is logged correctly
    - metadata dict is persisted and returned
"""

import pytest
from datetime import datetime, timezone, timedelta

from agentauth.audit import AuditLogger
from agentauth.db.models import AuditLogModel
from agentauth.exceptions import AuditChainCorruptedError


# ════════════════════════════════════════════════════════════════
# log()
# ════════════════════════════════════════════════════════════════

class TestAuditLog:

    def test_log_returns_dict(self, agentauth_session):
        audit = AuditLogger(agentauth_session)
        result = audit.log(event_type="login", outcome="success")
        assert isinstance(result, dict)

    def test_log_event_type(self, agentauth_session):
        audit = AuditLogger(agentauth_session)
        result = audit.log(event_type="token_issued", outcome="success")
        assert result["event_type"] == "token_issued"

    def test_log_outcome_success(self, agentauth_session):
        audit = AuditLogger(agentauth_session)
        result = audit.log(event_type="login", outcome="success")
        assert result["outcome"] == "success"

    def test_log_outcome_failure(self, agentauth_session):
        audit = AuditLogger(agentauth_session)
        result = audit.log(event_type="scope_denied", outcome="failure")
        assert result["outcome"] == "failure"

    def test_log_agent_id(self, agentauth_session):
        audit = AuditLogger(agentauth_session)
        result = audit.log(event_type="login", agent_id="agent-1", outcome="success")
        assert result["agent_id"] == "agent-1"

    def test_log_user_id(self, agentauth_session):
        audit = AuditLogger(agentauth_session)
        result = audit.log(event_type="login", user_id=42, outcome="success")
        assert result["user_id"] == 42

    def test_log_ip_address(self, agentauth_session):
        audit = AuditLogger(agentauth_session)
        result = audit.log(
            event_type="login", ip_address="10.0.0.1", outcome="success"
        )
        assert result["ip_address"] == "10.0.0.1"

    def test_log_scopes(self, agentauth_session):
        audit = AuditLogger(agentauth_session)
        result = audit.log(
            event_type="token_issued",
            scopes=["db:read", "email:send"],
            outcome="success",
        )
        assert "db:read" in result["scopes_involved"]

    def test_log_metadata(self, agentauth_session):
        audit = AuditLogger(agentauth_session)
        meta = {"ttl": 300, "bound_to": "192.168.1.1"}
        result = audit.log(
            event_type="token_issued", metadata=meta, outcome="success"
        )
        assert result["metadata"]["ttl"] == 300

    def test_log_has_event_id(self, agentauth_session):
        audit = AuditLogger(agentauth_session)
        result = audit.log(event_type="login", outcome="success")
        assert result["event_id"] is not None
        assert len(result["event_id"]) > 0

    def test_log_has_entry_hash(self, agentauth_session):
        audit = AuditLogger(agentauth_session)
        result = audit.log(event_type="login", outcome="success")
        assert result["entry_hash"] is not None
        assert len(result["entry_hash"]) == 64   # SHA-256 hex

    def test_log_first_entry_previous_hash_none(self, agentauth_session):
        audit = AuditLogger(agentauth_session)
        result = audit.log(event_type="login", outcome="success")
        assert result["previous_hash"] is None

    def test_log_has_timestamp(self, agentauth_session):
        audit = AuditLogger(agentauth_session)
        result = audit.log(event_type="login", outcome="success")
        assert result["timestamp"] is not None

    def test_log_two_events_different_hashes(self, agentauth_session):
        audit = AuditLogger(agentauth_session)
        r1 = audit.log(event_type="login", outcome="success")
        r2 = audit.log(event_type="token_issued", outcome="success")
        assert r1["entry_hash"] != r2["entry_hash"]


# ════════════════════════════════════════════════════════════════
# Hash chain linking
# ════════════════════════════════════════════════════════════════

class TestHashChain:

    def test_second_entry_chains_to_first(self, agentauth_session):
        audit = AuditLogger(agentauth_session)
        first  = audit.log(event_type="login", outcome="success")
        second = audit.log(event_type="token_issued", outcome="success")
        assert second["previous_hash"] == first["entry_hash"]

    def test_third_entry_chains_to_second(self, agentauth_session):
        audit = AuditLogger(agentauth_session)
        audit.log(event_type="login", outcome="success")
        second = audit.log(event_type="token_issued", outcome="success")
        third  = audit.log(event_type="scope_denied", outcome="failure")
        assert third["previous_hash"] == second["entry_hash"]

    def test_ten_entry_chain_is_valid(self, agentauth_session):
        audit = AuditLogger(agentauth_session)
        for i in range(10):
            audit.log(
                event_type="login" if i % 2 == 0 else "token_issued",
                agent_id=f"agent-{i}",
                outcome="success",
            )
        assert audit.verify_chain() is True


# ════════════════════════════════════════════════════════════════
# verify_chain()
# ════════════════════════════════════════════════════════════════

class TestVerifyChain:

    def test_empty_log_returns_true(self, agentauth_session):
        audit = AuditLogger(agentauth_session)
        assert audit.verify_chain() is True

    def test_single_entry_is_valid(self, agentauth_session):
        audit = AuditLogger(agentauth_session)
        audit.log(event_type="login", outcome="success")
        assert audit.verify_chain() is True

    def test_three_entries_valid(self, agentauth_session):
        audit = AuditLogger(agentauth_session)
        audit.log(event_type="login", outcome="success")
        audit.log(event_type="token_issued", outcome="success")
        audit.log(event_type="scope_denied", outcome="failure")
        assert audit.verify_chain() is True

    def test_tampered_entry_hash_detected(self, agentauth_session):
        audit = AuditLogger(agentauth_session)
        audit.log(event_type="login", outcome="success")
        audit.log(event_type="token_issued", outcome="success")

        first = (
            agentauth_session.query(AuditLogModel)
            .order_by(AuditLogModel.id.asc())
            .first()
        )
        first.entry_hash = "0" * 64
        agentauth_session.commit()

        with pytest.raises(AuditChainCorruptedError):
            audit.verify_chain()

    def test_tampered_previous_hash_detected(self, agentauth_session):
        audit = AuditLogger(agentauth_session)
        audit.log(event_type="login", outcome="success")
        audit.log(event_type="token_issued", outcome="success")

        second = (
            agentauth_session.query(AuditLogModel)
            .order_by(AuditLogModel.id.desc())
            .first()
        )
        second.previous_hash = "f" * 64
        agentauth_session.commit()

        with pytest.raises(AuditChainCorruptedError):
            audit.verify_chain()

    def test_tampered_event_type_detected(self, agentauth_session):
        """Changing event_type invalidates the computed hash."""
        audit = AuditLogger(agentauth_session)
        audit.log(event_type="login", outcome="success")
        audit.log(event_type="token_issued", outcome="success")

        first = (
            agentauth_session.query(AuditLogModel)
            .order_by(AuditLogModel.id.asc())
            .first()
        )
        first.event_type = "hacked_event"
        agentauth_session.commit()

        with pytest.raises(AuditChainCorruptedError):
            audit.verify_chain()

    def test_tampered_outcome_detected(self, agentauth_session):
        audit = AuditLogger(agentauth_session)
        audit.log(event_type="login", outcome="failure")

        entry = (
            agentauth_session.query(AuditLogModel)
            .order_by(AuditLogModel.id.asc())
            .first()
        )
        entry.outcome = "success"   # flip failure → success
        agentauth_session.commit()

        with pytest.raises(AuditChainCorruptedError):
            audit.verify_chain()

    def test_corrupted_error_status_code(self, agentauth_session):
        audit = AuditLogger(agentauth_session)
        audit.log(event_type="login", outcome="success")
        first = (
            agentauth_session.query(AuditLogModel)
            .order_by(AuditLogModel.id.asc())
            .first()
        )
        first.entry_hash = "tampered"
        agentauth_session.commit()

        with pytest.raises(AuditChainCorruptedError) as exc_info:
            audit.verify_chain()
        assert exc_info.value.status_code == 500


# ════════════════════════════════════════════════════════════════
# get_events()
# ════════════════════════════════════════════════════════════════

class TestGetEvents:

    def _seed(self, session):
        """Seed a consistent set of events for filter tests."""
        audit = AuditLogger(session)
        audit.log(event_type="login",        agent_id="agent-1", outcome="success")
        audit.log(event_type="token_issued", agent_id="agent-1", outcome="success")
        audit.log(event_type="login",        agent_id="agent-2", outcome="failure")
        audit.log(event_type="scope_denied", agent_id="agent-2", outcome="failure")
        audit.log(event_type="token_issued", agent_id="agent-2", outcome="success")
        return audit

    def test_no_filter_returns_all(self, agentauth_session):
        audit = self._seed(agentauth_session)
        events = audit.get_events()
        assert len(events) == 5

    def test_filter_agent_id(self, agentauth_session):
        audit = self._seed(agentauth_session)
        events = audit.get_events(agent_id="agent-1")
        assert len(events) == 2
        assert all(e["agent_id"] == "agent-1" for e in events)

    def test_filter_event_type(self, agentauth_session):
        audit = self._seed(agentauth_session)
        events = audit.get_events(event_type="login")
        assert len(events) == 2
        assert all(e["event_type"] == "login" for e in events)

    def test_filter_token_issued(self, agentauth_session):
        audit = self._seed(agentauth_session)
        events = audit.get_events(event_type="token_issued")
        assert len(events) == 2

    def test_filter_scope_denied(self, agentauth_session):
        audit = self._seed(agentauth_session)
        events = audit.get_events(event_type="scope_denied")
        assert len(events) == 1

    def test_filter_since_future_returns_empty(self, agentauth_session):
        audit = self._seed(agentauth_session)
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        events = audit.get_events(since=future)
        assert events == []

    def test_filter_since_past_returns_all(self, agentauth_session):
        audit = self._seed(agentauth_session)
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        events = audit.get_events(since=past)
        assert len(events) == 5

    def test_combined_agent_and_event_type(self, agentauth_session):
        audit = self._seed(agentauth_session)
        events = audit.get_events(agent_id="agent-2", event_type="login")
        assert len(events) == 1
        assert events[0]["agent_id"] == "agent-2"
        assert events[0]["event_type"] == "login"

    def test_returns_list_of_dicts(self, agentauth_session):
        audit = self._seed(agentauth_session)
        events = audit.get_events()
        assert isinstance(events, list)
        assert isinstance(events[0], dict)

    def test_dict_has_required_fields(self, agentauth_session):
        audit = AuditLogger(agentauth_session)
        audit.log(event_type="login", agent_id="agent-1", outcome="success")
        event = audit.get_events()[0]
        for field in ("event_id", "event_type", "agent_id", "outcome",
                      "timestamp", "entry_hash", "previous_hash"):
            assert field in event, f"Missing field: {field}"

    def test_empty_log_returns_empty_list(self, agentauth_session):
        audit = AuditLogger(agentauth_session)
        assert audit.get_events() == []

    def test_events_ordered_by_id(self, agentauth_session):
        audit = AuditLogger(agentauth_session)
        types = ["login", "token_issued", "scope_denied", "agent_registered"]
        for t in types:
            audit.log(event_type=t, outcome="success")
        events = audit.get_events()
        returned_types = [e["event_type"] for e in events]
        assert returned_types == types
