"""Tests for per-action scoped authorization (ScopeManager + @require_scope)."""

import pytest
from agentauth.scopes import (
    ScopeManager,
    require_scope,
    set_current_token,
    clear_current_token,
)
from agentauth.exceptions import (
    PermissionDeniedError,
    ScopeNotGrantedError,
    TrustLevelInsufficientError,
)


class TestScopeManager:
    """Test cases for ScopeManager."""

    def test_grant_scope(self, agentauth_session):
        """Test granting a scope to an agent."""
        sm = ScopeManager(agentauth_session)
        result = sm.grant_scope("agent-1", "db:read")
        assert result["agent_id"] == "agent-1"
        assert result["scope"] == "db:read"
        assert result["trust_level_required"] == "low"

    def test_grant_duplicate_scope_updates(self, agentauth_session):
        """Granting the same scope twice updates trust level."""
        sm = ScopeManager(agentauth_session)
        sm.grant_scope("agent-1", "db:read", trust_level_required="low")
        result = sm.grant_scope("agent-1", "db:read", trust_level_required="high")
        assert result["trust_level_required"] == "high"

    def test_revoke_scope(self, agentauth_session):
        """Test revoking a scope."""
        sm = ScopeManager(agentauth_session)
        sm.grant_scope("agent-1", "db:read")
        assert sm.revoke_scope("agent-1", "db:read") is True
        assert sm.list_scopes("agent-1") == []

    def test_revoke_nonexistent_scope(self, agentauth_session):
        """Revoking a non-existent scope returns False."""
        sm = ScopeManager(agentauth_session)
        assert sm.revoke_scope("agent-1", "nonexistent") is False

    def test_list_scopes(self, agentauth_session):
        """Test listing scopes."""
        sm = ScopeManager(agentauth_session)
        sm.grant_scope("agent-1", "db:read")
        sm.grant_scope("agent-1", "db:write")
        scopes = sm.list_scopes("agent-1")
        scope_names = [s["scope"] for s in scopes]
        assert "db:read" in scope_names
        assert "db:write" in scope_names

    def test_validate_scope_success(self, agentauth_session):
        """validate_scope returns True when scope and trust match."""
        sm = ScopeManager(agentauth_session)
        payload = {"scopes": ["db:read"], "trust_level": "high"}
        assert sm.validate_scope(payload, "db:read", trust_level="low") is True

    def test_validate_scope_missing(self, agentauth_session):
        """validate_scope raises ScopeNotGrantedError for missing scope."""
        sm = ScopeManager(agentauth_session)
        payload = {"scopes": ["db:read"], "trust_level": "low"}
        with pytest.raises(ScopeNotGrantedError):
            sm.validate_scope(payload, "db:write")

    def test_validate_scope_insufficient_trust(self, agentauth_session):
        """validate_scope raises TrustLevelInsufficientError."""
        sm = ScopeManager(agentauth_session)
        payload = {"scopes": ["db:write"], "trust_level": "low"}
        with pytest.raises(TrustLevelInsufficientError):
            sm.validate_scope(payload, "db:write", trust_level="high")

    def test_invalid_trust_level(self, agentauth_session):
        """Granting a scope with an invalid trust level raises ValueError."""
        sm = ScopeManager(agentauth_session)
        with pytest.raises(ValueError):
            sm.grant_scope("agent-1", "db:read", trust_level_required="extreme")


class TestRequireScopeDecorator:
    """Test cases for the @require_scope decorator."""

    def test_allows_with_valid_scope(self):
        """Decorator allows execution when scope and trust are satisfied."""

        @require_scope("calendar:read")
        def read_calendar():
            return "events"

        payload = {"scopes": ["calendar:read"], "trust_level": "low"}
        ctx_token = set_current_token(payload)
        try:
            assert read_calendar() == "events"
        finally:
            clear_current_token(ctx_token)

    def test_denies_without_token(self):
        """Decorator raises PermissionDeniedError when no token is set."""

        @require_scope("db:read")
        def query_db():
            return "data"

        with pytest.raises(PermissionDeniedError):
            query_db()

    def test_denies_missing_scope(self):
        """Decorator raises ScopeNotGrantedError for missing scope."""

        @require_scope("db:write")
        def write_db():
            return "done"

        payload = {"scopes": ["db:read"], "trust_level": "low"}
        ctx_token = set_current_token(payload)
        try:
            with pytest.raises(ScopeNotGrantedError):
                write_db()
        finally:
            clear_current_token(ctx_token)

    def test_denies_insufficient_trust(self):
        """Decorator raises TrustLevelInsufficientError."""

        @require_scope("db:write", trust_level="high")
        def delete_record():
            return "deleted"

        payload = {"scopes": ["db:write"], "trust_level": "low"}
        ctx_token = set_current_token(payload)
        try:
            with pytest.raises(TrustLevelInsufficientError):
                delete_record()
        finally:
            clear_current_token(ctx_token)

    @pytest.mark.asyncio
    async def test_async_allows_with_valid_scope(self):
        """Decorator works with async functions."""

        @require_scope("email:send")
        async def send_email():
            return "sent"

        payload = {"scopes": ["email:send"], "trust_level": "low"}
        ctx_token = set_current_token(payload)
        try:
            result = await send_email()
            assert result == "sent"
        finally:
            clear_current_token(ctx_token)
