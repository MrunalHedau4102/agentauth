"""
Tests for ScopeManager and @require_scope decorator.

Coverage:
    ScopeManager:
        - grant_scope basic
        - grant_scope with trust_level_required
        - grant_scope duplicate updates trust level
        - grant_scope invalid trust level raises ValueError
        - revoke_scope present
        - revoke_scope absent returns False
        - list_scopes empty
        - list_scopes multiple
        - list_scopes returns correct fields
        - validate_scope pass (scope + trust both satisfied)
        - validate_scope missing scope raises ScopeNotGrantedError
        - validate_scope insufficient trust raises TrustLevelInsufficientError
        - validate_scope exact trust match passes (boundary)
        - validate_scope trust hierarchy: high > medium > low

    @require_scope:
        - allows execution with valid scope + trust
        - raises PermissionDeniedError when no token in context
        - raises ScopeNotGrantedError for missing scope
        - raises TrustLevelInsufficientError for low trust
        - works with async functions
        - trust boundary: high token satisfies medium requirement
        - trust boundary: medium token fails high requirement
        - multiple decorators on nested functions
        - context is restored after clear_current_token
        - decorator preserves function name (functools.wraps)
"""

import asyncio
import pytest

from agentauth.scopes import (
    ScopeManager,
    require_scope,
    set_current_token,
    clear_current_token,
    get_current_token,
)
from agentauth.exceptions import (
    PermissionDeniedError,
    ScopeNotGrantedError,
    TrustLevelInsufficientError,
)


# ── Helpers ────────────────────────────────────────────────────────────────

def token_payload(scopes, trust="low"):
    return {"scopes": scopes, "trust_level": trust, "agent_id": "test-agent"}


# ════════════════════════════════════════════════════════════════
# ScopeManager
# ════════════════════════════════════════════════════════════════

class TestScopeManager:

    def test_grant_scope_returns_dict(self, agentauth_session):
        sm = ScopeManager(agentauth_session)
        result = sm.grant_scope("agent-1", "db:read")
        assert isinstance(result, dict)

    def test_grant_scope_agent_id(self, agentauth_session):
        sm = ScopeManager(agentauth_session)
        result = sm.grant_scope("agent-1", "db:read")
        assert result["agent_id"] == "agent-1"

    def test_grant_scope_name(self, agentauth_session):
        sm = ScopeManager(agentauth_session)
        result = sm.grant_scope("agent-1", "db:read")
        assert result["scope"] == "db:read"

    def test_grant_scope_default_trust_low(self, agentauth_session):
        sm = ScopeManager(agentauth_session)
        result = sm.grant_scope("agent-1", "db:read")
        assert result["trust_level_required"] == "low"

    def test_grant_scope_custom_trust(self, agentauth_session):
        sm = ScopeManager(agentauth_session)
        result = sm.grant_scope("agent-1", "db:delete", trust_level_required="high")
        assert result["trust_level_required"] == "high"

    def test_grant_scope_medium_trust(self, agentauth_session):
        sm = ScopeManager(agentauth_session)
        result = sm.grant_scope("agent-1", "db:write", trust_level_required="medium")
        assert result["trust_level_required"] == "medium"

    def test_grant_scope_duplicate_updates_trust(self, agentauth_session):
        sm = ScopeManager(agentauth_session)
        sm.grant_scope("agent-1", "db:read", trust_level_required="low")
        result = sm.grant_scope("agent-1", "db:read", trust_level_required="high")
        assert result["trust_level_required"] == "high"

    def test_grant_scope_invalid_trust_raises(self, agentauth_session):
        sm = ScopeManager(agentauth_session)
        with pytest.raises(ValueError):
            sm.grant_scope("agent-1", "db:read", trust_level_required="extreme")

    def test_grant_scope_invalid_trust_message(self, agentauth_session):
        sm = ScopeManager(agentauth_session)
        with pytest.raises(ValueError) as exc_info:
            sm.grant_scope("agent-1", "db:read", trust_level_required="root")
        assert "Invalid trust level" in str(exc_info.value)

    # ── revoke_scope ──────────────────────────────────────────────────────

    def test_revoke_scope_returns_true(self, agentauth_session):
        sm = ScopeManager(agentauth_session)
        sm.grant_scope("agent-1", "db:read")
        assert sm.revoke_scope("agent-1", "db:read") is True

    def test_revoke_scope_removes_from_list(self, agentauth_session):
        sm = ScopeManager(agentauth_session)
        sm.grant_scope("agent-1", "db:read")
        sm.revoke_scope("agent-1", "db:read")
        scopes = sm.list_scopes("agent-1")
        assert scopes == []

    def test_revoke_scope_absent_returns_false(self, agentauth_session):
        sm = ScopeManager(agentauth_session)
        assert sm.revoke_scope("agent-1", "nonexistent") is False

    def test_revoke_one_scope_leaves_others(self, agentauth_session):
        sm = ScopeManager(agentauth_session)
        sm.grant_scope("agent-1", "db:read")
        sm.grant_scope("agent-1", "db:write")
        sm.revoke_scope("agent-1", "db:write")
        scopes = sm.list_scopes("agent-1")
        names = [s["scope"] for s in scopes]
        assert "db:read" in names
        assert "db:write" not in names

    # ── list_scopes ───────────────────────────────────────────────────────

    def test_list_scopes_empty(self, agentauth_session):
        sm = ScopeManager(agentauth_session)
        assert sm.list_scopes("agent-with-no-scopes") == []

    def test_list_scopes_single(self, agentauth_session):
        sm = ScopeManager(agentauth_session)
        sm.grant_scope("agent-1", "db:read")
        scopes = sm.list_scopes("agent-1")
        assert len(scopes) == 1

    def test_list_scopes_multiple(self, agentauth_session):
        sm = ScopeManager(agentauth_session)
        for scope in ["db:read", "db:write", "email:send"]:
            sm.grant_scope("agent-1", scope)
        scopes = sm.list_scopes("agent-1")
        assert len(scopes) == 3

    def test_list_scopes_correct_names(self, agentauth_session):
        sm = ScopeManager(agentauth_session)
        sm.grant_scope("agent-1", "db:read")
        sm.grant_scope("agent-1", "email:send")
        names = [s["scope"] for s in sm.list_scopes("agent-1")]
        assert "db:read" in names
        assert "email:send" in names

    def test_list_scopes_returns_dict_with_fields(self, agentauth_session):
        sm = ScopeManager(agentauth_session)
        sm.grant_scope("agent-1", "db:read")
        scope = sm.list_scopes("agent-1")[0]
        assert "scope" in scope
        assert "agent_id" in scope
        assert "trust_level_required" in scope
        assert "granted_at" in scope

    def test_list_scopes_isolates_agents(self, agentauth_session):
        sm = ScopeManager(agentauth_session)
        sm.grant_scope("agent-1", "db:read")
        sm.grant_scope("agent-2", "email:send")
        assert len(sm.list_scopes("agent-1")) == 1
        assert sm.list_scopes("agent-1")[0]["scope"] == "db:read"

    # ── validate_scope ────────────────────────────────────────────────────

    def test_validate_scope_pass(self, agentauth_session):
        sm = ScopeManager(agentauth_session)
        payload = token_payload(["db:read"], "low")
        assert sm.validate_scope(payload, "db:read", trust_level="low") is True

    def test_validate_scope_missing_raises(self, agentauth_session):
        sm = ScopeManager(agentauth_session)
        payload = token_payload(["db:read"], "high")
        with pytest.raises(ScopeNotGrantedError):
            sm.validate_scope(payload, "db:write")

    def test_validate_scope_insufficient_trust(self, agentauth_session):
        sm = ScopeManager(agentauth_session)
        payload = token_payload(["db:write"], "low")
        with pytest.raises(TrustLevelInsufficientError):
            sm.validate_scope(payload, "db:write", trust_level="high")

    def test_validate_scope_high_token_satisfies_low_req(self, agentauth_session):
        sm = ScopeManager(agentauth_session)
        payload = token_payload(["db:write"], "high")
        assert sm.validate_scope(payload, "db:write", trust_level="low") is True

    def test_validate_scope_medium_satisfies_medium(self, agentauth_session):
        sm = ScopeManager(agentauth_session)
        payload = token_payload(["db:write"], "medium")
        assert sm.validate_scope(payload, "db:write", trust_level="medium") is True

    def test_validate_scope_medium_fails_high(self, agentauth_session):
        sm = ScopeManager(agentauth_session)
        payload = token_payload(["db:delete"], "medium")
        with pytest.raises(TrustLevelInsufficientError):
            sm.validate_scope(payload, "db:delete", trust_level="high")

    def test_validate_scope_empty_token_scopes(self, agentauth_session):
        sm = ScopeManager(agentauth_session)
        payload = token_payload([], "high")
        with pytest.raises(ScopeNotGrantedError):
            sm.validate_scope(payload, "db:read")


# ════════════════════════════════════════════════════════════════
# @require_scope decorator
# ════════════════════════════════════════════════════════════════

class TestRequireScopeDecorator:

    def test_allows_with_correct_scope_and_trust(self):
        @require_scope("db:read", trust_level="low")
        def fn():
            return "success"

        payload = token_payload(["db:read"], "low")
        ctx = set_current_token(payload)
        try:
            assert fn() == "success"
        finally:
            clear_current_token(ctx)

    def test_no_token_raises_permission_denied(self):
        @require_scope("db:read")
        def fn():
            return "success"

        # Ensure no token is set (context might carry state)
        with pytest.raises(PermissionDeniedError):
            fn()

    def test_missing_scope_raises_scope_not_granted(self):
        @require_scope("db:write")
        def fn():
            return "success"

        payload = token_payload(["db:read"], "low")
        ctx = set_current_token(payload)
        try:
            with pytest.raises(ScopeNotGrantedError):
                fn()
        finally:
            clear_current_token(ctx)

    def test_insufficient_trust_raises(self):
        @require_scope("db:delete", trust_level="high")
        def fn():
            return "success"

        payload = token_payload(["db:delete"], "low")
        ctx = set_current_token(payload)
        try:
            with pytest.raises(TrustLevelInsufficientError):
                fn()
        finally:
            clear_current_token(ctx)

    def test_high_trust_satisfies_medium_requirement(self):
        @require_scope("db:write", trust_level="medium")
        def fn():
            return "success"

        payload = token_payload(["db:write"], "high")
        ctx = set_current_token(payload)
        try:
            assert fn() == "success"
        finally:
            clear_current_token(ctx)

    def test_medium_trust_satisfies_low_requirement(self):
        @require_scope("db:read", trust_level="low")
        def fn():
            return "success"

        payload = token_payload(["db:read"], "medium")
        ctx = set_current_token(payload)
        try:
            assert fn() == "success"
        finally:
            clear_current_token(ctx)

    def test_function_return_value_preserved(self):
        @require_scope("email:send")
        def fn():
            return {"status": "sent", "count": 42}

        payload = token_payload(["email:send"], "low")
        ctx = set_current_token(payload)
        try:
            result = fn()
            assert result == {"status": "sent", "count": 42}
        finally:
            clear_current_token(ctx)

    def test_function_args_forwarded(self):
        @require_scope("db:read")
        def fn(x, y, z=None):
            return (x, y, z)

        payload = token_payload(["db:read"], "low")
        ctx = set_current_token(payload)
        try:
            assert fn(1, 2, z=3) == (1, 2, 3)
        finally:
            clear_current_token(ctx)

    def test_decorator_preserves_function_name(self):
        @require_scope("db:read")
        def my_special_function():
            pass

        assert my_special_function.__name__ == "my_special_function"

    def test_context_cleared_after_token_reset(self):
        @require_scope("db:read")
        def fn():
            return "success"

        payload = token_payload(["db:read"], "low")
        ctx = set_current_token(payload)
        assert fn() == "success"
        clear_current_token(ctx)

        # After clearing, should raise PermissionDeniedError
        with pytest.raises(PermissionDeniedError):
            fn()

    def test_get_current_token_returns_payload(self):
        payload = token_payload(["db:read"], "high")
        ctx = set_current_token(payload)
        try:
            retrieved = get_current_token()
            assert retrieved["agent_id"] == "test-agent"
            assert "db:read" in retrieved["scopes"]
        finally:
            clear_current_token(ctx)

    def test_get_current_token_none_when_unset(self):
        # Make sure no token is currently set
        # (fine for a fresh function scope)
        assert get_current_token() is None

    # ── Async support ─────────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_async_function_allowed(self):
        @require_scope("email:send")
        async def async_fn():
            return "async_result"

        payload = token_payload(["email:send"], "low")
        ctx = set_current_token(payload)
        try:
            result = await async_fn()
            assert result == "async_result"
        finally:
            clear_current_token(ctx)

    @pytest.mark.asyncio
    async def test_async_function_missing_scope(self):
        @require_scope("email:delete")
        async def async_fn():
            return "async_result"

        payload = token_payload(["email:send"], "low")
        ctx = set_current_token(payload)
        try:
            with pytest.raises(ScopeNotGrantedError):
                await async_fn()
        finally:
            clear_current_token(ctx)

    @pytest.mark.asyncio
    async def test_async_function_no_token(self):
        @require_scope("db:read")
        async def async_fn():
            return "done"

        with pytest.raises(PermissionDeniedError):
            await async_fn()
