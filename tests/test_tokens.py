"""
Tests for EphemeralTokenVault.

Coverage:
    - Basic issue + verify round-trip
    - All payload fields (agent_id, scopes, trust_level, bound_to)
    - Token expiry (TTL enforcement)
    - One-time-use tokens (first use passes, second use fails)
    - bound_to enforcement (match / mismatch)
    - Wrong secret key
    - Tampered / garbage tokens
    - Missing secret raises ValueError
    - One-time-use without session raises ValueError
    - Empty scopes list
    - Very short TTL (1 second)
    - Multiple tokens for same agent are independent
    - Token payload does NOT contain private key material
"""

import os
import time
import pytest

from agentauth.tokens import EphemeralTokenVault
from agentauth.exceptions import TokenExpiredError, InvalidTokenError

SECRET = "test-secret-key-min-32-chars-long-xyz1234"


# ── Helpers ────────────────────────────────────────────────────────────────

def make_vault(session, secret=SECRET):
    return EphemeralTokenVault(secret_key=secret, session=session)


# ── Basic round-trip ───────────────────────────────────────────────────────

class TestIssueAndVerify:

    def test_returns_string(self, agentauth_session):
        vault = make_vault(agentauth_session)
        token = vault.issue(agent_id="agent-1", scopes=["db:read"])
        assert isinstance(token, str)
        assert len(token) > 20

    def test_payload_agent_id(self, agentauth_session):
        vault = make_vault(agentauth_session)
        token = vault.issue(agent_id="agent-abc", scopes=[])
        payload = vault.verify(token)
        assert payload["agent_id"] == "agent-abc"

    def test_payload_scopes(self, agentauth_session):
        vault = make_vault(agentauth_session)
        scopes = ["db:read", "email:send", "files:write"]
        token = vault.issue(agent_id="agent-1", scopes=scopes)
        payload = vault.verify(token)
        assert set(payload["scopes"]) == set(scopes)

    def test_payload_trust_level_default(self, agentauth_session):
        vault = make_vault(agentauth_session)
        token = vault.issue(agent_id="agent-1", scopes=[])
        payload = vault.verify(token)
        assert payload["trust_level"] == "low"

    def test_payload_trust_level_custom(self, agentauth_session):
        vault = make_vault(agentauth_session)
        token = vault.issue(agent_id="agent-1", scopes=[], trust_level="high")
        payload = vault.verify(token)
        assert payload["trust_level"] == "high"

    def test_payload_no_private_key(self, agentauth_session):
        vault = make_vault(agentauth_session)
        token = vault.issue(agent_id="agent-1", scopes=[], trust_level="high")
        payload = vault.verify(token)
        assert "private_key" not in payload
        assert "secret" not in payload

    def test_empty_scopes(self, agentauth_session):
        vault = make_vault(agentauth_session)
        token = vault.issue(agent_id="agent-1", scopes=[])
        payload = vault.verify(token)
        assert payload["scopes"] == []

    def test_all_trust_levels(self, agentauth_session):
        vault = make_vault(agentauth_session)
        for level in ("low", "medium", "high"):
            token = vault.issue(agent_id="agent-1", scopes=[], trust_level=level)
            payload = vault.verify(token)
            assert payload["trust_level"] == level


# ── Expiry ─────────────────────────────────────────────────────────────────

class TestExpiry:

    def test_valid_within_ttl(self, agentauth_session):
        vault = make_vault(agentauth_session)
        token = vault.issue(agent_id="agent-1", scopes=[], ttl_seconds=60)
        # Should not raise
        payload = vault.verify(token)
        assert payload["agent_id"] == "agent-1"

    def test_expired_raises_token_expired_error(self, agentauth_session):
        vault = make_vault(agentauth_session)
        token = vault.issue(agent_id="agent-1", scopes=[], ttl_seconds=1)
        time.sleep(2)
        with pytest.raises(TokenExpiredError):
            vault.verify(token)

    def test_expired_error_message(self, agentauth_session):
        vault = make_vault(agentauth_session)
        token = vault.issue(agent_id="agent-1", scopes=[], ttl_seconds=1)
        time.sleep(2)
        with pytest.raises(TokenExpiredError) as exc_info:
            vault.verify(token)
        assert exc_info.value.status_code == 401

    def test_default_ttl_is_usable(self, agentauth_session):
        """Default TTL (30s) token should be immediately valid."""
        vault = make_vault(agentauth_session)
        token = vault.issue(agent_id="agent-1", scopes=[])
        payload = vault.verify(token)
        assert payload is not None


# ── Invalid tokens ─────────────────────────────────────────────────────────

class TestInvalidTokens:

    def test_garbage_string(self, agentauth_session):
        vault = make_vault(agentauth_session)
        with pytest.raises(InvalidTokenError):
            vault.verify("this.is.garbage")

    def test_empty_string(self, agentauth_session):
        vault = make_vault(agentauth_session)
        with pytest.raises(InvalidTokenError):
            vault.verify("")

    def test_wrong_secret_key(self, agentauth_session):
        vault1 = make_vault(agentauth_session, secret=SECRET)
        vault2 = make_vault(agentauth_session, secret="completely-different-secret-key")
        token = vault1.issue(agent_id="agent-1", scopes=[])
        with pytest.raises(InvalidTokenError):
            vault2.verify(token)

    def test_tampered_payload(self, agentauth_session):
        """Modifying any part of the JWT invalidates the signature."""
        import base64, json
        vault = make_vault(agentauth_session)
        token = vault.issue(agent_id="agent-1", scopes=["db:read"])

        # Decode header.payload.signature
        parts = token.split(".")
        # Decode payload and modify agent_id
        padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(padded))
        decoded["agent_id"] = "hacker"
        new_payload = base64.urlsafe_b64encode(
            json.dumps(decoded).encode()
        ).rstrip(b"=").decode()
        tampered = f"{parts[0]}.{new_payload}.{parts[2]}"

        with pytest.raises(InvalidTokenError):
            vault.verify(tampered)

    def test_invalid_error_status_code(self, agentauth_session):
        vault = make_vault(agentauth_session)
        with pytest.raises(InvalidTokenError) as exc_info:
            vault.verify("bad.token.here")
        assert exc_info.value.status_code == 401


# ── One-time-use ───────────────────────────────────────────────────────────

class TestOneTimeUse:

    def test_first_use_succeeds(self, agentauth_session):
        vault = make_vault(agentauth_session)
        token = vault.issue(agent_id="agent-1", scopes=[], one_time_use=True, ttl_seconds=60)
        payload = vault.verify(token)
        assert payload["agent_id"] == "agent-1"

    def test_second_use_raises(self, agentauth_session):
        vault = make_vault(agentauth_session)
        token = vault.issue(agent_id="agent-1", scopes=[], one_time_use=True, ttl_seconds=60)
        vault.verify(token)
        with pytest.raises(InvalidTokenError, match="already been used"):
            vault.verify(token)

    def test_third_use_also_raises(self, agentauth_session):
        vault = make_vault(agentauth_session)
        token = vault.issue(agent_id="agent-1", scopes=[], one_time_use=True, ttl_seconds=60)
        vault.verify(token)
        for _ in range(3):
            with pytest.raises(InvalidTokenError):
                vault.verify(token)

    def test_non_one_time_use_can_be_verified_multiple_times(self, agentauth_session):
        vault = make_vault(agentauth_session)
        token = vault.issue(agent_id="agent-1", scopes=[], ttl_seconds=60)
        for _ in range(5):
            payload = vault.verify(token)
            assert payload["agent_id"] == "agent-1"

    def test_one_time_use_without_session_raises(self):
        vault = EphemeralTokenVault(secret_key=SECRET, session=None)
        with pytest.raises(ValueError, match="database session"):
            vault.issue(agent_id="agent-1", scopes=[], one_time_use=True)

    def test_one_time_use_payload_flag(self, agentauth_session):
        vault = make_vault(agentauth_session)
        token = vault.issue(agent_id="agent-1", scopes=[], one_time_use=True, ttl_seconds=60)
        payload = vault.verify(token)
        assert payload.get("one_time_use") is True

    def test_regular_token_payload_flag(self, agentauth_session):
        vault = make_vault(agentauth_session)
        token = vault.issue(agent_id="agent-1", scopes=[], one_time_use=False, ttl_seconds=60)
        payload = vault.verify(token)
        assert payload.get("one_time_use") is False


# ── bound_to ───────────────────────────────────────────────────────────────

class TestBoundTo:

    def test_bound_to_in_payload(self, agentauth_session):
        vault = make_vault(agentauth_session)
        token = vault.issue(agent_id="agent-1", scopes=[], bound_to="192.168.1.1")
        payload = vault.verify(token)
        assert payload["bound_to"] == "192.168.1.1"

    def test_correct_bound_to_passes(self, agentauth_session):
        vault = make_vault(agentauth_session)
        token = vault.issue(agent_id="agent-1", scopes=[], bound_to="https://agent.example.com")
        payload = vault.verify(token, expected_bound_to="https://agent.example.com")
        assert payload is not None

    def test_wrong_bound_to_raises(self, agentauth_session):
        vault = make_vault(agentauth_session)
        token = vault.issue(agent_id="agent-1", scopes=[], bound_to="https://agent.example.com")
        with pytest.raises(InvalidTokenError, match="bound to"):
            vault.verify(token, expected_bound_to="https://evil.example.com")

    def test_no_bound_to_skips_check(self, agentauth_session):
        vault = make_vault(agentauth_session)
        # Token has no bound_to — expected_bound_to should be ignored
        token = vault.issue(agent_id="agent-1", scopes=[])
        payload = vault.verify(token, expected_bound_to="https://anything.com")
        assert payload["agent_id"] == "agent-1"

    def test_bound_to_not_in_token_no_check(self, agentauth_session):
        """If bound_to not in token payload, check is skipped."""
        vault = make_vault(agentauth_session)
        token = vault.issue(agent_id="agent-1", scopes=[])
        # Should not raise even though expected_bound_to is set
        payload = vault.verify(token, expected_bound_to="192.168.1.1")
        assert "bound_to" not in payload


# ── Validation ─────────────────────────────────────────────────────────────

class TestValidation:

    def test_missing_secret_raises(self):
        old = os.environ.pop("AGENTAUTH_SECRET_KEY", None)
        try:
            with pytest.raises(ValueError):
                EphemeralTokenVault(secret_key="")
        finally:
            if old is not None:
                os.environ["AGENTAUTH_SECRET_KEY"] = old

    def test_env_var_secret(self, agentauth_session):
        """Secret can be provided via environment variable."""
        os.environ["AGENTAUTH_SECRET_KEY"] = SECRET
        try:
            vault = EphemeralTokenVault(session=agentauth_session)
            token = vault.issue(agent_id="agent-env", scopes=[])
            payload = vault.verify(token)
            assert payload["agent_id"] == "agent-env"
        finally:
            del os.environ["AGENTAUTH_SECRET_KEY"]

    def test_multiple_tokens_independent(self, agentauth_session):
        """Two tokens for the same agent are independent."""
        vault = make_vault(agentauth_session)
        t1 = vault.issue(agent_id="agent-1", scopes=["db:read"], ttl_seconds=60)
        t2 = vault.issue(agent_id="agent-1", scopes=["email:send"], ttl_seconds=60)
        p1 = vault.verify(t1)
        p2 = vault.verify(t2)
        assert p1["scopes"] == ["db:read"]
        assert p2["scopes"] == ["email:send"]

    def test_different_agents_different_tokens(self, agentauth_session):
        vault = make_vault(agentauth_session)
        t1 = vault.issue(agent_id="agent-1", scopes=[])
        t2 = vault.issue(agent_id="agent-2", scopes=[])
        assert vault.verify(t1)["agent_id"] == "agent-1"
        assert vault.verify(t2)["agent_id"] == "agent-2"
