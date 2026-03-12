"""Tests for ephemeral scoped token issuance (EphemeralTokenVault)."""

import time
import pytest
from agentauth.tokens import EphemeralTokenVault
from agentauth.exceptions import TokenExpiredError, InvalidTokenError


class TestEphemeralTokenVault:
    """Test cases for EphemeralTokenVault."""

    SECRET = "test-secret-key-for-agentauth"

    def test_issue_and_verify(self, agentauth_session):
        """Issue a token and verify it successfully."""
        vault = EphemeralTokenVault(secret_key=self.SECRET, session=agentauth_session)
        token = vault.issue(
            agent_id="agent-1",
            scopes=["db:read", "email:send"],
            ttl_seconds=60,
        )
        assert isinstance(token, str)

        payload = vault.verify(token)
        assert payload["agent_id"] == "agent-1"
        assert "db:read" in payload["scopes"]
        assert "email:send" in payload["scopes"]

    def test_expired_token(self, agentauth_session):
        """Verification raises TokenExpiredError for expired tokens."""
        vault = EphemeralTokenVault(secret_key=self.SECRET, session=agentauth_session)
        token = vault.issue(
            agent_id="agent-1",
            scopes=["db:read"],
            ttl_seconds=1,
        )
        time.sleep(2)
        with pytest.raises(TokenExpiredError):
            vault.verify(token)

    def test_invalid_token(self, agentauth_session):
        """Verification raises InvalidTokenError for garbage tokens."""
        vault = EphemeralTokenVault(secret_key=self.SECRET, session=agentauth_session)
        with pytest.raises(InvalidTokenError):
            vault.verify("not.a.valid.token")

    def test_wrong_secret(self, agentauth_session):
        """Verification fails when the secret key doesn't match."""
        vault1 = EphemeralTokenVault(secret_key=self.SECRET, session=agentauth_session)
        vault2 = EphemeralTokenVault(
            secret_key="different-secret", session=agentauth_session
        )
        token = vault1.issue(agent_id="agent-1", scopes=["db:read"])
        with pytest.raises(InvalidTokenError):
            vault2.verify(token)

    def test_one_time_use(self, agentauth_session):
        """One-time-use token is invalidated after first verification."""
        vault = EphemeralTokenVault(secret_key=self.SECRET, session=agentauth_session)
        token = vault.issue(
            agent_id="agent-1",
            scopes=["db:read"],
            ttl_seconds=60,
            one_time_use=True,
        )

        # First verification succeeds
        payload = vault.verify(token)
        assert payload["agent_id"] == "agent-1"

        # Second verification fails
        with pytest.raises(InvalidTokenError, match="already been used"):
            vault.verify(token)

    def test_bound_to_match(self, agentauth_session):
        """Verification succeeds when bound_to matches."""
        vault = EphemeralTokenVault(secret_key=self.SECRET, session=agentauth_session)
        token = vault.issue(
            agent_id="agent-1",
            scopes=["db:read"],
            bound_to="https://agent.example.com",
        )
        payload = vault.verify(token, expected_bound_to="https://agent.example.com")
        assert payload["bound_to"] == "https://agent.example.com"

    def test_bound_to_mismatch(self, agentauth_session):
        """Verification raises InvalidTokenError for bound_to mismatch."""
        vault = EphemeralTokenVault(secret_key=self.SECRET, session=agentauth_session)
        token = vault.issue(
            agent_id="agent-1",
            scopes=["db:read"],
            bound_to="https://agent.example.com",
        )
        with pytest.raises(InvalidTokenError, match="bound to"):
            vault.verify(token, expected_bound_to="https://other.example.com")

    def test_missing_secret_raises(self):
        """Vault raises ValueError without a secret key."""
        import os

        old = os.environ.pop("AGENTAUTH_SECRET_KEY", None)
        try:
            with pytest.raises(ValueError):
                EphemeralTokenVault(secret_key="")
        finally:
            if old is not None:
                os.environ["AGENTAUTH_SECRET_KEY"] = old

    def test_one_time_use_requires_session(self):
        """One-time-use tokens require a database session."""
        vault = EphemeralTokenVault(secret_key=self.SECRET, session=None)
        with pytest.raises(ValueError, match="database session"):
            vault.issue(agent_id="agent-1", scopes=[], one_time_use=True)

    def test_trust_level_in_token(self, agentauth_session):
        """Trust level is correctly embedded in the token payload."""
        vault = EphemeralTokenVault(secret_key=self.SECRET, session=agentauth_session)
        token = vault.issue(
            agent_id="agent-1",
            scopes=["db:read"],
            trust_level="high",
        )
        payload = vault.verify(token)
        assert payload["trust_level"] == "high"
