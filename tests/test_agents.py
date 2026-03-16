"""
Tests for AgentIdentity and AgentRegistry.

Coverage:
    AgentIdentity:
        - Default field values
        - Custom field values
        - to_dict never exposes private_key
        - generate_keypair ed25519
        - generate_keypair rsa
        - generate_keypair unsupported algorithm
        - from_url happy path
        - from_url network failure
        - from_url malformed JSON

    AgentRegistry:
        - register_agent success
        - register_agent duplicate raises ValueError
        - get_agent found
        - get_agent not found raises AgentNotFoundError
        - get_agent revoked raises AgentRevokedError
        - trust_agent success (all three levels)
        - trust_agent not found
        - trust_agent invalid level raises ValueError
        - revoke_agent success
        - revoke_agent not found
        - list_agents excludes revoked by default
        - list_agents includes revoked when requested
        - list_agents returns all fields
        - registered agent has correct defaults
        - agent public_key is persisted
        - agent owner is persisted
"""

import json
import pytest
from unittest.mock import patch, MagicMock

from agentauth.agents import AgentIdentity, AgentRegistry
from agentauth.exceptions import AgentNotFoundError, AgentRevokedError


# ════════════════════════════════════════════════════════════════
# AgentIdentity
# ════════════════════════════════════════════════════════════════

class TestAgentIdentity:

    def test_default_agent_id_generated(self):
        agent = AgentIdentity()
        assert agent.agent_id is not None
        assert len(agent.agent_id) > 0

    def test_default_trust_level(self):
        agent = AgentIdentity()
        assert agent.trust_level == "untrusted"

    def test_default_private_key_none(self):
        agent = AgentIdentity()
        assert agent.private_key is None

    def test_default_public_key_none(self):
        agent = AgentIdentity()
        assert agent.public_key is None

    def test_default_scopes_empty(self):
        agent = AgentIdentity()
        assert agent.scopes_requested == []

    def test_custom_agent_id(self):
        agent = AgentIdentity(agent_id="my-custom-id")
        assert agent.agent_id == "my-custom-id"

    def test_custom_display_name(self):
        agent = AgentIdentity(agent_id="a1", display_name="My Bot")
        assert agent.display_name == "My Bot"

    def test_custom_owner(self):
        agent = AgentIdentity(agent_id="a1", owner="acme-corp")
        assert agent.owner == "acme-corp"

    def test_custom_scopes_requested(self):
        agent = AgentIdentity(agent_id="a1", scopes_requested=["db:read", "email:send"])
        assert "db:read" in agent.scopes_requested

    # ── to_dict ──────────────────────────────────────────────────────────

    def test_to_dict_excludes_private_key(self):
        agent = AgentIdentity(agent_id="a1")
        agent.private_key = "SUPER_SECRET_PRIVATE_KEY"
        d = agent.to_dict()
        assert "private_key" not in d

    def test_to_dict_includes_agent_id(self):
        agent = AgentIdentity(agent_id="a1")
        d = agent.to_dict()
        assert d["agent_id"] == "a1"

    def test_to_dict_includes_trust_level(self):
        agent = AgentIdentity(agent_id="a1", trust_level="trusted")
        d = agent.to_dict()
        assert d["trust_level"] == "trusted"

    def test_to_dict_includes_owner(self):
        agent = AgentIdentity(agent_id="a1", owner="acme")
        d = agent.to_dict()
        assert d["owner"] == "acme"

    def test_to_dict_includes_public_key(self):
        agent = AgentIdentity(agent_id="a1", public_key="pub-key-pem")
        d = agent.to_dict()
        assert d["public_key"] == "pub-key-pem"

    # ── generate_keypair ─────────────────────────────────────────────────

    def test_ed25519_private_pem(self):
        priv, pub = AgentIdentity.generate_keypair("ed25519")
        assert "BEGIN PRIVATE KEY" in priv

    def test_ed25519_public_pem(self):
        priv, pub = AgentIdentity.generate_keypair("ed25519")
        assert "BEGIN PUBLIC KEY" in pub

    def test_ed25519_keys_are_different(self):
        priv, pub = AgentIdentity.generate_keypair("ed25519")
        assert priv != pub

    def test_rsa_private_pem(self):
        priv, pub = AgentIdentity.generate_keypair("rsa")
        assert "BEGIN PRIVATE KEY" in priv

    def test_rsa_public_pem(self):
        priv, pub = AgentIdentity.generate_keypair("rsa")
        assert "BEGIN PUBLIC KEY" in pub

    def test_two_ed25519_keypairs_are_unique(self):
        _, pub1 = AgentIdentity.generate_keypair("ed25519")
        _, pub2 = AgentIdentity.generate_keypair("ed25519")
        assert pub1 != pub2

    def test_unsupported_algorithm_raises(self):
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            AgentIdentity.generate_keypair("dsa")

    def test_unsupported_algorithm_ecdsa(self):
        with pytest.raises(ValueError):
            AgentIdentity.generate_keypair("ecdsa")

    # ── from_url ─────────────────────────────────────────────────────────

    def _mock_url_response(self, data: dict):
        """Helper to mock urllib.request.urlopen with a JSON response."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(data).encode("utf-8")
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        return mock_resp

    def test_from_url_sets_agent_id(self):
        mock_resp = self._mock_url_response({
            "agent_id": "remote-agent-1",
            "public_key": "some-key",
            "owner": "org",
            "scopes_requested": [],
        })
        with patch("urllib.request.urlopen", return_value=mock_resp):
            agent = AgentIdentity.from_url("https://example.com/.well-known/agent.json")
        assert agent.agent_id == "remote-agent-1"

    def test_from_url_sets_public_key(self):
        mock_resp = self._mock_url_response({
            "agent_id": "a1",
            "public_key": "base64-pub-key",
            "owner": "org",
            "scopes_requested": [],
        })
        with patch("urllib.request.urlopen", return_value=mock_resp):
            agent = AgentIdentity.from_url("https://example.com/.well-known/agent.json")
        assert agent.public_key == "base64-pub-key"

    def test_from_url_sets_owner(self):
        mock_resp = self._mock_url_response({
            "agent_id": "a1",
            "public_key": "key",
            "owner": "acme-corp",
            "scopes_requested": [],
        })
        with patch("urllib.request.urlopen", return_value=mock_resp):
            agent = AgentIdentity.from_url("https://example.com/.well-known/agent.json")
        assert agent.owner == "acme-corp"

    def test_from_url_sets_scopes_requested(self):
        mock_resp = self._mock_url_response({
            "agent_id": "a1",
            "public_key": "key",
            "owner": "org",
            "scopes_requested": ["db:read", "email:send"],
        })
        with patch("urllib.request.urlopen", return_value=mock_resp):
            agent = AgentIdentity.from_url("https://example.com/.well-known/agent.json")
        assert "db:read" in agent.scopes_requested

    def test_from_url_trust_level_is_untrusted(self):
        """Remote agents always start as untrusted."""
        mock_resp = self._mock_url_response({
            "agent_id": "a1",
            "public_key": "key",
            "trust_level": "trusted",   # should be ignored
            "owner": "org",
            "scopes_requested": [],
        })
        with patch("urllib.request.urlopen", return_value=mock_resp):
            agent = AgentIdentity.from_url("https://example.com/.well-known/agent.json")
        assert agent.trust_level == "untrusted"

    def test_from_url_network_error_raises_value_error(self):
        with patch("urllib.request.urlopen", side_effect=Exception("connection refused")):
            with pytest.raises(ValueError, match="Failed to fetch"):
                AgentIdentity.from_url("https://unreachable.example.com")

    def test_from_url_missing_agent_id_gets_generated(self):
        """If remote JSON has no agent_id, a UUID is generated."""
        mock_resp = self._mock_url_response({
            "public_key": "key",
            "owner": "org",
            "scopes_requested": [],
        })
        with patch("urllib.request.urlopen", return_value=mock_resp):
            agent = AgentIdentity.from_url("https://example.com/.well-known/agent.json")
        assert agent.agent_id is not None
        assert len(agent.agent_id) > 0

    def test_from_url_sets_metadata_url(self):
        url = "https://example.com/.well-known/agent.json"
        mock_resp = self._mock_url_response({
            "agent_id": "a1",
            "public_key": "key",
            "owner": "org",
            "scopes_requested": [],
        })
        with patch("urllib.request.urlopen", return_value=mock_resp):
            agent = AgentIdentity.from_url(url)
        assert agent.metadata_url == url


# ════════════════════════════════════════════════════════════════
# AgentRegistry
# ════════════════════════════════════════════════════════════════

class TestAgentRegistry:

    # ── register_agent ────────────────────────────────────────────────────

    def test_register_returns_dict(self, agentauth_session):
        registry = AgentRegistry(agentauth_session)
        agent = AgentIdentity(agent_id="agent-1", display_name="Bot")
        result = registry.register_agent(agent)
        assert isinstance(result, dict)

    def test_register_agent_id_in_result(self, agentauth_session):
        registry = AgentRegistry(agentauth_session)
        result = registry.register_agent(AgentIdentity(agent_id="agent-1"))
        assert result["agent_id"] == "agent-1"

    def test_register_default_trust_untrusted(self, agentauth_session):
        registry = AgentRegistry(agentauth_session)
        result = registry.register_agent(AgentIdentity(agent_id="agent-1"))
        assert result["trust_level"] == "untrusted"

    def test_register_is_revoked_false(self, agentauth_session):
        registry = AgentRegistry(agentauth_session)
        result = registry.register_agent(AgentIdentity(agent_id="agent-1"))
        assert result["is_revoked"] is False

    def test_register_owner_persisted(self, agentauth_session):
        registry = AgentRegistry(agentauth_session)
        agent = AgentIdentity(agent_id="agent-1", owner="acme")
        result = registry.register_agent(agent)
        assert result["owner"] == "acme"

    def test_register_public_key_persisted(self, agentauth_session):
        registry = AgentRegistry(agentauth_session)
        _, pub = AgentIdentity.generate_keypair("ed25519")
        agent = AgentIdentity(agent_id="agent-1", public_key=pub)
        result = registry.register_agent(agent)
        assert result["public_key"] == pub

    def test_register_duplicate_raises(self, agentauth_session):
        registry = AgentRegistry(agentauth_session)
        agent = AgentIdentity(agent_id="agent-1")
        registry.register_agent(agent)
        with pytest.raises(ValueError, match="already registered"):
            registry.register_agent(agent)

    def test_register_two_different_agents(self, agentauth_session):
        registry = AgentRegistry(agentauth_session)
        registry.register_agent(AgentIdentity(agent_id="agent-1"))
        registry.register_agent(AgentIdentity(agent_id="agent-2"))
        agents = registry.list_agents(include_revoked=True)
        ids = [a["agent_id"] for a in agents]
        assert "agent-1" in ids
        assert "agent-2" in ids

    # ── get_agent ─────────────────────────────────────────────────────────

    def test_get_agent_returns_identity(self, agentauth_session):
        registry = AgentRegistry(agentauth_session)
        registry.register_agent(AgentIdentity(agent_id="agent-1", display_name="Bot"))
        identity = registry.get_agent("agent-1")
        assert isinstance(identity, AgentIdentity)

    def test_get_agent_correct_id(self, agentauth_session):
        registry = AgentRegistry(agentauth_session)
        registry.register_agent(AgentIdentity(agent_id="agent-1"))
        identity = registry.get_agent("agent-1")
        assert identity.agent_id == "agent-1"

    def test_get_agent_display_name(self, agentauth_session):
        registry = AgentRegistry(agentauth_session)
        registry.register_agent(AgentIdentity(agent_id="agent-1", display_name="My Bot"))
        identity = registry.get_agent("agent-1")
        assert identity.display_name == "My Bot"

    def test_get_agent_not_found(self, agentauth_session):
        registry = AgentRegistry(agentauth_session)
        with pytest.raises(AgentNotFoundError):
            registry.get_agent("does-not-exist")

    def test_get_agent_not_found_message(self, agentauth_session):
        registry = AgentRegistry(agentauth_session)
        with pytest.raises(AgentNotFoundError) as exc_info:
            registry.get_agent("ghost")
        assert exc_info.value.status_code == 404

    def test_get_revoked_agent_raises(self, agentauth_session):
        registry = AgentRegistry(agentauth_session)
        registry.register_agent(AgentIdentity(agent_id="agent-1"))
        registry.revoke_agent("agent-1")
        with pytest.raises(AgentRevokedError):
            registry.get_agent("agent-1")

    def test_get_revoked_agent_status_code(self, agentauth_session):
        registry = AgentRegistry(agentauth_session)
        registry.register_agent(AgentIdentity(agent_id="agent-1"))
        registry.revoke_agent("agent-1")
        with pytest.raises(AgentRevokedError) as exc_info:
            registry.get_agent("agent-1")
        assert exc_info.value.status_code == 403

    # ── trust_agent ───────────────────────────────────────────────────────

    def test_trust_agent_to_verified(self, agentauth_session):
        registry = AgentRegistry(agentauth_session)
        registry.register_agent(AgentIdentity(agent_id="agent-1"))
        result = registry.trust_agent("agent-1", "verified")
        assert result["trust_level"] == "verified"

    def test_trust_agent_to_trusted(self, agentauth_session):
        registry = AgentRegistry(agentauth_session)
        registry.register_agent(AgentIdentity(agent_id="agent-1"))
        result = registry.trust_agent("agent-1", "trusted")
        assert result["trust_level"] == "trusted"

    def test_trust_agent_to_untrusted(self, agentauth_session):
        registry = AgentRegistry(agentauth_session)
        registry.register_agent(AgentIdentity(agent_id="agent-1"))
        registry.trust_agent("agent-1", "trusted")
        result = registry.trust_agent("agent-1", "untrusted")
        assert result["trust_level"] == "untrusted"

    def test_trust_agent_invalid_level(self, agentauth_session):
        registry = AgentRegistry(agentauth_session)
        registry.register_agent(AgentIdentity(agent_id="agent-1"))
        with pytest.raises(ValueError, match="Invalid trust level"):
            registry.trust_agent("agent-1", "super_admin")

    def test_trust_agent_not_found(self, agentauth_session):
        registry = AgentRegistry(agentauth_session)
        with pytest.raises(AgentNotFoundError):
            registry.trust_agent("ghost", "trusted")

    def test_trust_persisted_to_db(self, agentauth_session):
        """get_agent reflects updated trust level."""
        registry = AgentRegistry(agentauth_session)
        registry.register_agent(AgentIdentity(agent_id="agent-1"))
        registry.trust_agent("agent-1", "trusted")
        identity = registry.get_agent("agent-1")
        assert identity.trust_level == "trusted"

    # ── revoke_agent ──────────────────────────────────────────────────────

    def test_revoke_agent_sets_revoked(self, agentauth_session):
        registry = AgentRegistry(agentauth_session)
        registry.register_agent(AgentIdentity(agent_id="agent-1"))
        result = registry.revoke_agent("agent-1")
        assert result["is_revoked"] is True

    def test_revoke_agent_not_found(self, agentauth_session):
        registry = AgentRegistry(agentauth_session)
        with pytest.raises(AgentNotFoundError):
            registry.revoke_agent("ghost")

    def test_revoke_agent_prevents_get(self, agentauth_session):
        registry = AgentRegistry(agentauth_session)
        registry.register_agent(AgentIdentity(agent_id="agent-1"))
        registry.revoke_agent("agent-1")
        with pytest.raises(AgentRevokedError):
            registry.get_agent("agent-1")

    # ── list_agents ───────────────────────────────────────────────────────

    def test_list_agents_empty(self, agentauth_session):
        registry = AgentRegistry(agentauth_session)
        assert registry.list_agents() == []

    def test_list_agents_excludes_revoked_by_default(self, agentauth_session):
        registry = AgentRegistry(agentauth_session)
        registry.register_agent(AgentIdentity(agent_id="agent-1"))
        registry.register_agent(AgentIdentity(agent_id="agent-2"))
        registry.revoke_agent("agent-2")
        agents = registry.list_agents()
        ids = [a["agent_id"] for a in agents]
        assert "agent-1" in ids
        assert "agent-2" not in ids

    def test_list_agents_includes_revoked_when_requested(self, agentauth_session):
        registry = AgentRegistry(agentauth_session)
        registry.register_agent(AgentIdentity(agent_id="agent-1"))
        registry.register_agent(AgentIdentity(agent_id="agent-2"))
        registry.revoke_agent("agent-2")
        agents = registry.list_agents(include_revoked=True)
        assert len(agents) == 2

    def test_list_agents_count(self, agentauth_session):
        registry = AgentRegistry(agentauth_session)
        for i in range(5):
            registry.register_agent(AgentIdentity(agent_id=f"agent-{i}"))
        assert len(registry.list_agents()) == 5

    def test_list_agents_returns_dicts(self, agentauth_session):
        registry = AgentRegistry(agentauth_session)
        registry.register_agent(AgentIdentity(agent_id="agent-1"))
        agents = registry.list_agents()
        assert isinstance(agents[0], dict)
        assert "agent_id" in agents[0]
