"""Tests for agent identity management (AgentIdentity + AgentRegistry)."""

import json
import pytest
from unittest.mock import patch, MagicMock
from agentauth.agents import AgentIdentity, AgentRegistry
from agentauth.exceptions import AgentNotFoundError, AgentRevokedError


class TestAgentIdentity:
    """Test cases for AgentIdentity."""

    def test_create_identity(self):
        """Test creating an AgentIdentity with defaults."""
        agent = AgentIdentity()
        assert agent.agent_id is not None
        assert agent.trust_level == "untrusted"
        assert agent.private_key is None

    def test_to_dict_excludes_private_key(self):
        """to_dict must never include the private key."""
        agent = AgentIdentity(private_key="SUPER_SECRET")
        d = agent.to_dict()
        assert "private_key" not in d
        assert "agent_id" in d

    def test_generate_keypair_ed25519(self):
        """Generate an Ed25519 key pair."""
        private_pem, public_pem = AgentIdentity.generate_keypair("ed25519")
        assert "BEGIN PRIVATE KEY" in private_pem
        assert "BEGIN PUBLIC KEY" in public_pem

    def test_generate_keypair_rsa(self):
        """Generate an RSA key pair."""
        private_pem, public_pem = AgentIdentity.generate_keypair("rsa")
        assert "BEGIN PRIVATE KEY" in private_pem
        assert "BEGIN PUBLIC KEY" in public_pem

    def test_generate_keypair_unsupported(self):
        """Unsupported algorithm raises ValueError."""
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            AgentIdentity.generate_keypair("dsa")

    def test_from_url_success(self):
        """from_url creates identity from a mocked remote JSON."""
        fake_json = json.dumps({
            "agent_id": "remote-agent-1",
            "public_key": "c29tZS1wdWJsaWMta2V5",
            "scopes_requested": ["db:read"],
            "owner": "test-org",
        }).encode("utf-8")

        mock_resp = MagicMock()
        mock_resp.read.return_value = fake_json
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            agent = AgentIdentity.from_url("https://agent.example.com/.well-known/agent.json")

        assert agent.agent_id == "remote-agent-1"
        assert agent.owner == "test-org"
        assert "db:read" in agent.scopes_requested
        assert agent.trust_level == "untrusted"

    def test_from_url_failure(self):
        """from_url raises ValueError on network error."""
        with patch("urllib.request.urlopen", side_effect=Exception("network error")):
            with pytest.raises(ValueError, match="Failed to fetch"):
                AgentIdentity.from_url("https://bad-url.example.com")


class TestAgentRegistry:
    """Test cases for AgentRegistry."""

    def test_register_agent(self, agentauth_session):
        """Test registering a new agent."""
        registry = AgentRegistry(agentauth_session)
        agent = AgentIdentity(
            agent_id="agent-1",
            display_name="Test Agent",
            public_key="pub-key-data",
            owner="test-org",
        )
        result = registry.register_agent(agent)
        assert result["agent_id"] == "agent-1"
        assert result["display_name"] == "Test Agent"
        assert result["is_revoked"] is False

    def test_register_duplicate_agent(self, agentauth_session):
        """Registering the same agent_id twice raises ValueError."""
        registry = AgentRegistry(agentauth_session)
        agent = AgentIdentity(agent_id="agent-1")
        registry.register_agent(agent)
        with pytest.raises(ValueError, match="already registered"):
            registry.register_agent(agent)

    def test_get_agent(self, agentauth_session):
        """Retrieve a registered agent."""
        registry = AgentRegistry(agentauth_session)
        agent = AgentIdentity(agent_id="agent-1", display_name="Test Agent")
        registry.register_agent(agent)

        retrieved = registry.get_agent("agent-1")
        assert retrieved.agent_id == "agent-1"
        assert retrieved.display_name == "Test Agent"

    def test_get_agent_not_found(self, agentauth_session):
        """Getting a non-existent agent raises AgentNotFoundError."""
        registry = AgentRegistry(agentauth_session)
        with pytest.raises(AgentNotFoundError):
            registry.get_agent("nonexistent")

    def test_get_revoked_agent(self, agentauth_session):
        """Getting a revoked agent raises AgentRevokedError."""
        registry = AgentRegistry(agentauth_session)
        agent = AgentIdentity(agent_id="agent-1")
        registry.register_agent(agent)
        registry.revoke_agent("agent-1")

        with pytest.raises(AgentRevokedError):
            registry.get_agent("agent-1")

    def test_trust_agent(self, agentauth_session):
        """Update an agent's trust level."""
        registry = AgentRegistry(agentauth_session)
        agent = AgentIdentity(agent_id="agent-1")
        registry.register_agent(agent)

        result = registry.trust_agent("agent-1", "trusted")
        assert result["trust_level"] == "trusted"

    def test_trust_agent_invalid_level(self, agentauth_session):
        """Invalid trust level raises ValueError."""
        registry = AgentRegistry(agentauth_session)
        agent = AgentIdentity(agent_id="agent-1")
        registry.register_agent(agent)

        with pytest.raises(ValueError, match="Invalid trust level"):
            registry.trust_agent("agent-1", "super_trusted")

    def test_revoke_agent(self, agentauth_session):
        """Revoke an agent."""
        registry = AgentRegistry(agentauth_session)
        agent = AgentIdentity(agent_id="agent-1")
        registry.register_agent(agent)

        result = registry.revoke_agent("agent-1")
        assert result["is_revoked"] is True

    def test_list_agents(self, agentauth_session):
        """List agents, optionally including revoked ones."""
        registry = AgentRegistry(agentauth_session)
        registry.register_agent(AgentIdentity(agent_id="agent-1"))
        registry.register_agent(AgentIdentity(agent_id="agent-2"))
        registry.revoke_agent("agent-2")

        active = registry.list_agents(include_revoked=False)
        all_agents = registry.list_agents(include_revoked=True)

        assert len(active) == 1
        assert len(all_agents) == 2
