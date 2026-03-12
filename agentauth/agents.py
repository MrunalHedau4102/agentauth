"""Agent identity management and registry (A2A trust)."""

import uuid
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List

from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

from agentauth.db.models import AgentRegistryModel
from agentauth.exceptions import (
    AgentNotFoundError,
    AgentRevokedError,
    TrustLevelInsufficientError,
)


@dataclass
class AgentIdentity:
    """
    Represents an AI agent's identity.

    Attributes:
        agent_id: Unique identifier (UUID string)
        public_key: Base64-encoded public key (RSA or Ed25519)
        private_key: Private key material — never logged or serialized
        metadata_url: Optional HTTPS URL serving the agent's public JSON
        trust_level: One of "untrusted", "verified", "trusted"
        display_name: Human-readable agent name
        owner: Organisation or person owning the agent
        scopes_requested: Scopes the agent requests at registration
    """

    agent_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    public_key: Optional[str] = None
    private_key: Optional[str] = field(default=None, repr=False)
    metadata_url: Optional[str] = None
    trust_level: str = "untrusted"
    display_name: Optional[str] = None
    owner: Optional[str] = None
    scopes_requested: List[str] = field(default_factory=list)

    @classmethod
    def from_url(cls, url: str) -> "AgentIdentity":
        """
        Create an AgentIdentity by fetching a remote agent.json document.

        Expected JSON schema::

            {
                "agent_id": "uuid",
                "public_key": "base64-encoded-public-key",
                "scopes_requested": ["db:read"],
                "owner": "org-name"
            }

        Args:
            url: HTTPS URL to the agent's ``/.well-known/agent.json``

        Returns:
            AgentIdentity populated from the remote document

        Raises:
            ValueError: If the URL is unreachable or JSON is malformed
        """
        import urllib.request
        import json

        try:
            req = urllib.request.Request(url, method="GET")
            req.add_header("Accept", "application/json")
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            raise ValueError(
                f"Failed to fetch agent identity from {url}: {exc}"
            ) from exc

        return cls(
            agent_id=data.get("agent_id", str(uuid.uuid4())),
            public_key=data.get("public_key"),
            metadata_url=url,
            owner=data.get("owner"),
            scopes_requested=data.get("scopes_requested", []),
            trust_level="untrusted",
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict (private_key excluded)."""
        return {
            "agent_id": self.agent_id,
            "public_key": self.public_key,
            "metadata_url": self.metadata_url,
            "trust_level": self.trust_level,
            "display_name": self.display_name,
            "owner": self.owner,
            "scopes_requested": self.scopes_requested,
        }

    @staticmethod
    def generate_keypair(algorithm: str = "ed25519") -> tuple:
        """
        Generate a cryptographic key pair.

        Args:
            algorithm: "ed25519" or "rsa"

        Returns:
            Tuple of (private_key_pem, public_key_pem) as strings

        Raises:
            ValueError: If the algorithm is unsupported
        """
        from cryptography.hazmat.primitives import serialization

        if algorithm == "ed25519":
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )

            private_key = Ed25519PrivateKey.generate()
        elif algorithm == "rsa":
            from cryptography.hazmat.primitives.asymmetric import rsa

            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        return private_pem, public_pem


class AgentRegistry:
    """
    Registry for managing AI agent identities in the database.
    """

    def __init__(self, session: Session) -> None:
        """
        Initialize AgentRegistry.

        Args:
            session: SQLAlchemy database session
        """
        self.session = session

    def register_agent(self, agent: AgentIdentity) -> Dict[str, Any]:
        """
        Register a new agent in the database.

        Args:
            agent: AgentIdentity to register

        Returns:
            Dictionary representation of the registered agent

        Raises:
            ValueError: If an agent with the same agent_id already exists
        """
        existing = (
            self.session.query(AgentRegistryModel)
            .filter(AgentRegistryModel.agent_id == agent.agent_id)
            .first()
        )
        if existing:
            raise ValueError(
                f"Agent with id '{agent.agent_id}' is already registered"
            )

        record = AgentRegistryModel(
            agent_id=agent.agent_id,
            display_name=agent.display_name,
            public_key=agent.public_key,
            trust_level=agent.trust_level,
            metadata_url=agent.metadata_url,
            owner=agent.owner,
            is_revoked=False,
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record.to_dict()

    def get_agent(self, agent_id: str) -> AgentIdentity:
        """
        Retrieve an agent by ID.

        Args:
            agent_id: UUID of the agent

        Returns:
            AgentIdentity

        Raises:
            AgentNotFoundError: If the agent does not exist
            AgentRevokedError: If the agent has been revoked
        """
        record = (
            self.session.query(AgentRegistryModel)
            .filter(AgentRegistryModel.agent_id == agent_id)
            .first()
        )
        if record is None:
            raise AgentNotFoundError(f"Agent '{agent_id}' not found")
        if record.is_revoked:
            raise AgentRevokedError(f"Agent '{agent_id}' has been revoked")

        return AgentIdentity(
            agent_id=record.agent_id,
            public_key=record.public_key,
            metadata_url=record.metadata_url,
            trust_level=record.trust_level,
            display_name=record.display_name,
            owner=record.owner,
        )

    def trust_agent(self, agent_id: str, trust_level: str) -> Dict[str, Any]:
        """
        Update an agent's trust level.

        Args:
            agent_id: UUID of the agent
            trust_level: New trust level ("untrusted", "verified", "trusted")

        Returns:
            Updated agent dictionary

        Raises:
            AgentNotFoundError: If the agent does not exist
            ValueError: If trust_level is invalid
        """
        valid_levels = ("untrusted", "verified", "trusted")
        if trust_level not in valid_levels:
            raise ValueError(
                f"Invalid trust level: {trust_level}. "
                f"Must be one of: {valid_levels}"
            )

        record = (
            self.session.query(AgentRegistryModel)
            .filter(AgentRegistryModel.agent_id == agent_id)
            .first()
        )
        if record is None:
            raise AgentNotFoundError(f"Agent '{agent_id}' not found")

        record.trust_level = trust_level
        self.session.commit()
        self.session.refresh(record)
        return record.to_dict()

    def revoke_agent(self, agent_id: str) -> Dict[str, Any]:
        """
        Revoke an agent.

        Args:
            agent_id: UUID of the agent

        Returns:
            Updated agent dictionary

        Raises:
            AgentNotFoundError: If the agent does not exist
        """
        record = (
            self.session.query(AgentRegistryModel)
            .filter(AgentRegistryModel.agent_id == agent_id)
            .first()
        )
        if record is None:
            raise AgentNotFoundError(f"Agent '{agent_id}' not found")

        record.is_revoked = True
        self.session.commit()
        self.session.refresh(record)
        return record.to_dict()

    def list_agents(
        self, include_revoked: bool = False
    ) -> List[Dict[str, Any]]:
        """
        List all registered agents.

        Args:
            include_revoked: Whether to include revoked agents

        Returns:
            List of agent dictionaries
        """
        query = self.session.query(AgentRegistryModel)
        if not include_revoked:
            query = query.filter(AgentRegistryModel.is_revoked == False)
        return [r.to_dict() for r in query.all()]
