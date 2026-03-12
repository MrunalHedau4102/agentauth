"""Database models for AgentAuth — new tables only."""

from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    DateTime,
    Text,
    Index,
    JSON,
)
from agentauth.db.base import Base


class AgentRegistryModel(Base):
    """Model for registered AI agents."""

    __tablename__ = "agent_registry"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(36), unique=True, nullable=False, index=True)
    display_name = Column(String(255), nullable=True)
    public_key = Column(Text, nullable=True)
    trust_level = Column(
        String(20), default="untrusted", nullable=False
    )  # untrusted | verified | trusted
    metadata_url = Column(String(2048), nullable=True)
    owner = Column(String(255), nullable=True)
    is_revoked = Column(Boolean, default=False, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    __table_args__ = (
        Index("idx_agent_registry_agent_id", "agent_id"),
        Index("idx_agent_registry_trust_level", "trust_level"),
    )

    def __repr__(self) -> str:
        """String representation of AgentRegistryModel."""
        return (
            f"<AgentRegistry(agent_id={self.agent_id}, "
            f"trust_level={self.trust_level}, is_revoked={self.is_revoked})>"
        )

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "agent_id": self.agent_id,
            "display_name": self.display_name,
            "public_key": self.public_key,
            "trust_level": self.trust_level,
            "metadata_url": self.metadata_url,
            "owner": self.owner,
            "is_revoked": self.is_revoked,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class AgentScopeModel(Base):
    """Model for agent scopes (per-action permissions)."""

    __tablename__ = "agent_scopes"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(36), nullable=False, index=True)
    scope = Column(String(255), nullable=False)
    trust_level_required = Column(
        String(20), default="low", nullable=False
    )  # low | medium | high
    granted_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    __table_args__ = (
        Index("idx_agent_scopes_agent_id", "agent_id"),
        Index("idx_agent_scopes_scope", "scope"),
    )

    def __repr__(self) -> str:
        """String representation of AgentScopeModel."""
        return f"<AgentScope(agent_id={self.agent_id}, scope={self.scope})>"

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "scope": self.scope,
            "trust_level_required": self.trust_level_required,
            "granted_at": self.granted_at.isoformat() if self.granted_at else None,
        }


class EphemeralTokenModel(Base):
    """Model for tracking one-time-use ephemeral tokens."""

    __tablename__ = "ephemeral_tokens"

    id = Column(Integer, primary_key=True, index=True)
    token_signature = Column(String(255), unique=True, nullable=False, index=True)
    agent_id = Column(String(36), nullable=False, index=True)
    scopes = Column(JSON, nullable=True)
    is_used = Column(Boolean, default=False, nullable=False)
    bound_to = Column(String(2048), nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    expires_at = Column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        Index("idx_ephemeral_tokens_signature", "token_signature"),
        Index("idx_ephemeral_tokens_agent_id", "agent_id"),
    )

    def __repr__(self) -> str:
        """String representation of EphemeralTokenModel."""
        return (
            f"<EphemeralToken(agent_id={self.agent_id}, "
            f"is_used={self.is_used})>"
        )

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "token_signature": self.token_signature,
            "agent_id": self.agent_id,
            "scopes": self.scopes,
            "is_used": self.is_used,
            "bound_to": self.bound_to,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }


class AuditLogModel(Base):
    """Model for tamper-evident audit log entries."""

    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(36), unique=True, nullable=False, index=True)
    event_type = Column(String(50), nullable=False, index=True)
    agent_id = Column(String(36), nullable=True, index=True)
    user_id = Column(Integer, nullable=True, index=True)
    timestamp = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    ip_address = Column(String(45), nullable=True)
    scopes_involved = Column(JSON, nullable=True)
    outcome = Column(String(20), nullable=False)  # success | failure
    metadata_json = Column(JSON, nullable=True)
    previous_hash = Column(String(64), nullable=True)
    entry_hash = Column(String(64), nullable=False)

    __table_args__ = (
        Index("idx_audit_log_event_id", "event_id"),
        Index("idx_audit_log_event_type", "event_type"),
        Index("idx_audit_log_agent_id", "agent_id"),
        Index("idx_audit_log_timestamp", "timestamp"),
    )

    def __repr__(self) -> str:
        """String representation of AuditLogModel."""
        return (
            f"<AuditLog(event_id={self.event_id}, "
            f"event_type={self.event_type}, outcome={self.outcome})>"
        )

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "agent_id": self.agent_id,
            "user_id": self.user_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "ip_address": self.ip_address,
            "scopes_involved": self.scopes_involved,
            "outcome": self.outcome,
            "metadata": self.metadata_json,
            "previous_hash": self.previous_hash,
            "entry_hash": self.entry_hash,
        }
