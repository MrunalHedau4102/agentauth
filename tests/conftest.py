"""
Pytest configuration and shared fixtures for agentauth tests.

Fixtures provided:
    agentauth_engine   — in-memory SQLite engine, tables created
    agentauth_session  — SQLAlchemy session, rolled back after each test
    vault              — EphemeralTokenVault wired to the test session
    registry           — AgentRegistry wired to the test session
    scope_manager      — ScopeManager wired to the test session
    audit              — AuditLogger wired to the test session
    guard              — PromptInjectionGuard (strict=False)
    guard_strict       — PromptInjectionGuard (strict=True)
    registered_agent   — a pre-registered AgentIdentity (agent_id="test-agent-001")
    agent_token        — a valid 60-second token for registered_agent
                         scopes: ["db:read", "db:write", "email:send"]
                         trust_level: "high"
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from agentauth.db import Base
from agentauth import (
    AgentIdentity,
    AgentRegistry,
    EphemeralTokenVault,
    ScopeManager,
    AuditLogger,
    PromptInjectionGuard,
)

TEST_SECRET = "test-secret-key-min-32-chars-long-xyz1234"
TEST_AGENT_ID = "test-agent-001"
TEST_SCOPES = ["db:read", "db:write", "email:send"]


# ── Engine — one per test function, fully isolated ─────────────────────────

@pytest.fixture(scope="function")
def agentauth_engine():
    """In-memory SQLite engine with all agentauth tables created."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture(scope="function")
def agentauth_session(agentauth_engine):
    """
    Database session. Uses a transaction that is rolled back after
    each test so every test starts with a completely clean slate.
    """
    connection = agentauth_engine.connect()
    transaction = connection.begin()
    Session = sessionmaker(bind=connection)
    session = Session()

    yield session

    session.close()
    transaction.rollback()
    connection.close()


# ── Component fixtures ─────────────────────────────────────────────────────

@pytest.fixture
def vault(agentauth_session):
    """EphemeralTokenVault bound to the test session."""
    return EphemeralTokenVault(secret_key=TEST_SECRET, session=agentauth_session)


@pytest.fixture
def registry(agentauth_session):
    """AgentRegistry bound to the test session."""
    return AgentRegistry(agentauth_session)


@pytest.fixture
def scope_manager(agentauth_session):
    """ScopeManager bound to the test session."""
    return ScopeManager(agentauth_session)


@pytest.fixture
def audit(agentauth_session):
    """AuditLogger bound to the test session."""
    return AuditLogger(agentauth_session)


@pytest.fixture
def guard(audit):
    """PromptInjectionGuard in non-strict mode with audit logger."""
    return PromptInjectionGuard(strict=False, audit_logger=audit)


@pytest.fixture
def guard_strict(audit):
    """PromptInjectionGuard in strict mode with audit logger."""
    return PromptInjectionGuard(strict=True, audit_logger=audit)


# ── Compound fixtures ──────────────────────────────────────────────────────

@pytest.fixture
def registered_agent(registry):
    """
    A pre-registered agent with trust_level='verified'.
    agent_id = TEST_AGENT_ID = "test-agent-001"
    """
    private_key, public_key = AgentIdentity.generate_keypair("ed25519")
    agent = AgentIdentity(
        agent_id=TEST_AGENT_ID,
        display_name="Test Agent",
        owner="test-org",
        trust_level="untrusted",
    )
    agent.public_key = public_key
    agent.private_key = private_key
    registry.register_agent(agent)
    registry.trust_agent(TEST_AGENT_ID, "verified")
    return agent


@pytest.fixture
def agent_token(vault, registered_agent):
    """
    A valid 60-second token for registered_agent.
    Scopes: db:read, db:write, email:send
    Trust level: high
    """
    return vault.issue(
        agent_id=TEST_AGENT_ID,
        scopes=TEST_SCOPES,
        ttl_seconds=60,
        trust_level="high",
    )


@pytest.fixture
def granted_scopes(scope_manager, registered_agent):
    """
    Pre-grants three scopes to the registered_agent.
    Returns the list of granted scope names.
    """
    grants = [
        ("db:read",    "low"),
        ("db:write",   "medium"),
        ("email:send", "low"),
    ]
    for scope, trust in grants:
        scope_manager.grant_scope(TEST_AGENT_ID, scope, trust_level_required=trust)
    return [s for s, _ in grants]
