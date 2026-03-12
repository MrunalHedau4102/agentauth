"""Pytest configuration and fixtures for AgentAuth tests."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from agentauth.db import Base


@pytest.fixture(scope="function")
def agentauth_engine():
    """Create an in-memory SQLite engine for AgentAuth tests."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture(scope="function")
def agentauth_session(agentauth_engine):
    """Create a test database session."""
    Session = sessionmaker(bind=agentauth_engine)
    session = Session()
    yield session
    session.close()
