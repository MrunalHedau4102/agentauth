"""
Example 2: Scope Enforcement
=============================
Demonstrates per-action authorization with @require_scope decorator.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from agentauth import (
    ScopeManager,
    set_current_token,
    clear_current_token,
    require_scope,
    EphemeralTokenVault,
)
from agentauth.db import Base
from agentauth.exceptions import ScopeNotGrantedError, TrustLevelInsufficientError


def main():
    # ============================================================
    # 1. Setup Database
    # ============================================================
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    vault = EphemeralTokenVault(
        secret_key="test-secret-key-min-32-chars-long-1234567890",
        session=session
    )

    print("✅ Database initialized\n")

    # ============================================================
    # 2. Grant Scopes to an Agent
    # ============================================================
    print("🔑 Granting scopes to agent...")
    
    scope_manager = ScopeManager(session)

    scopes_to_grant = [
        ("database:read", "low"),
        ("database:write", "medium"),
        ("database:delete", "high"),
    ]

    for scope, trust_level in scopes_to_grant:
        scope_manager.grant_scope(
            "agent-1",
            scope,
            trust_level_required=trust_level
        )
        print(f"  Granted: {scope:20s} (requires: {trust_level})")

    print()

    # ============================================================
    # 3. Define Protected Functions
    # ============================================================
    print("🛡️  Defining protected functions...\n")

    @require_scope("database:read", trust_level="low")
    def read_database():
        """Read from database (low trust required)."""
        return "SELECT * FROM users"

    @require_scope("database:write", trust_level="medium")
    def write_database():
        """Write to database (medium trust required)."""
        return "INSERT INTO users VALUES (...)"

    @require_scope("database:delete", trust_level="high")
    def delete_database():
        """Delete from database (high trust required)."""
        return "DELETE FROM users WHERE id = 123"

    # ============================================================
    # 4. Test: Call with sufficient permissions
    # ============================================================
    print("✅ Test 1: Call with sufficient scopes and trust...")
    
    token = vault.issue(
        agent_id="agent-1",
        scopes=["database:read", "database:write", "database:delete"],
        trust_level="high"
    )

    payload = vault.verify(token)
    ctx_token = set_current_token(payload)

    try:
        result = read_database()
        print(f"  read_database(): {result}")
        
        result = write_database()
        print(f"  write_database(): {result}")
        
        result = delete_database()
        print(f"  delete_database(): {result}")
        print()
    finally:
        clear_current_token(ctx_token)

    # ============================================================
    # 5. Test: Missing scope
    # ============================================================
    print("❌ Test 2: Call without required scope...")
    
    token = vault.issue(
        agent_id="agent-1",
        scopes=["database:read"],  # Only read scope
        trust_level="high"
    )

    payload = vault.verify(token)
    ctx_token = set_current_token(payload)

    try:
        result = write_database()
        print(f"  write_database(): {result}")
    except ScopeNotGrantedError as e:
        print(f"  ❌ ScopeNotGrantedError: {e}\n")
    finally:
        clear_current_token(ctx_token)

    # ============================================================
    # 6. Test: Insufficient trust level
    # ============================================================
    print("❌ Test 3: Call with insufficient trust level...")
    
    token = vault.issue(
        agent_id="agent-1",
        scopes=["database:read", "database:write", "database:delete"],
        trust_level="low"  # Only low trust
    )

    payload = vault.verify(token)
    ctx_token = set_current_token(payload)

    try:
        result = delete_database()
        print(f"  delete_database(): {result}")
    except TrustLevelInsufficientError as e:
        print(f"  ❌ TrustLevelInsufficientError: {e}\n")
    finally:
        clear_current_token(ctx_token)

    # ============================================================
    # 7. List all scopes for an agent
    # ============================================================
    print("📋 Scopes granted to agent-1:\n")
    
    granted_scopes = scope_manager.list_scopes("agent-1")
    for scope in granted_scopes:
        print(f"  {scope['scope']:20s} - Trust: {scope['trust_level_required']}")

    print()

    # ============================================================
    # Cleanup
    # ============================================================
    session.close()
    print("✅ Example completed successfully!")


if __name__ == "__main__":
    main()
