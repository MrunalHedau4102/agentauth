"""
Example 5: FastAPI Integration
===============================
Demonstrates integrating AgentAuth with a FastAPI application.
"""

from typing import Optional
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

# Note: This is a conceptual example. FastAPI may need to be installed: pip install agent-auth[fastapi]

from agentauth import (
    AgentIdentity,
    AgentRegistry,
    EphemeralTokenVault,
    PromptInjectionGuard,
    AuditLogger,
    set_current_token,
    clear_current_token,
    require_scope,
)
from agentauth.db import Base
from agentauth.exceptions import (
    InvalidTokenError,
    PromptInjectionSuspected,
    PermissionDeniedError,
)


# ============================================================
# Setup (would be in your app factory)
# ============================================================

def setup_database():
    """Initialize database."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)


SessionLocal = setup_database()

vault = EphemeralTokenVault(
    secret_key="test-secret-key-min-32-chars-long-1234567890",
    session=SessionLocal()
)

guard = PromptInjectionGuard(strict=True)


# ============================================================
# FastAPI Dependencies (Dependency Injection)
# ============================================================

def get_db():
    """Dependency to get database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_token(authorization: Optional[str]) -> dict:
    """
    Verify Bearer token from Authorization header.
    
    Raises:
        InvalidTokenError: If token is invalid or missing
    """
    if not authorization:
        raise InvalidTokenError("Missing Authorization header")

    if not authorization.startswith("Bearer "):
        raise InvalidTokenError("Invalid Authorization format. Use 'Bearer <token>'")

    token = authorization[7:]  # Remove "Bearer " prefix

    try:
        payload = vault.verify(token)
        return payload
    except Exception as e:
        raise InvalidTokenError(f"Token verification failed: {e}")


# ============================================================
# FastAPI Middleware & Exception Handlers
# ============================================================

def create_fastapi_app():
    """Create and configure FastAPI app with AgentAuth."""
    try:
        from fastapi import FastAPI, HTTPException, Depends
        from fastapi.responses import JSONResponse
    except ImportError:
        print("❌ FastAPI not installed. Install with: pip install agent-auth[fastapi]")
        return None

    app = FastAPI(title="AgentAuth Example API")

    # Exception handler for injection detection
    @app.exception_handler(PromptInjectionSuspected)
    async def injection_exception_handler(request, exc):
        return JSONResponse(
            status_code=400,
            content={"detail": "Prompt injection suspected"},
        )

    # Exception handler for authorization errors
    @app.exception_handler(PermissionDeniedError)
    async def permission_exception_handler(request, exc):
        return JSONResponse(
            status_code=403,
            content={"detail": "Permission denied"},
        )

    # ============================================================
    # Routes
    # ============================================================

    @app.post("/tokens/issue")
    def issue_token(
        agent_id: str,
        scopes: list,
        ttl_seconds: int = 300,
        db: Session = Depends(get_db)
    ):
        """
        Issue a new ephemeral token.
        
        Args:
            agent_id: Agent identifier
            scopes: List of scopes requested
            ttl_seconds: Token time-to-live in seconds
        """
        try:
            # Verify agent exists
            registry = AgentRegistry(db)
            agent = registry.get_agent(agent_id)

            # Issue token
            token = vault.issue(
                agent_id=agent_id,
                scopes=scopes,
                ttl_seconds=ttl_seconds,
                trust_level="low"
            )

            # Log event
            audit = AuditLogger(db)
            audit.log(
                event_type="token_issued",
                agent_id=agent_id,
                outcome="success",
                scopes=scopes,
            )

            return {
                "token": token,
                "agent_id": agent_id,
                "scopes": scopes,
                "ttl_seconds": ttl_seconds,
            }

        except Exception as e:
            return {"error": str(e)}, 400

    @app.post("/search")
    def search_knowledge(
        query: str,
        authorization: Optional[str] = Depends(verify_token),
        db: Session = Depends(get_db)
    ):
        """
        Search knowledge base (protected).
        
        Requires: 'knowledge:search' scope
        """
        # 1. Inspect input for injection attempts
        try:
            guard.inspect("search_knowledge", {"query": query})
        except PromptInjectionSuspected:
            audit = AuditLogger(db)
            audit.log(
                event_type="suspicious_activity",
                outcome="failure",
                metadata={"reason": "injection_detected"},
            )
            raise

        # 2. Verify token payload is in context
        ctx_token = set_current_token(authorization)

        try:
            # 3. This decorator will check for 'knowledge:search' scope
            @require_scope("knowledge:search", trust_level="low")
            def perform_search():
                # Simulate search
                results = [
                    {"id": 1, "title": "AI Safety", "match": 0.95},
                    {"id": 2, "title": "ML Best Practices", "match": 0.87},
                ]
                return results

            results = perform_search()

            # 4. Log successful access
            audit = AuditLogger(db)
            audit.log(
                event_type="knowledge_searched",
                agent_id=authorization.get("agent_id"),
                outcome="success",
                scopes=["knowledge:search"],
                metadata={"query": query, "results": len(results)},
            )

            return {
                "query": query,
                "results": results,
                "count": len(results),
            }

        finally:
            clear_current_token(ctx_token)

    @app.post("/tools/execute")
    def execute_tool(
        tool_name: str,
        parameters: dict,
        authorization: Optional[str] = Depends(verify_token),
        db: Session = Depends(get_db)
    ):
        """
        Execute a tool (protected).
        
        Requires: 'tools:execute' scope with 'high' trust level
        """
        # 1. Inspect parameters for injection
        guard.inspect(tool_name, parameters)

        # 2. Setup context
        ctx_token = set_current_token(authorization)

        try:
            @require_scope("tools:execute", trust_level="high")
            def run_tool():
                # Simulate tool execution
                return {"executed": True, "tool": tool_name, "params": parameters}

            result = run_tool()

            # Log execution
            audit = AuditLogger(db)
            audit.log(
                event_type="tool_executed",
                agent_id=authorization.get("agent_id"),
                outcome="success",
                scopes=["tools:execute"],
                metadata={"tool": tool_name},
            )

            return result

        finally:
            clear_current_token(ctx_token)

    @app.get("/audit/events")
    def get_audit_events(
        agent_id: Optional[str] = None,
        db: Session = Depends(get_db)
    ):
        """
        Retrieve audit events (admin only).
        """
        audit = AuditLogger(db)
        events = audit.get_events(agent_id=agent_id)
        return {"events": events}

    @app.get("/health")
    def health_check():
        """Health check endpoint."""
        return {"status": "healthy", "service": "AgentAuth API"}

    return app


# ============================================================
# Example Usage
# ============================================================

def main():
    """Demonstrate the FastAPI integration."""
    print("🚀 FastAPI + AgentAuth Integration Example\n")

    print("This example shows how to integrate AgentAuth with FastAPI:")
    print("  1. Dependency injection for token verification")
    print("  2. Exception handlers for security errors")
    print("  3. Protected endpoints with @require_scope")
    print("  4. Prompt injection detection middleware")
    print("  5. Audit logging for all API calls\n")

    print("To run this API:")
    print("  1. Install FastAPI: pip install agent-auth[fastapi]")
    print("  2. Run: uvicorn examples.fastapi_integration:app --reload")
    print("  3. Visit: http://localhost:8000/docs\n")

    print("Example requests:")
    print("  POST /tokens/issue")
    print("    - Issue an ephemeral token for an agent")
    print()
    print("  POST /search")
    print("    - Search knowledge base (requires 'knowledge:search' scope)")
    print("    - Parameter: query (will be inspected for injection)")
    print()
    print("  POST /tools/execute")
    print("    - Execute a tool (requires 'tools:execute' with high trust)")
    print("    - Parameters: tool_name, parameters dict")
    print()
    print("  GET /audit/events")
    print("    - Retrieve audit trail (optional: filter by agent_id)")
    print()
    print("  GET /health")
    print("    - Health check endpoint")
    print()

    app = create_fastapi_app()
    if app:
        print("✅ FastAPI app created successfully!")
        print("   (This is a conceptual example, not running)")
    else:
        print("❌ FastAPI could not be imported")


if __name__ == "__main__":
    main()
