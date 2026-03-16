"""
Example 5 — FastAPI Integration
=================================
A complete, runnable FastAPI app showing every agentauth integration pattern.

Install:
    pip install fastapi uvicorn

Run:
    uvicorn examples.fastapi_integration:app --reload

Then visit:
    http://localhost:8000/docs
"""

from typing import Optional, List, Any
from contextlib import asynccontextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from fastapi import FastAPI, Header, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from agentauth import (
    AgentIdentity,
    AgentRegistry,
    EphemeralTokenVault,
    ScopeManager,
    PromptInjectionGuard,
    AuditLogger,
    set_current_token,
    clear_current_token,
    require_scope,
)
from agentauth.db import Base
from agentauth.exceptions import (
    AgentAuthError,
    TokenExpiredError,
    InvalidTokenError,
    PermissionDeniedError,
    ScopeNotGrantedError,
    TrustLevelInsufficientError,
    PromptInjectionSuspected,
    AgentNotFoundError,
    AgentRevokedError,
)

# ── Database ───────────────────────────────────────────────────────────────

engine = create_engine(
    "sqlite:///./agentauth_fastapi_demo.db",
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

SECRET_KEY = "replace-this-with-a-real-secret-key-min-32-chars"


# ── Lifespan ───────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    print("✅ Database tables created")
    yield
    print("👋 App shutting down")


# ── App ────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="agentauth FastAPI Demo",
    description=(
        "Demonstrates agentauth: token issuance, scope enforcement, "
        "prompt injection guard, and audit logging."
    ),
    version="1.0.0",
    lifespan=lifespan,
)


# ── Dependencies ───────────────────────────────────────────────────────────

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_vault(db: Session = Depends(get_db)) -> EphemeralTokenVault:
    return EphemeralTokenVault(secret_key=SECRET_KEY, session=db)


def get_guard(db: Session = Depends(get_db)) -> PromptInjectionGuard:
    audit = AuditLogger(db)
    return PromptInjectionGuard(strict=True, audit_logger=audit)


def verify_bearer_token(
    authorization: str = Header(..., description="Bearer <token>"),
    db: Session = Depends(get_db),
) -> dict:
    """
    Extract and verify Bearer token from Authorization header.
    Returns decoded payload dict on success.
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Invalid Authorization header. Format: Bearer <token>",
        )
    token = authorization[7:]
    vault = EphemeralTokenVault(secret_key=SECRET_KEY, session=db)
    try:
        return vault.verify(token)
    except TokenExpiredError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=str(e))


# ── Global exception handlers ──────────────────────────────────────────────

@app.exception_handler(PromptInjectionSuspected)
async def injection_handler(request: Request, exc: PromptInjectionSuspected):
    return JSONResponse(
        status_code=400,
        content={"error": "PromptInjectionSuspected", "detail": str(exc)},
    )


@app.exception_handler(PermissionDeniedError)
async def permission_handler(request: Request, exc: PermissionDeniedError):
    return JSONResponse(
        status_code=403,
        content={"error": "PermissionDeniedError", "detail": str(exc)},
    )


@app.exception_handler(ScopeNotGrantedError)
async def scope_handler(request: Request, exc: ScopeNotGrantedError):
    return JSONResponse(
        status_code=403,
        content={"error": "ScopeNotGrantedError", "detail": str(exc)},
    )


@app.exception_handler(TrustLevelInsufficientError)
async def trust_handler(request: Request, exc: TrustLevelInsufficientError):
    return JSONResponse(
        status_code=403,
        content={"error": "TrustLevelInsufficientError", "detail": str(exc)},
    )


@app.exception_handler(AgentAuthError)
async def agentauth_handler(request: Request, exc: AgentAuthError):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": type(exc).__name__, "detail": str(exc)},
    )


# ── Pydantic models ────────────────────────────────────────────────────────

class RegisterAgentRequest(BaseModel):
    agent_id: str
    display_name: Optional[str] = None
    owner: Optional[str] = None
    scopes_requested: List[str] = []


class IssueTokenRequest(BaseModel):
    agent_id: str
    scopes: List[str]
    ttl_seconds: int = 300
    trust_level: str = "low"
    one_time_use: bool = False


class SearchRequest(BaseModel):
    query: str


class ExecuteToolRequest(BaseModel):
    tool_name: str
    parameters: dict


# ── Health ─────────────────────────────────────────────────────────────────

@app.get("/health", tags=["Health"])
def health():
    return {"status": "healthy", "service": "agentauth-fastapi-demo"}


# ── Agents ─────────────────────────────────────────────────────────────────

@app.post("/agents/register", tags=["Agents"])
def register_agent(body: RegisterAgentRequest, db: Session = Depends(get_db)):
    """Register a new AI agent. All agents start as 'untrusted'."""
    registry = AgentRegistry(db)
    _, public_key = AgentIdentity.generate_keypair("ed25519")
    agent = AgentIdentity(
        agent_id=body.agent_id,
        display_name=body.display_name,
        owner=body.owner,
        public_key=public_key,
        scopes_requested=body.scopes_requested,
    )
    result = registry.register_agent(agent)

    audit = AuditLogger(db)
    audit.log(event_type="agent_registered", agent_id=body.agent_id, outcome="success")

    return {"registered": True, "agent": result}


@app.patch("/agents/{agent_id}/trust", tags=["Agents"])
def update_trust(agent_id: str, trust_level: str, db: Session = Depends(get_db)):
    """Update an agent's trust level: untrusted | verified | trusted."""
    registry = AgentRegistry(db)
    result = registry.trust_agent(agent_id, trust_level)
    return {"updated": True, "agent": result}


@app.delete("/agents/{agent_id}/revoke", tags=["Agents"])
def revoke_agent(agent_id: str, db: Session = Depends(get_db)):
    """Permanently revoke an agent. All future requests will be denied."""
    registry = AgentRegistry(db)
    result = registry.revoke_agent(agent_id)

    audit = AuditLogger(db)
    audit.log(event_type="agent_revoked", agent_id=agent_id, outcome="success")

    return {"revoked": True, "agent": result}


# ── Tokens ─────────────────────────────────────────────────────────────────

@app.post("/tokens/issue", tags=["Tokens"])
def issue_token(body: IssueTokenRequest, db: Session = Depends(get_db)):
    """Issue an ephemeral scoped token for an agent."""
    vault = get_vault(db)
    token = vault.issue(
        agent_id=body.agent_id,
        scopes=body.scopes,
        ttl_seconds=body.ttl_seconds,
        trust_level=body.trust_level,
        one_time_use=body.one_time_use,
    )

    audit = AuditLogger(db)
    audit.log(
        event_type="token_issued",
        agent_id=body.agent_id,
        outcome="success",
        scopes=body.scopes,
        metadata={"ttl": body.ttl_seconds, "trust_level": body.trust_level},
    )

    return {
        "token": token,
        "agent_id": body.agent_id,
        "scopes": body.scopes,
        "ttl_seconds": body.ttl_seconds,
    }


@app.get("/tokens/verify", tags=["Tokens"])
def verify_token(payload: dict = Depends(verify_bearer_token)):
    """Verify a token and return its decoded payload."""
    return {"valid": True, "payload": payload}


# ── Scopes ─────────────────────────────────────────────────────────────────

@app.post("/scopes/grant", tags=["Scopes"])
def grant_scope(
    agent_id: str,
    scope: str,
    trust_level_required: str = "low",
    db: Session = Depends(get_db),
):
    """Grant a scope to an agent."""
    sm = ScopeManager(db)
    result = sm.grant_scope(agent_id, scope, trust_level_required=trust_level_required)
    return {"granted": True, "scope": result}


@app.get("/scopes/{agent_id}", tags=["Scopes"])
def list_scopes(agent_id: str, db: Session = Depends(get_db)):
    """List all scopes granted to an agent."""
    sm = ScopeManager(db)
    return {"agent_id": agent_id, "scopes": sm.list_scopes(agent_id)}


# ── Protected resources ────────────────────────────────────────────────────

@app.post("/search", tags=["Protected"])
def search(
    body: SearchRequest,
    payload: dict = Depends(verify_bearer_token),
    db: Session = Depends(get_db),
):
    """
    Search company data. Requires: db:read scope.
    Input is inspected for prompt injection before processing.
    """
    # 1. Injection guard
    guard = get_guard(db)
    guard.inspect("search", {"query": body.query})

    # 2. Scope enforcement via context
    ctx = set_current_token(payload)
    try:
        @require_scope("db:read", trust_level="low")
        def _do_search():
            return [
                {"id": 1, "title": "AI Safety Fundamentals", "score": 0.95},
                {"id": 2, "title": "ML Engineering Best Practices", "score": 0.87},
            ]

        results = _do_search()

        # 3. Audit
        audit = AuditLogger(db)
        audit.log(
            event_type="token_used",
            agent_id=payload.get("agent_id"),
            outcome="success",
            scopes=["db:read"],
            metadata={"action": "search", "query": body.query[:50]},
        )

        return {"query": body.query, "results": results, "count": len(results)}
    finally:
        clear_current_token(ctx)


@app.post("/tools/execute", tags=["Protected"])
def execute_tool(
    body: ExecuteToolRequest,
    payload: dict = Depends(verify_bearer_token),
    db: Session = Depends(get_db),
):
    """
    Execute a tool. Requires: tools:execute scope with high trust.
    """
    guard = get_guard(db)
    guard.inspect(body.tool_name, body.parameters)

    ctx = set_current_token(payload)
    try:
        @require_scope("tools:execute", trust_level="high")
        def _run():
            return {"executed": True, "tool": body.tool_name, "params": body.parameters}

        result = _run()

        audit = AuditLogger(db)
        audit.log(
            event_type="token_used",
            agent_id=payload.get("agent_id"),
            outcome="success",
            scopes=["tools:execute"],
            metadata={"tool": body.tool_name},
        )

        return result
    finally:
        clear_current_token(ctx)


# ── Audit ──────────────────────────────────────────────────────────────────

@app.get("/audit/events", tags=["Audit"])
def get_audit_events(
    agent_id: Optional[str] = None,
    event_type: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Query the audit log with optional filters."""
    audit = AuditLogger(db)
    return {"events": audit.get_events(agent_id=agent_id, event_type=event_type)}


@app.get("/audit/verify", tags=["Audit"])
def verify_audit_chain(db: Session = Depends(get_db)):
    """Verify the audit log hash chain has not been tampered with."""
    audit = AuditLogger(db)
    try:
        audit.verify_chain()
        return {"intact": True, "message": "Audit chain verified. No tampering detected."}
    except Exception as e:
        return {"intact": False, "message": str(e)}


# ── Standalone demo ────────────────────────────────────────────────────────

def main():
    """Print integration instructions (not starting the server)."""
    print("🚀 agentauth FastAPI Integration\n")
    print("Install dependencies:")
    print("  pip install fastapi uvicorn\n")
    print("Start the server:")
    print("  uvicorn examples.fastapi_integration:app --reload\n")
    print("Open Swagger UI:")
    print("  http://localhost:8000/docs\n")
    print("Example workflow:")
    print("  1. POST /agents/register        → register your agent")
    print("  2. POST /tokens/issue           → get a scoped token")
    print("  3. POST /scopes/grant           → grant db:read to your agent")
    print("  4. POST /search                 → search (token in Authorization header)")
    print("  5. GET  /audit/events           → see all audit events")
    print("  6. GET  /audit/verify           → verify chain integrity")


if __name__ == "__main__":
    main()
