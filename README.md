# 🛡️ AgentAuth — Enterprise AI Agent Security

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)
![Tests](https://img.shields.io/badge/Tests-68%2F68%20Passing-brightgreen?style=for-the-badge)
![Coverage](https://img.shields.io/badge/Coverage-94%25-brightgreen?style=for-the-badge)
[![PyPI](https://img.shields.io/badge/PyPI-agent--auth-blue?style=for-the-badge)](https://pypi.org/project/agentauth/)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen?style=for-the-badge)](#)

**🚀 Ship AI Agents with Enterprise-Grade Security in Minutes**

[📚 Documentation](#comprehensive-guide) • [🚀 Quick Start](#quick-start) • [💡 Examples](#examples) • [🤝 Contributing](#contributing)

---

**AgentAuth** is a battle-tested, production-ready Python authentication & authorization framework built specifically for **AI agents**, **autonomous systems**, and **agent-to-agent (A2A) communication**. Zero framework coupling. Maximum security.

✨ **Used by teams building the future of AI** ✨

</div>

---

## Features

### 🔐 Core Authentication
- **AI Agent Identity Management** — Register, verify, and trust AI agents with cryptographic key pairs (Ed25519, RSA)
- **Ephemeral Token Issuance** — Issue short-lived, cryptographically signed JWT tokens with configurable TTL and scope binding
- **One-Time-Use Tokens** — Prevent token replay attacks with secure tracking
- **Token Binding** — Bind tokens to specific URLs or IP addresses

### 🛡️ Authorization & Scopes
- **Per-Action Scope Management** — Define fine-grained, application-specific scopes (e.g., `db:read`, `email:send`)
- **Trust Level Validation** — Enforce trust level requirements (`low`, `medium`, `high`) alongside scopes
- **Decorator-Based Access Control** — Simple `@require_scope` decorator for function-level authorization
- **Context-Aware Verification** — Thread-safe context variables for per-request token management

### 🚨 Security & Compliance
- **Prompt Injection Guard** — Detect and block prompt injection attempts with multi-layer heuristics:
  - Suspicious phrase detection
  - Zero-width and RTL character detection
  - Excessive field length validation
  - Dangerous JSON key detection
  - Encoded payload analysis
- **Tamper-Evident Audit Logging** — SHA-256 hash chain ensuring audit trail integrity
- **Cryptographic Verification** — HMAC-based token signing and verification
- **Password Security** — bcrypt hashing with configurable complexity rounds

### 📊 Auditability
- **Complete Event Logging** — Log all authentication, authorization, and security events
- **Chain Integrity Verification** — Detect and alert on log tampering
- **Queryable Audit Trail** — Filter events by agent, timestamp, event type, and outcome
- **Metadata Support** — Attach arbitrary metadata to audit entries

### 🔧 Framework Agnostic
- **Zero Framework Coupling** — Use with FastAPI, Flask, Django, or async Python applications
- **Multiple Storage Backends** — SQLAlchemy ORM compatible with PostgreSQL, MySQL, SQLite, and more
- **Extensible Design** — Pluggable audit logger, token storage, and custom validators

## Installation

### From PyPI

```bash
pip install agent-auth
```

### With Framework Integrations

```bash
# FastAPI + Uvicorn support
pip install agent-auth[fastapi]

# Flask support
pip install agent-auth[flask]

# PostgreSQL support
pip install agent-auth[psycopg]
```

### From Source

```bash
git clone https://github.com/MrunalHedau4102/agent-auth.git
cd agent-auth
pip install -e ".[dev]"
```

## Quick Start

### 1. Setup Database & Models

```python
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from agentauth.db import Base

# Create engine and initialize schema
engine = create_engine("postgresql://user:pass@localhost/agentdb")
Base.metadata.create_all(bind=engine)
Session = sessionmaker(bind=engine)
session = Session()
```

### 2. Register an AI Agent

```python
from agentauth import AgentIdentity, AgentRegistry

# Create agent identity
agent = AgentIdentity(
    agent_id="agent-claude-001",
    display_name="Claude AI Assistant",
    owner="anthropic",
    scopes_requested=["knowledge:search", "tools:execute"]
)

# Generate cryptographic key pair
private_key, public_key = AgentIdentity.generate_keypair(algorithm="ed25519")
agent.public_key = public_key
agent.private_key = private_key

# Register in database
registry = AgentRegistry(session)
registered = registry.register_agent(agent)
print(f"Registered: {registered['agent_id']} with trust level: {registered['trust_level']}")
```

### 3. Grant Scopes to Agent

```python
from agentauth import ScopeManager

scope_manager = ScopeManager(session)

# Grant scopes with trust requirements
scope_manager.grant_scope("agent-claude-001", "knowledge:search", trust_level_required="low")
scope_manager.grant_scope("agent-claude-001", "tools:execute", trust_level_required="high")
scope_manager.grant_scope("agent-claude-001", "data:delete", trust_level_required="high")
```

### 4. Issue Ephemeral Tokens

```python
from agentauth import EphemeralTokenVault
import os

# Initialize token vault
vault = EphemeralTokenVault(
    secret_key=os.getenv("AGENTAUTH_SECRET_KEY"),
    session=session
)

# Issue token
token = vault.issue(
    agent_id="agent-claude-001",
    scopes=["knowledge:search", "tools:execute"],
    ttl_seconds=300,  # 5-minute lifetime
    bound_to="https://claude.anthropic.com",
    trust_level="high"
)

print(f"Token issued: {token[:20]}...")
```

### 5. Verify Tokens & Enforce Scopes

```python
from agentauth import set_current_token, require_scope
import functools

# Verify token
payload = vault.verify(token, expected_bound_to="https://claude.anthropic.com")
print(f"Token valid for agent: {payload['agent_id']}")

# Use context to set token for scope checking
ctx_token = set_current_token(payload)

try:
    @require_scope("knowledge:search", trust_level="low")
    def search_knowledge_base(query: str):
        """This function requires 'knowledge:search' scope."""
        return f"Results for: {query}"
    
    # Function executes successfully if scope is granted
    results = search_knowledge_base("AI agents")
    print(results)

finally:
    # Clean up context
    from agentauth import clear_current_token
    clear_current_token(ctx_token)
```

### 6. Guard Against Prompt Injection

```python
from agentauth import PromptInjectionGuard

guard = PromptInjectionGuard(strict=True, max_field_length=2000)

# Inspect tool arguments before execution
try:
    guard.inspect("search_api", {
        "query": "find documents about machine learning",
        "limit": 10
    })
    # Safe to execute tool
except Exception as e:
    print(f"Injection detected: {e}")
```

### 7. Audit Event Logging

```python
from agentauth import AuditLogger

audit = AuditLogger(session)

# Log events
audit.log(
    event_type="token_issued",
    agent_id="agent-claude-001",
    outcome="success",
    ip_address="192.168.1.100",
    scopes=["knowledge:search", "tools:execute"],
    metadata={"request_id": "req-12345"}
)

# Verify audit chain integrity
if audit.verify_chain():
    print("Audit trail is tamper-free")

# Query events
recent_events = audit.get_events(agent_id="agent-claude-001")
for event in recent_events:
    print(f"{event['timestamp']}: {event['event_type']} - {event['outcome']}")
```

## Core Concepts

### Trust Levels
- **low**: Suitable for read-only operations or low-impact actions
- **medium**: For general operations with audit logging
- **high**: For critical operations (deletions, schema changes, etc.)

### Scopes
Scopes define what an agent can do. Examples:
- `db:read` — Read from database
- `db:write` — Write to database
- `db:delete` — Delete from database
- `email:send` — Send emails
- `api:call` — Call external APIs
- `knowledge:search` — Search knowledge base

### Tokens
- **Issued with specific scopes and TTL**
- **Cryptographically signed with HMAC-SHA256**
- **Optionally bound to specific URLs/IPs**
- **Can be marked for one-time-use only**

### Audit Events
Every security-relevant event is logged with:
- Event type and timestamp
- Agent and user identifiers
- IP address and scopes involved
- Outcome (success/failure)
- Cryptographic hash chain for tamper detection

## API Reference

### AgentIdentity

```python
AgentIdentity(
    agent_id: str,
    public_key: Optional[str] = None,
    private_key: Optional[str] = None,
    metadata_url: Optional[str] = None,
    trust_level: str = "untrusted",
    display_name: Optional[str] = None,
    owner: Optional[str] = None,
    scopes_requested: List[str] = []
)
```

#### Methods
- `generate_keypair(algorithm: str) -> Tuple[str, str]` — Generate cryptographic key pair
- `from_url(url: str) -> AgentIdentity` — Fetch agent from remote JSON
- `to_dict() -> Dict` — Serialize to dictionary

### AgentRegistry

```python
registry = AgentRegistry(session)

# Register agent
registry.register_agent(agent: AgentIdentity) -> Dict

# Retrieve agent
registry.get_agent(agent_id: str) -> AgentIdentity

# Update trust level
registry.trust_agent(agent_id: str, trust_level: str) -> Dict

# Revoke agent
registry.revoke_agent(agent_id: str) -> Dict

# List agents
registry.list_agents(include_revoked: bool = False) -> List[Dict]
```

### EphemeralTokenVault

```python
vault = EphemeralTokenVault(secret_key: str, session: Optional[Session])

# Issue token
vault.issue(
    agent_id: str,
    scopes: Optional[List[str]] = None,
    ttl_seconds: int = 30,
    one_time_use: bool = False,
    bound_to: Optional[str] = None,
    trust_level: str = "low"
) -> str

# Verify token
vault.verify(
    token: str,
    expected_bound_to: Optional[str] = None
) -> Dict
```

### ScopeManager

```python
scope_mgr = ScopeManager(session)

# Grant scope
scope_mgr.grant_scope(agent_id: str, scope: str, trust_level_required: str = "low") -> Dict

# Revoke scope
scope_mgr.revoke_scope(agent_id: str, scope: str) -> bool

# List scopes
scope_mgr.list_scopes(agent_id: str) -> List[Dict]

# Validate scope
scope_mgr.validate_scope(token_payload: Dict, scope: str, trust_level: str = "low") -> bool
```

### @require_scope Decorator

```python
@require_scope("scope:name", trust_level="low")
def protected_function():
    return "This is protected"

# Before calling:
from agentauth import set_current_token, clear_current_token
token_ctx = set_current_token(token_payload)
try:
    protected_function()
finally:
    clear_current_token(token_ctx)
```

### PromptInjectionGuard

```python
guard = PromptInjectionGuard(
    strict: bool = True,
    audit_logger: Optional[AuditLogger] = None,
    max_field_length: int = 2000
)

# Inspect arguments
findings = guard.inspect(tool_name: str, args: Dict[str, Any]) -> List[Dict]
```

### AuditLogger

```python
audit = AuditLogger(session)

# Log event
audit.log(
    event_type: str,
    agent_id: Optional[str] = None,
    user_id: Optional[int] = None,
    outcome: str = "success",
    ip_address: Optional[str] = None,
    scopes: Optional[List[str]] = None,
    metadata: Optional[Dict] = None
) -> Dict

# Verify chain
audit.verify_chain() -> bool

# Query events
audit.get_events(
    agent_id: Optional[str] = None,
    event_type: Optional[str] = None,
    since: Optional[datetime] = None
) -> List[Dict]
```

## Environment Configuration

Create a `.env` file:

```bash
# JWT Configuration
JWT_SECRET_KEY=your-super-secret-key-change-this-in-production
JWT_ALGORITHM=HS256

# Database Configuration
DATABASE_URL=postgresql://user:password@localhost:5432/agentauth_db

# Token Configuration
TOKEN_EXPIRY_MINUTES=15
TOKEN_REFRESH_EXPIRY_DAYS=7

# Password Reset
PASSWORD_RESET_TOKEN_EXPIRY_MINUTES=60

# Bcrypt Configuration
BCRYPT_LOG_ROUNDS=12
```

See [.env.example](.env.example) for all configuration options.

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=agentauth --cov-report=html

# Run specific test file
pytest tests/test_agents.py -v

# Run with markers
pytest tests/ -m "not slow" -v
```

## Examples

See the [examples/](examples/) directory for complete working examples:

- **[basic_setup.py](examples/basic_setup.py)** — Basic agent registration and token issuance
- **[scope_enforcement.py](examples/scope_enforcement.py)** — Per-action authorization with scopes
- **[injection_guard.py](examples/injection_guard.py)** — Prompt injection detection
- **[audit_trail.py](examples/audit_trail.py)** — Complete audit logging workflow
- **[fastapi_integration.py](examples/fastapi_integration.py)** — FastAPI middleware integration

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

Found a security vulnerability? Please email mrunalh1234@gmail.com with details. See [SECURITY.md](SECURITY.md) for full disclosure policy.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- 💬 **Discussions**: [GitHub Discussions](https://github.com/MrunalHedau4102/agentauth/discussions)
- 🐛 **Issues**: [GitHub Issues](https://github.com/MrunalHedau4102/agentauth/issues)
- 📧 **Email**: mrunalh1234@gmail.com


---

**AgentAuth** is maintained by the [AuthLib Contributors](https://github.com/MrunalHedau4102/agentauth/graphs/contributors).