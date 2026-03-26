# Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    AgentAuth Library                         │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │         1. Agent Identity & Registry (A2A)          │   │
│  │                                                      │   │
│  │  • Agent registration with trust levels             │   │
│  │  • Cryptographic key pair generation (Ed25519, RSA)│   │
│  │  • Agent metadata management & revocation           │   │
│  │  • Remote agent fetching (.well-known/agent.json)  │   │
│  └──────────────────────────────────────────────────────┘   │
│                           ↓                                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │       2. Ephemeral Token Vault (JWT)                │   │
│  │                                                      │   │
│  │  • Short-lived token issuance (default 30 sec)      │   │
│  │  • HMAC-SHA256 cryptographic signing                │   │
│  │  • Token binding (URL/IP address)                   │   │
│  │  • One-time-use tracking (database backed)          │   │
│  │  • Scope & trust level embedding                    │   │
│  │  • Token expiration & verification                  │   │
│  └──────────────────────────────────────────────────────┘   │
│                           ↓                                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  3. Scope Manager & Access Control                  │   │
│  │                                                      │   │
│  │  • Per-action scope definition (db:read, etc.)      │   │
│  │  • Trust level enforcement (low/medium/high)        │   │
│  │  • Scope granting & revocation                      │   │
│  │  • @require_scope decorator for functions           │   │
│  │  • Context-aware token validation                   │   │
│  │  • Thread-safe context variables (contextvars)      │   │
│  └──────────────────────────────────────────────────────┘   │
│                           ↓                                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │    4. Prompt Injection Guard                        │   │
│  │                                                      │   │
│  │  Detection Rules:                                    │   │
│  │  • Suspicious phrase detection (case-insensitive)  │   │
│  │  • Unicode anomaly detection (zero-width, RTL)     │   │
│  │  • Field length validation (< max bytes)            │   │
│  │  • Dangerous key detection (__proto__, eval, etc.)  │   │
│  │  • Base64 payload analysis                          │   │
│  │  • Recursive structure inspection                   │   │
│  │                                                      │   │
│  │  Modes:                                              │   │
│  │  • Strict: Raises exception on detection            │   │
│  │  • Non-strict: Collects all findings                │   │
│  │  • Optional audit logging integration               │   │
│  └──────────────────────────────────────────────────────┘   │
│                           ↓                                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │     5. Audit Logger & Chain Verification           │   │
│  │                                                      │   │
│  │  Tamper-Evident Hash Chain:                         │   │
│  │  Event₀ → Hash₀ ─→ Event₁ → Hash₁ ─→ Event₂ → ... │   │
│  │                    ↑ previous_hash ↑               │   │
│  │                                                      │   │
│  │  • SHA-256 hash chaining (previous_hash field)      │   │
│  │  • Deterministic JSON serialization for hashing     │   │
│  │  • Event logging (auth, scopes, tokens, etc.)       │   │
│  │  • Event filtering (agent, type, timestamp)         │   │
│  │  • Chain corruption detection                       │   │
│  │  • Metadata & context tracking                      │   │
│  └──────────────────────────────────────────────────────┘   │
│                           ↓                                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │      6. Database Layer (SQLAlchemy ORM)            │   │
│  │                                                      │   │
│  │  Models:                                             │   │
│  │  • AgentRegistryModel — Registered agents            │   │
│  │  • AgentScopeModel — Per-agent scopes              │   │
│  │  • EphemeralTokenModel — One-time-use tracking      │   │
│  │  • AuditLogModel — Tamper-evident audit entry       │   │
│  │                                                      │   │
│  │  Supported Databases:                                │   │
│  │  • PostgreSQL (recommended)                         │   │
│  │  • MySQL/MariaDB                                    │   │
│  │  • SQLite (dev/testing)                             │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

## Data Flow

### 1. Agent Registration Flow

```
┌─────────────┐
│   Agent     │
│  Definition │
└──────┬──────┘
       │
       ├─→ Generate Ed25519/RSA keypair
       │
       ├─→ Create AgentIdentity object
       │
       └─→ AgentRegistry.register_agent()
           │
           └─→ INSERT INTO agent_registry
               (agent_id, public_key, trust_level, ...)
           │
           └─→ Return AgentRegistryModel
```

### 2. Token Issuance Flow

```
┌─────────────────────────────┐
│   Issue Token Request       │
│  (agent_id, scopes, ttl)    │
└──────────┬──────────────────┘
           │
           ├─→ EphemeralTokenVault.issue()
           │
           ├─→ Create JWT payload
           │   {
           │     "agent_id": "...",
           │     "scopes": [...],
           │     "trust_level": "...",
           │     "exp": now + ttl_seconds,
           │     "one_time_use": bool,
           │     "bound_to": optional_url
           │   }
           │
           ├─→ Sign with HMAC-SHA256
           │
           ├─→ If one_time_use:
           │   └─→ INSERT INTO ephemeral_tokens
           │       (token_signature, agent_id, is_used=false)
           │
           └─→ Return JWT token string
```

### 3. Token Verification & Scope Checking Flow

```
┌──────────────┐
│ Bearer Token │
└────────┬─────┘
         │
         ├─→ EphemeralTokenVault.verify(token)
         │
         ├─→ Decode JWT signature
         │
         ├─→ Check expiration (exp claim)
         │
         ├─→ If one_time_use:
         │   └─→ Check ephemeral_tokens table
         │       ├─→ If is_used == false: Mark as used
         │       └─→ If is_used == true: Raise InvalidTokenError
         │
         ├─→ Validate bound_to if provided
         │
         └─→ Return payload
             │
             ├─→ set_current_token(payload)
             │
             └─→ @require_scope decorator checks:
                 ├─→ Verify scope in payload["scopes"]
                 └─→ Verify trust_level >= required_level
```

### 4. Audit Logging Flow

```
┌─────────────────────────────┐
│   Security Event            │
│  (auth, token, scope, etc.) │
└──────────┬──────────────────┘
           │
           ├─→ AuditLogger.log()
           │
           ├─→ Get previous entry hash
           │   └─→ SELECT entry_hash FROM audit_log
           │       ORDER BY id DESC LIMIT 1
           │
           ├─→ Build entry content JSON
           │   {
           │     "event_id": uuid,
           │     "event_type": "...",
           │     "agent_id": "...",
           │     "timestamp": "...",
           │     "outcome": "success|failure",
           │     "previous_hash": "...",
           │     ...
           │   }
           │
           ├─→ Compute SHA-256 hash
           │
           ├─→ INSERT INTO audit_log
           │   (event_id, event_type, entry_hash, previous_hash, ...)
           │
           └─→ Return audit_log entry dict
```

### 5. Prompt Injection Guard Flow

```
┌──────────────────────────┐
│  Tool Call Arguments     │
│  (dict or nested)        │
└────────┬────────────────┘
         │
         ├─→ PromptInjectionGuard.inspect()
         │
         ├─→ _walk_and_inspect(obj, path, findings)
         │   │
         │   ├─→ If dict: Check keys for __proto__, eval, etc.
         │   │   └─→ If dangerous: Add finding
         │   │
         │   ├─→ If list: Recursively inspect each item
         │   │
         │   └─→ If string: _inspect_string()
         │       │
         │       ├─→ Check for suspicious phrases
         │       ├─→ Check for zero-width/RTL Unicode
         │       ├─→ Check field length
         │       ├─→ Check base64-encoded payloads
         │       └─→ Yield findings
         │
         ├─→ If strict mode + findings: Raise PromptInjectionSuspected
         │
         └─→ If audit_logger: Log "suspicious_activity" event
             └─→ Return findings list
```

## Component Interactions

### Example: Secure Tool Execution

```
1. User calls tool with arguments
   │
   ├─→ 2. PromptInjectionGuard.inspect(tool_name, args)
   │      └─→ REJECT if injection detected
   │
   ├─→ 3. Bearer token extraction
   │
   ├─→ 4. EphemeralTokenVault.verify(token)
   │      └─→ REJECT if expired/invalid
   │
   ├─→ 5. set_current_token(payload)
   │
   ├─→ 6. Call @require_scope("tools:execute")
   │      ├─→ Check ScopeManager
   │      └─→ REJECT if insufficient scope/trust
   │
   ├─→ 7. Execute tool function
   │
   ├─→ 8. AuditLogger.log(event_type="tool_executed", ...)
   │
   └─→ 9. clear_current_token()
```

## Trust Levels

```
┌─────────────────────────────────────────────┐
│           Trust Level Hierarchy             │
├─────────────────────────────────────────────┤
│ LOW (0)                                     │
│ • Read-only operations                      │
│ • Public data access                        │
│ • Limited tool execution                    │
│                                             │
│ MEDIUM (1)                                  │
│ • Regular write operations                  │
│ • Standard query execution                  │
│ • Moderate impact actions                   │
│                                             │
│ HIGH (2)                                    │
│ • Delete operations                         │
│ • Schema modifications                      │
│ • Critical system changes                   │
│ • Admin-level actions                       │
└─────────────────────────────────────────────┘

Requirements: high >= medium >= low
Example:
  Token with trust="medium" CAN access "high" scopes requiring trust="low|medium"
  Token with trust="low" CANNOT access "high" scopes requiring trust="medium|high"
```

## Security Properties

### 1. Token Security

- **Cryptographic Signing** — HMAC-SHA256 prevents forgery
- **Expiration** — Time-limited tokens reduce window of compromise
- **Binding** — Tokens can be bound to specific URLs/IPs
- **One-Time-Use** — Optional replay prevention via database tracking
- **Scope Embedding** — Scopes embedded in token, verified at use-time

### 2. Audit Trail Security

- **Tamper-Evident Hash Chain** — Each entry includes hash of previous entry
- **Deterministic Hashing** — Sorted JSON ensures reproducible hashes
- **No Rewriting** — Append-only design prevents retroactive changes
- **Chain Verification** — `verify_chain()` detects any tampering

```
Entry 1     Entry 2     Entry 3
┌──────┐    ┌──────┐    ┌──────┐
│prev=∅│    │prev=H1│   │prev=H2│
│H1←───┼───→│H2←───┼───→│H3←──ø
└──────┘    └──────┘    └──────┘
```

### 3. Authorization Security

- **Scope Verification** — Tokens must carry exact scope string
- **Trust Level Validation** — Hierarchical trust prevents privilege escalation
- **Context-Safe** — Thread-safe context variables prevent leakage
- **Stateless Validation** — No session state needed for verification

### 4. Injection Defense

- **Multi-Layer Detection** — 5+ independent detection rules
- **Encoding Analysis** — Detects payloads hidden in base64
- **Unicode Inspection** — Catches control characters (RTL, zero-width)
- **Structure Inspection** — Recursively checks nested data
- **Phrase Recognition** — Case-insensitive pattern matching

## Database Schema

### agent_registry
```sql
CREATE TABLE agent_registry (
  id INTEGER PRIMARY KEY,
  agent_id VARCHAR(36) UNIQUE NOT NULL,
  display_name VARCHAR(255),
  public_key TEXT,
  trust_level VARCHAR(20),        -- untrusted|verified|trusted
  metadata_url VARCHAR(2048),
  owner VARCHAR(255),
  is_revoked BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP WITH TIMEZONE,
  updated_at TIMESTAMP WITH TIMEZONE
);
```

### agent_scopes
```sql
CREATE TABLE agent_scopes (
  id INTEGER PRIMARY KEY,
  agent_id VARCHAR(36) NOT NULL,
  scope VARCHAR(255) NOT NULL,
  trust_level_required VARCHAR(20),  -- low|medium|high
  granted_at TIMESTAMP WITH TIMEZONE
);
```

### ephemeral_tokens
```sql
CREATE TABLE ephemeral_tokens (
  id INTEGER PRIMARY KEY,
  token_signature VARCHAR(255) UNIQUE NOT NULL,
  agent_id VARCHAR(36) NOT NULL,
  scopes JSON,
  is_used BOOLEAN DEFAULT FALSE,
  bound_to VARCHAR(2048),
  created_at TIMESTAMP WITH TIMEZONE,
  expires_at TIMESTAMP WITH TIMEZONE
);
```

### audit_log
```sql
CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY,
  event_id VARCHAR(36) UNIQUE NOT NULL,
  event_type VARCHAR(50) NOT NULL,
  agent_id VARCHAR(36),
  user_id INTEGER,
  timestamp TIMESTAMP WITH TIMEZONE,
  ip_address VARCHAR(45),
  scopes_involved JSON,
  outcome VARCHAR(20),              -- success|failure
  metadata_json JSON,
  previous_hash VARCHAR(64),         -- SHA-256 of prev entry
  entry_hash VARCHAR(64) NOT NULL    -- SHA-256 of this entry
);
```

## Performance Considerations

### Token Verification: O(1)
- JWT decode: O(1)
- One-time-use check: O(1) via unique index on token_signature
- No database query for normal verification (unless one_time_use)

### Scope Checking: O(n) where n = scope count
- Linear scan of token scopes
- Typically small (2-5 scopes per agent)

### Audit Query: O(m) where m = matching events
- Indexed on: agent_id, event_type, timestamp
- Range queries on timestamp are efficient

### Audit Chain Verification: O(k) where k = total events
- Must recompute all hashes (security requirement)
- Use periodically or incrementally

## Scalability

### Single-Node
- SQLite: 1K agents, 100K events
- PostgreSQL: 1M agents, 10M events, sub-second queries

### Distributed (PostgreSQL)
- Multiple API servers → single database
- Audit logging is write-heavy; use WAL replication
- No distributed transactions needed (append-only)

### Caching Strategy
- Cache agent registry (24hr TTL)
- Cache scopes per agent (1hr TTL)
- Never cache tokens or audit logs

---

**Architecture Version**: 1.0.0
**Last Updated**: March 26, 2026
