# Security Policy

## Reporting a Security Vulnerability

If you discover a security vulnerability in AgentAuth, please **do not** create a public GitHub issue. Instead, please follow responsible disclosure practices.

### How to Report

1. **Email**: Send a detailed report to **mrunalh1234@gmail.com**
2. **Include**:
   - Description of the vulnerability
   - Affected versions
   - Proof of concept (if possible)
   - Suggested fix (if you have one)
   - Your contact information

3. **Timeframe**: You will receive acknowledgment within **48 hours**

### What Happens Next

- We will investigate and confirm the vulnerability
- We will develop a fix and publish a security advisory
- A patched version will be released
- You will be credited in the security advisory (unless you prefer anonymity)

### Security Advisory Process

1. **Assessment** — We evaluate severity and impact
2. **Fix Development** — We create patches for affected versions
3. **Testing** — Comprehensive testing of the patch
4. **Release** — Patched versions published to PyPI with advisory
5. **Announcement** — GitHub security advisory published after coordinated disclosure

### Supported Versions

| Version | Security Fixes | Patch Support |
|---------|---|---|
| 1.x     | ✅ Yes | Until next major release or 2 years |
| 0.1.x   | ⚠️ Limited | Until 1.0 release |

## Security Best Practices

### For Library Users

1. **Always use HTTPS** for agent metadata URLs
2. **Rotate secrets regularly** — Change `AGENTAUTH_SECRET_KEY` periodically
3. **Use strong secrets** — Minimum 32 characters, cryptographically random
4. **Enable audit logging** — Always log security events
5. **Verify chains regularly** — Call `audit.verify_chain()` periodically
6. **Use trust levels** — Enforce higher trust levels for critical operations
7. **Monitor audit events** — Set up alerts for suspicious activity

### Database Security

```python
# ✅ DO: Use environment variables for secrets
import os
DATABASE_URL = os.getenv("DATABASE_URL")

# ❌ DON'T: Hardcode credentials
DATABASE_URL = "postgresql://user:password@localhost/db"
```

### Token Management

```python
# ✅ DO: Use ephemeral tokens with short TTL
token = vault.issue(
    agent_id="agent-1",
    ttl_seconds=300,  # 5 minutes
    one_time_use=True
)

# ❌ DON'T: Issue long-lived tokens
token = vault.issue(agent_id="agent-1", ttl_seconds=86400)  # 24 hours
```

### Prompt Injection Defense

```python
# ✅ DO: Always inspect inputs
guard = PromptInjectionGuard(strict=True, audit_logger=audit)
try:
    guard.inspect("api_call", user_input)
except PromptInjectionSuspected as e:
    # Log and reject
    audit.log(event_type="injection_attempt", outcome="failure")
    return {"error": "Invalid input"}

# ❌ DON'T: Skip validation
execute_tool(user_input)  # Dangerous!
```

### Key Rotation

```python
# Periodically rotate your signing secret
import secrets
import os

new_secret = secrets.token_urlsafe(32)
os.environ["AGENTAUTH_SECRET_KEY"] = new_secret
# Store securely (AWS Secrets Manager, HashiCorp Vault, etc.)
```

## Threat Model

### Threats We Protect Against

1. **Token Forgery** — Cryptographic signing prevents token tampering
2. **Privilege Escalation** — Trust levels enforce authorization hierarchy
3. **Replay Attacks** — One-time-use tokens and TTL prevent reuse
4. **Audit Tampering** — Hash chain makes log alterations detectable
5. **Prompt Injection** — Multi-layer guards detect malicious inputs
6. **Token Theft** — Token binding limits scope of compromised tokens
7. **Agent Impersonation** — Registry and revocation prevent unauthorized agents

### Threats We Don't Address

- **Network Security** — Use TLS/HTTPS for all communication
- **Secret Storage** — Use OS-level secret management
- **Physical Security** — Secure your infrastructure
- **Social Engineering** — Train users on security practices

## Security Advisories

### Current Advisories
None at this time.

### Past Advisories
None — this is the first production release.

## Contributing Security Fixes

If you want to contribute a security fix:

1. **Don't** create a public PR for a security vulnerability
2. **Email** mrunalh1234@gmail.com with details
3. We'll work with you confidentially
4. You'll be credited when the fix is published

## Cryptographic Standards

### Algorithms Used

| Purpose | Algorithm | Details |
|---------|-----------|---------|
| Token Signing | HS256 (HMAC-SHA256) | PyJWT library |
| Key Generation | Ed25519, RSA-2048 | Cryptography library |
| Audit Hash | SHA-256 | Python hashlib |
| Password Hashing | bcrypt | 12 rounds default |

### Compliance

- ✅ FIPS 140-2 compatible (NIST approved algorithms)
- ✅ No deprecated algorithms
- ✅ Key sizes meet current standards
- ✅ Uses constant-time comparisons where needed

## Dependency Security

We use minimal dependencies and regularly audit them:

```
sqlalchemy>=2.0.0          — Database ORM
PyJWT>=2.8.0              — Token signing
bcrypt>=4.1.0             — Password hashing
pydantic>=2.5.0           — Data validation
python-dotenv>=1.0.0      — Configuration
cryptography>=42.0.0      — Cryptographic primitives
```

All dependencies:
- Are actively maintained
- Have good security track records
- Use semantic versioning
- Are regularly updated

## Security Release Process

### Timeline
- **Critical** (0-day, active exploits): Patch within 24 hours
- **High** (significant impact): Patch within 7 days
- **Medium**: Included in next regular release
- **Low**: Included in next regular release

### Notification
Security advisories are announced via:
- GitHub Security Advisory
- Email to users (if possible)
- Changelog entry
- Release notes

## Contact

- **Email**: mrunalh1234@gmail.com
- **PGP Key**: [Available on request]
- **Response Time**: 48 hours

## Additional Resources

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)

---

**Last Updated**: March 12, 2026
**Status**: Active
