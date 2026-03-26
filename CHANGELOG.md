# Changelog

All notable changes to AgentAuth will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-03-26

### Added
- **Agent Identity Management** — Register and manage AI agents with Ed25519/RSA key pairs
- **Ephemeral Token Vault** — Issue short-lived JWT tokens with configurable TTL, scope binding, and one-time-use tracking
- **Scope Manager** — Fine-grained per-action authorization with trust level requirements
- **@require_scope Decorator** — Function-level access control with automatic token validation
- **Prompt Injection Guard** — Multi-layer detection of injection attempts:
  - Suspicious phrase detection (case-insensitive)
  - Unicode anomaly detection (zero-width, RTL override)
  - Field length validation
  - Dangerous JSON key detection
  - Base64 payload analysis
- **Audit Logger** — Tamper-evident cryptographic audit trail with SHA-256 hash chaining
- **Database Models** — SQLAlchemy ORM models for agents, scopes, tokens, and audit logs
- **Exception Hierarchy** — 10 custom exception types for precise error handling
- **Environment Configuration** — dotenv support for configuration management
- **Comprehensive Test Suite** — 50+ unit tests with 90%+ coverage
- **GitHub Actions Workflows** — Automated testing and PyPI publishing

### Features
- ✅ Framework-agnostic (FastAPI, Flask, async-compatible)
- ✅ Multi-database support (PostgreSQL, MySQL, SQLite)
- ✅ Context-aware token management with thread safety
- ✅ Queryable audit events with filtering
- ✅ Complete API documentation
- ✅ Quick start examples
- ✅ Production-ready security practices

### Documentation
- Complete README with quick start and architecture diagram
- API reference for all functions and classes
- Contributing guidelines (CONTRIBUTING.md)
- Security policy (SECURITY.md)
- Code of conduct (CODE_OF_CONDUCT.md)
- 5 runnable example scripts


## Version History

### Version Format
```
[Version Number] - [Release Date]

### Added
- New features

### Changed
- Modified features
- Breaking changes

### Fixed
- Bug fixes

### Deprecated
- Deprecated features

### Removed
- Removed features

### Security
- Security fixes
```

## Planned Releases

### [1.1.0] - Expected Q2 2026
- [ ] OpenID Connect provider support
- [ ] Refresh token rotation mechanism
- [ ] Multi-factor authentication hooks
- [ ] Rate limiting decorators
- [ ] Metrics/prometheus integration

### [1.2.0] - Expected Q3 2026
- [ ] Token revocation lists (TRL)
- [ ] Distributed cache support (Redis)
- [ ] Dashboard for agent management
- [ ] GraphQL mutation helpers
- [ ] Performance optimizations

### [2.0.0] - Expected Q4 2026
- [ ] Breaking changes if required
- [ ] New architecture components
- [ ] Enhanced cryptography options


## How to Report Security Issues

See [SECURITY.md](SECURITY.md) for responsible disclosure guidelines.

## Credits

AgentAuth is developed and maintained by the AuthLib Contributors.

---

**Latest Version**: 1.0.0 (March 12, 2026)

For more information, visit [GitHub](https://github.com/MrunalHedau4102/agentauth)
