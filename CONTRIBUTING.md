# How to Contribute to AgentAuth

Thank you for your interest in contributing to AgentAuth! We welcome contributions from everyone, whether it's code improvements, documentation, bug reports, or feature requests.

## Code of Conduct

Please read and follow our [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) to keep our community welcoming and respectful.

## Getting Started

### Prerequisites
- Python 3.10+
- Git
- PostgreSQL or SQLite (for development)

### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/MrunalHedau4102/agent-auth.git
cd agent-auth

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies with dev extras
pip install -e ".[dev]"

# Copy environment template
cp .env.example .env
# Edit .env with your local database credentials
```

### Run Tests Locally

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=agentauth --cov-report=html
open htmlcov/index.html  # View coverage report

# Run type checking
mypy agentauth/ --ignore-missing-imports

# Run linting
flake8 agentauth/ tests/ --max-line-length=88 --max-complexity=10

# Format code
black agentauth/ tests/
isort agentauth/ tests/
```

## Making Changes

### Branch Naming Convention

```
feature/description         # New features
bugfix/description          # Bug fixes
docs/description            # Documentation only
refactor/description        # Code refactoring
```

### Commit Message Format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): description

body (optional, wrap at 72 chars)

footer (optional): references #123
```

**Types:**
- `feat` — New feature
- `fix` — Bug fix
- `docs` — Documentation changes
- `refactor` — Code refactoring without feature changes
- `test` — Test additions or updates
- `perf` — Performance improvements
- `ci` — CI/CD configuration changes
- `chore` — Dependency updates, maintainence

**Examples:**
```
feat(tokens): add token binding to IP addresses
fix(guard): correct unicode detection for RTL override
docs(readme): add quickstart examples
test(audit): add chain corruption detection tests
```

## Contribution Types

### 🐛 Bug Reports

Before submitting, check if the issue already exists. Include:

1. **Description** — Clear, concise summary
2. **Reproduction** — Steps to reproduce the issue
3. **Expected behavior** — What should happen
4. **Actual behavior** — What actually happens
5. **Environment** — Python version, OS, dependencies
6. **Screenshots** — If applicable

### 🎯 Feature Requests

1. **Use case** — Why is this feature needed?
2. **Proposed solution** — How should it work?
3. **Alternatives** — Any alternatives you've considered?
4. **Examples** — Code examples of desired usage

### 📝 Code Contributions

#### Before You Start

1. Ensure no existing PR already addresses the issue
2. Comment on the issue to avoid duplicate work
3. For large changes, open a discussion first

#### Pull Request Process

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/my-feature`
3. **Make changes** following coding standards (see below)
4. **Add tests** for any new functionality
5. **Update docs** if behavior changes
6. **Commit** with clear, conventional commit messages
7. **Push** to your fork
8. **Open PR** with clear title and description

#### PR Description Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Related Issue
Closes #123

## Testing
- [ ] Unit tests added
- [ ] Integration tests added
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Tests pass locally
- [ ] Documentation updated
- [ ] Commit messages are clear
- [ ] No breaking changes (if not intentional)
```

### 📚 Documentation Contributions

Documentation improvements are always welcome!

```bash
# Preview markdown locally
pip install mkdocs
mkdocs serve  # http://localhost:8000
```

## Coding Standards

### Python Style Guide

We follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) with:

- Line length: **88 characters** (Black formatter)
- Imports: Organized with **isort**
- Type hints: **Required** for function signatures
- Docstrings: **Google-style**, present for all public APIs

### Code Quality Tools

These run automatically on commit via pre-commit hooks:

```bash
# Install pre-commit hooks
pre-commit install

# Run manually
black agentauth/ tests/
isort agentauth/ tests/
mypy agentauth/
flake8 agentauth/ tests/
```

### Example Function

```python
def grant_scope(
    self,
    agent_id: str,
    scope: str,
    trust_level_required: str = "low",
) -> Dict[str, Any]:
    """
    Grant a scope to an agent.

    Args:
        agent_id: UUID of the agent
        scope: Scope string (e.g., "db:read")
        trust_level_required: Minimum trust level for this scope

    Returns:
        Dictionary representation of the created scope record

    Raises:
        ValueError: If trust_level_required is invalid
        SQLAlchemyError: If database operation fails

    Example:
        >>> manager = ScopeManager(session)
        >>> result = manager.grant_scope(
        ...     "agent-1",
        ...     "db:read",
        ...     trust_level_required="low"
        ... )
        >>> print(result["scope"])
        db:read
    """
    if trust_level_required not in TRUST_LEVELS:
        raise ValueError(
            f"Invalid trust level: {trust_level_required}. "
            f"Must be one of: {list(TRUST_LEVELS.keys())}"
        )
    # ... implementation
```

## Testing Guidelines

### Test Structure

```python
class TestFeatureName:
    """Test cases for FeatureName."""

    def test_happy_path(self, agentauth_session):
        """Test successful operation."""
        # Arrange
        manager = ScopeManager(agentauth_session)
        
        # Act
        result = manager.grant_scope("agent-1", "db:read")
        
        # Assert
        assert result["scope"] == "db:read"

    def test_error_case(self, agentauth_session):
        """Test error handling."""
        manager = ScopeManager(agentauth_session)
        
        with pytest.raises(ValueError, match="Invalid trust level"):
            manager.grant_scope("agent-1", "db:read", trust_level_required="invalid")
```

### Coverage Requirements

- **New code must have >90% test coverage**
- **Bug fixes should include regression tests**
- **Existing tests should not be removed without justification**

### Running Tests

```bash
# Run tests with coverage report
pytest tests/ --cov=agentauth --cov-report=term-missing

# Run specific test
pytest tests/test_agents.py::TestAgentIdentity::test_create_identity -v

# Run with verbose output
pytest -vv --tb=short

# Run and stop on first failure
pytest -x
```

## Documentation Style

### README Sections

1. **Introduction** — What is it?
2. **Features** — Key capabilities
3. **Installation** — How to install
4. **Quick Start** — Minimal working example
5. **Architecture** — System design
6. **API Reference** — Detailed API docs
7. **Examples** — Real-world usage
8. **Troubleshooting** — Common issues

### API Documentation

```python
def method_name(param1: str, param2: int = 5) -> str:
    """
    One-line summary.

    Longer description that explains the method's
    purpose, behavior, and any special considerations.

    Args:
        param1: Description of param1
        param2: Description of param2 (default: 5)

    Returns:
        Description of return value

    Raises:
        ValueError: When param1 is empty
        TypeError: When param2 is not an integer

    Example:
        >>> result = method_name("test", param2=10)
        >>> print(result)
        test-10
    """
```

## Release Process

1. **Update version** in `agentauth/__init__.py` and `pyproject.toml`
2. **Update** [CHANGELOG.md](CHANGELOG.md) with changes
3. **Create tag**: `git tag v1.0.0`
4. **Push tag**: `git push origin v1.0.0`
5. **GitHub Actions** automatically publishes to PyPI

## Community

- **Discussions**: [GitHub Discussions](https://github.com/MrunalHedau4102/agentauth/discussions)
- **Issues**: [GitHub Issues](https://github.com/MrunalHedau4102/agentauth/issues)
- **Email**: support@authlib.dev

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).

## Recognition

Contributors are recognized in:
- [CONTRIBUTORS.md](CONTRIBUTORS.md)
- GitHub contributors graph
- Release changelogs

---

Thank you for helping make AgentAuth better! 🙏
