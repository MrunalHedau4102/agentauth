"""
AgentAuth — AI agent authentication, MCP server security, and per-action
authorization for the AuthLib ecosystem.
"""

__version__ = "0.1.0"
__author__ = "AuthLib Contributors"

# Exceptions
from agentauth.exceptions import (
    AgentAuthError,
    PermissionDeniedError,
    TokenExpiredError,
    InvalidTokenError,
    ScopeNotGrantedError,
    AgentNotFoundError,
    AgentRevokedError,
    TrustLevelInsufficientError,
    PromptInjectionSuspected,
    AuditChainCorruptedError,
)

# Scopes
from agentauth.scopes import (
    ScopeManager,
    require_scope,
    set_current_token,
    get_current_token,
    clear_current_token,
)

# Tokens
from agentauth.tokens import EphemeralTokenVault

# Agents
from agentauth.agents import AgentIdentity, AgentRegistry

# Audit
from agentauth.audit import AuditLogger

# Guard
from agentauth.guard import PromptInjectionGuard

# LLM Provider Support
from agentauth.llm import (
    LLMProvider,
    OpenAIProvider,
    GrokProvider,
    GroqProvider,
    ClaudeProvider,
    GeminiProvider,
    OllamaProvider,
)

__all__ = [
    # Exceptions
    "AgentAuthError",
    "PermissionDeniedError",
    "TokenExpiredError",
    "InvalidTokenError",
    "ScopeNotGrantedError",
    "AgentNotFoundError",
    "AgentRevokedError",
    "TrustLevelInsufficientError",
    "PromptInjectionSuspected",
    "AuditChainCorruptedError",
    # Scopes
    "ScopeManager",
    "require_scope",
    "set_current_token",
    "get_current_token",
    "clear_current_token",
    # Tokens
    "EphemeralTokenVault",
    # Agents
    "AgentIdentity",
    "AgentRegistry",
    # Audit
    "AuditLogger",
    # Guard
    "PromptInjectionGuard",
    # LLM Providers
    "LLMProvider",
    "OpenAIProvider",
    "GrokProvider",
    "GroqProvider",
    "ClaudeProvider",
    "GeminiProvider",
    "OllamaProvider",
]
