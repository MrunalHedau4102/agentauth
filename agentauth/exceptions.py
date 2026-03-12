"""Custom exception classes for AgentAuth."""


class AgentAuthError(Exception):
    """Base exception for agent authentication errors."""

    def __init__(self, message: str, status_code: int = 400) -> None:
        """
        Initialize AgentAuthError.

        Args:
            message: Error message
            status_code: HTTP status code
        """
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


class PermissionDeniedError(AgentAuthError):
    """Raised when an action is denied due to insufficient permissions."""

    def __init__(self, message: str = "Permission denied") -> None:
        super().__init__(message, status_code=403)


class TokenExpiredError(AgentAuthError):
    """Raised when an ephemeral token has expired."""

    def __init__(self, message: str = "Token has expired") -> None:
        super().__init__(message, status_code=401)


class InvalidTokenError(AgentAuthError):
    """Raised when a token is invalid or malformed."""

    def __init__(self, message: str = "Invalid or malformed token") -> None:
        super().__init__(message, status_code=401)


class ScopeNotGrantedError(AgentAuthError):
    """Raised when the required scope is not granted to the agent."""

    def __init__(self, message: str = "Required scope not granted") -> None:
        super().__init__(message, status_code=403)


class AgentNotFoundError(AgentAuthError):
    """Raised when an agent is not found in the registry."""

    def __init__(self, message: str = "Agent not found") -> None:
        super().__init__(message, status_code=404)


class AgentRevokedError(AgentAuthError):
    """Raised when an agent has been revoked."""

    def __init__(self, message: str = "Agent has been revoked") -> None:
        super().__init__(message, status_code=403)


class TrustLevelInsufficientError(AgentAuthError):
    """Raised when an agent's trust level is insufficient for the operation."""

    def __init__(self, message: str = "Trust level insufficient") -> None:
        super().__init__(message, status_code=403)


class PromptInjectionSuspected(AgentAuthError):
    """Raised when a prompt injection attempt is detected."""

    def __init__(self, message: str = "Prompt injection suspected") -> None:
        super().__init__(message, status_code=400)


class AuditChainCorruptedError(AgentAuthError):
    """Raised when the audit log hash chain is corrupted."""

    def __init__(self, message: str = "Audit chain integrity compromised") -> None:
        super().__init__(message, status_code=500)
