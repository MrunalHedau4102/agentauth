"""Per-action scoped authorization for AI agents."""

import contextvars
import functools
from typing import Optional, List, Dict, Any, Callable

from sqlalchemy import func, inspect
from sqlalchemy.orm import Session

import logging
logger = logging.getLogger("agentauth.scopes")
from sqlalchemy.exc import SQLAlchemyError

from agentauth.db.models import AgentScopeModel
from agentauth.exceptions import (
    PermissionDeniedError,
    ScopeNotGrantedError,
    TrustLevelInsufficientError,
)

# Context variable holding the current token payload for scope checks.
# Must be set before calling a @require_scope-decorated function.
_current_token_ctx: contextvars.ContextVar[Optional[Dict[str, Any]]] = (
    contextvars.ContextVar("_current_token_ctx", default=None)
)

# Trust level ordering
TRUST_LEVELS = {"low": 0, "medium": 1, "high": 2}


def set_current_token(payload: Dict[str, Any]) -> contextvars.Token:
    """
    Set the current token payload in the context for scope verification.

    Args:
        payload: Decoded token payload dict. Must contain 'scopes' (list)
                 and optionally 'trust_level' (str).

    Returns:
        A contextvars.Token that can be used to reset the value.
    """
    return _current_token_ctx.set(payload)


def get_current_token() -> Optional[Dict[str, Any]]:
    """
    Get the current token payload from context.

    Returns:
        The current token payload dict, or None.
    """
    return _current_token_ctx.get()


def clear_current_token(token: contextvars.Token) -> None:
    """
    Reset the current token context to its previous value.

    Args:
        token: The contextvars.Token returned by set_current_token.
    """
    _current_token_ctx.reset(token)


class ScopeManager:
    """Manages per-agent scopes stored in the database."""

    def __init__(self, session: Session) -> None:
        """
        Initialize ScopeManager.

        Args:
            session: SQLAlchemy database session
        """
        self.session = session

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
            scope: Scope string (e.g. "db:read")
            trust_level_required: Minimum trust level for this scope

        Returns:
            Dictionary representation of the created scope record

        Raises:
            ValueError: If trust_level_required is invalid
        """
        if trust_level_required not in TRUST_LEVELS:
            raise ValueError(
                f"Invalid trust level: {trust_level_required}. "
                f"Must be one of: {list(TRUST_LEVELS.keys())}"
            )

        # Check for duplicate
        existing = (
            self.session.query(AgentScopeModel)
            .filter(
                AgentScopeModel.agent_id == agent_id,
                AgentScopeModel.scope == scope,
            )
            .first()
        )
        if existing:
            # Update trust level if already granted
            existing.trust_level_required = trust_level_required
            self.session.commit()
            self.session.refresh(existing)
            return existing.to_dict()

        scope_record = AgentScopeModel(
            agent_id=agent_id,
            scope=scope,
            trust_level_required=trust_level_required,
        )
        self.session.add(scope_record)
        self.session.commit()
        self.session.refresh(scope_record)
        logger.debug("Scope granted: agent=%s scope=%s trust_required=%s", agent_id, scope, trust_level_required)
        return scope_record.to_dict()

    def revoke_scope(self, agent_id: str, scope: str) -> bool:
        """
        Revoke a scope from an agent.

        Args:
            agent_id: UUID of the agent
            scope: Scope string to revoke

        Returns:
            True if scope was revoked, False if not found
        """
        record = (
            self.session.query(AgentScopeModel)
            .filter(
                AgentScopeModel.agent_id == agent_id,
                AgentScopeModel.scope == scope,
            )
            .first()
        )
        if not record:
            return False

        self.session.delete(record)
        self.session.commit()
        logger.debug("Scope revoked: agent=%s scope=%s", agent_id, scope)
        return True

    def list_scopes(self, agent_id: str) -> List[Dict[str, Any]]:
        """
        List all scopes granted to an agent.

        Args:
            agent_id: UUID of the agent

        Returns:
            List of scope dictionaries
        """
        records = (
            self.session.query(AgentScopeModel)
            .filter(AgentScopeModel.agent_id == agent_id)
            .all()
        )
        return [r.to_dict() for r in records]

    def validate_scope(
        self,
        token_payload: Dict[str, Any],
        scope: str,
        trust_level: str = "low",
    ) -> bool:
        """
        Check whether a token payload carries the required scope and trust level.

        Args:
            token_payload: Decoded token payload with 'scopes' key
            scope: Required scope
            trust_level: Required trust level

        Returns:
            True if authorized

        Raises:
            ScopeNotGrantedError: If scope is not in the token
            TrustLevelInsufficientError: If trust level is too low
        """
        token_scopes = token_payload.get("scopes", [])
        if scope not in token_scopes:
            raise ScopeNotGrantedError(
                f"Scope '{scope}' is not granted in the token"
            )

        token_trust = token_payload.get("trust_level", "low")
        if TRUST_LEVELS.get(token_trust, 0) < TRUST_LEVELS.get(trust_level, 0):
            raise TrustLevelInsufficientError(
                f"Trust level '{token_trust}' is insufficient; "
                f"'{trust_level}' required"
            )

        return True


def require_scope(
    scope: str, trust_level: str = "low"
) -> Callable:
    """
    Decorator that enforces scope-based authorization on a function.

    The calling code must first set the current token payload via
    ``set_current_token(payload)`` before calling the decorated function.

    Args:
        scope: Required scope string (e.g. "db:read")
        trust_level: Minimum trust level ("low", "medium", "high")

    Returns:
        Decorated function

    Raises:
        PermissionDeniedError: If no token is set in context
        ScopeNotGrantedError: If the token lacks the required scope
        TrustLevelInsufficientError: If the token's trust level is too low

    Example::

        @require_scope("db:read")
        def query_users():
            ...

        @require_scope("db:write", trust_level="high")
        def delete_record():
            ...
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            payload = get_current_token()
            if payload is None:
                raise PermissionDeniedError(
                    "No authentication token found in context"
                )

            # Validate scope and trust level
            token_scopes = payload.get("scopes", [])
            if scope not in token_scopes:
                logger.warning("Scope denied: required=%s token_scopes=%s agent=%s",
                               scope, token_scopes, payload.get("agent_id"))
                raise ScopeNotGrantedError(
                    f"Scope '{scope}' is not granted in the token"
                )

            token_trust = payload.get("trust_level", "low")
            required_level = TRUST_LEVELS.get(trust_level, 0)
            actual_level = TRUST_LEVELS.get(token_trust, 0)
            if actual_level < required_level:
                logger.warning("Trust level insufficient: required=%s actual=%s agent=%s",
                               trust_level, token_trust, payload.get("agent_id"))
                raise TrustLevelInsufficientError(
                    f"Trust level '{token_trust}' is insufficient; "
                    f"'{trust_level}' required"
                )

            logger.debug("Scope check passed: scope=%s trust=%s agent=%s",
                         scope, token_trust, payload.get("agent_id"))
            return func(*args, **kwargs)

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            payload = get_current_token()
            if payload is None:
                raise PermissionDeniedError(
                    "No authentication token found in context"
                )

            token_scopes = payload.get("scopes", [])
            if scope not in token_scopes:
                raise ScopeNotGrantedError(
                    f"Scope '{scope}' is not granted in the token"
                )

            token_trust = payload.get("trust_level", "low")
            required_level = TRUST_LEVELS.get(trust_level, 0)
            actual_level = TRUST_LEVELS.get(token_trust, 0)
            if actual_level < required_level:
                raise TrustLevelInsufficientError(
                    f"Trust level '{token_trust}' is insufficient; "
                    f"'{trust_level}' required"
                )

            return await func(*args, **kwargs)

        import inspect

        if inspect.iscoroutinefunction(func):
            return async_wrapper
        return wrapper

    return decorator