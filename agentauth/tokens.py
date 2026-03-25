"""Ephemeral scoped token issuance and verification."""

import hashlib
import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any

import jwt
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

from agentauth.db.models import EphemeralTokenModel
from agentauth.exceptions import TokenExpiredError, InvalidTokenError

import logging
logger = logging.getLogger("agentauth.tokens")


class EphemeralTokenVault:
    """
    Issues and verifies short-lived, cryptographically signed ephemeral tokens
    for AI agent actions.

    Tokens are JWT (HS256) with embedded scopes, TTL, optional one-time-use,
    and optional binding to a specific agent URL or IP.

    All default values (TTL, trust level, one-time-use, bound_to) can be set
    via ``AgentAuthConfig.token`` and are used by ``SecureAgent`` automatically.
    They can also be overridden directly when calling ``issue()`` and
    ``verify()`` for standalone use.
    """

    def __init__(
        self,
        secret_key: Optional[str] = None,
        session: Optional[Session] = None,
        algorithm: str = "HS256",
    ) -> None:
        """
        Initialize EphemeralTokenVault.

        Args:
            secret_key: HMAC signing key. Falls back to the
                        ``AGENTAUTH_SECRET_KEY`` environment variable when
                        not supplied.
            session: SQLAlchemy database session (required for one-time-use
                     token tracking).
            algorithm: JWT signing algorithm. Currently only ``"HS256"`` is
                       supported. Sourced from ``AgentAuthConfig.token.algorithm``
                       when used via ``SecureAgent``.
        """
        self.secret_key = secret_key or os.getenv("AGENTAUTH_SECRET_KEY", "")
        if not self.secret_key:
            raise ValueError(
                "secret_key must be provided or set via "
                "AGENTAUTH_SECRET_KEY environment variable"
            )
        self.session   = session
        self.algorithm = algorithm.upper()

        _supported = {"HS256"}
        if self.algorithm not in _supported:
            raise ValueError(
                f"Unsupported JWT algorithm: '{algorithm}'. "
                f"Supported: {sorted(_supported)}"
            )

    def issue(
        self,
        agent_id: str,
        scopes: Optional[List[str]] = None,
        ttl_seconds: int = 30,
        one_time_use: bool = False,
        bound_to: Optional[str] = None,
        trust_level: str = "low",
    ) -> str:
        """
        Issue a new ephemeral token.

        When used via ``SecureAgent``, defaults for ``ttl_seconds``,
        ``one_time_use``, ``bound_to``, and ``trust_level`` are sourced from
        ``AgentAuthConfig.token`` and can be overridden per ``run()`` call.

        Args:
            agent_id: UUID of the agent.
            scopes: List of granted scope strings.
            ttl_seconds: Time-to-live in seconds. Default ``30``.
            one_time_use: If ``True``, the token is invalidated after first
                          verification. Requires a database session.
            bound_to: Optional IP or agent URL to bind the token to.
            trust_level: Trust level embedded in the token
                         (``"low"``, ``"medium"``, ``"high"``).

        Returns:
            Encoded JWT token string.

        Raises:
            ValueError: If ``agent_id`` is empty, or a session is missing
                        for one-time-use tokens.
        """
        if not agent_id:
            raise ValueError("agent_id is required")
        if one_time_use and self.session is None:
            raise ValueError(
                "A database session is required for one-time-use tokens"
            )

        now        = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=ttl_seconds)

        payload: Dict[str, Any] = {
            "agent_id":    agent_id,
            "scopes":      scopes or [],
            "trust_level": trust_level,
            "iat":         now,
            "exp":         expires_at,
            "one_time_use": one_time_use,
        }
        if bound_to:
            payload["bound_to"] = bound_to

        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

        # Persist one-time-use token signature for later invalidation.
        if one_time_use and self.session is not None:
            sig    = self._token_signature(token)
            record = EphemeralTokenModel(
                token_signature=sig,
                agent_id=agent_id,
                scopes=scopes or [],
                is_used=False,
                bound_to=bound_to,
                expires_at=expires_at,
            )
            self.session.add(record)
            self.session.commit()

        return token

    def verify(
        self,
        token: str,
        expected_bound_to: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Verify an ephemeral token and return its payload.

        Args:
            token: JWT token string.
            expected_bound_to: When provided, the token's ``bound_to`` field
                               must match this value.

        Returns:
            Decoded token payload dict.

        Raises:
            TokenExpiredError: If the token has expired.
            InvalidTokenError: If the token is invalid, already used, or the
                               ``bound_to`` value mismatches.
        """
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
            )
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired for agent (check token TTL)")
            raise TokenExpiredError("Ephemeral token has expired")
        except jwt.InvalidTokenError as exc:
            logger.warning("Invalid token signature or format: %s", exc)
            raise InvalidTokenError(f"Invalid ephemeral token: {exc}")

        # Check bound_to binding.
        token_bound = payload.get("bound_to")
        if expected_bound_to and token_bound:
            if token_bound != expected_bound_to:
                raise InvalidTokenError(
                    f"Token is bound to '{token_bound}', "
                    f"but expected '{expected_bound_to}'"
                )

        # One-time-use check.
        if payload.get("one_time_use") and self.session is not None:
            sig    = self._token_signature(token)
            record = (
                self.session.query(EphemeralTokenModel)
                .filter(EphemeralTokenModel.token_signature == sig)
                .first()
            )
            if record is None:
                raise InvalidTokenError(
                    "One-time-use token not found in registry"
                )
            if record.is_used:
                raise InvalidTokenError(
                    "One-time-use token has already been used"
                )
            record.is_used = True
            self.session.commit()

        logger.debug("Token verified for agent_id=%s scopes=%s",
                     payload.get("agent_id"), payload.get("scopes"))
        return payload

    @staticmethod
    def _token_signature(token: str) -> str:
        """SHA-256 hash of a token for storage (never store the raw JWT)."""
        return hashlib.sha256(token.encode("utf-8")).hexdigest()