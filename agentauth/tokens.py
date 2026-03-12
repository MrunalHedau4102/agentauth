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


class EphemeralTokenVault:
    """
    Issues and verifies short-lived, cryptographically signed ephemeral tokens
    for AI agent actions.

    Tokens are JWT (HS256) with embedded scopes, TTL, optional one-time-use,
    and optional binding to a specific agent URL or IP.
    """

    def __init__(
        self,
        secret_key: Optional[str] = None,
        session: Optional[Session] = None,
    ) -> None:
        """
        Initialize EphemeralTokenVault.

        Args:
            secret_key: HMAC signing key. Falls back to
                        AGENTAUTH_SECRET_KEY env var.
            session: SQLAlchemy database session (required for
                     one-time-use token tracking).
        """
        self.secret_key = secret_key or os.getenv("AGENTAUTH_SECRET_KEY", "")
        if not self.secret_key:
            raise ValueError(
                "secret_key must be provided or set via "
                "AGENTAUTH_SECRET_KEY environment variable"
            )
        self.session = session

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

        Args:
            agent_id: UUID of the agent
            scopes: List of granted scope strings
            ttl_seconds: Time-to-live in seconds (default 30)
            one_time_use: If True, token is invalidated after first use
            bound_to: Optional IP or agent URL to bind the token to
            trust_level: Trust level embedded in the token

        Returns:
            Encoded JWT token string

        Raises:
            ValueError: If agent_id is empty or session is missing for
                        one-time-use tokens
        """
        if not agent_id:
            raise ValueError("agent_id is required")
        if one_time_use and self.session is None:
            raise ValueError(
                "A database session is required for one-time-use tokens"
            )

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=ttl_seconds)

        payload: Dict[str, Any] = {
            "agent_id": agent_id,
            "scopes": scopes or [],
            "trust_level": trust_level,
            "iat": now,
            "exp": expires_at,
            "one_time_use": one_time_use,
        }
        if bound_to:
            payload["bound_to"] = bound_to

        token = jwt.encode(payload, self.secret_key, algorithm="HS256")

        # Persist one-time-use token signature for later invalidation
        if one_time_use and self.session is not None:
            sig = self._token_signature(token)
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
            token: JWT token string
            expected_bound_to: If provided, checks the token's bound_to
                               field matches this value.

        Returns:
            Decoded token payload dict

        Raises:
            TokenExpiredError: If the token has expired
            InvalidTokenError: If the token is invalid, already used,
                               or bound_to mismatch
        """
        # Decode and verify signature + expiry
        try:
            payload = jwt.decode(
                token, self.secret_key, algorithms=["HS256"]
            )
        except jwt.ExpiredSignatureError:
            raise TokenExpiredError("Ephemeral token has expired")
        except jwt.InvalidTokenError as e:
            raise InvalidTokenError(f"Invalid ephemeral token: {e}")

        # Check bound_to
        token_bound = payload.get("bound_to")
        if expected_bound_to and token_bound:
            if token_bound != expected_bound_to:
                raise InvalidTokenError(
                    f"Token is bound to '{token_bound}', "
                    f"but expected '{expected_bound_to}'"
                )

        # One-time-use check
        if payload.get("one_time_use") and self.session is not None:
            sig = self._token_signature(token)
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

            # Mark as used
            record.is_used = True
            self.session.commit()

        return payload

    @staticmethod
    def _token_signature(token: str) -> str:
        """
        Compute a SHA-256 signature of a token for storage.

        Args:
            token: JWT token string

        Returns:
            Hex digest of the SHA-256 hash
        """
        return hashlib.sha256(token.encode("utf-8")).hexdigest()
