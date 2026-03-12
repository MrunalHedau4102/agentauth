"""Cryptographic audit trail with tamper-evident hash chain."""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

from agentauth.db.models import AuditLogModel
from agentauth.exceptions import AuditChainCorruptedError


class AuditLogger:
    """
    Tamper-evident audit logger.

    Each log entry is chained via SHA-256 hashes: every entry includes
    the hash of the previous entry, making the log append-only and
    verifiable.
    """

    # Recognised event types
    EVENT_TYPES = (
        "login",
        "token_issued",
        "token_used",
        "token_expired",
        "scope_denied",
        "agent_registered",
        "agent_revoked",
        "suspicious_activity",
    )

    def __init__(self, session: Session) -> None:
        """
        Initialize AuditLogger.

        Args:
            session: SQLAlchemy database session
        """
        self.session = session

    def log(
        self,
        event_type: str,
        agent_id: Optional[str] = None,
        user_id: Optional[int] = None,
        outcome: str = "success",
        ip_address: Optional[str] = None,
        scopes: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Record a new audit event.

        Args:
            event_type: Type of event (see EVENT_TYPES)
            agent_id: Agent UUID, if applicable
            user_id: User integer ID, if applicable
            outcome: "success" or "failure"
            ip_address: Originating IP
            scopes: List of scope strings involved
            metadata: Arbitrary metadata dict

        Returns:
            Dictionary representation of the logged entry
        """
        event_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)

        # Get the hash of the previous entry
        previous_hash = self._get_last_hash()

        # Build the entry content to hash
        entry_content = self._build_hash_content(
            event_id=event_id,
            event_type=event_type,
            agent_id=agent_id,
            user_id=user_id,
            timestamp=now.isoformat(),
            ip_address=ip_address,
            scopes=scopes,
            outcome=outcome,
            metadata=metadata,
            previous_hash=previous_hash,
        )
        entry_hash = hashlib.sha256(entry_content.encode("utf-8")).hexdigest()

        record = AuditLogModel(
            event_id=event_id,
            event_type=event_type,
            agent_id=agent_id,
            user_id=user_id,
            timestamp=now,
            ip_address=ip_address,
            scopes_involved=scopes,
            outcome=outcome,
            metadata_json=metadata,
            previous_hash=previous_hash,
            entry_hash=entry_hash,
        )

        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record.to_dict()

    def verify_chain(self) -> bool:
        """
        Verify the integrity of the entire audit log hash chain.

        Returns:
            True if the chain is intact

        Raises:
            AuditChainCorruptedError: If any entry's hash is inconsistent
        """
        entries = (
            self.session.query(AuditLogModel)
            .order_by(AuditLogModel.id.asc())
            .all()
        )

        if not entries:
            return True

        previous_hash: Optional[str] = None

        for entry in entries:
            # The stored previous_hash must match what we tracked
            if entry.previous_hash != previous_hash:
                raise AuditChainCorruptedError(
                    f"Previous hash mismatch at event {entry.event_id}"
                )

            # Recompute the entry hash
            expected_content = self._build_hash_content(
                event_id=entry.event_id,
                event_type=entry.event_type,
                agent_id=entry.agent_id,
                user_id=entry.user_id,
                timestamp=entry.timestamp.isoformat(),
                ip_address=entry.ip_address,
                scopes=entry.scopes_involved,
                outcome=entry.outcome,
                metadata=entry.metadata_json,
                previous_hash=entry.previous_hash,
            )
            expected_hash = hashlib.sha256(
                expected_content.encode("utf-8")
            ).hexdigest()

            if entry.entry_hash != expected_hash:
                raise AuditChainCorruptedError(
                    f"Entry hash mismatch at event {entry.event_id}"
                )

            previous_hash = entry.entry_hash

        return True

    def get_events(
        self,
        agent_id: Optional[str] = None,
        event_type: Optional[str] = None,
        since: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """
        Query audit events with optional filters.

        Args:
            agent_id: Filter by agent UUID
            event_type: Filter by event type
            since: Only entries after this datetime (UTC)

        Returns:
            List of audit event dictionaries
        """
        query = self.session.query(AuditLogModel)

        if agent_id is not None:
            query = query.filter(AuditLogModel.agent_id == agent_id)
        if event_type is not None:
            query = query.filter(AuditLogModel.event_type == event_type)
        if since is not None:
            query = query.filter(AuditLogModel.timestamp >= since)

        query = query.order_by(AuditLogModel.id.asc())
        return [r.to_dict() for r in query.all()]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_last_hash(self) -> Optional[str]:
        """Return the entry_hash of the most recent audit log entry."""
        last = (
            self.session.query(AuditLogModel)
            .order_by(AuditLogModel.id.desc())
            .first()
        )
        return last.entry_hash if last else None

    @staticmethod
    def _build_hash_content(
        event_id: str,
        event_type: str,
        agent_id: Optional[str],
        user_id: Optional[int],
        timestamp: str,
        ip_address: Optional[str],
        scopes: Optional[List[str]],
        outcome: str,
        metadata: Optional[Dict[str, Any]],
        previous_hash: Optional[str],
    ) -> str:
        """Build a deterministic string for hashing."""
        parts = {
            "event_id": event_id,
            "event_type": event_type,
            "agent_id": agent_id,
            "user_id": user_id,
            "timestamp": timestamp,
            "ip_address": ip_address,
            "scopes": scopes,
            "outcome": outcome,
            "metadata": metadata,
            "previous_hash": previous_hash,
        }
        return json.dumps(parts, sort_keys=True, default=str)
