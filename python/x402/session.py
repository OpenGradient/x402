"""Session store for upto payment scheme.

Provides thread-safe in-memory session management for tracking
accumulated costs under a Permit2 spend cap.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass
class UptoSession:
    """An active upto payment session.

    Tracks accumulated cost against a signed Permit2 spend cap.
    """

    session_id: str
    permit_payload: dict[str, Any]
    """The original Permit2 payment payload (for settlement)."""
    requirements: dict[str, Any]
    """The payment requirements associated with this session."""
    max_amount: int
    """Maximum amount the client signed for (spend cap)."""
    accumulated_cost: int = 0
    """Total cost accumulated across all requests in this session."""
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    settled: bool = False
    """Whether this session has been settled on-chain."""
    settlement_tx: str = ""
    """Transaction hash from settlement, if settled."""
    settling: bool = False
    """Whether a settlement attempt is in progress."""
    route_method: str | None = None
    """Optional HTTP method this session is bound to."""
    route_path: str | None = None
    """Optional HTTP path this session is bound to."""

    @property
    def remaining_budget(self) -> int:
        """How much budget remains in this session."""
        return max(0, self.max_amount - self.accumulated_cost)

    @property
    def is_exhausted(self) -> bool:
        """Whether the spend cap has been fully consumed."""
        return self.accumulated_cost >= self.max_amount

    def to_dict(self) -> dict[str, Any]:
        """Serialize session to a dict (for Redis/JSON storage)."""
        return {
            "session_id": self.session_id,
            "permit_payload": self.permit_payload,
            "requirements": self.requirements,
            "max_amount": self.max_amount,
            "accumulated_cost": self.accumulated_cost,
            "created_at": self.created_at,
            "last_activity": self.last_activity,
            "settled": self.settled,
            "settlement_tx": self.settlement_tx,
            "settling": self.settling,
            "route_method": self.route_method,
            "route_path": self.route_path,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> UptoSession:
        """Deserialize session from a dict."""
        return cls(
            session_id=data["session_id"],
            permit_payload=data["permit_payload"],
            requirements=data["requirements"],
            max_amount=int(data["max_amount"]),
            accumulated_cost=int(data["accumulated_cost"]),
            created_at=float(data["created_at"]),
            last_activity=float(data["last_activity"]),
            settled=bool(data.get("settled", False)),
            settlement_tx=str(data.get("settlement_tx", "")),
            settling=bool(data.get("settling", False)),
            route_method=data.get("route_method"),
            route_path=data.get("route_path"),
        )


@runtime_checkable
class SessionStoreProtocol(Protocol):
    """Protocol for session stores (in-memory, Redis, etc.)."""

    def create_session(
        self,
        permit_payload: dict[str, Any],
        requirements: dict[str, Any],
        max_amount: int,
        route_method: str | None = None,
        route_path: str | None = None,
    ) -> str: ...

    def get_session(self, session_id: str) -> UptoSession | None: ...

    def add_cost(self, session_id: str, cost: int) -> bool: ...

    def close_session(self, session_id: str) -> UptoSession | None: ...

    def mark_settled(self, session_id: str, tx_hash: str) -> None: ...

    def get_expired_sessions(self, idle_timeout_seconds: int) -> list[UptoSession]: ...

    def get_exhausted_sessions(self) -> list[UptoSession]: ...

    @property
    def active_count(self) -> int: ...


class SessionStore:
    """Thread-safe in-memory session store for upto payments.

    Stores active sessions keyed by session_id. Sessions accumulate
    cost until the cap is reached or idle timeout expires.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, UptoSession] = {}
        self._lock = threading.Lock()

    def create_session(
        self,
        permit_payload: dict[str, Any],
        requirements: dict[str, Any],
        max_amount: int,
        route_method: str | None = None,
        route_path: str | None = None,
    ) -> str:
        """Create a new upto session.

        Args:
            permit_payload: The Permit2 payment payload (for later settlement).
            requirements: Payment requirements.
            max_amount: Spend cap (permitted amount from Permit2 signature).

        Returns:
            Newly generated session ID.
        """
        session_id = str(uuid.uuid4())
        session = UptoSession(
            session_id=session_id,
            permit_payload=permit_payload,
            requirements=requirements,
            max_amount=max_amount,
            route_method=route_method,
            route_path=route_path,
        )
        with self._lock:
            self._sessions[session_id] = session
        return session_id

    def get_session(self, session_id: str) -> UptoSession | None:
        """Retrieve a session by ID.

        Args:
            session_id: The session identifier.

        Returns:
            The session, or None if not found.
        """
        with self._lock:
            return self._sessions.get(session_id)

    def add_cost(self, session_id: str, cost: int) -> bool:
        """Add cost to a session.

        Updates accumulated_cost and last_activity timestamp.

        Args:
            session_id: The session identifier.
            cost: Cost to add (in token smallest unit).

        Returns:
            True if cost was added successfully (within cap).
            False if adding cost would exceed the cap or session not found.
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or session.settled or session.settling:
                return False
            if session.accumulated_cost + cost > session.max_amount:
                return False
            session.accumulated_cost += cost
            session.last_activity = time.time()
            return True

    def close_session(self, session_id: str) -> UptoSession | None:
        """Close and remove a session from the store.

        Args:
            session_id: The session identifier.

        Returns:
            The closed session, or None if not found.
        """
        with self._lock:
            return self._sessions.pop(session_id, None)

    def mark_settled(self, session_id: str, tx_hash: str) -> None:
        """Mark a session as settled.

        Args:
            session_id: The session identifier.
            tx_hash: Settlement transaction hash.
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if session:
                session.settled = True
                session.settlement_tx = tx_hash

    def get_expired_sessions(self, idle_timeout_seconds: int) -> list[UptoSession]:
        """Get sessions that have been idle longer than the timeout.

        Does NOT remove them from the store.

        Args:
            idle_timeout_seconds: Max idle time before expiry.

        Returns:
            List of expired (but unsettled) sessions.
        """
        now = time.time()
        expired: list[UptoSession] = []
        with self._lock:
            for session in self._sessions.values():
                if session.settled:
                    continue
                if now - session.last_activity > idle_timeout_seconds:
                    expired.append(session)
        return expired

    def get_exhausted_sessions(self) -> list[UptoSession]:
        """Get sessions where the spend cap has been fully consumed.

        Returns:
            List of exhausted (but unsettled) sessions.
        """
        exhausted: list[UptoSession] = []
        with self._lock:
            for session in self._sessions.values():
                if session.settled:
                    continue
                if session.is_exhausted:
                    exhausted.append(session)
        return exhausted

    @property
    def active_count(self) -> int:
        """Number of active (unsettled) sessions."""
        with self._lock:
            return sum(1 for s in self._sessions.values() if not s.settled)
