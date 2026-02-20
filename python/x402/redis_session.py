"""Redis-backed session store for upto payment scheme.

Provides cross-process session management using Redis for tracking
accumulated costs under a Permit2 spend cap. This is a drop-in
replacement for the in-memory SessionStore, designed for multi-worker
deployments (e.g., Gunicorn).

Requires the redis extra: pip install x402[redis]
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

try:
    import redis as redis_lib
except ImportError as e:
    raise ImportError(
        "Redis session store requires the redis package. "
        "Install with: pip install x402[redis]"
    ) from e

from .session import UptoSession

# ---------------------------------------------------------------------------
# Lua scripts — executed atomically on the Redis server
# ---------------------------------------------------------------------------

# Atomically add cost to a session. Returns 1 on success, 0 on failure.
_ADD_COST_SCRIPT = """
local data = redis.call('GET', KEYS[1])
if not data then return 0 end

local session = cjson.decode(data)
if session['settled'] then return 0 end
if session['settling'] then return 0 end

local new_cost = session['accumulated_cost'] + tonumber(ARGV[1])
if new_cost > session['max_amount'] then return 0 end

session['accumulated_cost'] = new_cost
session['last_activity'] = tonumber(ARGV[2])
redis.call('SET', KEYS[1], cjson.encode(session))
return 1
"""

# Atomically mark a session as settled. Returns 1 on success, 0 if not found.
_MARK_SETTLED_SCRIPT = """
local data = redis.call('GET', KEYS[1])
if not data then return 0 end

local session = cjson.decode(data)
session['settled'] = true
session['settlement_tx'] = ARGV[1]
redis.call('SET', KEYS[1], cjson.encode(session))
return 1
"""

# Atomically close (GET + DEL + SREM). Returns session JSON or nil.
_CLOSE_SESSION_SCRIPT = """
local data = redis.call('GET', KEYS[1])
if not data then return nil end
redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[2], ARGV[1])
return data
"""

# Atomically claim a session for settlement by setting a 'settling' flag.
# Returns the session JSON if successfully claimed, nil otherwise.
# This prevents duplicate settlements when multiple workers race.
_CLAIM_FOR_SETTLEMENT_SCRIPT = """
local data = redis.call('GET', KEYS[1])
if not data then return nil end

local session = cjson.decode(data)
if session['settled'] then return nil end
if session['settling'] then return nil end

session['settling'] = true
redis.call('SET', KEYS[1], cjson.encode(session))
return data
"""


class RedisSessionStore:
    """Redis-backed session store for upto payments.

    Drop-in replacement for SessionStore that works across multiple
    processes (e.g., Gunicorn workers). All mutations use Lua scripts
    for atomicity.

    Usage::

        from x402.redis_session import RedisSessionStore

        store = RedisSessionStore("redis://localhost:6379/0")
        # or with a pre-configured client:
        store = RedisSessionStore(redis_client=my_redis)
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        *,
        redis_client: redis_lib.Redis | None = None,
        key_prefix: str = "x402:session:",
    ) -> None:
        if redis_client is not None:
            self._redis = redis_client
        else:
            self._redis = redis_lib.Redis.from_url(
                redis_url, decode_responses=True
            )

        self._key_prefix = key_prefix
        self._active_set_key = f"{key_prefix}active"

        # Register Lua scripts (auto-re-registers after Redis restart)
        self._add_cost = self._redis.register_script(_ADD_COST_SCRIPT)
        self._mark_settled_script = self._redis.register_script(_MARK_SETTLED_SCRIPT)
        self._close_session_script = self._redis.register_script(_CLOSE_SESSION_SCRIPT)
        self._claim_script = self._redis.register_script(_CLAIM_FOR_SETTLEMENT_SCRIPT)

    # ------------------------------------------------------------------
    # Key helpers
    # ------------------------------------------------------------------

    def _session_key(self, session_id: str) -> str:
        return f"{self._key_prefix}{session_id}"

    # ------------------------------------------------------------------
    # Public API (same interface as SessionStore)
    # ------------------------------------------------------------------

    def create_session(
        self,
        permit_payload: dict[str, Any],
        requirements: dict[str, Any],
        max_amount: int,
        route_method: str | None = None,
        route_path: str | None = None,
    ) -> str:
        session_id = str(uuid.uuid4())
        session = UptoSession(
            session_id=session_id,
            permit_payload=permit_payload,
            requirements=requirements,
            max_amount=max_amount,
            route_method=route_method,
            route_path=route_path,
        )
        key = self._session_key(session_id)
        pipe = self._redis.pipeline()
        pipe.set(key, json.dumps(session.to_dict()))
        pipe.sadd(self._active_set_key, session_id)
        pipe.execute()
        return session_id

    def get_session(self, session_id: str) -> UptoSession | None:
        data = self._redis.get(self._session_key(session_id))
        if data is None:
            return None
        return UptoSession.from_dict(json.loads(data))

    def add_cost(self, session_id: str, cost: int) -> bool:
        result = self._add_cost(
            keys=[self._session_key(session_id)],
            args=[cost, time.time()],
        )
        return int(result) == 1

    def close_session(self, session_id: str) -> UptoSession | None:
        data = self._close_session_script(
            keys=[self._session_key(session_id), self._active_set_key],
            args=[session_id],
        )
        if data is None:
            return None
        return UptoSession.from_dict(json.loads(data))

    def mark_settled(self, session_id: str, tx_hash: str) -> None:
        self._mark_settled_script(
            keys=[self._session_key(session_id)],
            args=[tx_hash],
        )

    def get_expired_sessions(self, idle_timeout_seconds: int) -> list[UptoSession]:
        now = time.time()
        expired: list[UptoSession] = []
        for session in self._iter_active_sessions():
            if session.settled:
                continue
            if now - session.last_activity > idle_timeout_seconds:
                # Atomically claim to prevent duplicate settlement
                claimed = self._claim_script(
                    keys=[self._session_key(session.session_id)],
                    args=[],
                )
                if claimed is not None:
                    expired.append(session)
        return expired

    def get_exhausted_sessions(self) -> list[UptoSession]:
        exhausted: list[UptoSession] = []
        for session in self._iter_active_sessions():
            if session.settled:
                continue
            if session.is_exhausted:
                # Atomically claim to prevent duplicate settlement
                claimed = self._claim_script(
                    keys=[self._session_key(session.session_id)],
                    args=[],
                )
                if claimed is not None:
                    exhausted.append(session)
        return exhausted

    @property
    def active_count(self) -> int:
        count = 0
        for session in self._iter_active_sessions():
            if not session.settled:
                count += 1
        return count

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _iter_active_sessions(self) -> list[UptoSession]:
        """Fetch all active sessions from Redis."""
        session_ids = self._redis.smembers(self._active_set_key)
        if not session_ids:
            return []

        ids = list(session_ids)
        keys = [self._session_key(sid) for sid in ids]

        # Batch fetch with MGET
        values = self._redis.mget(keys)

        sessions: list[UptoSession] = []
        stale_ids: list[str] = []
        for sid, val in zip(ids, values):
            if val is None:
                # Key was deleted but still in active set — clean up
                stale_ids.append(sid)
                continue
            sessions.append(UptoSession.from_dict(json.loads(val)))

        # Remove stale entries from the active set
        if stale_ids:
            self._redis.srem(self._active_set_key, *stale_ids)

        return sessions
