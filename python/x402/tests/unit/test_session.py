"""Unit tests for x402.session — upto draw-down session store.

Focus: the settlement-deadline safeguards that prevent a long-lived session
from outliving its signed authorization and silently dropping the tab.
"""

from __future__ import annotations

import time

from x402.session import (
    SessionStore,
    UptoSession,
    signed_authorization_deadline,
)


def _permit_payload(deadline: int) -> dict:
    """A minimal upto Permit2 payload carrying a signed deadline."""
    return {
        "x402Version": 2,
        "scheme": "upto",
        "network": "eip155:8453",
        "payload": {
            "permit2Authorization": {"deadline": str(deadline)},
            "signature": "0xsig",
        },
    }


def _requirements(max_timeout_seconds: int = 300) -> dict:
    return {
        "scheme": "upto",
        "network": "eip155:8453",
        "asset": "0x0000000000000000000000000000000000000000",
        "amount": "1000",
        "payTo": "0x1234567890123456789012345678901234567890",
        "maxTimeoutSeconds": max_timeout_seconds,
    }


def test_settlement_deadline_prefers_signed_permit_deadline():
    """The exact signed Permit2 deadline is used when present."""
    deadline = int(time.time()) + 300
    session = UptoSession(
        session_id="s1",
        permit_payload=_permit_payload(deadline),
        requirements=_requirements(),
        max_amount=1000,
    )
    assert session.settlement_deadline == float(deadline)


def test_settlement_deadline_falls_back_to_created_plus_window():
    """Without a signed deadline, fall back to created_at + maxTimeoutSeconds."""
    session = UptoSession(
        session_id="s2",
        permit_payload={"payload": {"signature": "0xsig"}},  # no deadline
        requirements=_requirements(max_timeout_seconds=450),
        max_amount=1000,
    )
    assert session.settlement_deadline == session.created_at + 450.0


def test_settlement_deadline_none_when_undeterminable():
    session = UptoSession(
        session_id="s3",
        permit_payload={"payload": {}},
        requirements={"scheme": "upto", "network": "eip155:8453"},
        max_amount=1000,
    )
    assert session.settlement_deadline is None


def test_signed_deadline_reads_permit2_deadline():
    """signed_deadline reflects the canonical Permit2 signed deadline."""
    deadline = int(time.time()) + 300
    session = UptoSession(
        session_id="s1",
        permit_payload=_permit_payload(deadline),
        requirements=_requirements(),
        max_amount=1000,
    )
    assert session.signed_deadline == float(deadline)


def test_signed_deadline_reads_eip3009_valid_before():
    """EIP-3009 authorizations expose the deadline as validBefore."""
    valid_before = int(time.time()) + 300
    session = UptoSession(
        session_id="s2",
        permit_payload={"payload": {"authorization": {"validBefore": str(valid_before)}}},
        requirements=_requirements(),
        max_amount=1000,
    )
    assert session.signed_deadline == float(valid_before)


def test_signed_deadline_is_none_without_signed_value():
    """signed_deadline never substitutes the advertised-window fallback.

    settlement_deadline may guess from created_at + maxTimeoutSeconds, but
    signed_deadline must stay None so admission decisions can fail closed.
    """
    session = UptoSession(
        session_id="s3",
        permit_payload={"payload": {"signature": "0xsig"}},  # no deadline
        requirements=_requirements(max_timeout_seconds=450),
        max_amount=1000,
    )
    assert session.signed_deadline is None
    # ...while settlement_deadline still falls back for the reaper.
    assert session.settlement_deadline == session.created_at + 450.0


def test_signed_authorization_deadline_helper_rejects_malformed():
    """The extractor returns None (not a guess) for absent/garbled deadlines."""
    assert signed_authorization_deadline({"payload": {}}) is None
    assert signed_authorization_deadline({}) is None
    assert (
        signed_authorization_deadline(
            {"payload": {"permit2Authorization": {"deadline": "not-a-number"}}}
        )
        is None
    )


def test_get_settlement_due_sessions_returns_near_deadline_sessions():
    """A session inside the safety margin of its deadline is due for settlement."""
    store = SessionStore()
    now = int(time.time())

    # Deadline 60s out — inside a 180s safety margin → due.
    due_id = store.create_session(
        permit_payload=_permit_payload(now + 60),
        requirements=_requirements(),
        max_amount=1000,
    )
    # Deadline 600s out — well outside the margin → not due.
    fresh_id = store.create_session(
        permit_payload=_permit_payload(now + 600),
        requirements=_requirements(),
        max_amount=1000,
    )

    due = store.get_settlement_due_sessions(safety_margin_seconds=180)
    due_ids = {s.session_id for s in due}
    assert due_id in due_ids
    assert fresh_id not in due_ids


def test_get_settlement_due_sessions_skips_settled_and_settling():
    store = SessionStore()
    now = int(time.time())
    sid = store.create_session(
        permit_payload=_permit_payload(now + 30),
        requirements=_requirements(),
        max_amount=1000,
    )

    assert store.get_settlement_due_sessions(180)  # due while active

    store.mark_settling(sid)
    assert store.get_settlement_due_sessions(180) == []  # claimed → skipped

    store.clear_settling(sid)
    store.mark_settled(sid, "0xabc")
    assert store.get_settlement_due_sessions(180) == []  # settled → skipped
