"""Unit tests for x402.http.facilitator_client."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from x402.http.facilitator_client import (
    HTTPFacilitatorClient,
    HTTPFacilitatorClientSync,
)
from x402.http.facilitator_client_base import (
    FacilitatorConfig,
    FacilitatorResponseError,
)
from x402.schemas import PaymentPayload, PaymentRequirements


def make_payment_requirements() -> PaymentRequirements:
    """Helper to create valid PaymentRequirements."""
    return PaymentRequirements(
        scheme="exact",
        network="eip155:8453",
        asset="0x0000000000000000000000000000000000000000",
        amount="1000000",
        pay_to="0x1234567890123456789012345678901234567890",
        max_timeout_seconds=300,
    )


def make_v2_payload(signature: str = "0xmock") -> PaymentPayload:
    """Helper to create valid V2 PaymentPayload."""
    return PaymentPayload(
        x402_version=2,
        payload={"signature": signature},
        accepted=make_payment_requirements(),
    )


@pytest.mark.asyncio
async def test_async_verify_raises_facilitator_response_error_for_invalid_json():
    """Async verify should surface invalid JSON as facilitator boundary error."""
    response = MagicMock(status_code=200, text="not-json")
    response.json.side_effect = json.JSONDecodeError("Expecting value", "not-json", 0)

    http_client = MagicMock()
    http_client.post = AsyncMock(return_value=response)

    client = HTTPFacilitatorClient(
        FacilitatorConfig(url="https://facilitator.test", http_client=http_client)
    )

    with pytest.raises(
        FacilitatorResponseError,
        match="Facilitator verify returned invalid JSON",
    ):
        await client.verify(make_v2_payload(), make_payment_requirements())


@pytest.mark.asyncio
async def test_async_settle_raises_facilitator_response_error_for_invalid_schema():
    """Async settle should surface schema drift as facilitator boundary error."""
    response = MagicMock(status_code=200, text='{"success": true}')
    response.json.return_value = {"success": True}

    http_client = MagicMock()
    http_client.post = AsyncMock(return_value=response)

    client = HTTPFacilitatorClient(
        FacilitatorConfig(url="https://facilitator.test", http_client=http_client)
    )

    with pytest.raises(
        FacilitatorResponseError,
        match="Facilitator settle returned invalid data",
    ):
        await client.settle(make_v2_payload(), make_payment_requirements())


def test_sync_verify_raises_facilitator_response_error_for_invalid_json():
    """Sync verify should surface invalid JSON as facilitator boundary error."""
    response = MagicMock(status_code=200, text="not-json")
    response.json.side_effect = json.JSONDecodeError("Expecting value", "not-json", 0)

    http_client = MagicMock()
    http_client.post.return_value = response

    client = HTTPFacilitatorClientSync(
        FacilitatorConfig(url="https://facilitator.test", http_client=http_client)
    )

    with pytest.raises(
        FacilitatorResponseError,
        match="Facilitator verify returned invalid JSON",
    ):
        client.verify(make_v2_payload(), make_payment_requirements())


def test_sync_settle_raises_facilitator_response_error_for_invalid_schema():
    """Sync settle should surface schema drift as facilitator boundary error."""
    response = MagicMock(status_code=200, text='{"success": true}')
    response.json.return_value = {"success": True}

    http_client = MagicMock()
    http_client.post.return_value = response

    client = HTTPFacilitatorClientSync(
        FacilitatorConfig(url="https://facilitator.test", http_client=http_client)
    )

    with pytest.raises(
        FacilitatorResponseError,
        match="Facilitator settle returned invalid data",
    ):
        client.settle(make_v2_payload(), make_payment_requirements())


def _accepted_202_response() -> MagicMock:
    """A facilitator 202 async-settlement acceptance carrying a job id."""
    response = MagicMock(status_code=202, text='{"paymentJob": {"jobId": "payment-abc"}}')
    response.json.return_value = {"paymentJob": {"jobId": "payment-abc"}}
    return response


def _job_status_response(body: dict) -> MagicMock:
    response = MagicMock(status_code=200, text=json.dumps(body))
    response.json.return_value = body
    return response


def test_sync_settle_202_optimistic_when_not_waiting():
    """Default behavior: a 202 is reported as accepted (job id as transaction)."""
    http_client = MagicMock()
    http_client.post.return_value = _accepted_202_response()

    client = HTTPFacilitatorClientSync(
        FacilitatorConfig(url="https://facilitator.test", http_client=http_client)
    )

    result = client.settle(make_v2_payload(), make_payment_requirements())
    assert result.success is True
    assert result.transaction == "payment-abc"
    http_client.get.assert_not_called()


def test_sync_settle_waits_and_reports_onchain_success():
    """With wait_for_settlement, poll the job and return the real tx on success."""
    http_client = MagicMock()
    http_client.post.return_value = _accepted_202_response()
    http_client.get.side_effect = [
        _job_status_response({"status": "processing"}),
        _job_status_response(
            {
                "status": "succeeded",
                "result": {
                    "success": True,
                    "transaction": "0xdeadbeef",
                    "network": "eip155:8453",
                },
            }
        ),
    ]

    client = HTTPFacilitatorClientSync(
        FacilitatorConfig(
            url="https://facilitator.test",
            http_client=http_client,
            wait_for_settlement=True,
            settlement_poll_interval=0,
        )
    )

    result = client.settle(make_v2_payload(), make_payment_requirements())
    assert result.success is True
    assert result.transaction == "0xdeadbeef"
    assert http_client.get.call_count == 2


def test_sync_settle_waits_and_reports_failure_when_job_reverts():
    """Regression: a job that completes with success=False must NOT report success.

    The facilitator marks a reverted/expired settlement job "succeeded" at the
    queue level; the client must inspect result.success and surface a failure so
    the session is not marked settled without an on-chain transaction.
    """
    http_client = MagicMock()
    http_client.post.return_value = _accepted_202_response()
    http_client.get.return_value = _job_status_response(
        {
            "status": "succeeded",
            "result": {
                "success": False,
                "transaction": "",
                "network": "eip155:8453",
                "errorReason": "permit2_deadline_expired",
            },
        }
    )

    client = HTTPFacilitatorClientSync(
        FacilitatorConfig(
            url="https://facilitator.test",
            http_client=http_client,
            wait_for_settlement=True,
            settlement_poll_interval=0,
        )
    )

    result = client.settle(make_v2_payload(), make_payment_requirements())
    assert result.success is False
    assert result.error_reason == "permit2_deadline_expired"


def test_sync_settle_waits_and_times_out_without_reporting_success():
    """If the job never confirms, the client reports failure, not success."""
    http_client = MagicMock()
    http_client.post.return_value = _accepted_202_response()
    http_client.get.return_value = _job_status_response({"status": "queued"})

    client = HTTPFacilitatorClientSync(
        FacilitatorConfig(
            url="https://facilitator.test",
            http_client=http_client,
            wait_for_settlement=True,
            settlement_poll_interval=0,
            settlement_poll_timeout=0,
        )
    )

    result = client.settle(make_v2_payload(), make_payment_requirements())
    assert result.success is False
    assert result.error_reason == "settlement_timeout"


def test_negative_poll_values_are_clamped_dataclass_config():
    """Negative poll interval/timeout must clamp to 0 (time.sleep rejects <0)."""
    client = HTTPFacilitatorClientSync(
        FacilitatorConfig(
            url="https://facilitator.test",
            wait_for_settlement=True,
            settlement_poll_interval=-5.0,
            settlement_poll_timeout=-1.0,
        )
    )
    assert client._settlement_poll_interval == 0.0
    assert client._settlement_poll_timeout == 0.0


def test_negative_poll_values_are_clamped_dict_config():
    """Same clamping applies when configured via a dict."""
    client = HTTPFacilitatorClientSync(
        {
            "url": "https://facilitator.test",
            "wait_for_settlement": True,
            "settlement_poll_interval": -2.0,
            "settlement_poll_timeout": -10.0,
        }
    )
    assert client._settlement_poll_interval == 0.0
    assert client._settlement_poll_timeout == 0.0
