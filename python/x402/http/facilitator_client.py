"""HTTP-based facilitator client for x402 protocol.

Provides both async (HTTPFacilitatorClient) and sync (HTTPFacilitatorClientSync)
implementations for communicating with remote facilitator services.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import TYPE_CHECKING, Any, TypeVar

logger = logging.getLogger("x402.facilitator_client")

from pydantic import ValidationError

from ..schemas import (
    PaymentPayload,
    PaymentRequirements,
    SettleResponse,
    SupportedResponse,
    VerifyResponse,
)
from ..schemas.v1 import PaymentPayloadV1, PaymentRequirementsV1
from .facilitator_client_base import (
    AuthHeaders,
    AuthProvider,
    CreateHeadersAuthProvider,
    FacilitatorClient,
    FacilitatorClientSync,
    FacilitatorConfig,
    FacilitatorResponseError,
    HTTPFacilitatorClientBase,
)

if TYPE_CHECKING:
    import httpx

# Re-export for external use
__all__ = [
    "HTTPFacilitatorClient",
    "HTTPFacilitatorClientSync",
    "FacilitatorConfig",
    "FacilitatorResponseError",
    "FacilitatorClient",
    "FacilitatorClientSync",
    "AuthProvider",
    "AuthHeaders",
    "CreateHeadersAuthProvider",
]

_ResponseModelT = TypeVar(
    "_ResponseModelT",
    VerifyResponse,
    SettleResponse,
    SupportedResponse,
)


def _response_excerpt(response: Any, limit: int = 200) -> str:
    """Build a compact response preview for parse errors."""
    text = str(getattr(response, "text", "") or "").strip()
    if not text:
        return "<empty response>"

    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return f"{compact[: limit - 3]}..."


def _parse_facilitator_response(
    response: Any,
    model_cls: type[_ResponseModelT],
    operation: str,
) -> _ResponseModelT:
    """Parse facilitator JSON into a validated response model."""
    try:
        response_data = response.json()
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        raise FacilitatorResponseError(
            f"Facilitator {operation} returned invalid JSON: {_response_excerpt(response)}"
        ) from exc

    try:
        return model_cls.model_validate(response_data)
    except (ValidationError, ValueError, TypeError) as exc:
        raise FacilitatorResponseError(
            f"Facilitator {operation} returned invalid data: {_response_excerpt(response)}"
        ) from exc


def _parse_async_settle_acceptance(
    response: Any,
    requirements_dict: dict[str, Any],
) -> SettleResponse:
    """Convert an async facilitator 202 response into a settle result."""
    transaction = ""

    try:
        response_data = response.json()
    except (json.JSONDecodeError, ValueError, TypeError):
        response_data = None

    if isinstance(response_data, dict):
        payment_job = response_data.get("paymentJob")
        if isinstance(payment_job, dict):
            job_id = payment_job.get("jobId")
            if isinstance(job_id, str):
                transaction = job_id

    return SettleResponse(
        success=True,
        transaction=transaction,
        network=requirements_dict["network"],
        amount=requirements_dict.get("amount"),
    )


def _extract_job_id(response: Any) -> str | None:
    """Pull the settlement job id out of a facilitator 202 acceptance body."""
    try:
        response_data = response.json()
    except (json.JSONDecodeError, ValueError, TypeError):
        return None
    if not isinstance(response_data, dict):
        return None
    payment_job = response_data.get("paymentJob") or response_data.get("settlementJob")
    if isinstance(payment_job, dict):
        job_id = payment_job.get("jobId")
        if isinstance(job_id, str) and job_id:
            return job_id
    return None


def _settle_response_from_job_status(
    status_body: Any,
    requirements_dict: dict[str, Any],
) -> SettleResponse | None:
    """Map a ``GET /settle/:jobId`` body to a terminal SettleResponse.

    The facilitator marks a settlement job "succeeded" once the worker finishes
    even when the worker returned ``success: false`` (e.g. the on-chain settle
    reverted because the authorization expired). We therefore inspect the
    embedded ``result.success`` rather than trusting the job state alone.

    Returns:
        A terminal SettleResponse, or ``None`` if the job is still pending and
        polling should continue.
    """
    if not isinstance(status_body, dict):
        return None

    status = status_body.get("status")
    network = requirements_dict["network"]

    if status == "succeeded":
        result = status_body.get("result")
        if isinstance(result, dict):
            transaction = result.get("transaction") or status_body.get("txHash") or ""
            if result.get("success"):
                return SettleResponse(
                    success=True,
                    transaction=transaction,
                    network=result.get("network") or network,
                    payer=result.get("payer"),
                    amount=result.get("amount") or requirements_dict.get("amount"),
                )
            return SettleResponse(
                success=False,
                transaction=transaction,
                network=result.get("network") or network,
                error_reason=result.get("errorReason") or "settlement_failed",
                error_message=result.get("errorMessage"),
                payer=result.get("payer"),
            )
        # Completed with no structured result — fail closed rather than assume success.
        return SettleResponse(
            success=False,
            transaction=str(status_body.get("txHash") or ""),
            network=network,
            error_reason="settlement_result_missing",
        )

    if status == "failed":
        return SettleResponse(
            success=False,
            transaction="",
            network=network,
            error_reason=status_body.get("error") or "settlement_failed",
        )

    # queued / processing / unknown → not terminal yet.
    return None


# ============================================================================
# Async HTTP Facilitator Client (Default)
# ============================================================================


class HTTPFacilitatorClient(HTTPFacilitatorClientBase):
    """Async HTTP-based facilitator client.

    Communicates with remote x402 facilitator services over HTTP using
    async httpx.AsyncClient. Use with x402ResourceServer (async).

    Example:
        ```python
        from x402.http import HTTPFacilitatorClient, FacilitatorConfig

        facilitator = HTTPFacilitatorClient(FacilitatorConfig(url="https://..."))

        # In async context
        result = await facilitator.verify(payload, requirements)
        ```
    """

    def _get_sync_client(self) -> httpx.Client:
        """Get or create sync HTTP client for get_supported (initialization)."""
        import httpx

        # Create temporary sync client for initialization
        return httpx.Client(timeout=self._timeout, follow_redirects=True)

    def _get_async_client(self) -> httpx.AsyncClient:
        """Get or create async HTTP client."""
        if self._http_client is None:
            import httpx

            self._http_client = httpx.AsyncClient(timeout=self._timeout, follow_redirects=True)
        return self._http_client

    async def aclose(self) -> None:
        """Close async HTTP client if we own it."""
        if self._owns_client and self._http_client:
            await self._http_client.aclose()
            self._http_client = None

    async def __aenter__(self) -> HTTPFacilitatorClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.aclose()

    # =========================================================================
    # FacilitatorClient Implementation (Async)
    # =========================================================================

    async def verify(
        self,
        payload: PaymentPayload | PaymentPayloadV1,
        requirements: PaymentRequirements | PaymentRequirementsV1,
    ) -> VerifyResponse:
        """Verify a payment with the facilitator (async).

        Args:
            payload: Payment payload to verify.
            requirements: Requirements to verify against.

        Returns:
            VerifyResponse.

        Raises:
            httpx.HTTPError: If request fails.
            ValueError: If response is invalid.
        """
        return await self._verify_http(
            payload.x402_version,
            payload.model_dump(by_alias=True, exclude_none=True),
            requirements.model_dump(by_alias=True, exclude_none=True),
        )

    async def settle(
        self,
        payload: PaymentPayload | PaymentPayloadV1,
        requirements: PaymentRequirements | PaymentRequirementsV1,
        settlement_type: str | None = None,
        settlement_data: str | None = None,
    ) -> SettleResponse:
        """Settle a payment with the facilitator (async).

        Args:
            payload: Payment payload to settle.
            requirements: Requirements for settlement.

        Returns:
            SettleResponse.

        Raises:
            httpx.HTTPError: If request fails.
            ValueError: If response is invalid.
        """
        return await self._settle_http(
            payload.x402_version,
            payload.model_dump(by_alias=True, exclude_none=True),
            requirements.model_dump(by_alias=True, exclude_none=True),
        )

    async def settle_data(
        self,
        settlement_type: str,
        settlement_data: str | None = None,
    ) -> None:
        """Submit settlement data to facilitator (async)."""
        await self._settle_data_http(settlement_type, settlement_data)

    def get_supported(self) -> SupportedResponse:
        """Get supported payment kinds and extensions.

        Note: This is sync because it's called during initialization.

        Returns:
            SupportedResponse.

        Raises:
            httpx.HTTPError: If request fails.
        """
        # Use sync client for initialization (called from sync initialize())
        with self._get_sync_client() as client:
            response = client.get(
                f"{self._url}/supported",
                headers=self._get_supported_headers(),
            )

            if response.status_code != 200:
                raise ValueError(
                    f"Facilitator get_supported failed ({response.status_code}): {response.text}"
                )

            return _parse_facilitator_response(response, SupportedResponse, "supported")

    # =========================================================================
    # Bytes-Based Methods (Network Boundary)
    # =========================================================================

    async def verify_from_bytes(
        self,
        payload_bytes: bytes,
        requirements_bytes: bytes,
    ) -> VerifyResponse:
        """Verify payment from raw JSON bytes.

        Operates at network boundary - detects version from bytes.

        Args:
            payload_bytes: JSON bytes of payment payload.
            requirements_bytes: JSON bytes of requirements.

        Returns:
            VerifyResponse.
        """
        from ..schemas.helpers import detect_version

        version = detect_version(payload_bytes)
        payload_dict = json.loads(payload_bytes)
        requirements_dict = json.loads(requirements_bytes)

        return await self._verify_http(version, payload_dict, requirements_dict)

    async def settle_from_bytes(
        self,
        payload_bytes: bytes,
        requirements_bytes: bytes,
        settlement_type: str | None = None,
        settlement_data: str | None = None,
    ) -> SettleResponse:
        """Settle payment from raw JSON bytes.

        Operates at network boundary - detects version from bytes.

        Args:
            payload_bytes: JSON bytes of payment payload.
            requirements_bytes: JSON bytes of requirements.

        Returns:
            SettleResponse.
        """
        from ..schemas.helpers import detect_version

        version = detect_version(payload_bytes)
        payload_dict = json.loads(payload_bytes)
        requirements_dict = json.loads(requirements_bytes)

        return await self._settle_http(
            version,
            payload_dict,
            requirements_dict,
        )

    # =========================================================================
    # Internal HTTP Methods (Async)
    # =========================================================================

    async def _verify_http(
        self,
        version: int,
        payload_dict: dict[str, Any],
        requirements_dict: dict[str, Any],
    ) -> VerifyResponse:
        """Internal verify via HTTP (async)."""
        client = self._get_async_client()
        request_body = self._build_request_body(version, payload_dict, requirements_dict)

        response = await client.post(
            f"{self._url}/verify",
            headers=self._get_verify_headers(),
            json=request_body,
        )

        if response.status_code != 200:
            raise ValueError(f"Facilitator verify failed ({response.status_code}): {response.text}")

        return _parse_facilitator_response(response, VerifyResponse, "verify")

    async def _settle_http(
        self,
        version: int,
        payload_dict: dict[str, Any],
        requirements_dict: dict[str, Any],
    ) -> SettleResponse:
        """Internal settle via HTTP (async)."""
        client = self._get_async_client()
        request_body = self._build_request_body(version, payload_dict, requirements_dict)

        response = await client.post(
            f"{self._url}/settle",
            headers=self._get_settle_headers(),
            json=request_body,
        )

        if response.status_code == 202:
            if not self._wait_for_settlement:
                return _parse_async_settle_acceptance(response, requirements_dict)
            job_id = _extract_job_id(response)
            if job_id is None:
                logger.warning(
                    "SETTLE_HTTP: 202 acceptance had no job id; cannot confirm settlement"
                )
                return _parse_async_settle_acceptance(response, requirements_dict)
            return await self._poll_settlement_job(job_id, requirements_dict)

        if response.status_code != 200:
            raise ValueError(f"Facilitator settle failed ({response.status_code}): {response.text}")

        return _parse_facilitator_response(response, SettleResponse, "settle")

    async def _poll_settlement_job(
        self,
        job_id: str,
        requirements_dict: dict[str, Any],
    ) -> SettleResponse:
        """Poll ``GET /settle/:jobId`` until the settlement is terminal (async)."""
        client = self._get_async_client()
        url = f"{self._url}/settle/{job_id}"
        deadline = time.monotonic() + self._settlement_poll_timeout

        while True:
            try:
                response = await client.get(url, headers=self._get_settle_headers())
                if response.status_code == 200:
                    result = _settle_response_from_job_status(response.json(), requirements_dict)
                    if result is not None:
                        return result
                elif response.status_code != 404:
                    logger.warning(
                        "SETTLE_POLL: unexpected status=%d for job %s",
                        response.status_code,
                        job_id,
                    )
            except (json.JSONDecodeError, ValueError, TypeError) as exc:
                logger.warning("SETTLE_POLL: bad status body for job %s: %s", job_id, exc)

            if time.monotonic() >= deadline:
                logger.error(
                    "SETTLE_POLL: settlement job %s did not confirm within %.0fs",
                    job_id,
                    self._settlement_poll_timeout,
                )
                return SettleResponse(
                    success=False,
                    transaction=job_id,
                    network=requirements_dict["network"],
                    error_reason="settlement_timeout",
                )
            await asyncio.sleep(self._settlement_poll_interval)

    async def _settle_data_http(
        self,
        settlement_type: str,
        settlement_data: str | None = None,
    ) -> None:
        """Internal settle_data via HTTP (async)."""
        client = self._get_async_client()
        response = await client.post(
            f"{self._url}/settle_data",
            headers=self._get_settle_data_headers(settlement_type, settlement_data),
            json={},
        )
        if response.status_code not in (200, 202):
            raise ValueError(
                f"Facilitator settle_data failed ({response.status_code}): {response.text}"
            )


# ============================================================================
# Sync HTTP Facilitator Client
# ============================================================================


class HTTPFacilitatorClientSync(HTTPFacilitatorClientBase):
    """Sync HTTP-based facilitator client.

    Communicates with remote x402 facilitator services over HTTP using
    sync httpx.Client. Use with x402ResourceServerSync (sync).

    Example:
        ```python
        from x402.http import HTTPFacilitatorClientSync, FacilitatorConfig

        facilitator = HTTPFacilitatorClientSync(FacilitatorConfig(url="https://..."))

        # Sync usage
        result = facilitator.verify(payload, requirements)
        ```
    """

    def _get_client(self) -> httpx.Client:
        """Get or create HTTP client."""
        if self._http_client is None:
            import httpx

            self._http_client = httpx.Client(timeout=self._timeout, follow_redirects=True)
        return self._http_client

    def close(self) -> None:
        """Close HTTP client if we own it."""
        if self._owns_client and self._http_client:
            self._http_client.close()
            self._http_client = None

    def __enter__(self) -> HTTPFacilitatorClientSync:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    # =========================================================================
    # FacilitatorClientSync Implementation
    # =========================================================================

    def verify(
        self,
        payload: PaymentPayload | PaymentPayloadV1,
        requirements: PaymentRequirements | PaymentRequirementsV1,
    ) -> VerifyResponse:
        """Verify a payment with the facilitator.

        Args:
            payload: Payment payload to verify.
            requirements: Requirements to verify against.

        Returns:
            VerifyResponse.

        Raises:
            httpx.HTTPError: If request fails.
            ValueError: If response is invalid.
        """
        return self._verify_http(
            payload.x402_version,
            payload.model_dump(by_alias=True, exclude_none=True),
            requirements.model_dump(by_alias=True, exclude_none=True),
        )

    def settle(
        self,
        payload: PaymentPayload | PaymentPayloadV1,
        requirements: PaymentRequirements | PaymentRequirementsV1,
        settlement_type: str | None = None,
        settlement_data: str | None = None,
    ) -> SettleResponse:
        """Settle a payment with the facilitator.

        Args:
            payload: Payment payload to settle.
            requirements: Requirements for settlement.

        Returns:
            SettleResponse.

        Raises:
            httpx.HTTPError: If request fails.
            ValueError: If response is invalid.
        """
        return self._settle_http(
            payload.x402_version,
            payload.model_dump(by_alias=True, exclude_none=True),
            requirements.model_dump(by_alias=True, exclude_none=True),
        )

    def settle_data(
        self,
        settlement_type: str,
        settlement_data: str | None = None,
    ) -> None:
        """Submit settlement data to facilitator (sync)."""
        self._settle_data_http(settlement_type, settlement_data)

    def get_supported(self) -> SupportedResponse:
        """Get supported payment kinds and extensions.

        Returns:
            SupportedResponse.

        Raises:
            httpx.HTTPError: If request fails.
        """
        client = self._get_client()

        response = client.get(
            f"{self._url}/supported",
            headers=self._get_supported_headers(),
        )

        if response.status_code != 200:
            raise ValueError(
                f"Facilitator get_supported failed ({response.status_code}): {response.text}"
            )

        return _parse_facilitator_response(response, SupportedResponse, "supported")

    # =========================================================================
    # Bytes-Based Methods (Network Boundary)
    # =========================================================================

    def verify_from_bytes(
        self,
        payload_bytes: bytes,
        requirements_bytes: bytes,
    ) -> VerifyResponse:
        """Verify payment from raw JSON bytes.

        Operates at network boundary - detects version from bytes.

        Args:
            payload_bytes: JSON bytes of payment payload.
            requirements_bytes: JSON bytes of requirements.

        Returns:
            VerifyResponse.
        """
        from ..schemas.helpers import detect_version

        version = detect_version(payload_bytes)
        payload_dict = json.loads(payload_bytes)
        requirements_dict = json.loads(requirements_bytes)

        return self._verify_http(version, payload_dict, requirements_dict)

    def settle_from_bytes(
        self,
        payload_bytes: bytes,
        requirements_bytes: bytes,
        settlement_type: str | None = None,
        settlement_data: str | None = None,
    ) -> SettleResponse:
        """Settle payment from raw JSON bytes.

        Operates at network boundary - detects version from bytes.

        Args:
            payload_bytes: JSON bytes of payment payload.
            requirements_bytes: JSON bytes of requirements.

        Returns:
            SettleResponse.
        """
        from ..schemas.helpers import detect_version

        version = detect_version(payload_bytes)
        payload_dict = json.loads(payload_bytes)
        requirements_dict = json.loads(requirements_bytes)

        return self._settle_http(
            version,
            payload_dict,
            requirements_dict,
        )

    # =========================================================================
    # Internal HTTP Methods
    # =========================================================================

    def _verify_http(
        self,
        version: int,
        payload_dict: dict[str, Any],
        requirements_dict: dict[str, Any],
    ) -> VerifyResponse:
        """Internal verify via HTTP."""
        client = self._get_client()
        request_body = self._build_request_body(version, payload_dict, requirements_dict)

        response = client.post(
            f"{self._url}/verify",
            headers=self._get_verify_headers(),
            json=request_body,
        )

        if response.status_code != 200:
            raise ValueError(f"Facilitator verify failed ({response.status_code}): {response.text}")

        return _parse_facilitator_response(response, VerifyResponse, "verify")

    def _settle_http(
        self,
        version: int,
        payload_dict: dict[str, Any],
        requirements_dict: dict[str, Any],
    ) -> SettleResponse:
        """Internal settle via HTTP."""
        client = self._get_client()
        request_body = self._build_request_body(version, payload_dict, requirements_dict)
        url = f"{self._url}/settle"

        logger.info(
            "SETTLE_HTTP: POST %s scheme=%s network=%s amount=%s",
            url,
            requirements_dict.get("scheme", "?"),
            requirements_dict.get("network", "?"),
            requirements_dict.get("amount", "?"),
        )

        response = client.post(url, headers=self._get_settle_headers(), json=request_body)

        logger.info("SETTLE_HTTP: response status=%d", response.status_code)

        if response.status_code == 202:
            if not self._wait_for_settlement:
                return _parse_async_settle_acceptance(response, requirements_dict)
            job_id = _extract_job_id(response)
            if job_id is None:
                logger.warning(
                    "SETTLE_HTTP: 202 acceptance had no job id; cannot confirm settlement"
                )
                return _parse_async_settle_acceptance(response, requirements_dict)
            return self._poll_settlement_job(job_id, requirements_dict)

        if response.status_code != 200:
            logger.error(
                "SETTLE_HTTP: failed status=%d body=%s",
                response.status_code,
                response.text[:500],
            )
            raise ValueError(f"Facilitator settle failed ({response.status_code}): {response.text}")

        return _parse_facilitator_response(response, SettleResponse, "settle")

    def _poll_settlement_job(
        self,
        job_id: str,
        requirements_dict: dict[str, Any],
    ) -> SettleResponse:
        """Poll ``GET /settle/:jobId`` until the settlement is terminal.

        Returns a failure SettleResponse (rather than optimistically reporting
        success) if the job reverts or does not confirm within the timeout, so
        the caller can keep the session for retry / re-challenge.
        """
        client = self._get_client()
        url = f"{self._url}/settle/{job_id}"
        deadline = time.monotonic() + self._settlement_poll_timeout

        while True:
            try:
                response = client.get(url, headers=self._get_settle_headers())
                if response.status_code == 200:
                    result = _settle_response_from_job_status(response.json(), requirements_dict)
                    if result is not None:
                        return result
                elif response.status_code != 404:
                    logger.warning(
                        "SETTLE_POLL: unexpected status=%d for job %s",
                        response.status_code,
                        job_id,
                    )
            except (json.JSONDecodeError, ValueError, TypeError) as exc:
                logger.warning("SETTLE_POLL: bad status body for job %s: %s", job_id, exc)

            if time.monotonic() >= deadline:
                logger.error(
                    "SETTLE_POLL: settlement job %s did not confirm within %.0fs",
                    job_id,
                    self._settlement_poll_timeout,
                )
                return SettleResponse(
                    success=False,
                    transaction=job_id,
                    network=requirements_dict["network"],
                    error_reason="settlement_timeout",
                )
            time.sleep(self._settlement_poll_interval)

    def _settle_data_http(
        self,
        settlement_type: str,
        settlement_data: str | None = None,
    ) -> None:
        """Internal settle_data via HTTP."""
        client = self._get_client()
        url = f"{self._url}/settle_data"
        headers = self._get_settle_data_headers(settlement_type, settlement_data)
        logger.debug(
            "POST %s type=%s data_len=%d",
            url,
            settlement_type,
            len(settlement_data) if settlement_data else 0,
        )
        response = client.post(url, headers=headers, json={})
        if response.status_code not in (200, 202):
            raise ValueError(
                f"Facilitator settle_data failed ({response.status_code}): {response.text}"
            )
        logger.debug("settle_data response: %s", response.status_code)
