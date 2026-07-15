"""Flask middleware for x402 payment handling.

Provides payment-gated route protection for Flask applications.
Uses x402HTTPResourceServerSync for synchronous request processing without asyncio overhead.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import logging
import re
import threading
from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING, Any

try:
    from flask import Flask, Request, g, request
except ImportError as e:
    raise ImportError(
        "Flask middleware requires the flask package. Install with: uv add x402[flask]"
    ) from e

from ...schemas import SettleResponse, VerifiedPaymentCancelOptions
from ..constants import PAYMENT_RESPONSE_HEADER, SETTLEMENT_OVERRIDES_HEADER
from ..facilitator_client_base import FacilitatorResponseError
from ..types import (
    HTTPAdapter,
    HTTPRequestContext,
    HTTPTransportContext,
    PaywallConfig,
    RoutesConfig,
)
from ..x402_http_server import PaywallProvider, x402HTTPResourceServerSync

if TYPE_CHECKING:
    from ...server import x402ResourceServerSync


# ============================================================================
# Extension Auto-Registration
# ============================================================================

from ._bazaar_utils import (
    check_if_bazaar_needed as _check_if_bazaar_needed,
)
from ._bazaar_utils import (
    register_bazaar_extension as _register_bazaar_extension,
)
from ._bazaar_utils import (
    validate_bazaar_extensions as _validate_bazaar_extensions,
)

logger = logging.getLogger(__name__)

StreamingCostCalculator = Callable[[dict[str, Any]], int | str]
StreamingReceiptEncoder = Callable[[dict[str, Any], dict[str, Any] | None], bytes]


def _parse_json_bytes(data: bytes) -> Any | None:
    try:
        return json.loads(data) if data else None
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def _parse_sse_final_json(data: bytes) -> dict[str, Any] | None:
    last_json: dict[str, Any] | None = None
    for line in data.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        payload = line[len("data:") :].strip()
        if payload == "[DONE]":
            continue
        try:
            parsed = json.loads(payload)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(parsed, dict):
            last_json = parsed
    return last_json


def _is_sse_done_event(event: bytes) -> bool:
    for line in event.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if line.startswith("data:"):
            return line[len("data:") :].strip() == "[DONE]"
    return False


def _encode_sse_event(name: str, payload: dict[str, Any]) -> bytes:
    encoded = json.dumps(payload, separators=(",", ":"), default=str)
    return f"event: {name}\ndata: {encoded}\n\n".encode()


def _read_body_bytes(environ: dict[str, Any]) -> bytes:
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except (TypeError, ValueError):
        length = 0
    if length <= 0:
        return b""
    body = environ["wsgi.input"].read(length)
    environ["wsgi.input"] = io.BytesIO(body)
    return body


def _sha256_bytes32(data: bytes) -> str:
    return "0x" + hashlib.sha256(data).hexdigest()


def _to_serializable_body(value: Any) -> Any:
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        return str(value)


def _encode_settlement_data(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8")
    return base64.b64encode(encoded).decode("ascii")


def _normalize_settlement_type(raw_value: str | None) -> str | None:
    if not raw_value:
        return None
    normalized = re.sub(r"[\s_-]+", "", raw_value).lower()
    if normalized in {"private", "pivate"}:
        return "private"
    if normalized == "batch":
        return "batch"
    if normalized in {"individual", "inidvidual"}:
        return "individual"
    return None


def _extract_eth_address_from_payment_payload(payment_payload: Any) -> str | None:
    if not hasattr(payment_payload, "model_dump"):
        return None
    payload = payment_payload.model_dump(by_alias=True, exclude_none=True)
    inner = payload.get("payload", {})
    if not isinstance(inner, dict):
        return None
    authorization = inner.get("authorization")
    if isinstance(authorization, dict):
        address = authorization.get("from")
        if isinstance(address, str) and address:
            return address
    permit2 = inner.get("permit2Authorization", inner.get("permit2_authorization"))
    if isinstance(permit2, dict):
        address = permit2.get("spender")
        if isinstance(address, str) and address:
            return address
    return None

# ============================================================================
# Flask Adapter
# ============================================================================


class FlaskAdapter(HTTPAdapter):
    """Adapter for Flask Request.

    Implements HTTPAdapter protocol for Flask framework.
    """

    def __init__(self, request: Request) -> None:
        """Create adapter from Flask request.

        Args:
            request: Flask request object.
        """
        self._request = request

    def get_header(self, name: str) -> str | None:
        """Get header value (case-insensitive).

        Args:
            name: Header name.

        Returns:
            Header value or None.
        """
        return self._request.headers.get(name)

    def get_method(self) -> str:
        """Get HTTP method.

        Returns:
            HTTP method (GET, POST, etc.).
        """
        return self._request.method

    def get_path(self) -> str:
        """Get request path.

        Returns:
            Request path.
        """
        return self._request.path

    def get_url(self) -> str:
        """Get full request URL.

        Returns:
            Full URL string.
        """
        return self._request.url

    def get_accept_header(self) -> str:
        """Get Accept header.

        Returns:
            Accept header value.
        """
        return self._request.headers.get("accept", "")

    def get_user_agent(self) -> str:
        """Get User-Agent header.

        Returns:
            User-Agent header value.
        """
        return self._request.headers.get("user-agent", "")

    def get_query_params(self) -> dict[str, str | list[str]]:
        """Get query parameters.

        Returns:
            Dict of query parameters.
        """
        return dict(self._request.args)

    def get_query_param(self, name: str) -> str | None:
        """Get single query parameter.

        Args:
            name: Parameter name.

        Returns:
            Parameter value or None.
        """
        return self._request.args.get(name)

    def get_body(self) -> Any:
        """Get request body.

        Returns:
            Parsed JSON body or None.
        """
        return self._request.get_json(silent=True)


# ============================================================================
# Response Wrapper for Settlement
# ============================================================================


def _facilitator_error_wsgi_response(
    start_response: Callable[..., Any],
    error: FacilitatorResponseError,
) -> list[bytes]:
    """Map invalid facilitator responses to a stable HTTP error."""
    body = json.dumps({"error": str(error)}).encode("utf-8")
    start_response(
        "502 Bad Gateway",
        [("Content-Type", "application/json")],
    )
    return [body]


class ResponseWrapper:
    """Wrapper to capture and buffer WSGI response for settlement.

    Captures status, headers, and body from the WSGI response so we can
    process settlement before releasing to the client.
    """

    def __init__(self, start_response: Callable[..., Any]) -> None:
        """Create response wrapper.

        Args:
            start_response: Original WSGI start_response callable.
        """
        self._original_start_response = start_response
        self.status: str | None = None
        self.status_code: int | None = None
        self.headers: list[tuple[str, str]] = []
        self._write_chunks: list[bytes] = []

    def __call__(
        self,
        status: str,
        headers: list[tuple[str, str]],
        exc_info: Any = None,
    ) -> Callable[[bytes], None]:
        """Capture status and headers, return buffered write function.

        Args:
            status: HTTP status string.
            headers: Response headers.
            exc_info: Exception info (if any).

        Returns:
            Buffered write function.
        """
        self.status = status
        self.status_code = int(status.split()[0])
        self.headers = list(headers)

        def buffered_write(data: bytes) -> None:
            if data:
                self._write_chunks.append(data)

        return buffered_write

    def add_header(self, name: str, value: str) -> None:
        """Add header to response.

        Args:
            name: Header name.
            value: Header value.
        """
        self.headers.append((name, value))

    def send_response(self, body_chunks: list[bytes]) -> None:
        """Send buffered response to client.

        Args:
            body_chunks: Response body chunks.
        """
        write = self._original_start_response(self.status, self.headers)

        # Send write() chunks first
        for chunk in self._write_chunks:
            if chunk:
                write(chunk)

        # Then body iterator chunks
        for chunk in body_chunks:
            if chunk:
                write(chunk)


class StatusCapture:
    """Capture WSGI response headers until either buffering or streaming is selected."""

    def __init__(self, start_response: Callable[..., Any]) -> None:
        self._start_response = start_response
        self.status_code = 200
        self.status: str | None = None
        self.headers: list[tuple[str, str]] = []
        self._write_chunks: list[bytes] = []
        self._started = False

    def __call__(
        self,
        status: str,
        headers: list[tuple[str, str]],
        exc_info: Any = None,
    ) -> Callable[[bytes], None]:
        self.status = status
        self.status_code = int(status.split()[0])
        self.headers = list(headers)

        def buffered_write(data: bytes) -> None:
            if data:
                self._write_chunks.append(data)

        return buffered_write

    def add_header(self, name: str, value: str) -> None:
        self.headers.append((name, value))

    def start_streaming(self) -> Callable[[bytes], None]:
        if self._started:
            raise RuntimeError("WSGI response has already started")
        self._started = True
        return self._start_response(self.status, self.headers)

    def send_response(self, body_chunks: list[bytes]) -> None:
        write = self.start_streaming()
        for chunk in self._write_chunks:
            write(chunk)
        for chunk in body_chunks:
            if chunk:
                write(chunk)


class BatchSettlementStreamingResponse:
    """Stream a batch payment response and settle its actual cost at completion."""

    def __init__(
        self,
        upstream: Iterator[bytes],
        middleware: PaymentMiddleware,
        payment_payload: Any,
        payment_requirements: Any,
        declared_extensions: dict[str, Any] | None,
        context: HTTPRequestContext,
        transport_context: HTTPTransportContext,
        request_body_bytes: bytes,
        status_capture: StatusCapture,
        dispatcher: Any,
        requested_settlement_type: str | None,
        streaming_cost_context: dict[str, Any] | None = None,
        settlement_boundary: bytes | None = None,
        receipt_encoder: StreamingReceiptEncoder | None = None,
    ) -> None:
        self._upstream = upstream
        self._middleware = middleware
        self._payment_payload = payment_payload
        self._payment_requirements = payment_requirements
        self._declared_extensions = declared_extensions
        self._context = context
        self._transport_context = transport_context
        self._request_body_bytes = request_body_bytes
        self._status_capture = status_capture
        self._dispatcher = dispatcher
        self._requested_settlement_type = requested_settlement_type
        self._streaming_cost_context = streaming_cost_context
        self._settlement_boundary = settlement_boundary
        self._receipt_encoder = receipt_encoder
        self._captured: list[bytes] = []
        self._buffer = b""
        self._done_event = b"data: [DONE]\n\n"
        self._completed = False
        self._saw_done_event = False

    def _cancel_verified_payment(self, error: Exception | None = None) -> None:
        """Release a channel reservation when streaming cannot settle it."""
        if self._completed:
            return
        self._completed = True
        if self._dispatcher is not None:
            self._dispatcher.cancel_sync(
                VerifiedPaymentCancelOptions(reason="handler_failed", error=error)
            )

    def __iter__(self) -> Iterator[bytes]:
        try:
            write = self._status_capture.start_streaming()
            is_opaque_stream = self._settlement_boundary is not None
            for chunk in self._status_capture._write_chunks:
                self._captured.append(chunk)
                write(chunk)
            for chunk in self._upstream:
                if not chunk:
                    continue

                # Opaque streaming transports (such as chunked OHTTP) cannot
                # carry a late HTTP header. Their application yields this
                # private boundary after it has computed the actual cost but
                # before its final protocol chunk. Settle here, replace the
                # boundary with a transport-specific private receipt frame,
                # then continue streaming the final protocol chunk unchanged.
                if self._settlement_boundary is not None and chunk == self._settlement_boundary:
                    receipt = self._middleware._complete_batch_streaming_settlement(
                        payment_payload=self._payment_payload,
                        payment_requirements=self._payment_requirements,
                        declared_extensions=self._declared_extensions,
                        context=self._context,
                        transport_context=self._transport_context,
                        request_body_bytes=self._request_body_bytes,
                        response_body_bytes=b"".join(self._captured),
                        response_headers=dict(self._status_capture.headers),
                        requested_settlement_type=self._requested_settlement_type,
                        streaming_cost_context=self._streaming_cost_context,
                    )
                    if receipt.get("success"):
                        self._completed = True
                    else:
                        self._cancel_verified_payment(
                            RuntimeError(
                                "batch streaming settlement failed: "
                                f"{receipt.get('error', 'unknown error')}"
                            )
                        )
                    if self._receipt_encoder is not None:
                        receipt_frame = self._receipt_encoder(
                            receipt, self._streaming_cost_context
                        )
                        if receipt_frame:
                            yield receipt_frame
                    continue

                self._captured.append(chunk)
                if is_opaque_stream:
                    # OHTTP bytes are opaque and may coincidentally contain
                    # SSE delimiters. Forward them immediately and unchanged.
                    yield chunk
                    continue
                self._buffer += chunk

                while b"\n\n" in self._buffer:
                    event, self._buffer = self._buffer.split(b"\n\n", 1)
                    event_bytes = event + b"\n\n"
                    if _is_sse_done_event(event_bytes):
                        self._done_event = event_bytes
                        self._saw_done_event = True
                        continue
                    yield event_bytes

            if self._buffer:
                if _is_sse_done_event(self._buffer):
                    self._done_event = (
                        self._buffer
                        if self._buffer.endswith(b"\n\n")
                        else self._buffer + b"\n\n"
                    )
                    self._saw_done_event = True
                else:
                    yield self._buffer
                self._buffer = b""

            if is_opaque_stream:
                if not self._completed:
                    self._cancel_verified_payment(
                        RuntimeError("stream missing settlement boundary")
                    )
                return

            # SSE has no private boundary: its final settlement event is part
            # of the public stream and is emitted immediately before [DONE].
            if self._completed:
                return
            if not self._saw_done_event:
                self._cancel_verified_payment(RuntimeError("stream ended without [DONE]"))
                return
            receipt = self._middleware._complete_batch_streaming_settlement(
                payment_payload=self._payment_payload,
                payment_requirements=self._payment_requirements,
                declared_extensions=self._declared_extensions,
                context=self._context,
                transport_context=self._transport_context,
                request_body_bytes=self._request_body_bytes,
                response_body_bytes=b"".join(self._captured),
                response_headers=dict(self._status_capture.headers),
                requested_settlement_type=self._requested_settlement_type,
                streaming_cost_context=self._streaming_cost_context,
            )
            if receipt.get("success"):
                self._completed = True
            else:
                self._cancel_verified_payment(
                    RuntimeError(
                        "batch streaming settlement failed: "
                        f"{receipt.get('error', 'unknown error')}"
                    )
                )
            yield _encode_sse_event("x402-settlement", receipt)
            yield self._done_event
        finally:
            if not self._completed:
                self._cancel_verified_payment(RuntimeError("stream interrupted"))
            if hasattr(self._upstream, "close"):
                self._upstream.close()

    def close(self) -> None:
        if hasattr(self._upstream, "close"):
            self._upstream.close()
        if not self._completed:
            self._cancel_verified_payment(RuntimeError("stream closed before settlement"))


# ============================================================================
# Flask Middleware Class
# ============================================================================


class PaymentMiddleware:
    """Flask WSGI middleware for x402 payment handling.

    Example:
        ```python
        from flask import Flask
        from x402 import x402ResourceServer
        from x402.http import HTTPFacilitatorClient
        from x402.http.middleware import FlaskPaymentMiddleware

        app = Flask(__name__)

        # Configure server
        facilitator = HTTPFacilitatorClient()
        server = x402ResourceServer(facilitator)

        # Define routes
        routes = {
            "GET /api/weather/*": {
                "accepts": {...}
            }
        }

        # Add middleware
        middleware = FlaskPaymentMiddleware(app, routes, server)
        ```
    """

    def __init__(
        self,
        app: Flask,
        routes: RoutesConfig,
        server: x402ResourceServerSync,
        paywall_config: PaywallConfig | None = None,
        paywall_provider: PaywallProvider | None = None,
        sync_facilitator_on_start: bool = True,
        streaming_cost_calculator: StreamingCostCalculator | None = None,
        settlement_data_enabled: bool = False,
        streaming_settlement_boundary: bytes | None = None,
        streaming_receipt_encoder: StreamingReceiptEncoder | None = None,
    ) -> None:
        """Initialize Flask payment middleware.

        Args:
            app: Flask application.
            routes: Route configuration.
            server: x402ResourceServerSync instance (must be sync variant).
            paywall_config: Optional paywall configuration.
            paywall_provider: Optional custom paywall provider.
            sync_facilitator_on_start: Initialize on first protected request.
        """
        # Auto-register bazaar extension if routes declare it
        if _check_if_bazaar_needed(routes):
            _register_bazaar_extension(server)
            _validate_bazaar_extensions(routes)

        self._app = app
        self._resource_server = server
        self._http_server = x402HTTPResourceServerSync(server, routes)
        self._paywall_config = paywall_config
        self._sync_on_start = sync_facilitator_on_start
        self._init_done = False
        self._init_lock = threading.Lock()
        self._original_wsgi = app.wsgi_app
        self._streaming_cost_calculator = streaming_cost_calculator
        self._settlement_data_enabled = settlement_data_enabled
        self._streaming_settlement_boundary = streaming_settlement_boundary
        self._streaming_receipt_encoder = streaming_receipt_encoder

        if paywall_provider:
            self._http_server.register_paywall_provider(paywall_provider)

        # Replace WSGI app
        app.wsgi_app = self._wsgi_middleware  # type: ignore

    def _is_dynamic_batch_payment(
        self,
        payment_payload: Any,
        payment_requirements: Any,
    ) -> bool:
        """Return whether this batch payment needs a post-response cost."""
        if self._streaming_cost_calculator is None:
            return False
        if getattr(payment_requirements, "scheme", None) != "batch-settlement":
            return False
        payload = getattr(payment_payload, "payload", None)
        return isinstance(payload, dict) and payload.get("type") in {"voucher", "deposit"}

    def _is_streamable_dynamic_batch_payment(
        self,
        payment_payload: Any,
        payment_requirements: Any,
        status_capture: StatusCapture,
    ) -> bool:
        if not self._is_dynamic_batch_payment(payment_payload, payment_requirements):
            return False
        if not 200 <= status_capture.status_code < 300:
            return False
        is_sse = any(
            name.lower() == "content-type" and "text/event-stream" in value.lower()
            for name, value in status_capture.headers
        )
        is_opaque_stream = (
            self._streaming_settlement_boundary is not None
            and self._streaming_receipt_encoder is not None
            and any(
                name.lower() == "content-type"
                and "message/ohttp-chunked-res" in value.lower()
                for name, value in status_capture.headers
            )
        )
        return is_sse or is_opaque_stream

    def _calculate_dynamic_batch_charge(
        self,
        *,
        context: HTTPRequestContext,
        payment_payload: Any,
        payment_requirements: Any,
        request_body_bytes: bytes,
        response_body_bytes: bytes,
        streaming_cost_context: dict[str, Any] | None,
        is_streaming: bool,
    ) -> tuple[str, Any]:
        """Calculate the server-owned charge after a batch response completes."""
        output_object = _parse_sse_final_json(response_body_bytes)
        if not is_streaming:
            output_object = _parse_json_bytes(response_body_bytes) or output_object
        if streaming_cost_context is not None:
            inner_response = streaming_cost_context.get("inner_response_json")
            if isinstance(inner_response, dict):
                output_object = inner_response
        cost_context = {
            "method": context.method,
            "path": context.path,
            "request_body_bytes": request_body_bytes,
            "request_json": _parse_json_bytes(request_body_bytes),
            "payment_payload": payment_payload,
            "payment_requirements": payment_requirements,
            "response_body_bytes": response_body_bytes,
            "response_json": output_object,
            "response_object": output_object,
            "is_streaming": is_streaming,
        }
        if streaming_cost_context is not None:
            cost_context.update(streaming_cost_context)
        assert self._streaming_cost_calculator is not None
        return str(self._streaming_cost_calculator(cost_context)), output_object

    def _build_settlement_metadata(
        self,
        *,
        request_body_bytes: bytes,
        response_body_bytes: bytes,
        payment_payload: Any,
        requested_settlement_type: str | None = None,
        output_object: Any | None = None,
    ) -> tuple[str, str | None]:
        """Build the legacy TEE settlement-data payload without changing its shape."""
        if requested_settlement_type == "private":
            return "private", None

        if output_object is None:
            output_object = _parse_json_bytes(response_body_bytes)

        response = output_object if isinstance(output_object, dict) else {}
        tee_signature = response.get("tee_signature")
        tee_id = response.get("tee_id")
        tee_timestamp = response.get("tee_timestamp")
        input_hash = response.get("tee_request_hash") or _sha256_bytes32(request_body_bytes)
        output_hash = response.get("tee_output_hash") or _sha256_bytes32(response_body_bytes)

        if not tee_id:
            tee_id = "0xddc21f2d5d0af861b4fc1390df47f1c93bc5aee54e7e31763e97256d56148253"
        if not tee_signature:
            if requested_settlement_type == "individual":
                return "private", None
            logger.warning(
                "TEE signature missing in response; using placeholder "
                "tee_signature=0x for batch settlement"
            )
            tee_signature = "0x"

        tee_id = str(tee_id)
        if not tee_id.startswith("0x"):
            tee_id = f"0x{tee_id}"

        batch_payload: dict[str, Any] = {
            "tee_id": tee_id,
            "input_hash": input_hash,
            "output_hash": output_hash,
            "tee_signature": tee_signature,
            "tee_timestamp": tee_timestamp,
            "timestamp": tee_timestamp,
        }
        if requested_settlement_type in (None, "batch"):
            return "batch", _encode_settlement_data(batch_payload)

        if requested_settlement_type == "individual":
            eth_address = _extract_eth_address_from_payment_payload(payment_payload)
            if not eth_address or not tee_timestamp:
                logger.warning(
                    "Requested x-settlement-type=individual but eth_address or "
                    "tee_timestamp missing; falling back to batch"
                )
                return "batch", _encode_settlement_data(batch_payload)
            request_object = _parse_json_bytes(request_body_bytes)
            if request_object is None:
                request_object = request_body_bytes.decode("utf-8", errors="replace")
            individual_payload = {
                **batch_payload,
                "input": _to_serializable_body(request_object),
                "output": _to_serializable_body(output_object),
                "timestamp": str(tee_timestamp),
                "eth_address": str(eth_address),
            }
            return "individual", _encode_settlement_data(individual_payload)

        return "batch", _encode_settlement_data(batch_payload)

    def _submit_settlement_data_in_background(
        self,
        payment_payload: Any,
        payment_requirements: Any,
        settlement_type: str,
        settlement_data: str | None,
    ) -> None:
        if not self._settlement_data_enabled or settlement_type == "private" or not settlement_data:
            return

        def submit() -> None:
            try:
                self._resource_server.submit_settlement_data(
                    payment_payload,
                    payment_requirements,
                    settlement_type,
                    settlement_data,
                )
            except Exception:
                logger.exception("Failed to submit settlement data to the facilitator")

        threading.Thread(target=submit, daemon=True, name="x402-settlement-data").start()

    def _complete_batch_streaming_settlement(
        self,
        *,
        payment_payload: Any,
        payment_requirements: Any,
        declared_extensions: dict[str, Any] | None,
        context: HTTPRequestContext,
        transport_context: HTTPTransportContext,
        request_body_bytes: bytes,
        response_body_bytes: bytes,
        response_headers: dict[str, str],
        requested_settlement_type: str | None,
        streaming_cost_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            amount, output_object = self._calculate_dynamic_batch_charge(
                context=context,
                payment_payload=payment_payload,
                payment_requirements=payment_requirements,
                request_body_bytes=request_body_bytes,
                response_body_bytes=response_body_bytes,
                streaming_cost_context=streaming_cost_context,
                is_streaming=True,
            )
            transport_context.response_body = output_object
            transport_context.response_headers = response_headers
            payload = getattr(payment_payload, "payload", None)
            is_deposit = isinstance(payload, dict) and payload.get("type") == "deposit"
            # A deposit funds the channel at its signed buffer amount; only the
            # server's local claim ledger receives the dynamic inference cost.
            # This private context value never becomes an HTTP header, voucher,
            # facilitator payload, or on-chain contract argument.
            if is_deposit:
                setattr(transport_context, "_x402_batch_settlement_charge_amount", amount)
            settle_result = self._http_server.process_settlement(
                payment_payload,
                payment_requirements,
                context=context,
                settlement_overrides=None if is_deposit else {"amount": amount},
                declared_extensions=declared_extensions,
                transport_context=transport_context,
            )
            if not settle_result.success:
                return {"success": False, "error": settle_result.error_reason}

            settlement_type, settlement_data = self._build_settlement_metadata(
                request_body_bytes=request_body_bytes,
                response_body_bytes=response_body_bytes,
                payment_payload=payment_payload,
                requested_settlement_type=requested_settlement_type,
                output_object=output_object,
            )
            self._submit_settlement_data_in_background(
                payment_payload,
                payment_requirements,
                settlement_type,
                settlement_data,
            )
            return {
                "success": True,
                "paymentResponse": settle_result.headers.get(PAYMENT_RESPONSE_HEADER),
            }
        except Exception as error:
            logger.exception("Failed to complete batch streaming settlement")
            return {"success": False, "error": str(error)}

    def _wsgi_middleware(
        self,
        environ: dict[str, Any],
        start_response: Callable[..., Any],
    ) -> Iterator[bytes]:
        """WSGI middleware entry point.

        Args:
            environ: WSGI environment.
            start_response: WSGI start_response callable.

        Returns:
            Response body iterator.
        """
        with self._app.request_context(environ):
            # Create adapter and context
            adapter = FlaskAdapter(request)
            context = HTTPRequestContext(
                adapter=adapter,
                path=request.path,
                method=request.method,
                payment_header=(
                    adapter.get_header("payment-signature") or adapter.get_header("x-payment")
                ),
            )

            # Check if route requires payment
            if not self._http_server.requires_payment(context):
                return self._original_wsgi(environ, start_response)

            # Initialize on first protected request (double-checked locking)
            if self._sync_on_start and not self._init_done:
                with self._init_lock:
                    if not self._init_done:
                        try:
                            self._http_server.initialize()
                        except FacilitatorResponseError as error:
                            return _facilitator_error_wsgi_response(start_response, error)
                        self._init_done = True

            # Process payment request synchronously (no asyncio overhead)
            try:
                result = self._http_server.process_http_request(context, self._paywall_config)
            except FacilitatorResponseError as error:
                return _facilitator_error_wsgi_response(start_response, error)

            if result.type == "no-payment-required":
                return self._original_wsgi(environ, start_response)

            if result.type == "payment-error":
                # Return 402 response
                response = result.response
                if response is None:
                    status = "402 Payment Required"
                    headers = [("Content-Type", "application/json")]
                    body = json.dumps({"error": "Payment required"}).encode("utf-8")
                    start_response(status, headers)
                    return [body]

                status = f"{response.status} Payment Required"
                headers = list(response.headers.items())

                if response.is_html:
                    headers.append(("Content-Type", "text/html; charset=utf-8"))
                    body = (
                        response.body.encode("utf-8")
                        if isinstance(response.body, str)
                        else response.body
                    )
                else:
                    headers.append(("Content-Type", "application/json"))
                    body = json.dumps(response.body or {}).encode("utf-8")

                start_response(status, headers)
                return [body]

            if result.type == "payment-verified":
                # Store in Flask g object
                g.payment_payload = result.payment_payload
                g.payment_requirements = result.payment_requirements
                dispatcher = result.cancellation_dispatcher
                transport_context = HTTPTransportContext(request=context)

                request_body_bytes = _read_body_bytes(environ)
                streaming_cost_context = environ.get("x402.cost_context")
                if not isinstance(streaming_cost_context, dict):
                    streaming_cost_context = {}
                    environ["x402.cost_context"] = streaming_cost_context
                response_wrapper = StatusCapture(start_response)
                body_chunks: list[bytes] = []

                try:
                    upstream = self._original_wsgi(environ, response_wrapper)
                    if self._is_streamable_dynamic_batch_payment(
                        result.payment_payload,
                        result.payment_requirements,
                        response_wrapper,
                    ):
                        return BatchSettlementStreamingResponse(
                            upstream,
                            self,
                            result.payment_payload,
                            result.payment_requirements,
                            result.declared_extensions,
                            context,
                            transport_context,
                            request_body_bytes,
                            response_wrapper,
                            dispatcher,
                            _normalize_settlement_type(adapter.get_header("x-settlement-type")),
                            streaming_cost_context,
                            self._streaming_settlement_boundary,
                            self._streaming_receipt_encoder,
                        )
                    for chunk in upstream:
                        body_chunks.append(chunk)
                except BaseException as error:
                    if dispatcher is not None:
                        dispatcher.cancel_sync(
                            VerifiedPaymentCancelOptions(reason="handler_threw", error=error)
                        )
                    raise

                if response_wrapper.status_code is not None and response_wrapper.status_code >= 400:
                    if dispatcher is not None:
                        dispatcher.cancel_sync(
                            VerifiedPaymentCancelOptions(
                                reason="handler_failed",
                                response_status=response_wrapper.status_code,
                            )
                        )
                    response_wrapper.send_response(body_chunks)
                    return []

                # Check if successful response
                if response_wrapper.status_code is not None and response_wrapper.status_code < 400:
                    # Extract settlement overrides from response headers and strip them
                    overrides = self._http_server._extract_settlement_overrides(
                        response_wrapper.headers,
                    )
                    response_wrapper.headers = [
                        (k, v)
                        for k, v in response_wrapper.headers
                        if k.lower() != SETTLEMENT_OVERRIDES_HEADER.lower()
                    ]
                    transport_context.response_headers = dict(response_wrapper.headers)

                    # Settle payment
                    try:
                        if self._is_dynamic_batch_payment(
                            result.payment_payload,
                            result.payment_requirements,
                        ):
                            response_body_bytes = b"".join(
                                response_wrapper._write_chunks + body_chunks
                            )
                            amount, output_object = self._calculate_dynamic_batch_charge(
                                context=context,
                                payment_payload=result.payment_payload,
                                payment_requirements=result.payment_requirements,
                                request_body_bytes=request_body_bytes,
                                response_body_bytes=response_body_bytes,
                                streaming_cost_context=streaming_cost_context,
                                is_streaming=False,
                            )
                            transport_context.response_body = output_object
                            payload = getattr(result.payment_payload, "payload", None)
                            if isinstance(payload, dict) and payload.get("type") == "deposit":
                                setattr(
                                    transport_context,
                                    "_x402_batch_settlement_charge_amount",
                                    amount,
                                )
                            else:
                                overrides = {**(overrides or {}), "amount": amount}
                        settle_result = self._http_server.process_settlement(
                            result.payment_payload,
                            result.payment_requirements,
                            context=context,
                            settlement_overrides=overrides,
                            declared_extensions=result.declared_extensions,
                            transport_context=transport_context,
                        )

                        if settle_result.success:
                            # Add settlement headers
                            for key, value in settle_result.headers.items():
                                response_wrapper.add_header(key, value)
                            if self._settlement_data_enabled:
                                response_body_bytes = b"".join(
                                    response_wrapper._write_chunks + body_chunks
                                )
                                output_object = _parse_json_bytes(response_body_bytes)
                                if output_object is None:
                                    output_object = _parse_sse_final_json(response_body_bytes)
                                settlement_type, settlement_data = self._build_settlement_metadata(
                                    request_body_bytes=request_body_bytes,
                                    response_body_bytes=response_body_bytes,
                                    payment_payload=result.payment_payload,
                                    requested_settlement_type=_normalize_settlement_type(
                                        adapter.get_header("x-settlement-type")
                                    ),
                                    output_object=output_object,
                                )
                                self._submit_settlement_data_in_background(
                                    result.payment_payload,
                                    result.payment_requirements,
                                    settlement_type,
                                    settlement_data,
                                )
                        else:
                            # Settlement failed - use response from process_settlement
                            # (includes PAYMENT-RESPONSE header and empty body by default)
                            response = settle_result.response
                            if response is None:
                                status = "402 Payment Required"
                                headers = [("Content-Type", "application/json")]
                                body = json.dumps({}).encode("utf-8")
                            else:
                                status = f"{response.status} Payment Required"
                                headers = list(response.headers.items())
                                if response.is_html:
                                    body = (
                                        response.body.encode("utf-8")
                                        if isinstance(response.body, str)
                                        else response.body
                                    )
                                else:
                                    body = json.dumps(response.body or {}).encode("utf-8")
                            start_response(status, headers)
                            return [body]

                    except FacilitatorResponseError as error:
                        return _facilitator_error_wsgi_response(start_response, error)

                    except Exception:
                        # An unexpected error here (RPC failure, bug, ...) is a
                        # server-side failure, not a payment problem. Log it so
                        # operators get a signal (the module otherwise logs
                        # nothing), and surface it as a settle failure
                        # (402 + PAYMENT-RESPONSE, success=False) - consistent with
                        # the not-settle_result.success path and distinguishable
                        # from a genuine "payment required". The client-facing
                        # reason stays generic; the raw exception detail is logged
                        # only. Mirrors the FastAPI fix in #2622.
                        logger.exception("x402: unexpected error while settling a verified payment")
                        settle_response = SettleResponse(
                            success=False,
                            error_reason="unexpected_settle_error",
                            error_message="Unexpected error during settlement",
                            transaction="",
                            network=result.payment_requirements.network,
                        )
                        settle_headers = self._http_server._create_settlement_headers(
                            settle_response, result.payment_requirements
                        )
                        start_response(
                            "402 Payment Required",
                            [("Content-Type", "application/json"), *settle_headers.items()],
                        )
                        return [json.dumps({}).encode("utf-8")]

                # Send buffered response
                response_wrapper.send_response(body_chunks)
                return []

        # Fallthrough
        return self._original_wsgi(environ, start_response)


# ============================================================================
# Convenience Functions
# ============================================================================


def set_settlement_overrides(response: Any, overrides: dict[str, Any]) -> None:
    """Set settlement overrides on a Flask response for partial settlement.

    The middleware extracts these before settlement and strips the header
    from the client response.

    Args:
        response: Flask ``Response`` object (or ``make_response()`` result).
        overrides: Settlement overrides, e.g. ``{"amount": "500"}``.
    """
    response.headers[SETTLEMENT_OVERRIDES_HEADER] = json.dumps(overrides)


def payment_middleware(
    app: Flask,
    routes: RoutesConfig,
    server: x402ResourceServerSync,
    paywall_config: PaywallConfig | None = None,
    paywall_provider: PaywallProvider | None = None,
    sync_facilitator_on_start: bool = True,
    streaming_cost_calculator: StreamingCostCalculator | None = None,
    settlement_data_enabled: bool = False,
    streaming_settlement_boundary: bytes | None = None,
    streaming_receipt_encoder: StreamingReceiptEncoder | None = None,
) -> PaymentMiddleware:
    """Create Flask payment middleware with pre-configured server.

    Args:
        app: Flask application.
        routes: Route configuration for protected endpoints.
        server: Pre-configured x402ResourceServerSync (must be sync variant).
        paywall_config: Optional paywall UI configuration.
        paywall_provider: Optional custom paywall provider.
        sync_facilitator_on_start: Fetch facilitator support on first request.
        streaming_cost_calculator: Resolves actual cost after an SSE response so
            voucher-only batch payments can stream live.
        settlement_data_enabled: Submit legacy TEE metadata to ``/settle_data``
            without delaying the user response.

    Returns:
        PaymentMiddleware instance.
    """
    return PaymentMiddleware(
        app,
        routes,
        server,
        paywall_config,
        paywall_provider,
        sync_facilitator_on_start,
        streaming_cost_calculator,
        settlement_data_enabled,
        streaming_settlement_boundary,
        streaming_receipt_encoder,
    )


def payment_middleware_from_config(
    app: Flask,
    routes: RoutesConfig,
    facilitator_client: Any = None,
    schemes: list[dict[str, Any]] | None = None,
    paywall_config: PaywallConfig | None = None,
    paywall_provider: PaywallProvider | None = None,
    sync_facilitator_on_start: bool = True,
) -> PaymentMiddleware:
    """Create Flask payment middleware from configuration.

    Args:
        app: Flask application.
        routes: Route configuration for protected endpoints.
        facilitator_client: Facilitator client(s) for payment processing.
        schemes: Scheme registrations for server-side processing.
        paywall_config: Optional paywall UI configuration.
        paywall_provider: Optional custom paywall provider.
        sync_facilitator_on_start: Fetch facilitator support on first request.

    Returns:
        PaymentMiddleware instance.
    """
    # Flask's PaymentMiddleware drives x402HTTPResourceServerSync, which rejects a
    # server whose verify_payment is async. Use the sync server; the async
    # x402ResourceServer would raise TypeError at construction. (The FastAPI
    # factory correctly uses the async x402ResourceServer for its async server.)
    from ...server import x402ResourceServerSync

    server = x402ResourceServerSync(facilitator_client)

    if schemes:
        for registration in schemes:
            server.register(registration["network"], registration["server"])

    return PaymentMiddleware(
        app, routes, server, paywall_config, paywall_provider, sync_facilitator_on_start
    )
