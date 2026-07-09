"""Flask middleware for x402 payment handling.

Provides payment-gated route protection for Flask applications.
Uses x402HTTPResourceServerSync for synchronous request processing without asyncio overhead.

Supports two modes:
  - **Legacy (per-request):** Full response buffering + synchronous settlement.
    Active when no ``session_store`` is provided. Backward compatible.
  - **Session (optimistic):** Streaming-friendly, deferred settlement.
    Active when a ``session_store`` is provided.  The response streams
    through immediately, per-request cost is accumulated in a session,
    and a background reaper settles expired / exhausted sessions.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import logging
import re
import threading
import time
from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING, Any

try:
    from flask import Flask, Request, g, request
except ImportError as e:
    raise ImportError(
        "Flask middleware requires the flask package. Install with: uv add x402[flask]"
    ) from e

from ..facilitator_client_base import FacilitatorResponseError
from ..types import (
    HTTPAdapter,
    HTTPRequestContext,
    PaywallConfig,
    RouteConfig,
    RoutesConfig,
)
from ..x402_http_server import PaywallProvider, x402HTTPResourceServerSync
from ...schemas import PaymentPayload, PaymentRequirements, SettlementOverrides
from ...schemas.v1 import PaymentPayloadV1
from ...session import SessionStoreProtocol, UptoSession, signed_authorization_deadline

if TYPE_CHECKING:
    from ...server import x402ResourceServerSync

logger = logging.getLogger("x402.flask")
UPTO_SESSION_HEADER = "X-Upto-Session"


# ============================================================================
# Extension Auto-Registration
# ============================================================================


def _check_if_bazaar_needed(routes: RoutesConfig) -> bool:
    """Check if any routes in the configuration declare bazaar extensions.

    Args:
        routes: Route configuration.

    Returns:
        True if any route has extensions.bazaar defined.
    """
    # Handle single RouteConfig instance
    if isinstance(routes, RouteConfig):
        return bool(routes.extensions and "bazaar" in routes.extensions)

    # Handle dict of routes
    if isinstance(routes, dict):
        # Check if it's a single route config dict (has "accepts" key)
        if "accepts" in routes:
            extensions = routes.get("extensions", {})
            return bool(extensions and "bazaar" in extensions)

        # Handle multiple routes
        for route_config in routes.values():
            if isinstance(route_config, RouteConfig):
                if route_config.extensions and "bazaar" in route_config.extensions:
                    return True
            elif isinstance(route_config, dict):
                extensions = route_config.get("extensions", {})
                if extensions and "bazaar" in extensions:
                    return True

    return False


def _register_bazaar_extension(server: x402ResourceServerSync) -> None:
    """Register bazaar extension with server if available.

    Args:
        server: x402ResourceServerSync to register extension with.
    """
    try:
        from ...extensions.bazaar import bazaar_resource_server_extension

        server.register_extension(bazaar_resource_server_extension)
    except ImportError:
        # Bazaar extension not available, skip silently
        pass


# ============================================================================
# Helpers
# ============================================================================


def _try_parse_json(data: bytes) -> dict | list | None:
    """Attempt to parse bytes as JSON, returning None on failure."""
    try:
        return json.loads(data) if data else None
    except (json.JSONDecodeError, ValueError):
        return None


def _parse_sse_final_json(data: bytes) -> dict | None:
    """Extract the last SSE data event's JSON from a stream of SSE bytes.

    SSE format: lines like ``data: {...}\\n\\n``.  The final non-[DONE]
    data line typically contains usage information (prompt_tokens,
    completion_tokens).
    """
    text = data.decode("utf-8", errors="replace")
    last_json: dict | None = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("data:"):
            payload = line[len("data:"):].strip()
            if payload == "[DONE]":
                continue
            try:
                parsed = json.loads(payload)
                if isinstance(parsed, dict):
                    last_json = parsed
            except (json.JSONDecodeError, ValueError):
                continue
    return last_json


def _read_body_bytes(environ: dict[str, Any]) -> bytes:
    """Read the request body from the WSGI environ and rewind the stream.

    After reading, replaces ``wsgi.input`` with a ``BytesIO`` so
    downstream handlers can re-read the body.
    """
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except (ValueError, TypeError):
        length = 0
    if length <= 0:
        return b""
    body = environ["wsgi.input"].read(length)
    environ["wsgi.input"] = io.BytesIO(body)
    return body


def _session_key_from_payment(payment_header: str) -> str:
    """Derive a deterministic session key from the raw payment header."""
    return hashlib.sha256(payment_header.encode("utf-8")).hexdigest()


# ============================================================================
# TEE Proof Helpers
# ============================================================================

TEE_SIGNATURE_HEADER = "X-TEE-Signature"
TEE_ID_HEADER = "X-TEE-ID"
TEE_TIMESTAMP_HEADER = "X-TEE-Timestamp"
TEE_REQUEST_HASH_HEADER = "X-TEE-Request-Hash"
TEE_OUTPUT_HASH_HEADER = "X-TEE-Output-Hash"


def _parse_json_bytes(data: bytes) -> Any | None:
    """Parse bytes as JSON, returning None on failure."""
    if not data:
        return None
    try:
        return json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def _bytes_to_text(data: bytes) -> str:
    """Decode bytes to text with error replacement."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace")


def _sha256_bytes32(data: bytes) -> str:
    """Return 0x-prefixed SHA-256 hex digest."""
    return "0x" + hashlib.sha256(data).hexdigest()


def _is_hex_bytes32(value: str) -> bool:
    """Check if a string is a valid 0x-prefixed 32-byte hex string."""
    normalized = value if value.startswith("0x") else f"0x{value}"
    return bool(re.fullmatch(r"0x[0-9a-fA-F]{64}", normalized))


def _normalize_bytes32(value: str) -> str:
    """Ensure 0x prefix on a hex string."""
    return value if value.startswith("0x") else f"0x{value}"


def _normalize_lookup_key(value: str) -> str:
    """Collapse whitespace/hyphens/underscores and lowercase."""
    return re.sub(r"[\s_-]+", "", value).lower()


def _find_first_by_normalized_key(obj: Any, normalized_keys: set[str]) -> Any | None:
    """Recursively search a dict/list for the first value matching any key."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(key, str) and _normalize_lookup_key(key) in normalized_keys:
                if value is not None:
                    return value
        for value in obj.values():
            found = _find_first_by_normalized_key(value, normalized_keys)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = _find_first_by_normalized_key(item, normalized_keys)
            if found is not None:
                return found
    return None


def _extract_tee_fields(
    output_obj: Any, fallback_text: str | None = None,
) -> tuple[str | None, str | None]:
    """Extract tee_signature and tee_id from a response object."""
    sig_keys = {"teesignature", "teesingature"}
    id_keys = {"teeid"}
    sig_val = _find_first_by_normalized_key(output_obj, sig_keys)
    id_val = _find_first_by_normalized_key(output_obj, id_keys)
    tee_sig = str(sig_val) if sig_val else None
    tee_id = str(id_val) if id_val else None
    if fallback_text:
        if not tee_sig:
            m = re.search(
                r'"tee(?:[_\s-]?signature|[_\s-]?singature)"\s*:\s*"([^"]+)"',
                fallback_text, re.IGNORECASE,
            )
            if m:
                tee_sig = m.group(1)
        if not tee_id:
            m = re.search(r'"tee[_\s-]?id"\s*:\s*"([^"]+)"', fallback_text, re.IGNORECASE)
            if m:
                tee_id = m.group(1)
    return tee_sig, tee_id


def _extract_tee_hashes(
    output_obj: Any, fallback_text: str | None = None,
) -> tuple[str | None, str | None]:
    """Extract request_hash and output_hash from a response object."""
    ih: str | None = None
    oh: str | None = None
    if isinstance(output_obj, dict):
        for k in ("tee_request_hash", "request_hash", "input_hash"):
            v = output_obj.get(k)
            if isinstance(v, str) and v:
                ih = v
                break
        for k in ("tee_output_hash", "output_hash"):
            v = output_obj.get(k)
            if isinstance(v, str) and v:
                oh = v
                break
    if not ih or not oh:
        norm_ih = {"teerequesthash", "requesthash", "inputhash"}
        norm_oh = {"teeoutputhash", "outputhash"}
        if not ih:
            v = _find_first_by_normalized_key(output_obj, norm_ih)
            if v is not None:
                ih = str(v)
        if not oh:
            v = _find_first_by_normalized_key(output_obj, norm_oh)
            if v is not None:
                oh = str(v)
    if fallback_text:
        if not ih:
            m = re.search(
                r'"(?:tee[_\s-]?request[_\s-]?hash|request[_\s-]?hash|input[_\s-]?hash)"\s*:\s*"([^"]+)"',
                fallback_text, re.IGNORECASE,
            )
            if m:
                ih = m.group(1)
        if not oh:
            m = re.search(
                r'"(?:tee[_\s-]?output[_\s-]?hash|output[_\s-]?hash)"\s*:\s*"([^"]+)"',
                fallback_text, re.IGNORECASE,
            )
            if m:
                oh = m.group(1)
    nih = _normalize_bytes32(ih) if ih and _is_hex_bytes32(ih) else None
    noh = _normalize_bytes32(oh) if oh and _is_hex_bytes32(oh) else None
    return nih, noh


def _to_unix_uint256_timestamp(value: Any) -> int | None:
    """Convert common timestamp formats into unix epoch seconds."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        ts = int(value)
        return ts if ts >= 0 else None
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None
        if re.fullmatch(r"\d+", raw):
            ts = int(raw)
            return ts if ts >= 0 else None
        from datetime import datetime, timezone

        iso_value = raw.replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(iso_value)
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        ts = int(dt.timestamp())
        return ts if ts >= 0 else None
    return None


def _extract_tee_timestamp(
    output_obj: Any, fallback_text: str | None = None,
) -> int | None:
    """Extract tee_timestamp from a response object."""
    val = _find_first_by_normalized_key(output_obj, {"teetimestamp"})
    ts = _to_unix_uint256_timestamp(val)
    if fallback_text and not ts:
        m = re.search(
            r'"tee[_\s-]?timestamp"\s*:\s*("([^"]+)"|([0-9]+))',
            fallback_text, re.IGNORECASE,
        )
        if m:
            ts = _to_unix_uint256_timestamp(m.group(2) or m.group(3))
    return ts


def _extract_tee_proof_metadata(
    output_obj: Any, fallback_text: str | None = None,
) -> dict[str, Any]:
    """Extract all TEE proof metadata from a response."""
    tee_sig, tee_id = _extract_tee_fields(output_obj, fallback_text)
    ih, oh = _extract_tee_hashes(output_obj, fallback_text)
    ts = _extract_tee_timestamp(output_obj, fallback_text)
    return {
        "tee_signature": tee_sig,
        "tee_id": tee_id,
        "tee_timestamp": ts,
        "tee_input_hash": ih,
        "tee_output_hash": oh,
    }


def _extract_eth_address_from_payment_payload(payment_payload: Any) -> str | None:
    """Extract the payer's Ethereum address from a payment payload."""
    pd: dict[str, Any] | None = None
    if hasattr(payment_payload, "model_dump"):
        pd = payment_payload.model_dump(by_alias=True, exclude_none=True)
    elif isinstance(payment_payload, dict):
        pd = payment_payload
    if not pd:
        return None
    inner = pd.get("payload", {}) or {}
    if not isinstance(inner, dict):
        return None
    auth = inner.get("authorization")
    if isinstance(auth, dict):
        addr = auth.get("from")
        if isinstance(addr, str) and addr:
            return addr
    p2 = inner.get("permit2Authorization", inner.get("permit2_authorization"))
    if isinstance(p2, dict):
        sp = p2.get("spender")
        if isinstance(sp, str) and sp:
            return sp
    return None


def _to_serializable_body(value: Any) -> Any:
    """Ensure value is JSON-serializable."""
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        return str(value)


def _encode_settlement_data(payload: dict[str, Any]) -> str:
    """Base64-encode a JSON settlement metadata payload."""
    encoded = json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8")
    return base64.b64encode(encoded).decode("ascii")


def _normalize_settlement_type(raw_value: str | None) -> str | None:
    """Normalize client-provided x-settlement-type header."""
    if not raw_value:
        return None
    normalized = _normalize_lookup_key(raw_value)
    if normalized in {"private", "pivate"}:
        return "private"
    if normalized == "batch":
        return "batch"
    if normalized in {"individual", "inidvidual"}:
        return "individual"
    return None


def _extract_sse_json_events(text: str) -> list[Any]:
    """Extract all JSON SSE data events from text."""
    events: list[Any] = []
    for line in text.splitlines():
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if not payload or payload == "[DONE]":
            continue
        try:
            events.append(json.loads(payload))
        except json.JSONDecodeError:
            continue
    return events


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
# Settlement Override Helpers (Flask g-object)
# ============================================================================


def set_settlement_overrides(overrides: SettlementOverrides | None) -> None:
    """Store settlement overrides on Flask's request-global state."""
    g.x402_settlement_overrides = overrides


def get_settlement_overrides() -> SettlementOverrides | None:
    """Read settlement overrides previously stored during the request."""
    return getattr(g, "x402_settlement_overrides", None)


# ============================================================================
# Response Wrappers
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
    """Wrapper to capture and buffer WSGI response for per-request settlement.

    Captures status, headers, and body from the WSGI response so we can
    process settlement before releasing to the client.  Used in legacy mode.
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
    """Thin start_response wrapper that records status code but passes through.

    Used in session mode so headers are committed immediately (streaming).
    """

    def __init__(self, real_start_response: Callable[..., Any]) -> None:
        """Create status capture wrapper.

        Args:
            real_start_response: Original WSGI start_response callable.
        """
        self._real = real_start_response
        self.status_code: int = 200
        self._extra_headers: list[tuple[str, str]] = []

    def add_header(self, name: str, value: str) -> None:
        """Attach a header before the upstream response starts."""
        self._extra_headers.append((name, value))

    def __call__(
        self,
        status: str,
        headers: list[tuple[str, str]],
        exc_info: Any = None,
    ) -> Callable[[bytes], None]:
        """Record status code and delegate to real start_response.

        Args:
            status: HTTP status string.
            headers: Response headers.
            exc_info: Exception info (if any).

        Returns:
            The real write callable.
        """
        self.status_code = int(status.split()[0])
        merged_headers = list(headers)
        if self._extra_headers:
            merged_headers.extend(self._extra_headers)
        return self._real(status, merged_headers, exc_info)


class StreamingSessionResponse:
    """WSGI iterable that tees response bytes for cost calculation.

    Chunks flow through to the client immediately.  After iteration
    completes, ``close()`` computes cost and accumulates it in the session.
    """

    def __init__(
        self,
        upstream_iter: Iterator[bytes],
        middleware: PaymentMiddleware,
        session_id: str,
        cost_context: dict[str, Any],
        status_ref: StatusCapture,
    ) -> None:
        """Create streaming session response wrapper.

        Args:
            upstream_iter: Original WSGI response iterator.
            middleware: Parent middleware for cost accumulation.
            session_id: Active session identifier.
            cost_context: Mutable dict pre-populated with request-side context.
            status_ref: Status capture for reading the response status code.
        """
        self._upstream = upstream_iter
        self._captured: list[bytes] = []
        self._middleware = middleware
        self._session_id = session_id
        self._cost_context = cost_context
        self._status_ref = status_ref

    def __iter__(self) -> Iterator[bytes]:
        """Yield chunks, capturing a copy of each."""
        for chunk in self._upstream:
            if chunk:
                self._captured.append(chunk)
            yield chunk

    def close(self) -> None:
        """Accumulate cost after response completes (WSGI guarantees call)."""
        if hasattr(self._upstream, "close"):
            self._upstream.close()
        try:
            self._middleware._accumulate_session_cost(
                self._session_id,
                self._captured,
                self._status_ref,
                self._cost_context,
            )
        except Exception:
            logger.exception(
                "Failed to compute/accumulate session cost for session %s",
                self._session_id,
            )


# ============================================================================
# Flask Middleware Class
# ============================================================================


class PaymentMiddleware:
    """Flask WSGI middleware for x402 payment handling.

    Supports two modes:

    **Legacy (per-request)** — default when ``session_store`` is None.
    Buffers the full response, settles synchronously, then sends.

    **Session (optimistic)** — when ``session_store`` is provided.
    Streams the response immediately, accumulates cost per-request,
    and defers settlement to a background reaper thread.
    """

    def __init__(
        self,
        app: Flask,
        routes: RoutesConfig,
        server: x402ResourceServerSync,
        paywall_config: PaywallConfig | None = None,
        paywall_provider: PaywallProvider | None = None,
        sync_facilitator_on_start: bool = True,
        # Session-mode parameters
        session_store: SessionStoreProtocol | None = None,
        session_cost_calculator: Callable[[dict[str, Any]], int] | None = None,
        cost_per_request: int | None = None,
        session_idle_timeout: int = 3600,
        settlement_safety_margin: int = 60,
    ) -> None:
        """Initialize Flask payment middleware.

        Args:
            app: Flask application.
            routes: Route configuration.
            server: x402ResourceServerSync instance (must be sync variant).
            paywall_config: Optional paywall configuration.
            paywall_provider: Optional custom paywall provider.
            sync_facilitator_on_start: Initialize on first protected request.
            session_store: Session store for deferred settlement mode.
            session_cost_calculator: Callback ``(context_dict) -> int`` for
                computing per-request cost in token smallest units.
            cost_per_request: Static fallback cost when calculator is absent.
            session_idle_timeout: Seconds before an idle session is settled.
            settlement_safety_margin: Seconds before a session's signed
                authorization deadline at which the reaper force-settles it
                (and stops accepting new draw-downs against it). Guards against
                a long-lived session outliving its own Permit2/EIP-3009
                deadline, which would make the on-chain settlement revert and
                silently drop the tab. Must be smaller than the advertised
                ``max_timeout_seconds`` for a route.
        """
        # Auto-register bazaar extension if routes declare it
        if _check_if_bazaar_needed(routes):
            _register_bazaar_extension(server)

        self._app = app
        self._http_server = x402HTTPResourceServerSync(server, routes)
        self._paywall_config = paywall_config
        self._sync_on_start = sync_facilitator_on_start
        self._init_done = False
        self._init_lock = threading.Lock()
        self._original_wsgi = app.wsgi_app

        if paywall_provider:
            self._http_server.register_paywall_provider(paywall_provider)

        # Session-mode state
        self._session_store = session_store
        self._session_cost_calculator = session_cost_calculator
        self._cost_per_request = cost_per_request
        self._session_idle_timeout = session_idle_timeout
        self._settlement_safety_margin = max(0, int(settlement_safety_margin))
        self._payment_to_session: dict[str, str] = {}
        self._session_map_lock = threading.Lock()
        self._reaper_thread: threading.Thread | None = None
        self._reaper_stop = threading.Event()

        # Replace WSGI app
        app.wsgi_app = self._wsgi_middleware  # type: ignore

    # =========================================================================
    # WSGI Entry Point
    # =========================================================================

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
            payment_header = (
                adapter.get_header("payment-signature")
                or adapter.get_header("x-payment")
            )
            context = HTTPRequestContext(
                adapter=adapter,
                path=request.path,
                method=request.method,
                payment_header=payment_header,
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

            if self._session_store is not None:
                resumed = self._resume_session_request(environ, start_response, context, adapter)
                if resumed is not None:
                    return resumed

            # Process payment request synchronously
            try:
                result = self._http_server.process_http_request(context, self._paywall_config)
            except FacilitatorResponseError as error:
                return _facilitator_error_wsgi_response(start_response, error)

            if result.type == "no-payment-required":
                return self._original_wsgi(environ, start_response)

            if result.type == "payment-error":
                return self._handle_payment_error(result, start_response)

            if result.type == "payment-verified":
                # -----------------------------------------------------------
                # Session mode: optimistic streaming + deferred settlement
                # -----------------------------------------------------------
                if self._session_store is not None:
                    return self._handle_session_mode(
                        environ, start_response, result, context, payment_header,
                    )

                # -----------------------------------------------------------
                # Legacy mode: full buffering + per-request settlement
                # -----------------------------------------------------------
                return self._handle_legacy_mode(
                    environ, start_response, result, context,
                )

        # Fallthrough
        return self._original_wsgi(environ, start_response)

    # =========================================================================
    # Payment Error Response
    # =========================================================================

    def _handle_payment_error(
        self,
        result: Any,
        start_response: Callable[..., Any],
    ) -> list[bytes]:
        """Build and return a 402 response for payment errors."""
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

    # =========================================================================
    # Session Mode (Optimistic / Streaming)
    # =========================================================================

    def _handle_session_mode(
        self,
        environ: dict[str, Any],
        start_response: Callable[..., Any],
        result: Any,
        context: HTTPRequestContext,
        payment_header: str | None,
    ) -> Iterator[bytes]:
        """Handle a verified request in session mode.

        The response streams through immediately.  Cost is accumulated
        in ``StreamingSessionResponse.close()`` and settlement is
        deferred to the background reaper.
        """
        store = self._session_store
        assert store is not None  # guaranteed by caller

        # Derive session key from payment header
        session_key = _session_key_from_payment(payment_header or "")

        # Look up or create session
        with self._session_map_lock:
            session_id = self._payment_to_session.get(session_key)

        if session_id:
            session = store.get_session(session_id)
            if (
                session is None
                or session.settled
                or session.settling
                or session.is_exhausted
                or self._session_needs_resign(session)
            ):
                # Session gone, being settled, used up, or nearing its
                # authorization deadline — require a new payment so the client
                # re-signs a fresh window. (settling must be terminal for reuse:
                # add_cost() rejects settling sessions, so reusing one would
                # serve a response without charging.)
                start_response(
                    "402 Payment Required",
                    [("Content-Type", "application/json")],
                )
                return [json.dumps({"error": "Session expired or exhausted"}).encode()]
        else:
            # Create new session
            payload_dict = result.payment_payload.model_dump(by_alias=True)
            reqs_dict = result.payment_requirements.model_dump(by_alias=True)
            max_amount = int(result.payment_requirements.amount)
            if not self._authorization_admissible(payload_dict):
                # Refuse to open a draw-down session we cannot safely settle.
                # We do NOT stream (and thus do not perform paid work) here.
                start_response(
                    "402 Payment Required",
                    [("Content-Type", "application/json")],
                )
                return [
                    json.dumps(
                        {"error": "Payment authorization deadline missing or too soon"}
                    ).encode()
                ]
            session_id = store.create_session(
                permit_payload=payload_dict,
                requirements=reqs_dict,
                max_amount=max_amount,
                route_method=context.method,
                route_path=context.path,
            )
            with self._session_map_lock:
                self._payment_to_session[session_key] = session_id
            logger.info(
                "UPTO_SESSION_CREATED id=%s method=%s path=%s cap=%d",
                session_id,
                context.method,
                context.path,
                max_amount,
            )

        return self._stream_session_response(
            environ,
            start_response,
            context,
            session_id,
            result.payment_payload,
            result.payment_requirements,
        )


    def _authorization_admissible(self, permit_payload: dict[str, Any]) -> bool:
        """Whether a fresh authorization may open a draw-down session.

        Strict / fail-closed — this gates paid work, so anything we cannot prove
        safe is rejected:

        * **Signed deadline required.** We admit only if the payload carries a
          parseable *signed* deadline (Permit2 ``deadline`` / EIP-3009
          ``validBefore``). We never fall back to ``created_at +
          maxTimeoutSeconds`` for admission: that guess can outlive the true
          on-chain deadline, so settlement would revert and the tab would be
          lost. A malformed/absent deadline is a rejection, not an assumption.
        * **Enough runway.** The signed deadline must be further out than the
          settlement safety margin. Otherwise the session would be force-settled
          (and require a re-sign) almost immediately, letting a client drive a
          rapid settle/re-sign churn — each settlement a full-gas on-chain tx —
          with an already-near-expiry authorization.
        """
        deadline = signed_authorization_deadline(permit_payload)
        if deadline is None:
            return False
        return time.time() < deadline - self._settlement_safety_margin

    def _session_needs_resign(self, session: UptoSession) -> bool:
        """Whether a session is too close to its authorization deadline to reuse.

        Once within the settlement safety margin, the reaper will force-settle
        the accumulated tab; we must stop accepting new draw-downs so the
        settled amount is final and the client re-signs a fresh authorization
        (fresh deadline) instead of piling cost onto an expiring one.

        Keys off the *signed* deadline only (fail closed): reuse serves new paid
        work, so we refuse rather than keep drawing down an authorization whose
        on-chain deadline we cannot verify. The reaper still uses
        ``settlement_deadline`` (with its advertised-window fallback) to settle
        whatever tab already accumulated.
        """
        deadline = session.signed_deadline
        if deadline is None:
            return True
        return time.time() >= deadline - self._settlement_safety_margin

    def _resume_session_request(
        self,
        environ: dict[str, Any],
        start_response: Callable[..., Any],
        context: HTTPRequestContext,
        adapter: HTTPAdapter,
    ) -> Iterator[bytes] | None:
        """Resume an active upto session from X-Upto-Session when present."""
        session_id = adapter.get_header(UPTO_SESSION_HEADER)
        if not session_id:
            return None

        store = self._session_store
        assert store is not None
        session = store.get_session(session_id)
        if (
            session is None
            or session.settled
            or session.settling
            or session.is_exhausted
            or self._session_needs_resign(session)
            or (session.route_method and session.route_method != context.method)
            or (session.route_path and session.route_path != context.path)
        ):
            start_response(
                "402 Payment Required",
                [("Content-Type", "application/json")],
            )
            return [json.dumps({"error": "Session expired or exhausted"}).encode()]

        try:
            payment_payload = PaymentPayload.model_validate(session.permit_payload)
            payment_requirements = PaymentRequirements.model_validate(session.requirements)
        except Exception:
            logger.exception("Failed to resume session %s", session_id)
            start_response(
                "402 Payment Required",
                [("Content-Type", "application/json")],
            )
            return [json.dumps({"error": "Session expired or exhausted"}).encode()]

        return self._stream_session_response(
            environ,
            start_response,
            context,
            session_id,
            payment_payload,
            payment_requirements,
        )

    def _stream_session_response(
        self,
        environ: dict[str, Any],
        start_response: Callable[..., Any],
        context: HTTPRequestContext,
        session_id: str,
        payment_payload: PaymentPayload,
        payment_requirements: PaymentRequirements,
    ) -> Iterator[bytes]:
        """Stream a response while accounting cost against an active session."""
        self._start_reaper()

        request_body_bytes = _read_body_bytes(environ)
        request_json = _try_parse_json(request_body_bytes)

        g.payment_payload = payment_payload
        g.payment_requirements = payment_requirements
        g.x402_session_id = session_id

        # Normalize settlement type from request header
        raw_settlement_type = environ.get("HTTP_X_SETTLEMENT_TYPE", "")
        requested_settlement_type = _normalize_settlement_type(raw_settlement_type)

        cost_context: dict[str, Any] = {
            "method": context.method,
            "path": context.path,
            "request_body_bytes": request_body_bytes,
            "request_json": request_json if isinstance(request_json, (dict, list)) else None,
            "payment_payload": payment_payload,
            "payment_requirements": payment_requirements,
            "requested_settlement_type": requested_settlement_type,
        }

        status_capture = StatusCapture(start_response)
        status_capture.add_header(UPTO_SESSION_HEADER, session_id)

        upstream_iter = self._original_wsgi(environ, status_capture)

        return StreamingSessionResponse(
            upstream_iter,
            middleware=self,
            session_id=session_id,
            cost_context=cost_context,
            status_ref=status_capture,
        )

    def _accumulate_session_cost(
        self,
        session_id: str,
        captured_chunks: list[bytes],
        status_ref: StatusCapture,
        cost_context: dict[str, Any],
    ) -> None:
        """Compute request cost and add it to the session.

        Called from ``StreamingSessionResponse.close()`` after the
        response iterator is exhausted.
        """
        status_code = status_ref.status_code
        if not (200 <= status_code < 300):
            return  # don't charge for errors

        body_bytes = b"".join(captured_chunks)

        if self._session_cost_calculator:
            # Detect SSE vs plain JSON
            is_sse = body_bytes.lstrip().startswith(b"data:")
            if is_sse:
                response_json = _parse_sse_final_json(body_bytes)
            else:
                response_json = _try_parse_json(body_bytes)

            cost_context["response_body_bytes"] = body_bytes
            cost_context["status_code"] = status_code
            cost_context["response_json"] = response_json
            cost_context["response_object"] = response_json
            cost_context["is_streaming"] = is_sse

            cost = self._session_cost_calculator(cost_context)
            if cost is None:
                raise ValueError(
                    f"session_cost_calculator returned None for {cost_context.get('method')} "
                    f"{cost_context.get('path')}"
                )
        elif self._cost_per_request is not None:
            cost = self._cost_per_request
        else:
            return

        cost = max(0, int(cost))
        if cost > 0:
            assert self._session_store is not None
            ok = self._session_store.add_cost(session_id, cost)
            if not ok:
                logger.warning(
                    "Could not add cost %d to session %s (exhausted or settled)",
                    cost,
                    session_id,
                )

        # -----------------------------------------------------------------
        # Submit settlement data (TEE hashes, metadata) per-request
        # -----------------------------------------------------------------
        request_body_bytes = cost_context.get("request_body_bytes", b"")
        payment_payload = cost_context.get("payment_payload")
        payment_requirements = cost_context.get("payment_requirements")
        requested_settlement_type = cost_context.get("requested_settlement_type")

        # Resolve output_object from cost_context (already parsed during cost calc)
        output_object = cost_context.get("response_object")

        if payment_payload and payment_requirements:
            try:
                settlement_type, settlement_data = self._build_settlement_metadata(
                    request_body_bytes=request_body_bytes,
                    response_body_bytes=body_bytes,
                    payment_payload=payment_payload,
                    requested_settlement_type=requested_settlement_type,
                    output_object=output_object,
                )
                if settlement_type != "private" and settlement_data:
                    logger.info(
                        "Submitting settlement data for session %s type=%s",
                        session_id,
                        settlement_type,
                    )
                    self._submit_settlement_data_in_background(
                        payment_payload,
                        payment_requirements,
                        settlement_type=settlement_type,
                        settlement_data=settlement_data,
                    )
            except Exception:
                logger.exception(
                    "Failed to build/submit settlement data for session %s",
                    session_id,
                )

    # =========================================================================
    # Settlement Data Submission & TEE Response Headers
    # =========================================================================

    def _build_settlement_metadata(
        self,
        *,
        request_body_bytes: bytes,
        response_body_bytes: bytes,
        payment_payload: Any,
        requested_settlement_type: str | None = None,
        output_object: Any | None = None,
        input_hash: str | None = None,
        output_hash: str | None = None,
    ) -> tuple[str, str | None]:
        """Build settlement metadata for ``/settle_data``.

        The gateway response body contains TEE proof fields at the top level::

            {
                "tee_signature": "...",
                "tee_request_hash": "...",
                "tee_output_hash": "...",
                "tee_timestamp": 1234567890,
                "tee_id": "0x...",
                ...
            }

        Returns:
            ``(settlement_type, base64-encoded JSON)`` or ``("private", None)``.
        """
        if requested_settlement_type == "private":
            return "private", None

        # Parse response if not already provided
        if output_object is None:
            output_object = _parse_json_bytes(response_body_bytes)

        # Extract TEE fields directly from the response dict
        resp = output_object if isinstance(output_object, dict) else {}

        tee_signature = resp.get("tee_signature")
        tee_id = resp.get("tee_id")
        tee_timestamp = resp.get("tee_timestamp")
        resolved_input_hash = resp.get("tee_request_hash") or input_hash or _sha256_bytes32(request_body_bytes)
        resolved_output_hash = resp.get("tee_output_hash") or output_hash or _sha256_bytes32(response_body_bytes)

        # Fallback tee_id for environments without real TEE
        if not tee_id:
            tee_id = "0xddc21f2d5d0af861b4fc1390df47f1c93bc5aee54e7e31763e97256d56148253"

        if not tee_signature:
            if requested_settlement_type == "individual":
                return "private", None
            logger.warning(
                "TEE signature missing in response; using placeholder "
                "tee_signature=0x for batch settlement",
            )
            tee_signature = "0x"

        # Ensure tee_id is 0x-prefixed
        if not str(tee_id).startswith("0x"):
            tee_id = f"0x{tee_id}"

        # Batch payload — matches facilitator's parseBatchSettlementData:
        #   tee_id, input_hash, output_hash, tee_signature, tee_timestamp
        batch_payload: dict[str, Any] = {
            "tee_id": tee_id,
            "input_hash": resolved_input_hash,
            "output_hash": resolved_output_hash,
            "tee_signature": tee_signature,
            "tee_timestamp": tee_timestamp,
            "timestamp": tee_timestamp,
        }

        if requested_settlement_type == "batch" or requested_settlement_type is None:
            return "batch", _encode_settlement_data(batch_payload)

        if requested_settlement_type == "individual":
            eth_address = _extract_eth_address_from_payment_payload(payment_payload)
            if not eth_address or not tee_timestamp:
                logger.warning(
                    "Requested x-settlement-type=individual but "
                    "eth_address or tee_timestamp missing; falling back to batch",
                )
                return "batch", _encode_settlement_data(batch_payload)

            request_object = _parse_json_bytes(request_body_bytes)
            if request_object is None:
                request_object = _bytes_to_text(request_body_bytes)

            # Individual payload — matches facilitator's parseIndividualSettlementData:
            #   (all batch fields) + input, output, tee_id, timestamp, eth_address
            individual_payload: dict[str, Any] = {
                **batch_payload,
                "input": _to_serializable_body(request_object),
                "output": _to_serializable_body(output_object),
                "timestamp": str(tee_timestamp),
                "eth_address": str(eth_address),
            }
            return "individual", _encode_settlement_data(individual_payload)

        # Unknown type — default to batch
        return "batch", _encode_settlement_data(batch_payload)

    def _append_tee_response_headers(
        self,
        *,
        response_wrapper: Any,
        request_body_bytes: bytes,
        response_body_bytes: bytes,
        output_object: Any | None = None,
        tee_signature: str | None = None,
        tee_id: str | None = None,
        input_hash: str | None = None,
        output_hash: str | None = None,
    ) -> None:
        """Expose TEE proof metadata to the client as response headers."""
        resolved = output_object
        if resolved is None:
            resolved = _parse_json_bytes(response_body_bytes)
            if resolved is None:
                resolved = _bytes_to_text(response_body_bytes)

        fallback_text = _bytes_to_text(response_body_bytes)
        extracted = _extract_tee_proof_metadata(resolved, fallback_text=fallback_text)

        resolved_sig = tee_signature or extracted.get("tee_signature")
        resolved_id = tee_id or extracted.get("tee_id")
        resolved_ts = extracted.get("tee_timestamp")
        resolved_ih = (
            extracted.get("tee_input_hash")
            or input_hash
            or _sha256_bytes32(request_body_bytes)
        )
        resolved_oh = (
            extracted.get("tee_output_hash")
            or output_hash
            or _sha256_bytes32(response_body_bytes)
        )

        if resolved_sig and resolved_sig != "0x":
            response_wrapper.add_header(TEE_SIGNATURE_HEADER, str(resolved_sig))
        if resolved_id and _is_hex_bytes32(str(resolved_id)):
            response_wrapper.add_header(TEE_ID_HEADER, _normalize_bytes32(str(resolved_id)))
        if resolved_ts is not None:
            response_wrapper.add_header(TEE_TIMESTAMP_HEADER, str(resolved_ts))
        if resolved_ih:
            response_wrapper.add_header(TEE_REQUEST_HASH_HEADER, str(resolved_ih))
        if resolved_oh:
            response_wrapper.add_header(TEE_OUTPUT_HASH_HEADER, str(resolved_oh))

    def _submit_settlement_data_in_background(
        self,
        payment_payload: Any,
        payment_requirements: Any,
        settlement_type: str,
        settlement_data: str | None = None,
    ) -> None:
        """Submit settlement data to the facilitator in a background thread."""

        def _submit() -> None:
            try:
                payload_obj = payment_payload
                requirements_obj = payment_requirements
                if isinstance(payment_payload, dict):
                    payload_obj = PaymentPayload.model_validate(payment_payload)
                if isinstance(payment_requirements, dict):
                    requirements_obj = PaymentRequirements.model_validate(
                        payment_requirements
                    )

                result = self._http_server.process_settlement_data(
                    payload_obj,
                    requirements_obj,
                    settlement_type=settlement_type,
                    settlement_data=settlement_data,
                )
                if result.success:
                    logger.info(
                        "Settlement data submitted type=%s", settlement_type
                    )
                else:
                    logger.warning(
                        "Settlement data submission failed: %s",
                        result.error_reason,
                    )
            except Exception as e:
                logger.warning("Settlement data background error: %s", e)

        t = threading.Thread(target=_submit, daemon=True)
        t.start()

    # =========================================================================
    # Legacy Mode (Per-Request Settlement)
    # =========================================================================

    def _handle_legacy_mode(
        self,
        environ: dict[str, Any],
        start_response: Callable[..., Any],
        result: Any,
        context: HTTPRequestContext,
    ) -> Iterator[bytes]:
        """Handle a verified request in legacy mode.

        Buffers the full response, settles synchronously, then sends.
        """
        # Store in Flask g object
        g.payment_payload = result.payment_payload
        g.payment_requirements = result.payment_requirements
        g.x402_settlement_overrides = None

        # Capture response
        response_wrapper = ResponseWrapper(start_response)
        body_chunks: list[bytes] = []

        for chunk in self._original_wsgi(environ, response_wrapper):
            body_chunks.append(chunk)

        # Check if successful response
        if (
            response_wrapper.status_code is not None
            and 200 <= response_wrapper.status_code < 300
        ):
            # Settle payment
            try:
                settle_result = self._http_server.process_settlement(
                    result.payment_payload,
                    result.payment_requirements,
                    context=context,
                    settlement_overrides=get_settlement_overrides(),
                )

                if settle_result.success:
                    # Add settlement headers
                    for key, value in settle_result.headers.items():
                        response_wrapper.add_header(key, value)
                else:
                    # Settlement failed
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
                # Settlement error - return empty body with 402
                start_response(
                    "402 Payment Required",
                    [("Content-Type", "application/json")],
                )
                return [json.dumps({}).encode("utf-8")]

        # Send buffered response
        response_wrapper.send_response(body_chunks)
        return []

    # =========================================================================
    # Background Reaper (Deferred Settlement)
    # =========================================================================

    def _start_reaper(self) -> None:
        """Start the session reaper thread if not already running."""
        if self._reaper_thread is not None:
            return
        self._reaper_thread = threading.Thread(
            target=self._reaper_loop,
            daemon=True,
            name="x402-session-reaper",
        )
        self._reaper_thread.start()
        logger.info(
            "Session reaper started (idle_timeout=%ds)",
            self._session_idle_timeout,
        )

    def _reaper_loop(self) -> None:
        """Background loop that periodically settles ready sessions."""
        # Cadence must be fine-grained enough to catch a session before its
        # authorization deadline, so it also tracks the safety margin.
        cadence_basis = min(self._session_idle_timeout, self._settlement_safety_margin)
        interval = min(cadence_basis // 4, 30)
        interval = max(interval, 5)
        while not self._reaper_stop.wait(timeout=interval):
            try:
                self._settle_ready_sessions()
            except Exception:
                logger.exception("Error in session reaper cycle")

    def _settle_ready_sessions(self) -> None:
        """Settle all deadline-due, expired, and exhausted sessions."""
        store = self._session_store
        if store is None:
            return

        # Deadline-approaching sessions first: they MUST settle before their
        # signed authorization expires or the on-chain settle reverts.
        get_due = getattr(store, "get_settlement_due_sessions", None)
        if callable(get_due):
            for session in get_due(self._settlement_safety_margin):
                self._settle_session(session)
        for session in store.get_expired_sessions(self._session_idle_timeout):
            self._settle_session(session)
        for session in store.get_exhausted_sessions():
            self._settle_session(session)

    def _settle_session(self, session: UptoSession) -> None:
        """Settle a single session on-chain via the facilitator."""
        if session.settled or session.settling or session.accumulated_cost <= 0:
            return

        store = self._session_store
        assert store is not None

        claimed = False
        mark_settling = getattr(store, "mark_settling", None)
        clear_settling = getattr(store, "clear_settling", None)
        if callable(mark_settling):
            claimed = bool(mark_settling(session.session_id))
            if not claimed:
                return

        try:
            payload = PaymentPayload.model_validate(session.permit_payload)
            requirements = PaymentRequirements.model_validate(session.requirements)
            overrides = SettlementOverrides(amount=str(session.accumulated_cost))

            settle_result = self._http_server.process_settlement(
                payload,
                requirements,
                settlement_overrides=overrides,
            )

            if settle_result.success:
                store = self._session_store
                assert store is not None
                store.mark_settled(
                    session.session_id, settle_result.transaction or ""
                )
                store.close_session(session.session_id)
                # Clean up payment→session mapping
                with self._session_map_lock:
                    self._payment_to_session = {
                        k: v
                        for k, v in self._payment_to_session.items()
                        if v != session.session_id
                    }
                logger.info(
                    "Settled session %s: tx=%s amount=%d",
                    session.session_id,
                    settle_result.transaction,
                    session.accumulated_cost,
                )
            else:
                if callable(clear_settling):
                    clear_settling(session.session_id)
                logger.error(
                    "Settlement failed for session %s: %s",
                    session.session_id,
                    settle_result.error_reason,
                )
        except Exception:
            if callable(clear_settling):
                clear_settling(session.session_id)
            logger.exception("Error settling session %s", session.session_id)

    def shutdown(self) -> None:
        """Gracefully stop the reaper and flush pending sessions."""
        self._reaper_stop.set()
        if self._reaper_thread is not None:
            self._reaper_thread.join(timeout=10)
        # Final flush
        try:
            self._settle_ready_sessions()
        except Exception:
            logger.exception("Error during shutdown settlement flush")


# ============================================================================
# Convenience Functions
# ============================================================================


def payment_middleware(
    app: Flask,
    routes: RoutesConfig,
    server: x402ResourceServerSync,
    paywall_config: PaywallConfig | None = None,
    paywall_provider: PaywallProvider | None = None,
    sync_facilitator_on_start: bool = True,
    # Session-mode parameters
    session_store: SessionStoreProtocol | None = None,
    session_cost_calculator: Callable[[dict[str, Any]], int] | None = None,
    cost_per_request: int | None = None,
    session_idle_timeout: int = 3600,
    settlement_safety_margin: int = 60,
) -> PaymentMiddleware:
    """Create Flask payment middleware with pre-configured server.

    Args:
        app: Flask application.
        routes: Route configuration for protected endpoints.
        server: Pre-configured x402ResourceServerSync (must be sync variant).
        paywall_config: Optional paywall UI configuration.
        paywall_provider: Optional custom paywall provider.
        sync_facilitator_on_start: Fetch facilitator support on first request.
        session_store: Session store for deferred settlement mode.
        session_cost_calculator: Callback for per-request cost calculation.
        cost_per_request: Static fallback cost per request.
        session_idle_timeout: Idle timeout before session is settled.
        settlement_safety_margin: Seconds before the signed authorization
            deadline at which the reaper force-settles a session.

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
        session_store=session_store,
        session_cost_calculator=session_cost_calculator,
        cost_per_request=cost_per_request,
        session_idle_timeout=session_idle_timeout,
        settlement_safety_margin=settlement_safety_margin,
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
    from ...server import x402ResourceServer

    server = x402ResourceServer(facilitator_client)

    if schemes:
        for registration in schemes:
            server.register(registration["network"], registration["server"])

    return PaymentMiddleware(
        app, routes, server, paywall_config, paywall_provider, sync_facilitator_on_start
    )
