"""Flask middleware for x402 payment handling.

Provides payment-gated route protection for Flask applications.
Uses x402HTTPResourceServerSync for synchronous request processing without asyncio overhead.
"""

from __future__ import annotations

import io
import json
import logging
import re
import time
from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING, Any
import threading

if TYPE_CHECKING:
    from ...session import SessionStoreProtocol, UptoSession

try:
    from flask import Flask, Request, g, request
except ImportError as e:
    raise ImportError(
            "Flask middleware requires the flask package. Install with: uv add x402[flask]"
    ) from e

from ..types import (
    HTTPAdapter,
    HTTPRequestContext,
    PaywallConfig,
    RouteConfig,
    RoutesConfig,
)
from ..x402_http_server import PaywallProvider, x402HTTPResourceServerSync

if TYPE_CHECKING:
    from ...server import x402ResourceServerSync

logger = logging.getLogger("x402.middleware")


# ============================================================================
# Extension Auto-Registration
# ============================================================================


def _check_if_bazaar_needed(routes: RoutesConfig) -> bool:
    if isinstance(routes, RouteConfig):
        return bool(routes.extensions and "bazaar" in routes.extensions)

    if isinstance(routes, dict):
        if "accepts" in routes:
            extensions = routes.get("extensions", {})
            return bool(extensions and "bazaar" in extensions)

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
    try:
        from ...extensions.bazaar import bazaar_resource_server_extension

        server.register_extension(bazaar_resource_server_extension)
    except ImportError:
        pass


# ============================================================================
# Flask Adapter
# ============================================================================


class FlaskAdapter(HTTPAdapter):
    """Adapter for Flask Request."""

    def __init__(self, flask_request: Request) -> None:
        self._request = flask_request

    def get_header(self, name: str) -> str | None:
        return self._request.headers.get(name)

    def get_method(self) -> str:
        return self._request.method

    def get_path(self) -> str:
        return self._request.path

    def get_url(self) -> str:
        return self._request.url

    def get_accept_header(self) -> str:
        return self._request.headers.get("accept", "")

    def get_user_agent(self) -> str:
        return self._request.headers.get("user-agent", "")

    def get_query_params(self) -> dict[str, str | list[str]]:
        return dict(self._request.args)

    def get_query_param(self, name: str) -> str | None:
        return self._request.args.get(name)

    def get_body(self) -> Any:
        return self._request.get_json(silent=True)


# ============================================================================
# Lightweight request parsing (no Flask context needed)
# ============================================================================


def _parse_environ(environ: dict[str, Any]) -> dict[str, str]:
    """Extract method, path, and key headers from raw WSGI environ.

    This avoids creating a Flask request context just to read headers.
    """
    method = environ.get("REQUEST_METHOD", "GET")
    path = environ.get("PATH_INFO", "/")
    accept = environ.get("HTTP_ACCEPT", "")

    # WSGI stores headers as HTTP_UPPER_CASE
    payment_header = (
        environ.get("HTTP_PAYMENT_SIGNATURE")
        or environ.get("HTTP_X_PAYMENT")
    )

    return {
        "method": method,
        "path": path,
        "accept": accept,
        "payment_header": payment_header,
    }


def _read_body_bytes(environ: dict[str, Any]) -> bytes:
    """Read and buffer the raw request body from WSGI environ.

    After calling this, environ['wsgi.input'] is replaced with a
    seekable BytesIO so it can be read again by the upstream app.

    Returns:
        The raw body bytes.
    """
    wsgi_input = environ.get("wsgi.input")
    if wsgi_input is None:
        return b""

    # Already buffered from a previous call
    if isinstance(wsgi_input, io.BytesIO):
        wsgi_input.seek(0)
        data = wsgi_input.read()
        wsgi_input.seek(0)
        return data

    try:
        content_length = int(environ.get("CONTENT_LENGTH") or 0)
    except (ValueError, TypeError):
        content_length = 0

    if content_length > 0:
        data = wsgi_input.read(content_length)
    else:
        data = wsgi_input.read()

    # Replace with seekable buffer
    buf = io.BytesIO(data)
    environ["wsgi.input"] = buf
    environ["CONTENT_LENGTH"] = str(len(data))

    return data


def _is_streaming_from_body(body_bytes: bytes) -> bool:
    """Check if the JSON body has stream=true."""
    if not body_bytes:
        return False
    try:
        parsed = json.loads(body_bytes)
        return isinstance(parsed, dict) and parsed.get("stream") is True
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False


def _is_streaming(environ: dict[str, Any], body_bytes: bytes) -> bool:
    """Detect if request expects a streaming response."""
    accept = environ.get("HTTP_ACCEPT", "")
    if "text/event-stream" in accept:
        return True
    return _is_streaming_from_body(body_bytes)


# ============================================================================
# Response Wrappers
# ============================================================================


class ResponseWrapper:
    """Buffers the entire upstream response for post-response settlement."""

    def __init__(self, start_response: Callable[..., Any]) -> None:
        self._original_start_response = start_response
        self.status: str | None = None
        self.status_code: int | None = None
        self.headers: list[tuple[str, str]] = []
        self._extra_headers: list[tuple[str, str]] = []
        self._write_chunks: list[bytes] = []

    def __call__(
        self,
        status: str,
        headers: list[tuple[str, str]],
        exc_info: Any = None,
    ) -> Callable[[bytes], None]:
        self.status = status
        self.status_code = int(status.split()[0])
        self.headers = list(headers)
        if self._extra_headers:
            self.headers.extend(self._extra_headers)

        def buffered_write(data: bytes) -> None:
            if data:
                self._write_chunks.append(data)

        return buffered_write

    def add_header(self, name: str, value: str) -> None:
        pair = (name, value)
        self._extra_headers.append(pair)
        if self.status is not None:
            self.headers.append(pair)

    def send_response(self, body_chunks: list[bytes]) -> None:
        write = self._original_start_response(self.status, self.headers)
        for chunk in self._write_chunks:
            if chunk:
                write(chunk)
        for chunk in body_chunks:
            if chunk:
                write(chunk)


class StreamingResponseWrapper:
    """Passes chunks through, injecting headers before the first chunk."""

    def __init__(self, start_response: Callable[..., Any]) -> None:
        self._original_start_response = start_response
        self.status: str | None = None
        self.status_code: int | None = None
        self.headers: list[tuple[str, str]] = []
        self._extra_headers: list[tuple[str, str]] = []
        self._headers_sent = False
        self._write_fn: Callable[[bytes], None] | None = None

    def __call__(
        self,
        status: str,
        headers: list[tuple[str, str]],
        exc_info: Any = None,
    ) -> Callable[[bytes], None]:
        self.status = status
        self.status_code = int(status.split()[0])
        self.headers = list(headers)
        if self._extra_headers:
            self.headers.extend(self._extra_headers)

        def buffered_write(data: bytes) -> None:
            self._ensure_headers_sent()
            if self._write_fn and data:
                self._write_fn(data)

        return buffered_write

    def add_header(self, name: str, value: str) -> None:
        pair = (name, value)
        self._extra_headers.append(pair)
        if self.status is not None:
            self.headers.append(pair)

    def _ensure_headers_sent(self) -> None:
        if not self._headers_sent:
            self._write_fn = self._original_start_response(self.status, self.headers)
            self._headers_sent = True

    def stream_body(self, body_iter: Iterator[bytes]) -> Iterator[bytes]:
        try:
            for chunk in body_iter:
                self._ensure_headers_sent()
                if chunk:
                    yield chunk
        finally:
            if hasattr(body_iter, "close"):
                body_iter.close()


# ============================================================================
# Minimal adapter for payment processing (works without Flask context)
# ============================================================================


class _EnvironAdapter(HTTPAdapter):
    """Lightweight HTTPAdapter built directly from WSGI environ + raw body.

    This avoids the need for a Flask request context during the payment
    processing phase.
    """

    def __init__(self, environ: dict[str, Any], body_bytes: bytes) -> None:
        self._environ = environ
        self._body_bytes = body_bytes
        self._parsed_body: Any = None
        self._body_parsed = False

    def get_header(self, name: str) -> str | None:
        # WSGI convention: headers are HTTP_UPPER_CASE with hyphens → underscores
        key = "HTTP_" + name.upper().replace("-", "_")
        return self._environ.get(key)

    def get_method(self) -> str:
        return self._environ.get("REQUEST_METHOD", "GET")

    def get_path(self) -> str:
        return self._environ.get("PATH_INFO", "/")

    def get_url(self) -> str:
        scheme = self._environ.get("wsgi.url_scheme", "http")
        host = self._environ.get("HTTP_HOST", "localhost")
        path = self._environ.get("PATH_INFO", "/")
        qs = self._environ.get("QUERY_STRING", "")
        url = f"{scheme}://{host}{path}"
        if qs:
            url += f"?{qs}"
        return url

    def get_accept_header(self) -> str:
        return self._environ.get("HTTP_ACCEPT", "")

    def get_user_agent(self) -> str:
        return self._environ.get("HTTP_USER_AGENT", "")

    def get_query_params(self) -> dict[str, str | list[str]]:
        from urllib.parse import parse_qs

        qs = self._environ.get("QUERY_STRING", "")
        parsed = parse_qs(qs)
        result: dict[str, str | list[str]] = {}
        for k, v in parsed.items():
            result[k] = v[0] if len(v) == 1 else v
        return result

    def get_query_param(self, name: str) -> str | None:
        params = self.get_query_params()
        val = params.get(name)
        if isinstance(val, list):
            return val[0] if val else None
        return val

    def get_body(self) -> Any:
        if not self._body_parsed:
            self._body_parsed = True
            if self._body_bytes:
                try:
                    self._parsed_body = json.loads(self._body_bytes)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    self._parsed_body = None
            else:
                self._parsed_body = None
        return self._parsed_body


# ============================================================================
# Flask Middleware Class
# ============================================================================


class PaymentMiddleware:
    """Flask WSGI middleware for x402 payment handling.

    Supports both buffered and streaming responses. Streaming is auto-detected
    from the request (Accept: text/event-stream or {"stream": true} in body).
    For streaming responses, settlement happens eagerly before the first chunk
    is sent to the client.

    Session support (upto scheme):
    When an upto payment is verified, a session is created and the session ID
    is returned in X-Upto-Session header. Subsequent requests with the same
    session ID skip payment verification and accumulate cost. Settlement
    happens when the session expires or the cap is reached.
    """

    def __init__(
        self,
        app: Flask,
        routes: RoutesConfig,
        server: x402ResourceServerSync,
        paywall_config: PaywallConfig | None = None,
        paywall_provider: PaywallProvider | None = None,
        sync_facilitator_on_start: bool = True,
        session_store: "SessionStoreProtocol | None" = None,
        cost_per_request: int | None = None,
        session_idle_timeout: int = 180,
    ) -> None:
        if _check_if_bazaar_needed(routes):
            _register_bazaar_extension(server)

        self._app = app
        self._http_server = x402HTTPResourceServerSync(server, routes)
        self._paywall_config = paywall_config
        self._sync_on_start = sync_facilitator_on_start
        self._init_done = False
        self._init_lock = threading.Lock()
        self._original_wsgi = app.wsgi_app
        self._reaper_started = False
        self._reaper_lock = threading.Lock()

        # Session support for upto scheme
        self._session_store = session_store
        self._cost_per_request = cost_per_request
        self._session_idle_timeout = session_idle_timeout

        if paywall_provider:
            self._http_server.register_paywall_provider(paywall_provider)

        app.wsgi_app = self._wsgi_middleware  # type: ignore

    def _ensure_session_reaper_started(self) -> None:
        """Start session reaper lazily inside worker process."""
        if not self._session_store or self._reaper_started:
            return

        with self._reaper_lock:
            if not self._session_store or self._reaper_started:
                return
            self._start_session_reaper()
            self._reaper_started = True

    # ------------------------------------------------------------------
    # Session Management
    # ------------------------------------------------------------------

    def _start_session_reaper(self) -> None:
        """Start background thread to settle expired sessions."""
        def _reaper() -> None:
            while True:
                try:
                    time.sleep(min(30, self._session_idle_timeout // 2))

                    if not self._session_store:
                        continue

                    # Settle expired sessions
                    expired = self._session_store.get_expired_sessions(
                        self._session_idle_timeout
                    )
                    if expired:
                        logger.info(
                            "Session reaper queued %d expired session(s) for settlement",
                            len(expired),
                        )
                    for session in expired:
                        self._settle_session(session, reason="expired")

                    # Settle exhausted sessions
                    exhausted = self._session_store.get_exhausted_sessions()
                    if exhausted:
                        logger.info(
                            "Session reaper queued %d exhausted session(s) for settlement",
                            len(exhausted),
                        )
                    for session in exhausted:
                        self._settle_session(session, reason="exhausted")

                except Exception as e:
                    logger.warning("Session reaper error: %s", e)

        t = threading.Thread(target=_reaper, daemon=True, name="x402-session-reaper")
        t.start()
        logger.info(
            "Session reaper started (idle_timeout=%ss)",
            self._session_idle_timeout,
        )

    def _ensure_initialized(self) -> bool:
        """Ensure the HTTP server is initialized (for background settlement).

        Returns True if initialized, False if initialization failed.
        """
        if self._init_done:
            return True

        with self._init_lock:
            if self._init_done:
                return True
            try:
                self._http_server.initialize()
                self._init_done = True
                return True
            except Exception as e:
                logger.debug(
                    "Server not yet initialized, will retry settlement: %s", e
                )
                return False

    def _settle_session(self, session: "UptoSession", reason: str = "unknown") -> None:
        """Settle an upto session on-chain with accumulated cost."""
        logger.info(
            "Session %s about to settle (reason=%s, accumulated=%d, cap=%d)",
            session.session_id,
            reason,
            session.accumulated_cost,
            session.max_amount,
        )

        if session.settled or session.accumulated_cost == 0:
            # Nothing to settle — just clean up
            if self._session_store:
                self._session_store.close_session(session.session_id)
            logger.info(
                "Session %s skipped settlement (reason=%s, settled=%s, accumulated=%d)",
                session.session_id,
                reason,
                session.settled,
                session.accumulated_cost,
            )
            return

        # Server must be initialized before we can settle on-chain.
        # If not ready yet, skip — the reaper will retry next cycle.
        if not self._ensure_initialized():
            logger.debug(
                "Deferring settlement for session %s: server not initialized",
                session.session_id,
            )
            return

        # Freeze session state before settlement to avoid concurrent cost mutations.
        settle_session = session
        if self._session_store:
            latest = self._session_store.close_session(session.session_id)
            if latest is None:
                logger.debug("Session %s already closed", session.session_id)
                return
            settle_session = latest

        if settle_session.accumulated_cost == 0:
            logger.info(
                "Session %s skipped settlement after close (reason=%s, accumulated=%d)",
                settle_session.session_id,
                reason,
                settle_session.accumulated_cost,
            )
            return

        try:
            from ...schemas import PaymentPayload, PaymentRequirements

            # Reconstruct from stored dicts
            payload = PaymentPayload.model_validate(settle_session.permit_payload)

            # Override amount to accumulated cost before constructing
            req_dict = dict(settle_session.requirements)
            req_dict["amount"] = str(settle_session.accumulated_cost)
            requirements = PaymentRequirements.model_validate(req_dict)

            logger.info(
                "Session %s settlement attempt started (reason=%s, amount=%d)",
                settle_session.session_id,
                reason,
                settle_session.accumulated_cost,
            )
            settle_result = self._http_server.process_settlement(
                payload,
                requirements,
            )

            if settle_result.success:
                logger.info(
                    "Session %s settled: amount=%d, tx=%s",
                    settle_session.session_id,
                    settle_session.accumulated_cost,
                    settle_result.transaction,
                )
            elif self._is_settlement_queued_error(settle_result.error_reason):
                logger.info(
                    "Session %s settlement queued (reason=%s, facilitator_status=202)",
                    settle_session.session_id,
                    reason,
                )
            else:
                logger.warning(
                    "Session %s settlement failed (reason=%s): %s",
                    settle_session.session_id,
                    reason,
                    settle_result.error_reason,
                )
        except Exception as e:
            logger.warning(
                "Session %s settlement error (reason=%s): %s",
                settle_session.session_id,
                reason,
                e,
            )

    def _get_session_cost(self, requirements: Any) -> int:
        """Resolve per-request session cost.

        Priority:
        1. Explicit middleware config (cost_per_request)
        2. Requirements amount (fallback)
        """
        def _parse_positive_int(value: Any) -> int:
            if value is None:
                return 0
            try:
                return max(0, int(value))
            except (TypeError, ValueError):
                try:
                    from decimal import Decimal, InvalidOperation

                    return max(0, int(Decimal(str(value))))
                except (InvalidOperation, ValueError, TypeError):
                    return 0

        if self._cost_per_request is not None:
            return _parse_positive_int(self._cost_per_request)

        amount: Any = None
        if hasattr(requirements, "amount"):
            amount = getattr(requirements, "amount")
        elif isinstance(requirements, dict):
            amount = requirements.get("amount")

        return _parse_positive_int(amount)

    @staticmethod
    def _should_charge_response(status_code: int | None) -> bool:
        """Charge only when upstream completed successfully."""
        return status_code is not None and 200 <= status_code < 300

    @staticmethod
    def _is_settlement_queued_error(error_reason: str | None) -> bool:
        """Detect facilitator queued settlement (HTTP 202 Accepted)."""
        if not error_reason:
            return False
        reason = error_reason.lower()
        if "queued" in reason:
            return True
        if "settle failed (202)" in reason:
            return True
        return bool(re.search(r"\b202\b.*accepted", reason))

    def _route_supports_upto(self, method: str, path: str) -> bool:
        """Check if the matched route accepts the upto scheme."""
        get_route_config = getattr(self._http_server, "_get_route_config", None)
        if not callable(get_route_config):
            return False

        route_config = get_route_config(path, method)
        if route_config is None:
            return False

        accepts = route_config.accepts
        if not isinstance(accepts, list):
            accepts = [accepts]

        for option in accepts:
            scheme = getattr(option, "scheme", "")
            if scheme == "upto":
                return True

        return False

    def _handle_upto_session_request(
        self,
        session_id: str,
        environ: dict[str, Any],
        start_response: Callable[..., Any],
    ) -> Iterator[bytes]:
        """Handle a request with an existing upto session.

        Validates the session, adds cost, and forwards to upstream.
        """
        if not self._session_store:
            return self._make_error_response(
                start_response,
                "500 Internal Server Error",
                {"error": "Session store not configured"},
            )

        method = environ.get("REQUEST_METHOD", "GET")
        path = environ.get("PATH_INFO", "/")
        if not self._route_supports_upto(method, path):
            return self._make_error_response(
                start_response,
                "402 Payment Required",
                {
                    "error": "Session cannot be used for this route",
                    "code": "upto_session_route_mismatch",
                },
            )

        session = self._session_store.get_session(session_id)
        if session is None:
            return self._make_error_response(
                start_response,
                "402 Payment Required",
                {"error": "Session not found or expired", "code": "upto_session_not_found"},
            )

        if session.settled:
            return self._make_error_response(
                start_response,
                "402 Payment Required",
                {"error": "Session already settled", "code": "upto_session_settled"},
            )

        session_scheme = str((session.requirements or {}).get("scheme", ""))
        if session_scheme != "upto":
            return self._make_error_response(
                start_response,
                "402 Payment Required",
                {
                    "error": "Session scheme mismatch",
                    "code": "upto_session_scheme_mismatch",
                },
            )

        # Scope session reuse to the original request method/path.
        if (
            session.route_method
            and session.route_path
            and (
                session.route_method.upper() != method.upper()
                or session.route_path != path
            )
        ):
            return self._make_error_response(
                start_response,
                "402 Payment Required",
                {
                    "error": "Session bound to different route",
                    "code": "upto_session_route_mismatch",
                },
            )

        # Check if session can afford the request
        cost = self._get_session_cost(session.requirements)
        if cost <= 0:
            logger.warning(
                "Session %s has non-positive per-request cost; refusing session reuse",
                session_id,
            )
            return self._make_error_response(
                start_response,
                "500 Internal Server Error",
                {
                    "error": "Invalid session cost configuration",
                    "code": "upto_invalid_session_cost",
                },
            )
        if cost > session.remaining_budget:
            self._settle_session(session, reason="cap_reached_precheck")
            return self._make_error_response(
                start_response,
                "402 Payment Required",
                {
                    "error": "Session spend cap reached, please create new payment",
                    "code": "upto_session_cap_reached",
                },
            )

        # Session is valid — forward to upstream
        environ["x402.upto_session_id"] = session_id
        environ["x402.payment_payload"] = session.permit_payload
        environ["x402.payment_requirements"] = session.requirements

        # Rewind body
        body_bytes = _read_body_bytes(environ)
        wsgi_input = environ.get("wsgi.input")
        if wsgi_input and hasattr(wsgi_input, "seek"):
            wsgi_input.seek(0)

        def _charge_session_if_needed(status_code: int | None) -> None:
            if not self._session_store:
                return
            if not self._should_charge_response(status_code):
                logger.info(
                    "UPTO_SESSION_NOT_CHARGED id=%s method=%s path=%s status=%s",
                    session_id,
                    method,
                    path,
                    status_code,
                )
                return
            if self._session_store.add_cost(session_id, cost):
                return
            logger.warning(
                "Session %s cost application failed after successful response; likely cap race",
                session_id,
            )
            latest = self._session_store.get_session(session_id)
            if latest is not None:
                self._settle_session(latest, reason="cap_reached_post_response")

        streaming = _is_streaming(environ, body_bytes)

        if streaming:
            streaming_wrapper = StreamingResponseWrapper(start_response)
            streaming_wrapper.add_header("X-Upto-Session", session_id)
            body_iter = iter(self._original_wsgi(environ, streaming_wrapper))

            def _iter() -> Iterator[bytes]:
                charged = False
                try:
                    for chunk in streaming_wrapper.stream_body(body_iter):
                        if not charged and streaming_wrapper.status_code is not None:
                            _charge_session_if_needed(streaming_wrapper.status_code)
                            charged = True
                        yield chunk
                finally:
                    if not charged:
                        _charge_session_if_needed(streaming_wrapper.status_code)

            return _iter()
        else:
            response_wrapper = ResponseWrapper(start_response)
            body_chunks: list[bytes] = []
            try:
                upstream_iter = self._original_wsgi(environ, response_wrapper)
                for chunk in upstream_iter:
                    body_chunks.append(chunk)
                if hasattr(upstream_iter, "close"):
                    upstream_iter.close()
            except Exception as e:
                logger.error("Upstream app error: %s", e, exc_info=True)
                return self._make_error_response(
                    start_response,
                    "502 Bad Gateway",
                    {"error": "Upstream application error", "details": str(e)},
                )
            _charge_session_if_needed(response_wrapper.status_code)
            response_wrapper.add_header("X-Upto-Session", session_id)
            response_wrapper.send_response(body_chunks)
            return []

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _make_error_response(
        self,
        start_response: Callable[..., Any],
        status: str,
        body: dict[str, Any],
    ) -> list[bytes]:
        encoded = json.dumps(body).encode("utf-8")
        start_response(
            status,
            [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(encoded))),
            ],
        )
        return [encoded]

    def _handle_payment_error(
        self,
        result: Any,
        start_response: Callable[..., Any],
    ) -> list[bytes]:
        response = result.response
        if response is None:
            return self._make_error_response(
                start_response,
                "402 Payment Required",
                {"error": "Payment required"},
            )

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

  # ------------------------------------------------------------------
    # Buffered (non-streaming) path
    # ------------------------------------------------------------------

    def _handle_buffered_response(
        self,
        result: Any,
        environ: dict[str, Any],
        start_response: Callable[..., Any],
    ) -> Iterator[bytes]:
        response_wrapper = ResponseWrapper(start_response)
        body_chunks: list[bytes] = []

        try:
            upstream_iter = self._original_wsgi(environ, response_wrapper)
            for chunk in upstream_iter:
                body_chunks.append(chunk)
            if hasattr(upstream_iter, "close"):
                upstream_iter.close()
        except Exception as e:
            logger.error("Upstream app error: %s", e, exc_info=True)
            return self._make_error_response(
                start_response,
                "502 Bad Gateway",
                {"error": "Upstream application error", "details": str(e)},
            )

        # Fire-and-forget settlement in background thread
        if (
            response_wrapper.status_code is not None
            and 200 <= response_wrapper.status_code < 300
        ):
            self._settle_in_background(result.payment_payload, result.payment_requirements)

        response_wrapper.send_response(body_chunks)
        return []

    # ------------------------------------------------------------------
    # Streaming path
    # ------------------------------------------------------------------

    def _handle_streaming_response(
        self,
        result: Any,
        environ: dict[str, Any],
        start_response: Callable[..., Any],
    ) -> Iterator[bytes]:
        streaming_wrapper = StreamingResponseWrapper(start_response)
        body_iter = iter(self._original_wsgi(environ, streaming_wrapper))
        payment_payload = result.payment_payload
        payment_requirements = result.payment_requirements

        def _iter() -> Iterator[bytes]:
            settled = False
            try:
                for chunk in streaming_wrapper.stream_body(body_iter):
                    if not settled and streaming_wrapper.status_code is not None:
                        settled = True
                        if self._should_charge_response(streaming_wrapper.status_code):
                            self._settle_in_background(
                                payment_payload, payment_requirements
                            )
                        else:
                            logger.info(
                                "Skipping settlement for non-success streaming response status=%s",
                                streaming_wrapper.status_code,
                            )
                    yield chunk
            finally:
                if not settled:
                    if self._should_charge_response(streaming_wrapper.status_code):
                        self._settle_in_background(
                            payment_payload, payment_requirements
                        )
                    else:
                        logger.info(
                            "Skipping settlement for non-success streaming response status=%s",
                            streaming_wrapper.status_code,
                        )

        return _iter()

    # ------------------------------------------------------------------
    # Background settlement
    # ------------------------------------------------------------------

    def _settle_in_background(self, payment_payload: Any, payment_requirements: Any) -> None:
        """Run settlement in a daemon thread so it doesn't block the response."""
        def _settle() -> None:
            try:
                settle_result = self._http_server.process_settlement(
                    payment_payload,
                    payment_requirements,
                )
                if settle_result.success:
                    logger.info("Background settlement succeeded")
                elif self._is_settlement_queued_error(settle_result.error_reason):
                    logger.info(
                        "Background settlement queued (facilitator_status=202)",
                    )
                else:
                    logger.warning(
                        "Background settlement failed: %s",
                        settle_result.error_reason,
                    )
            except Exception as e:
                logger.warning("Background settlement error: %s", e)

        t = threading.Thread(target=_settle, daemon=True)
        t.start()

    # ------------------------------------------------------------------
    # Main WSGI entry point
    # ------------------------------------------------------------------

    def _wsgi_middleware(
        self,
        environ: dict[str, Any],
        start_response: Callable[..., Any],
    ) -> Iterator[bytes]:
        # Important for Gunicorn preload/fork safety:
        # start background threads only after worker boot.
        self._ensure_session_reaper_started()

        info = _parse_environ(environ)

        # ---------------------------------------------------------------
        # Phase 0: Check for upto session header
        # ---------------------------------------------------------------
        session_header = environ.get("HTTP_X_UPTO_SESSION")
        if session_header and self._session_store:
            # Do not allow session headers to short-circuit non-protected routes.
            probe_context = HTTPRequestContext(
                adapter=_EnvironAdapter(environ, b""),
                path=info["path"],
                method=info["method"],
                payment_header=info["payment_header"],
            )
            if self._http_server.requires_payment(probe_context):
                return self._handle_upto_session_request(
                    session_header, environ, start_response
                )

        # ---------------------------------------------------------------
        # Phase 1: Lightweight check using raw environ (NO Flask context)
        # ---------------------------------------------------------------

        # Buffer the body so it can be read multiple times
        body_bytes = _read_body_bytes(environ)

        # Build a lightweight adapter from environ directly
        adapter = _EnvironAdapter(environ, body_bytes)

        context = HTTPRequestContext(
            adapter=adapter,
            path=info["path"],
            method=info["method"],
            payment_header=info["payment_header"],
        )

        logger.info(
            "x402: %s %s | payment_header=%s",
            info["method"],
            info["path"],
            info["payment_header"] is not None,
        )

        # Fast path: route doesn't need payment at all
        if not self._http_server.requires_payment(context):
            return self._original_wsgi(environ, start_response)

        # ---------------------------------------------------------------
        # Phase 2: Payment processing (still no Flask context needed)
        # ---------------------------------------------------------------

        if self._sync_on_start and not self._init_done:
            try:
                self._http_server.initialize()
                self._init_done = True
            except Exception as e:
                logger.error("Facilitator init failed: %s", e, exc_info=True)
                return self._make_error_response(
                    start_response,
                    "500 Internal Server Error",
                    {
                        "error": "Payment system initialization failed",
                        "details": str(e),
                    },
                )

        try:
            result = self._http_server.process_http_request(
                context, self._paywall_config
            )
            logger.debug("Payment result: %s", result.type)
        except Exception as e:
            logger.error("Payment processing failed: %s", e, exc_info=True)
            return self._make_error_response(
                start_response,
                "500 Internal Server Error",
                {"error": "Payment processing failed", "details": str(e)},
            )

        if result.type == "no-payment-required":
            return self._original_wsgi(environ, start_response)

        if result.type == "payment-error":
            return self._handle_payment_error(result, start_response)

        if result.type == "payment-verified":
            # ---------------------------------------------------------------
            # Phase 2.5: Check if this is an upto payment — create session
            # ---------------------------------------------------------------
            is_upto = False
            if self._session_store and hasattr(result, "payment_payload"):
                payload_dict = result.payment_payload
                if hasattr(payload_dict, "accepted"):
                    is_upto = getattr(payload_dict.accepted, "scheme", "") == "upto"
                elif isinstance(payload_dict, dict):
                    accepted = payload_dict.get("accepted", {})
                    is_upto = accepted.get("scheme", "") == "upto"

            if is_upto and self._session_store:
                # Create session instead of settling per-request
                # Serialize Pydantic models to dicts
                pp = result.payment_payload
                if hasattr(pp, "model_dump"):
                    payload_data = pp.model_dump()
                elif hasattr(pp, "to_dict"):
                    payload_data = pp.to_dict()
                elif isinstance(pp, dict):
                    payload_data = pp
                else:
                    payload_data = dict(pp)

                pr = result.payment_requirements
                if hasattr(pr, "model_dump"):
                    req_data = pr.model_dump()
                elif hasattr(pr, "to_dict"):
                    req_data = pr.to_dict()
                elif isinstance(pr, dict):
                    req_data = pr
                else:
                    req_data = dict(pr)

                # Extract max amount from Permit2 authorization
                # Handle both dict access and Pydantic attribute access
                inner_payload = payload_data.get("payload", {}) or {}
                permit2_auth = inner_payload.get("permit2Authorization", inner_payload.get("permit2_authorization", {})) or {}
                permitted = permit2_auth.get("permitted", {}) or {}
                max_amount = int(permitted.get("amount", 0))
                deadline = permit2_auth.get("deadline")

                if max_amount <= 0:
                    return self._make_error_response(
                        start_response,
                        "402 Payment Required",
                        {
                            "error": "Invalid upto permit amount",
                            "code": "upto_invalid_permit_amount",
                        },
                    )

                session_id = self._session_store.create_session(
                    permit_payload=payload_data,
                    requirements=req_data,
                    max_amount=max_amount,
                    route_method=info["method"],
                    route_path=info["path"],
                )

                cost = self._get_session_cost(req_data)
                logger.info(
                    "UPTO_SESSION_CREATED id=%s method=%s path=%s cap=%d initial_cost=%d deadline=%s",
                    session_id,
                    info["method"],
                    info["path"],
                    max_amount,
                    cost,
                    deadline,
                )

                if cost <= 0:
                    logger.warning(
                        "Refusing upto session creation with non-positive per-request cost"
                    )
                    self._session_store.close_session(session_id)
                    return self._make_error_response(
                        start_response,
                        "500 Internal Server Error",
                        {
                            "error": "Invalid session cost configuration",
                            "code": "upto_invalid_session_cost",
                        },
                    )
                if cost > max_amount:
                    self._session_store.close_session(session_id)
                    return self._make_error_response(
                        start_response,
                        "402 Payment Required",
                        {
                            "error": "Session spend cap reached, please create new payment",
                            "code": "upto_session_cap_reached",
                        },
                    )

                def _charge_initial_cost_if_needed(status_code: int | None) -> bool:
                    if not self._session_store:
                        return False
                    if not self._should_charge_response(status_code):
                        logger.info(
                            "UPTO_SESSION_NOT_CHARGED id=%s method=%s path=%s status=%s",
                            session_id,
                            info["method"],
                            info["path"],
                            status_code,
                        )
                        return False
                    if self._session_store.add_cost(session_id, cost):
                        return True
                    logger.warning(
                        "Session %s initial cost application failed after successful response",
                        session_id,
                    )
                    current = self._session_store.get_session(session_id)
                    if current is not None:
                        self._settle_session(current, reason="initial_cost_post_response")
                    return False

                # Forward to upstream with session header
                environ["x402.upto_session_id"] = session_id
                environ["x402.payment_payload"] = result.payment_payload
                environ["x402.payment_requirements"] = result.payment_requirements

                # Rewind body
                body_bytes = _read_body_bytes(environ)
                wsgi_input = environ.get("wsgi.input")
                if wsgi_input and hasattr(wsgi_input, "seek"):
                    wsgi_input.seek(0)

                streaming = _is_streaming(environ, body_bytes)

                if streaming:
                    streaming_wrapper = StreamingResponseWrapper(start_response)
                    streaming_wrapper.add_header("X-Upto-Session", session_id)
                    body_iter = iter(self._original_wsgi(environ, streaming_wrapper))

                    def _iter() -> Iterator[bytes]:
                        charged = False
                        try:
                            for chunk in streaming_wrapper.stream_body(body_iter):
                                if not charged and streaming_wrapper.status_code is not None:
                                    _charge_initial_cost_if_needed(
                                        streaming_wrapper.status_code
                                    )
                                    charged = True
                                yield chunk
                        finally:
                            if not charged:
                                _charge_initial_cost_if_needed(
                                    streaming_wrapper.status_code
                                )

                    return _iter()
                else:
                    response_wrapper = ResponseWrapper(start_response)
                    body_chunks: list[bytes] = []
                    try:
                        upstream_iter = self._original_wsgi(environ, response_wrapper)
                        for chunk in upstream_iter:
                            body_chunks.append(chunk)
                        if hasattr(upstream_iter, "close"):
                            upstream_iter.close()
                    except Exception as e:
                        logger.error("Upstream app error: %s", e, exc_info=True)
                        return self._make_error_response(
                            start_response,
                            "502 Bad Gateway",
                            {"error": "Upstream application error", "details": str(e)},
                        )
                    _charge_initial_cost_if_needed(response_wrapper.status_code)
                    response_wrapper.add_header("X-Upto-Session", session_id)
                    response_wrapper.send_response(body_chunks)
                    return []

            # ---------------------------------------------------------------
            # Phase 3: Rewind body and dispatch to upstream app (exact scheme)
            # ---------------------------------------------------------------

            # Rewind the buffered input for the upstream app
            wsgi_input = environ.get("wsgi.input")
            if wsgi_input and hasattr(wsgi_input, "seek"):
                wsgi_input.seek(0)

            # Make payment info available to route handlers via environ
            environ["x402.payment_payload"] = result.payment_payload
            environ["x402.payment_requirements"] = result.payment_requirements

            streaming = _is_streaming(environ, body_bytes)
            logger.debug("Streaming: %s", streaming)

            if streaming:
                return self._handle_streaming_response(
                    result, environ, start_response
                )
            else:
                return self._handle_buffered_response(
                    result, environ, start_response
                )

        # Fallthrough — should not happen
        logger.warning("Unexpected payment result type: %s", getattr(result, "type", "unknown"))
        return self._original_wsgi(environ, start_response)


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
    session_store: "SessionStoreProtocol | None" = None,
    cost_per_request: int | None = None,
    session_idle_timeout: int = 300,
) -> PaymentMiddleware:
    return PaymentMiddleware(
        app,
        routes,
        server,
        paywall_config,
        paywall_provider,
        sync_facilitator_on_start,
        session_store,
        cost_per_request,
        session_idle_timeout,
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
    from ...server import x402ResourceServer

    server = x402ResourceServer(facilitator_client)

    if schemes:
        for registration in schemes:
            server.register(registration["network"], registration["server"])

    return PaymentMiddleware(
        app,
        routes,
        server,
        paywall_config,
        paywall_provider,
        sync_facilitator_on_start,
    )
