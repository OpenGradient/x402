"""httpx client wrapper with automatic x402 payment handling.

Provides transport wrapper and convenience classes for httpx AsyncClient.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

try:
    import httpx
    from httpx import AsyncBaseTransport, Request, Response
except ImportError as e:
    raise ImportError(
        "httpx client requires the httpx package. Install with: uv add x402[httpx]"
    ) from e

if TYPE_CHECKING:
    from ...client import x402Client, x402ClientConfig
    from ..x402_http_client import x402HTTPClient

logger = logging.getLogger("x402.httpx")


class PaymentError(Exception):
    """Base class for payment-related errors."""

    pass


class PaymentAlreadyAttemptedError(PaymentError):
    """Raised when payment has already been attempted for this request."""

    pass


class MissingRequestConfigError(PaymentError):
    """Raised when request configuration is missing."""

    pass


# ============================================================================
# Transport Implementation (replaces event hooks which can't modify responses)
# ============================================================================


class x402AsyncTransport(AsyncBaseTransport):
    """Async transport that handles 402 Payment Required responses.

    Wraps another transport to intercept 402 responses, create payment
    payloads, and retry with payment headers automatically.

    For the upto scheme, this transport also:
    - Captures the X-Upto-Session header from responses
    - Attaches it on subsequent requests to the same host+path
    - Handles session expiry (402 after an active session)

    Unlike event hooks, transports can control the response returned.
    """

    RETRY_KEY = "_x402_is_retry"
    SESSION_HEADER = "X-Upto-Session"

    def __init__(
        self,
        client: x402Client | x402HTTPClient,
        transport: AsyncBaseTransport | None = None,
    ) -> None:
        """Initialize payment transport.

        Args:
            client: x402Client or x402HTTPClient for payment handling.
            transport: Optional underlying transport. If None, uses httpx default.
        """
        from ..x402_http_client import x402HTTPClient as HTTPClient

        if isinstance(client, HTTPClient):
            self._http_client = client
        else:
            self._http_client = HTTPClient(client)
        self._client = client
        self._transport = transport or httpx.AsyncHTTPTransport()

        # Session store: maps "host:path" -> session_id
        self._sessions: dict[str, str] = {}
        self._session_lock = __import__("threading").Lock()

    def _session_key(self, request: Request) -> str:
        """Build a normalized session key from request endpoint.

        Scope to method + scheme + authority + path (without query params)
        so reusable sessions are not fragmented by benign query variance.
        """
        scheme = request.url.scheme or "http"
        host = request.url.host or ""
        port = request.url.port
        authority = host if port is None else f"{host}:{port}"
        method = request.method.upper()
        path = request.url.path or "/"
        if len(path) > 1 and path.endswith("/"):
            path = path.rstrip("/")
        return f"{method} {scheme}://{authority}{path}"

    def _get_session(self, request: Request) -> str | None:
        """Get stored session ID for this request's endpoint."""
        key = self._session_key(request)
        with self._session_lock:
            session = self._sessions.get(key)
        logger.debug(
            "UPTO_CLIENT_SESSION_LOOKUP key=%s found=%s",
            key,
            bool(session),
        )
        return session

    def _store_session(self, request: Request, session_id: str) -> None:
        """Store a session ID for this request's endpoint."""
        key = self._session_key(request)
        with self._session_lock:
            self._sessions[key] = session_id
        logger.debug(
            "UPTO_CLIENT_SESSION_STORE key=%s session_id=%s",
            key,
            session_id,
        )

    def _clear_session(self, request: Request) -> None:
        """Clear stored session for this request's endpoint."""
        key = self._session_key(request)
        with self._session_lock:
            self._sessions.pop(key, None)
        logger.debug("UPTO_CLIENT_SESSION_CLEAR key=%s", key)

    async def handle_async_request(self, request: Request) -> Response:
        """Handle request with automatic 402 payment retry and session reuse.

        Flow:
        1. If we have a stored session, attach X-Upto-Session header
        2. Send request
        3. If 200-299 with X-Upto-Session in response, store it
        4. If 402 with active session, clear session and create new payment
        5. If 402 without session, create payment normally

        Args:
            request: The outgoing HTTP request.

        Returns:
            Response (original or retried with payment).
        """
        # Check for existing session
        session_id = self._get_session(request)
        if session_id and not request.extensions.get(self.RETRY_KEY):
            # Attach session header to request
            new_headers = dict(request.headers)
            new_headers[self.SESSION_HEADER] = session_id
            logger.debug(
                "UPTO_CLIENT_SESSION_ATTACH key=%s session_id=%s",
                self._session_key(request),
                session_id,
            )
            request = Request(
                method=request.method,
                url=request.url,
                headers=new_headers,
                content=request.content,
                extensions=request.extensions,
            )

        # Send the request
        response = await self._transport.handle_async_request(request)

        # Capture session from successful responses
        if 200 <= response.status_code < 300:
            resp_session = response.headers.get(self.SESSION_HEADER.lower()) or \
                           response.headers.get(self.SESSION_HEADER)
            if resp_session:
                self._store_session(request, resp_session)
            else:
                logger.debug(
                    "UPTO_CLIENT_SESSION_MISS_ON_SUCCESS key=%s status=%s headers_present=%s",
                    self._session_key(request),
                    response.status_code,
                    self.SESSION_HEADER in response.headers
                    or self.SESSION_HEADER.lower() in response.headers,
                )
            return response

        # Not a 402, return as-is
        if response.status_code != 402:
            return response

        # If we had a session and got 402, the session expired/was settled
        if session_id:
            self._clear_session(request)

        # Check if already a retry (via request extensions)
        if request.extensions.get(self.RETRY_KEY):
            return response  # Return 402 without retry

        try:
            # Read response body before parsing
            await response.aread()

            # Parse PaymentRequired (try header first for V2, then body for V1)
            def get_header(name: str) -> str | None:
                return response.headers.get(name)

            body = None
            try:
                body = response.json()
            except json.JSONDecodeError:
                pass

            payment_required = self._http_client.get_payment_required_response(get_header, body)

            # Create payment payload
            payment_payload = await self._client.create_payment_payload(payment_required)

            # Encode payment headers
            payment_headers = self._http_client.encode_payment_signature_header(payment_payload)

            # Clone request with payment headers and retry flag
            new_headers = dict(request.headers)
            new_headers.update(payment_headers)
            new_headers["Access-Control-Expose-Headers"] = "PAYMENT-RESPONSE,X-PAYMENT-RESPONSE"

            # Remove stale session header if present
            new_headers.pop(self.SESSION_HEADER, None)

            # Mark as retry in extensions
            new_extensions = dict(request.extensions)
            new_extensions[self.RETRY_KEY] = True

            # Create new request
            retry_request = Request(
                method=request.method,
                url=request.url,
                headers=new_headers,
                content=request.content,
                extensions=new_extensions,
            )

            # Retry using same transport
            retry_response = await self._transport.handle_async_request(retry_request)

            # Capture session from the retry response (server creates session on first payment)
            if 200 <= retry_response.status_code < 300:
                resp_session = retry_response.headers.get(self.SESSION_HEADER.lower()) or \
                               retry_response.headers.get(self.SESSION_HEADER)
                if resp_session:
                    self._store_session(request, resp_session)
                else:
                    logger.debug(
                        "UPTO_CLIENT_SESSION_MISS_ON_RETRY_SUCCESS key=%s status=%s headers_present=%s",
                        self._session_key(request),
                        retry_response.status_code,
                        self.SESSION_HEADER in retry_response.headers
                        or self.SESSION_HEADER.lower() in retry_response.headers,
                    )

            return retry_response

        except PaymentError:
            raise
        except Exception as e:
            raise PaymentError(f"Failed to handle payment: {e}") from e


    async def aclose(self) -> None:
        """Close the underlying transport."""
        await self._transport.aclose()


def x402_httpx_transport(
    client: x402Client | x402HTTPClient,
    transport: AsyncBaseTransport | None = None,
) -> x402AsyncTransport:
    """Create an httpx transport with 402 payment handling.

    Args:
        client: x402Client or x402HTTPClient for payment handling.
        transport: Optional underlying transport. If None, uses httpx default.

    Returns:
        Transport that handles 402 responses with automatic payment retry.

    Example:
        ```python
        from x402 import x402Client
        from x402.http.clients import x402_httpx_transport
        import httpx

        client = x402Client()
        # ... register schemes ...

        async with httpx.AsyncClient(
            transport=x402_httpx_transport(client)
        ) as http:
            response = await http.get("https://api.example.com/paid")
        ```
    """
    return x402AsyncTransport(client, transport)


# Legacy alias for backwards compatibility (event hooks don't work correctly)
def x402_httpx_hooks(
    client: x402Client | x402HTTPClient,
) -> dict[str, list[Callable[..., Any]]]:
    """DEPRECATED: Event hooks cannot modify responses in httpx.

    Use x402_httpx_transport() instead, or x402HttpxClient class.

    This function is kept for API compatibility but logs a warning.
    """
    import warnings

    warnings.warn(
        "x402_httpx_hooks is deprecated because httpx event hooks cannot modify "
        "responses. Use x402_httpx_transport() or x402HttpxClient instead.",
        DeprecationWarning,
        stacklevel=2,
    )

    # Return empty hooks - the transport approach should be used
    return {"request": [], "response": []}


# ============================================================================
# Wrapper Functions
# ============================================================================


def wrapHttpxWithPayment(
    x402_client: x402Client | x402HTTPClient,
    **httpx_kwargs: Any,
) -> httpx.AsyncClient:
    """Create an httpx AsyncClient with automatic 402 payment handling.

    Creates a new client with payment transport configured.

    Note: Unlike the old API, this creates a new client rather than
    wrapping an existing one, because httpx doesn't allow replacing
    the transport of an existing client.

    Args:
        x402_client: x402Client or x402HTTPClient for payments.
        **httpx_kwargs: Additional arguments for httpx.AsyncClient.

    Returns:
        New AsyncClient with payment handling configured.

    Example:
        ```python
        import httpx
        from x402 import x402Client
        from x402.http.clients import wrapHttpxWithPayment

        x402 = x402Client()
        # ... register schemes ...

        async with wrapHttpxWithPayment(x402) as client:
            response = await client.get("https://api.example.com/paid")
        ```
    """
    transport = x402AsyncTransport(x402_client)
    return httpx.AsyncClient(transport=transport, **httpx_kwargs)


def wrapHttpxWithPaymentFromConfig(
    config: x402ClientConfig,
    **httpx_kwargs: Any,
) -> httpx.AsyncClient:
    """Create httpx client with payment handling using configuration.

    Creates a new x402Client from the configuration and wraps it
    in an httpx AsyncClient with automatic 402 payment handling.

    Args:
        config: x402ClientConfig with schemes, policies, and selector.
        **httpx_kwargs: Additional arguments for httpx.AsyncClient.

    Returns:
        New AsyncClient with payment handling configured.

    Example:
        ```python
        import httpx
        from x402 import x402ClientConfig, SchemeRegistration
        from x402.http.clients import wrapHttpxWithPaymentFromConfig
        from x402.mechanisms.evm.exact import ExactEvmScheme

        config = x402ClientConfig(
            schemes=[
                SchemeRegistration(
                    network="eip155:8453",
                    client=ExactEvmScheme(signer=my_signer),
                ),
            ],
        )

        async with wrapHttpxWithPaymentFromConfig(config) as client:
            response = await client.get("https://api.example.com/paid")
        ```
    """
    from ...client import x402Client as Client

    client = Client.from_config(config)
    return wrapHttpxWithPayment(client, **httpx_kwargs)


# ============================================================================
# Convenience Class (like legacy Python)
# ============================================================================


class x402HttpxClient(httpx.AsyncClient):
    """AsyncClient with built-in x402 payment handling.

    Convenience class that wraps httpx.AsyncClient with automatic
    402 payment handling using a custom transport.

    Example:
        ```python
        from x402 import x402Client
        from x402.http.clients import x402HttpxClient

        x402 = x402Client()
        # ... register schemes ...

        async with x402HttpxClient(x402) as client:
            response = await client.get("https://api.example.com/paid")
        ```
    """

    def __init__(
        self,
        x402_client: x402Client | x402HTTPClient,
        **kwargs: Any,
    ) -> None:
        """Initialize payment-enabled httpx client.

        Args:
            x402_client: x402Client or x402HTTPClient for payments.
            **kwargs: Additional arguments for httpx.AsyncClient.
        """
        # Create payment transport
        transport = x402AsyncTransport(x402_client)
        super().__init__(transport=transport, **kwargs)
