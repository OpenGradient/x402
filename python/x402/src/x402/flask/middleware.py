import base64
import json
from typing import Any, Dict, Optional, Union, get_args, cast
from flask import Flask, request, g
from x402.path import path_is_match
from x402.types import (
    Price,
    PaymentPayload,
    PaymentRequirements,
    x402PaymentRequiredResponse,
    PaywallConfig,
    SupportedNetworks,
    HTTPInputSchema,
)
import threading
import hashlib
from x402.common import (
    process_price_to_atomic_amount,
    x402_VERSION,
    find_matching_payment_requirements,
)
from x402.encoding import safe_base64_decode
from x402.facilitator import FacilitatorClient, FacilitatorConfig
from x402.paywall import is_browser_request, get_paywall_html
import os
from web3 import Web3
from eth_account import Account
from io import BytesIO
import asyncio


class ResponseWrapper:
    """Wrapper to capture response status and headers."""

    def __init__(self, start_response):
        self.original_start_response = start_response
        self.status_code = None
        self.status = None
        self.headers = []
        self.write_callable_chunks = []
        self._headers_sent = False
        self._write_func = None

    def __call__(self, status, headers, exc_info=None):
        self.status = status
        self.status_code = int(status.split()[0])
        self.headers = list(headers)

        def buffered_write(data):
            if data:
                self.write_callable_chunks.append(data)

        return buffered_write

    def add_header(self, name, value):
        """Add a header to the response."""
        self.headers.append((name, value))

    def send_headers(self):
        """Send headers immediately for streaming."""
        if not self._headers_sent:
            self._write_func = self.original_start_response(self.status, self.headers)
            self._headers_sent = True
            for chunk in self.write_callable_chunks:
                if chunk:
                    self._write_func(chunk)

    def send_response(self, body_chunks):
        """Send the buffered response (non-streaming mode)."""
        write = self.original_start_response(self.status, self.headers)
        for chunk in self.write_callable_chunks:
            if chunk:
                write(chunk)
        for chunk in body_chunks:
            if chunk:
                write(chunk)


def is_streaming_request(body_bytes: bytes) -> bool:
    """
    Detect if this is a streaming request by checking:
    1. Request body contains "stream": true (OpenAI/Anthropic style)
    2. Accept header contains text/event-stream
    """
    # Check request body for stream parameter
    try:
        body = json.loads(body_bytes.decode('utf-8'))
        if body.get('stream', False) is True:
            return True
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    
    return False


def is_streaming_response(headers: list) -> bool:
    """
    Detect if the response is a streaming response by checking Content-Type.
    """
    for name, value in headers:
        if name.lower() == 'content-type':
            if 'text/event-stream' in value.lower():
                return True
            if 'application/x-ndjson' in value.lower():
                return True
    return False


class PaymentMiddleware:
    """
    Flask middleware for x402 payment requirements.
    Automatically detects and handles streaming vs non-streaming responses.
    """

    def __init__(self, app: Flask):
        self.app = app
        self.middleware_configs = []
        self.original_wsgi_app = app.wsgi_app

    def add(
        self,
        price: Price,
        pay_to_address: str,
        path: Union[str, list[str]] = "*",
        description: str = "",
        mime_type: str = "",
        max_deadline_seconds: int = 60,
        input_schema: Optional[HTTPInputSchema] = None,
        output_schema: Optional[Any] = None,
        discoverable: Optional[bool] = True,
        facilitator_config: Optional[FacilitatorConfig] = None,
        network: str = "base-sepolia",
        resource: Optional[str] = None,
        paywall_config: Optional[PaywallConfig] = None,
        custom_paywall_html: Optional[str] = None,
        streaming: Optional[bool] = None,  # None = auto-detect, True/False = force
    ):
        """
        Add a payment middleware configuration.

        Args:
            ... (existing args)
            streaming (Optional[bool]): 
                - None (default): Auto-detect based on request body ("stream": true)
                - True: Force streaming mode
                - False: Force non-streaming mode
        """
        config = {
            "price": price,
            "pay_to_address": pay_to_address,
            "path": path,
            "description": description,
            "mime_type": mime_type,
            "max_deadline_seconds": max_deadline_seconds,
            "input_schema": input_schema,
            "output_schema": output_schema,
            "discoverable": discoverable,
            "facilitator_config": facilitator_config,
            "network": network,
            "resource": resource,
            "paywall_config": paywall_config,
            "custom_paywall_html": custom_paywall_html,
            "streaming": streaming,
        }
        self.middleware_configs.append(config)
        self._apply_middleware()

    def _apply_middleware(self):
        """Apply all middleware configurations to the Flask app."""
        current_wsgi_app = self.original_wsgi_app

        for config in self.middleware_configs:
            middleware = self._create_middleware(config, current_wsgi_app)
            current_wsgi_app = middleware

        self.app.wsgi_app = current_wsgi_app

    def _create_middleware(self, config: Dict[str, Any], next_app):
        """Create a WSGI middleware function for the given configuration."""

        supported_networks = get_args(SupportedNetworks)
        if config["network"] not in supported_networks:
            raise ValueError(
                f"Unsupported network: {config['network']}. Must be one of: {supported_networks}"
            )

        try:
            max_amount_required, asset_address, eip712_domain = (
                process_price_to_atomic_amount(config["price"], config["network"])
            )
        except Exception as e:
            raise ValueError(f"Invalid price: {config['price']}. Error: {e}")

        facilitator = FacilitatorClient(config["facilitator_config"])

        def middleware(environ, start_response):
            with self.app.request_context(environ):
                body_bytes = request.get_data()
                req_headers = request.headers
                input_hash = hashlib.sha256(body_bytes).hexdigest()
                environ["wsgi.input"] = BytesIO(body_bytes)

                if not path_is_match(config["path"], request.path):
                    return next_app(environ, start_response)

                # Determine if this request should use streaming
                # Priority: config override > request body detection
                if config.get("streaming") is not None:
                    use_streaming = config["streaming"]
                else:
                    # Auto-detect from request body
                    use_streaming = is_streaming_request(body_bytes)

                original_uri = req_headers.get("X-Original-URI")
                if original_uri:
                    resource_url = f"{request.scheme}://{request.host}{original_uri}"
                else:
                    resource_url = config["resource"] or request.url

                payment_requirements = [
                    PaymentRequirements(
                        scheme="exact",
                        network=cast(SupportedNetworks, config["network"]),
                        asset=asset_address,
                        max_amount_required=max_amount_required,
                        resource=resource_url,
                        description=config["description"],
                        mime_type=config["mime_type"],
                        pay_to=config["pay_to_address"],
                        max_timeout_seconds=config["max_deadline_seconds"],
                        output_schema={
                            "input": {
                                "type": "http",
                                "method": request.method.upper(),
                                "discoverable": config.get("discoverable", True),
                                **(
                                    config["input_schema"].model_dump()
                                    if config["input_schema"]
                                    else {}
                                ),
                            },
                            "output": config["output_schema"],
                        },
                        extra=eip712_domain,
                    )
                ]

                def x402_response(error: str):
                    """Create a 402 response with payment requirements."""
                    request_headers = dict(request.headers)
                    status = "402 Payment Required"

                    if is_browser_request(request_headers):
                        html_content = config["custom_paywall_html"] or get_paywall_html(
                            error, payment_requirements, config["paywall_config"]
                        )
                        resp_headers = [("Content-Type", "text/html; charset=utf-8")]
                        start_response(status, resp_headers)
                        return [html_content.encode("utf-8")]
                    else:
                        response_data = x402PaymentRequiredResponse(
                            x402_version=x402_VERSION,
                            accepts=payment_requirements,
                            error=error,
                        ).model_dump(by_alias=True)
                        resp_headers = [
                            ("Content-Type", "application/json"),
                            ("Content-Length", str(len(json.dumps(response_data)))),
                        ]
                        start_response(status, resp_headers)
                        return [json.dumps(response_data).encode("utf-8")]

                # Check for payment header
                payment_header = request.headers.get("X-PAYMENT", "")

                if payment_header == "":
                    return x402_response("No X-PAYMENT header provided")

                try:
                    payment_dict = json.loads(safe_base64_decode(payment_header))
                    payment = PaymentPayload(**payment_dict)
                except Exception as e:
                    return x402_response(f"Invalid payment header format: {str(e)}")

                selected_payment_requirements = find_matching_payment_requirements(
                    payment_requirements, payment
                )

                if not selected_payment_requirements:
                    return x402_response("No matching payment requirements found")

                # Verify payment
                try:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    verify_response = loop.run_until_complete(
                        facilitator.verify(payment, selected_payment_requirements)
                    )
                finally:
                    loop.close()

                if not verify_response.is_valid:
                    error_reason = verify_response.invalid_reason or "Unknown error"
                    return x402_response(f"Invalid payment: {error_reason}")

                g.payment_details = selected_payment_requirements
                g.verify_response = verify_response

                # Get settlement metadata
                settlement_type = req_headers.get("x-settlement-type", "settle-batch")
                model_name = ""
                if settlement_type == "settle-metadata":
                    try:
                        request_body = json.loads(body_bytes.decode('utf-8'))
                        model_name = request_body.get("model", "")
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        model_name = ""

                if use_streaming:
                    response_wrapper = ResponseWrapper(start_response)

                    def streaming_generator():
                        """
                        Generator that:
                        1. Yields chunks to client IMMEDIATELY
                        2. Calculates hash incrementally
                        3. Sends settlement to facilitator AFTER stream completes
                        """
                        output_hasher = hashlib.sha256()
                        first_chunk = True
                        is_success = False
                        actual_streaming_response = False

                        for chunk in next_app(environ, response_wrapper):
                            if first_chunk:
                                first_chunk = False
                                is_success = (
                                    response_wrapper.status_code is not None
                                    and 200 <= response_wrapper.status_code < 300
                                )
                                actual_streaming_response = is_streaming_response(
                                    response_wrapper.headers
                                )
                                response_wrapper.send_headers()

                            if chunk:
                                output_hasher.update(chunk)
                                yield chunk

                        if is_success:
                            output_hash = output_hasher.hexdigest()
                            threading.Thread(
                                target=lambda: asyncio.run(
                                    facilitator.settle(
                                        payment,
                                        selected_payment_requirements,
                                        "0x" + input_hash,
                                        "0x" + output_hash,
                                        settlement_type,
                                        model_name,
                                    )
                                )
                            ).start()

                    return streaming_generator()

                response_wrapper = ResponseWrapper(start_response)

                response_body_chunks = []
                for chunk in next_app(environ, response_wrapper):
                    response_body_chunks.append(chunk)

                response_body = b"".join(response_body_chunks)
                output_hash = hashlib.sha256(response_body).hexdigest()

                if (
                    response_wrapper.status_code is not None
                    and 200 <= response_wrapper.status_code < 300
                ):
                    threading.Thread(
                        target=lambda: asyncio.run(
                            facilitator.settle(
                                payment,
                                selected_payment_requirements,
                                "0x" + input_hash,
                                "0x" + output_hash,
                                settlement_type,
                                model_name,
                            )
                        )
                    ).start()

                response_wrapper.send_response(response_body_chunks)
                return []

        return middleware