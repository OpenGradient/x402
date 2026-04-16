"""Facilitator-side upto EVM scheme."""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any

from .....interfaces import FacilitatorContext
from .....schemas import PaymentPayload, PaymentRequirements, SettleResponse, VerifyResponse
from ...constants import SCHEME_UPTO
from ...signer import FacilitatorEvmSigner
from ...types import UptoPermit2Payload
from .errors import ERR_UPTO_INVALID_PAYLOAD
from .permit2 import settle_upto_permit2, verify_upto_permit2


@dataclass
class UptoEvmSchemeConfig:
    """Configuration for facilitator-side upto EVM support."""

    simulate_in_settle: bool = False


class UptoEvmScheme:
    """EVM facilitator implementation for the upto payment scheme."""

    scheme = SCHEME_UPTO
    caip_family = "eip155:*"

    def __init__(
        self,
        signer: FacilitatorEvmSigner,
        config: UptoEvmSchemeConfig | None = None,
    ):
        self._signer = signer
        self._config = config or UptoEvmSchemeConfig()

    def get_extra(self, network: str) -> dict[str, Any] | None:
        addresses = self._signer.get_addresses()
        if not addresses:
            return None
        return {"facilitatorAddress": random.choice(addresses)}

    def get_signers(self, network: str) -> list[str]:
        return self._signer.get_addresses()

    def verify(
        self,
        payload: PaymentPayload,
        requirements: PaymentRequirements,
        context: FacilitatorContext | None = None,
    ) -> VerifyResponse:
        if "permit2Authorization" not in payload.payload:
            return VerifyResponse(is_valid=False, invalid_reason=ERR_UPTO_INVALID_PAYLOAD)

        permit2_payload = UptoPermit2Payload.from_dict(payload.payload)
        return verify_upto_permit2(
            self._signer,
            payload,
            requirements,
            permit2_payload,
            context,
            simulate=True,
        )

    def settle(
        self,
        payload: PaymentPayload,
        requirements: PaymentRequirements,
        context: FacilitatorContext | None = None,
    ) -> SettleResponse:
        if "permit2Authorization" not in payload.payload:
            return SettleResponse(
                success=False,
                error_reason=ERR_UPTO_INVALID_PAYLOAD,
                network=str(payload.accepted.network),
                transaction="",
            )

        permit2_payload = UptoPermit2Payload.from_dict(payload.payload)
        return settle_upto_permit2(
            self._signer,
            payload,
            requirements,
            permit2_payload,
            context,
            simulate_in_settle=self._config.simulate_in_settle,
        )


__all__ = [
    "UptoEvmScheme",
    "UptoEvmSchemeConfig",
]
