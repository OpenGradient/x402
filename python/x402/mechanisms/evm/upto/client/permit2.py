"""Client-side upto Permit2 helpers."""

from __future__ import annotations

import time
from typing import Any

from .....schemas import PaymentRequirements
from ...constants import (
    PERMIT2_ADDRESS,
    UPTO_PERMIT2_WITNESS_TYPES,
    X402_UPTO_PERMIT2_PROXY_ADDRESS,
)
from ...types import (
    ExactPermit2TokenPermissions,
    TypedDataField,
    UptoPermit2Authorization,
    UptoPermit2Payload,
    UptoPermit2Witness,
)
from ...utils import create_permit2_nonce, get_evm_chain_id, normalize_address
from .errors import ERR_FAILED_TO_SIGN_PERMIT2_AUTHORIZATION, ERR_MISSING_FACILITATOR_ADDRESS


def create_upto_permit2_payload(
    signer: Any,
    requirements: PaymentRequirements,
) -> dict[str, Any]:
    """Create a signed upto Permit2 payload."""
    extra = requirements.extra or {}
    facilitator_address = extra.get("facilitatorAddress")
    if not facilitator_address:
        raise ValueError(
            f"{ERR_MISSING_FACILITATOR_ADDRESS}: "
            "paymentRequirements.extra.facilitatorAddress is required"
        )

    now = int(time.time())
    permit2_authorization = UptoPermit2Authorization(
        from_address=signer.address,
        permitted=ExactPermit2TokenPermissions(
            token=normalize_address(requirements.asset),
            amount=requirements.amount,
        ),
        spender=X402_UPTO_PERMIT2_PROXY_ADDRESS,
        nonce=create_permit2_nonce(),
        deadline=str(now + (requirements.max_timeout_seconds or 3600)),
        witness=UptoPermit2Witness(
            to=normalize_address(requirements.pay_to),
            facilitator=normalize_address(str(facilitator_address)),
            valid_after=str(now - 600),
        ),
    )

    try:
        signature = _sign_upto_permit2_authorization(signer, permit2_authorization, requirements)
    except Exception as exc:
        raise ValueError(f"{ERR_FAILED_TO_SIGN_PERMIT2_AUTHORIZATION}: {exc}") from exc

    return UptoPermit2Payload(
        permit2_authorization=permit2_authorization,
        signature=signature,
    ).to_dict()


def _sign_upto_permit2_authorization(
    signer: Any,
    permit2_authorization: UptoPermit2Authorization,
    requirements: PaymentRequirements,
) -> str:
    chain_id = get_evm_chain_id(str(requirements.network))
    domain_dict, typed_fields, primary_type, message = build_upto_permit2_typed_data(
        permit2_authorization, chain_id
    )
    sig_bytes = signer.sign_typed_data(
        domain_dict,  # type: ignore[arg-type]
        typed_fields,
        primary_type,
        message,
    )
    return "0x" + sig_bytes.hex()


def build_upto_permit2_typed_data(
    permit2_authorization: UptoPermit2Authorization,
    chain_id: int,
) -> tuple[dict[str, Any], dict[str, list[TypedDataField]], str, dict[str, Any]]:
    """Build the EIP-712 payload for upto Permit2 signatures."""
    domain_dict: dict[str, Any] = {
        "name": "Permit2",
        "chainId": chain_id,
        "verifyingContract": PERMIT2_ADDRESS,
    }

    message = {
        "permitted": {
            "token": permit2_authorization.permitted.token,
            "amount": int(permit2_authorization.permitted.amount),
        },
        "spender": permit2_authorization.spender,
        "nonce": int(permit2_authorization.nonce),
        "deadline": int(permit2_authorization.deadline),
        "witness": {
            "to": permit2_authorization.witness.to,
            "facilitator": permit2_authorization.witness.facilitator,
            "validAfter": int(permit2_authorization.witness.valid_after),
        },
    }

    typed_fields: dict[str, list[TypedDataField]] = {
        type_name: [TypedDataField(name=field["name"], type=field["type"]) for field in fields]
        for type_name, fields in UPTO_PERMIT2_WITNESS_TYPES.items()
    }

    return domain_dict, typed_fields, "PermitWitnessTransferFrom", message


__all__ = [
    "build_upto_permit2_typed_data",
    "create_upto_permit2_payload",
]
