"""EVM client implementation for the Upto payment scheme.

Creates Permit2 payloads with a spend-cap amount. The signed amount
represents the maximum the client is willing to spend across a session.
Actual settlement uses the accumulated cost (≤ signed amount).

Reuses the Permit2 signing from exact/permit2.py — the only difference
is the spender address (x402UptoPermit2Proxy) and the scheme name.
"""

import os
import time
from typing import Any

from ....schemas import PaymentRequirements
from ..constants import (
    PERMIT2_ADDRESS,
    PERMIT2_WITNESS_TYPES,
    SCHEME_UPTO,
    X402_UPTO_PERMIT2_PROXY_ADDRESS,
)
from ..signer import ClientEvmSigner
from ..types import (
    ExactPermit2Payload,
    Permit2Authorization,
    Permit2TokenPermissions,
    Permit2Witness,
    TypedDataDomain,
    TypedDataField,
)
from ..utils import get_evm_chain_id, hex_to_bytes, normalize_address


class UptoEvmScheme:
    """EVM client implementation for the Upto payment scheme (V2).

    Creates Permit2 payloads with spender = x402UptoPermit2Proxy.
    The amount in the payload is the spend cap (max amount).

    Implements SchemeNetworkClient protocol.

    Attributes:
        scheme: The scheme identifier ("upto").
    """

    scheme = SCHEME_UPTO

    def __init__(self, signer: ClientEvmSigner):
        """Create UptoEvmScheme.

        Args:
            signer: EVM signer for payment authorizations.
        """
        self._signer = signer

    def create_payment_payload(
        self,
        requirements: PaymentRequirements,
    ) -> dict[str, Any]:
        """Create signed Permit2 inner payload for upto scheme.

        The permitted amount is set to the requirements.amount which
        represents the spend cap for this session.

        Args:
            requirements: Payment requirements from server.

        Returns:
            Inner payload dict (permit2Authorization + signature).
        """
        return _create_upto_permit2_payload(self._signer, requirements)


def _create_upto_permit2_nonce() -> str:
    """Generate a random 256-bit nonce for Permit2.

    Returns:
        Decimal string representation of a random uint256.
    """
    nonce_bytes = os.urandom(32)
    return str(int.from_bytes(nonce_bytes, "big"))


def _create_upto_permit2_payload(
    signer: ClientEvmSigner,
    requirements: PaymentRequirements,
) -> dict[str, Any]:
    """Create a Permit2 payload for the upto scheme.

    Same as exact Permit2 but with spender = x402UptoPermit2Proxy.

    Args:
        signer: EVM signer.
        requirements: Payment requirements.

    Returns:
        Inner payload dict (permit2Authorization + signature).
    """
    nonce = _create_upto_permit2_nonce()

    now = int(time.time())
    valid_after = now - 600  # 10 minutes buffer for clock skew
    deadline = now + (requirements.max_timeout_seconds or 3600)

    # Normalize addresses
    token_address = normalize_address(requirements.asset)
    pay_to = normalize_address(requirements.pay_to)

    # Witness data
    witness = Permit2Witness(
        to=pay_to,
        valid_after=valid_after,
        extra="0x",
    )

    # Token permissions — amount is the spend cap
    permitted = Permit2TokenPermissions(
        token=token_address,
        amount=int(requirements.amount),
    )

    # Full authorization — spender is the UPTO proxy
    authorization = Permit2Authorization(
        permitted=permitted,
        spender=X402_UPTO_PERMIT2_PROXY_ADDRESS,
        nonce=int(nonce),
        deadline=deadline,
        witness=witness,
        from_address=signer.address,
    )

    # Sign the authorization
    signature = _sign_upto_permit2(signer, authorization, requirements)

    # Create payload
    payload = ExactPermit2Payload(
        permit2_authorization=authorization,
        signature=signature,
    )

    return payload.to_dict()


def _sign_upto_permit2(
    signer: ClientEvmSigner,
    authorization: Permit2Authorization,
    requirements: PaymentRequirements,
) -> str:
    """Sign Permit2 authorization using EIP-712 for upto scheme.

    Uses the same Permit2 witness types as exact — the on-chain
    difference is only in the spender address.

    Args:
        signer: EVM signer.
        authorization: Permit2 authorization data.
        requirements: Payment requirements (for chain ID).

    Returns:
        Hex-encoded signature with 0x prefix.
    """
    chain_id = get_evm_chain_id(str(requirements.network))

    domain = TypedDataDomain(
        name="Permit2",
        version=None,
        chain_id=chain_id,
        verifying_contract=PERMIT2_ADDRESS,
    )

    extra_bytes = hex_to_bytes(authorization.witness.extra)

    message = {
        "permitted": {
            "token": authorization.permitted.token,
            "amount": int(authorization.permitted.amount),
        },
        "spender": authorization.spender,
        "nonce": int(authorization.nonce),
        "deadline": int(authorization.deadline),
        "witness": {
            "to": authorization.witness.to,
            "validAfter": int(authorization.witness.valid_after),
            "extra": extra_bytes,
        },
    }

    typed_fields: dict[str, list[TypedDataField]] = {}
    for type_name, fields in PERMIT2_WITNESS_TYPES.items():
        typed_fields[type_name] = [
            TypedDataField(name=f["name"], type=f["type"]) for f in fields
        ]

    primary_type = "PermitWitnessTransferFrom"

    sig_bytes = signer.sign_typed_data(domain, typed_fields, primary_type, message)

    return "0x" + sig_bytes.hex()
