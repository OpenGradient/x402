"""Permit2 client implementation for the Exact payment scheme.

Mirrors the Go implementation in go/mechanisms/evm/exact/client/permit2.go.
"""

import os
import time
from typing import Any

from ....schemas import PaymentRequirements
from ..constants import (
    PERMIT2_ADDRESS,
    PERMIT2_WITNESS_TYPES,
    X402_EXACT_PERMIT2_PROXY_ADDRESS,
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


def create_permit2_nonce() -> str:
    """Generate a random 256-bit nonce for Permit2.

    Permit2 uses uint256 nonces (not bytes32 like EIP-3009).
    Returns the nonce as a decimal string, matching Go's CreatePermit2Nonce.

    Returns:
        Decimal string representation of a random uint256.
    """
    nonce_bytes = os.urandom(32)
    return str(int.from_bytes(nonce_bytes, "big"))


def create_permit2_payload(
    signer: ClientEvmSigner,
    requirements: PaymentRequirements,
) -> dict[str, Any]:
    """Create a Permit2 payload using the x402Permit2Proxy witness pattern.

    The spender is set to x402Permit2Proxy, which enforces that funds
    can only be sent to the witness.to address.

    Args:
        signer: EVM signer.
        requirements: Payment requirements.

    Returns:
        Inner payload dict (permit2Authorization + signature).
    """
    nonce = create_permit2_nonce()

    now = int(time.time())
    valid_after = now - 600  # 10 minutes buffer for clock skew (matches Go)
    deadline = now + (requirements.max_timeout_seconds or 3600)

    # Normalize addresses (matches Go's NormalizeAddress)
    token_address = normalize_address(requirements.asset)
    pay_to = normalize_address(requirements.pay_to)

    # Witness data (custom for x402)
    witness = Permit2Witness(
        to=pay_to,
        valid_after=valid_after,
        extra="0x",
    )

    # Token permissions
    permitted = Permit2TokenPermissions(
        token=token_address,
        amount=int(requirements.amount),
    )

    # Full authorization struct
    authorization = Permit2Authorization(
        permitted=permitted,
        spender=X402_EXACT_PERMIT2_PROXY_ADDRESS,
        nonce=int(nonce),
        deadline=deadline,
        witness=witness,
        from_address=signer.address,
    )

    # Sign the authorization
    signature = sign_permit2_authorization(signer, authorization, requirements)

    # Create payload
    payload = ExactPermit2Payload(
        permit2_authorization=authorization,
        signature=signature,
    )

    return payload.to_dict()


def sign_permit2_authorization(
    signer: ClientEvmSigner,
    authorization: Permit2Authorization,
    requirements: PaymentRequirements,
) -> str:
    """Sign Permit2 authorization using EIP-712.

    Args:
        signer: EVM signer.
        authorization: Permit2 authorization data.
        requirements: Payment requirements (for chain ID).

    Returns:
        Hex-encoded signature with 0x prefix.
    """
    chain_id = get_evm_chain_id(str(requirements.network))

    # Create EIP-712 domain (Permit2 uses fixed name, no version)
    domain = TypedDataDomain(
        name="Permit2",
        version=None,
        chain_id=chain_id,
        verifying_contract=PERMIT2_ADDRESS,
    )

    # Convert witness.extra from hex string to bytes for EIP-712 encoding
    extra_bytes = hex_to_bytes(authorization.witness.extra)

    # Message to sign — matches Go's message structure
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

    # Convert types dict to match signer protocol
    typed_fields: dict[str, list[TypedDataField]] = {}
    for type_name, fields in PERMIT2_WITNESS_TYPES.items():
        typed_fields[type_name] = [
            TypedDataField(name=f["name"], type=f["type"]) for f in fields
        ]

    primary_type = "PermitWitnessTransferFrom"

    sig_bytes = signer.sign_typed_data(domain, typed_fields, primary_type, message)

    return "0x" + sig_bytes.hex()


class ExactPermit2Scheme:
    """EVM client implementation for the Exact Permit2 payment scheme (V2).

    Thin wrapper around create_permit2_payload for direct Permit2-only usage.
    Implements SchemeNetworkClient protocol.
    """

    scheme = "exact"

    def __init__(self, signer: ClientEvmSigner):
        """Create ExactPermit2Scheme.

        Args:
            signer: EVM signer.
        """
        self._signer = signer

    def create_payment_payload(
        self,
        requirements: PaymentRequirements,
    ) -> dict[str, Any]:
        """Create signed Permit2 inner payload.

        Args:
            requirements: Payment requirements from server.

        Returns:
            Inner payload dict.
        """
        return create_permit2_payload(self._signer, requirements)
