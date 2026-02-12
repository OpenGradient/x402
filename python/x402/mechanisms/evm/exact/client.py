"""EVM client implementation for the Exact payment scheme (V2).

Routes to EIP-3009 or Permit2 based on requirements.extra["assetTransferMethod"].
Defaults to EIP-3009 for backward compatibility.
Mirrors Go implementation in go/mechanisms/evm/exact/client/scheme.go.
"""

from datetime import timedelta
from typing import Any

from ....schemas import PaymentRequirements
from ..constants import SCHEME_EXACT
from ..eip712 import build_typed_data_for_signing
from ..signer import ClientEvmSigner
from ..types import ExactEIP3009Authorization, ExactEIP3009Payload, TypedDataField
from ..utils import (
    create_nonce,
    create_validity_window,
    get_asset_info,
    get_evm_chain_id,
)
from .permit2 import create_permit2_payload

# Asset transfer method constants (matches Go's AssetTransferMethod type)
ASSET_TRANSFER_METHOD_EIP3009 = "eip3009"
ASSET_TRANSFER_METHOD_PERMIT2 = "permit2"


class ExactEvmScheme:
    """EVM client implementation for the Exact payment scheme (V2).

    Routes to EIP-3009 or Permit2 based on requirements.extra["assetTransferMethod"].
    Defaults to EIP-3009 for backward compatibility.

    Implements SchemeNetworkClient protocol. Returns the inner payload dict,
    which x402Client wraps into a full PaymentPayload.

    Attributes:
        scheme: The scheme identifier ("exact").
    """

    scheme = SCHEME_EXACT

    def __init__(self, signer: ClientEvmSigner):
        """Create ExactEvmScheme.

        Args:
            signer: EVM signer for payment authorizations.
        """
        self._signer = signer

    def create_payment_payload(
        self,
        requirements: PaymentRequirements,
    ) -> dict[str, Any]:
        """Create signed inner payload.

        Routes to EIP-3009 or Permit2 based on requirements.extra["assetTransferMethod"].
        Defaults to EIP-3009 for backward compatibility.

        Args:
            requirements: Payment requirements from server.

        Returns:
            Inner payload dict (authorization + signature).
            x402Client wraps this with x402_version, accepted, resource, extensions.
        """
        # Check asset transfer method (matches Go scheme.go logic)
        extra = requirements.extra or {}
        asset_transfer_method = extra.get(
            "assetTransferMethod", ASSET_TRANSFER_METHOD_EIP3009
        )

        # Route based on method
        if asset_transfer_method == ASSET_TRANSFER_METHOD_PERMIT2:
            return create_permit2_payload(self._signer, requirements)

        # Default to EIP-3009
        return self._create_eip3009_payload(requirements)

    def _create_eip3009_payload(
        self,
        requirements: PaymentRequirements,
    ) -> dict[str, Any]:
        """Create EIP-3009 (transferWithAuthorization) payload.

        Args:
            requirements: Payment requirements from server.

        Returns:
            Inner payload dict (authorization + signature).
        """
        nonce = create_nonce()
        valid_after, valid_before = create_validity_window(
            timedelta(seconds=requirements.max_timeout_seconds or 3600)
        )

        authorization = ExactEIP3009Authorization(
            from_address=self._signer.address,
            to=requirements.pay_to,
            value=requirements.amount,
            valid_after=str(valid_after),
            valid_before=str(valid_before),
            nonce=nonce,
        )

        signature = self._sign_authorization(authorization, requirements)

        payload = ExactEIP3009Payload(authorization=authorization, signature=signature)

        # Return inner payload dict - x402Client wraps this
        return payload.to_dict()

    def _sign_authorization(
        self,
        authorization: ExactEIP3009Authorization,
        requirements: PaymentRequirements,
    ) -> str:
        """Sign EIP-3009 authorization using EIP-712.

        Requires requirements.extra to contain 'name' and 'version'
        for the EIP-712 domain separator.

        Args:
            authorization: The authorization to sign.
            requirements: Payment requirements with EIP-712 domain info.

        Returns:
            Hex-encoded signature with 0x prefix.

        Raises:
            ValueError: If EIP-712 domain parameters are missing.
        """
        chain_id = get_evm_chain_id(str(requirements.network))

        extra = requirements.extra or {}
        if "name" not in extra:
            # Try to get from asset info
            try:
                asset_info = get_asset_info(str(requirements.network), requirements.asset)
                extra["name"] = asset_info["name"]
                extra["version"] = asset_info.get("version", "1")
            except ValueError:
                raise ValueError(
                    "EIP-712 domain parameters (name, version) required in extra"
                ) from None

        name = extra["name"]
        version = extra.get("version", "1")

        domain, types, primary_type, message = build_typed_data_for_signing(
            authorization,
            chain_id,
            requirements.asset,
            name,
            version,
        )

        # Convert types dict to match signer protocol
        typed_fields: dict[str, list[TypedDataField]] = {}
        for type_name, fields in types.items():
            typed_fields[type_name] = [
                TypedDataField(name=f["name"], type=f["type"]) for f in fields
            ]

        sig_bytes = self._signer.sign_typed_data(domain, typed_fields, primary_type, message)

        return "0x" + sig_bytes.hex()

