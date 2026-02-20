"""EVM facilitator implementation for the Upto payment scheme (V2).

Verifies Permit2 payloads and settles via x402UptoPermit2Proxy.settle().
The settle call sends the actual accumulated amount (≤ signed max).
"""

import time
from dataclasses import dataclass
from typing import Any

from ....schemas import (
    Network,
    PaymentPayload,
    PaymentRequirements,
    SettleResponse,
    VerifyResponse,
)
from ..constants import (
    ERR_FAILED_TO_GET_ASSET_INFO,
    ERR_FAILED_TO_GET_NETWORK_CONFIG,
    ERR_INSUFFICIENT_BALANCE,
    ERR_NETWORK_MISMATCH,
    ERR_TRANSACTION_FAILED,
    ERR_UPTO_AMOUNT_EXCEEDS_PERMITTED,
    ERR_UPTO_DEADLINE_EXPIRED,
    ERR_UPTO_INSUFFICIENT_AMOUNT,
    ERR_UPTO_INVALID_SIGNATURE,
    ERR_UPTO_INVALID_SPENDER,
    ERR_UPTO_NOT_YET_VALID,
    ERR_UPTO_RECIPIENT_MISMATCH,
    ERR_UPTO_TOKEN_MISMATCH,
    ERR_UNSUPPORTED_SCHEME,
    PERMIT2_ADDRESS,
    SCHEME_UPTO,
    TX_STATUS_SUCCESS,
    X402_UPTO_PERMIT2_PROXY_ADDRESS,
)
from ..signer import FacilitatorEvmSigner
from ..types import ExactPermit2Payload
from ..utils import get_asset_info, get_evm_chain_id, get_network_config, hex_to_bytes
from ..verify import verify_universal_signature


def _hash_permit2_authorization(auth, chain_id: int) -> bytes:
    """Hash Permit2 authorization for EIP-712 verification.

    Computes the EIP-712 struct hash that Permit2 uses for
    permitWitnessTransferFrom with the x402 witness type.
    """
    from eth_abi import encode
    from eth_utils import keccak

    from ..constants import PERMIT2_ADDRESS, PERMIT2_WITNESS_TYPES

    # Build type hashes
    # TokenPermissions type hash
    token_permissions_type = "TokenPermissions(address token,uint256 amount)"
    token_permissions_typehash = keccak(token_permissions_type.encode())

    # Witness type hash
    witness_type = "Witness(address to,uint256 validAfter,bytes extra)"
    witness_typehash = keccak(witness_type.encode())

    # PermitWitnessTransferFrom type hash (includes nested types)
    permit_type = (
        "PermitWitnessTransferFrom("
        "TokenPermissions permitted,"
        "address spender,"
        "uint256 nonce,"
        "uint256 deadline,"
        "Witness witness)"
        "TokenPermissions(address token,uint256 amount)"
        "Witness(address to,uint256 validAfter,bytes extra)"
    )
    permit_typehash = keccak(permit_type.encode())

    # Hash TokenPermissions
    token_permissions_hash = keccak(
        encode(
            ["bytes32", "address", "uint256"],
            [token_permissions_typehash, auth.permitted.token, auth.permitted.amount],
        )
    )

    # Hash Witness
    extra_bytes = hex_to_bytes(auth.witness.extra)
    witness_hash = keccak(
        encode(
            ["bytes32", "address", "uint256", "bytes32"],
            [
                witness_typehash,
                auth.witness.to,
                auth.witness.valid_after,
                keccak(extra_bytes),
            ],
        )
    )

    # Hash the full struct
    struct_hash = keccak(
        encode(
            ["bytes32", "bytes32", "address", "uint256", "uint256", "bytes32"],
            [
                permit_typehash,
                token_permissions_hash,
                auth.spender,
                auth.nonce,
                auth.deadline,
                witness_hash,
            ],
        )
    )

    # EIP-712 domain separator for Permit2
    domain_typehash = keccak(
        b"EIP712Domain(string name,uint256 chainId,address verifyingContract)"
    )
    domain_separator = keccak(
        encode(
            ["bytes32", "bytes32", "uint256", "address"],
            [domain_typehash, keccak(b"Permit2"), chain_id, PERMIT2_ADDRESS],
        )
    )

    # Final EIP-712 hash
    return keccak(b"\x19\x01" + domain_separator + struct_hash)


# ABI for x402UptoPermit2Proxy.settle()
X402_UPTO_PROXY_SETTLE_ABI = {
    "type": "function",
    "name": "settle",
    "inputs": [
        {
            "name": "permit",
            "type": "tuple",
            "components": [
                {
                    "name": "permitted",
                    "type": "tuple",
                    "components": [
                        {"name": "token", "type": "address"},
                        {"name": "amount", "type": "uint256"},
                    ],
                },
                {"name": "nonce", "type": "uint256"},
                {"name": "deadline", "type": "uint256"},
            ],
        },
        {"name": "owner", "type": "address"},
        {
            "name": "witness",
            "type": "tuple",
            "components": [
                {"name": "to", "type": "address"},
                {"name": "validAfter", "type": "uint256"},
                {"name": "extra", "type": "bytes"},
            ],
        },
        {"name": "signature", "type": "bytes"},
    ],
    "outputs": [],
    "stateMutability": "nonpayable",
}


@dataclass
class UptoEvmSchemeConfig:
    """Configuration for UptoEvmFacilitatorScheme."""

    pass


class UptoEvmFacilitatorScheme:
    """EVM facilitator implementation for the Upto payment scheme (V2).

    Verifies Permit2 signatures and settles via x402UptoPermit2Proxy.

    Attributes:
        scheme: The scheme identifier ("upto").
        caip_family: The CAIP family pattern ("eip155:*").
    """

    scheme = SCHEME_UPTO
    caip_family = "eip155:*"

    def __init__(
        self,
        signer: FacilitatorEvmSigner,
        config: UptoEvmSchemeConfig | None = None,
    ):
        """Create UptoEvmFacilitatorScheme.

        Args:
            signer: EVM signer for verification and settlement.
            config: Optional configuration.
        """
        self._signer = signer
        self._config = config or UptoEvmSchemeConfig()

    def get_extra(self, network: Network) -> dict[str, Any] | None:
        """Get mechanism-specific extra data.

        Returns assetTransferMethod=permit2 so clients use Permit2.
        """
        return {"assetTransferMethod": "permit2"}

    def get_signers(self, network: Network) -> list[str]:
        """Get facilitator wallet addresses."""
        return self._signer.get_addresses()

    def verify(
        self,
        payload: PaymentPayload,
        requirements: PaymentRequirements,
    ) -> VerifyResponse:
        """Verify Permit2 payment payload for upto scheme.

        Validates:
        - Scheme is "upto"
        - Network matches
        - Spender is x402UptoPermit2Proxy
        - Token matches requirements.asset
        - Amount >= requirements.amount (spend cap)
        - Recipient (witness.to) matches requirements.pay_to
        - Deadline not expired
        - validAfter not in the future
        - Permit2 signature is valid
        - Payer has sufficient balance

        Args:
            payload: Payment payload from client.
            requirements: Payment requirements.

        Returns:
            VerifyResponse with is_valid and payer.
        """
        permit2_payload = ExactPermit2Payload.from_dict(payload.payload)
        auth = permit2_payload.permit2_authorization
        payer = auth.from_address
        network = str(requirements.network)

        # Validate scheme
        if payload.accepted.scheme != SCHEME_UPTO:
            return VerifyResponse(
                is_valid=False, invalid_reason=ERR_UNSUPPORTED_SCHEME, payer=payer
            )

        # Validate network
        if payload.accepted.network != requirements.network:
            return VerifyResponse(
                is_valid=False, invalid_reason=ERR_NETWORK_MISMATCH, payer=payer
            )

        # Get configs
        try:
            get_network_config(network)
        except ValueError as e:
            return VerifyResponse(
                is_valid=False,
                invalid_reason=ERR_FAILED_TO_GET_NETWORK_CONFIG,
                invalid_message=str(e),
                payer=payer,
            )

        try:
            asset_info = get_asset_info(network, requirements.asset)
        except ValueError as e:
            return VerifyResponse(
                is_valid=False,
                invalid_reason=ERR_FAILED_TO_GET_ASSET_INFO,
                invalid_message=str(e),
                payer=payer,
            )

        # Validate spender is the upto proxy
        if auth.spender.lower() != X402_UPTO_PERMIT2_PROXY_ADDRESS.lower():
            return VerifyResponse(
                is_valid=False, invalid_reason=ERR_UPTO_INVALID_SPENDER, payer=payer
            )

        # Validate token matches
        if auth.permitted.token.lower() != requirements.asset.lower():
            return VerifyResponse(
                is_valid=False, invalid_reason=ERR_UPTO_TOKEN_MISMATCH, payer=payer
            )

        # Validate amount (permitted >= required spend cap)
        if auth.permitted.amount < int(requirements.amount):
            return VerifyResponse(
                is_valid=False, invalid_reason=ERR_UPTO_INSUFFICIENT_AMOUNT, payer=payer
            )

        # Validate recipient
        if auth.witness.to.lower() != requirements.pay_to.lower():
            return VerifyResponse(
                is_valid=False, invalid_reason=ERR_UPTO_RECIPIENT_MISMATCH, payer=payer
            )

        # Validate timing
        now = int(time.time())

        if auth.deadline < now + 6:
            return VerifyResponse(
                is_valid=False, invalid_reason=ERR_UPTO_DEADLINE_EXPIRED, payer=payer
            )

        if auth.witness.valid_after > now:
            return VerifyResponse(
                is_valid=False, invalid_reason=ERR_UPTO_NOT_YET_VALID, payer=payer
            )

        # Check balance
        try:
            balance = self._signer.get_balance(payer, asset_info["address"])
            if balance < auth.permitted.amount:
                return VerifyResponse(
                    is_valid=False, invalid_reason=ERR_INSUFFICIENT_BALANCE, payer=payer
                )
        except Exception:
            pass  # Continue if balance check fails

        # Verify Permit2 signature using EIP-712 hash
        if not permit2_payload.signature:
            return VerifyResponse(
                is_valid=False, invalid_reason=ERR_UPTO_INVALID_SIGNATURE, payer=payer
            )

        try:
            chain_id = get_evm_chain_id(network)
            hash_bytes = _hash_permit2_authorization(auth, chain_id)
            signature = hex_to_bytes(permit2_payload.signature)

            valid, _ = verify_universal_signature(
                self._signer, payer, hash_bytes, signature, allow_undeployed=True
            )
            if not valid:
                return VerifyResponse(
                    is_valid=False, invalid_reason=ERR_UPTO_INVALID_SIGNATURE, payer=payer
                )
        except Exception as e:
            return VerifyResponse(
                is_valid=False,
                invalid_reason=ERR_UPTO_INVALID_SIGNATURE,
                invalid_message=str(e),
                payer=payer,
            )

        return VerifyResponse(is_valid=True, payer=payer)

    def settle(
        self,
        payload: PaymentPayload,
        requirements: PaymentRequirements,
        actual_amount: int | None = None,
    ) -> SettleResponse:
        """Settle upto payment on-chain via x402UptoPermit2Proxy.

        Calls proxy.settle() which calls Permit2.permitWitnessTransferFrom
        with the actual consumed amount (≤ signed max).

        Args:
            payload: Verified payment payload.
            requirements: Payment requirements.
            actual_amount: Actual amount to settle (≤ permitted).
                If None, settles for the full permitted amount.

        Returns:
            SettleResponse with success, transaction, and payer.
        """
        # First verify
        verify_result = self.verify(payload, requirements)
        if not verify_result.is_valid:
            return SettleResponse(
                success=False,
                error_reason=verify_result.invalid_reason,
                network=str(payload.accepted.network),
                payer=verify_result.payer,
                transaction="",
            )

        permit2_payload = ExactPermit2Payload.from_dict(payload.payload)
        auth = permit2_payload.permit2_authorization
        payer = auth.from_address
        network = str(requirements.network)

        # Determine settlement amount
        if actual_amount is not None:
            settle_amount = actual_amount
        else:
            # Default to requested amount so session settlement can settle consumed value.
            try:
                settle_amount = int(requirements.amount)
            except (TypeError, ValueError):
                settle_amount = auth.permitted.amount

        if settle_amount > auth.permitted.amount:
            return SettleResponse(
                success=False,
                error_reason=ERR_UPTO_AMOUNT_EXCEEDS_PERMITTED,
                network=network,
                payer=payer,
                transaction="",
            )

        # Build settle call args matching the ABI
        # permit struct: (permitted: (token, amount), nonce, deadline)
        permit_struct = (
            (auth.permitted.token, settle_amount),  # Use actual amount, not max
            auth.nonce,
            auth.deadline,
        )

        # witness struct: (to, validAfter, extra)
        extra_bytes = hex_to_bytes(auth.witness.extra)
        witness_struct = (
            auth.witness.to,
            auth.witness.valid_after,
            extra_bytes,
        )

        # signature
        signature = hex_to_bytes(permit2_payload.signature)

        try:
            tx_hash = self._signer.write_contract(
                X402_UPTO_PERMIT2_PROXY_ADDRESS,
                X402_UPTO_PROXY_SETTLE_ABI,
                "settle",
                permit_struct,   # permit
                payer,           # owner
                witness_struct,  # witness
                signature,       # signature
            )

            receipt = self._signer.wait_for_transaction_receipt(tx_hash)
            if receipt.status != TX_STATUS_SUCCESS:
                return SettleResponse(
                    success=False,
                    error_reason=ERR_TRANSACTION_FAILED,
                    transaction=tx_hash,
                    network=network,
                    payer=payer,
                )

            return SettleResponse(
                success=True,
                transaction=tx_hash,
                network=network,
                payer=payer,
            )

        except Exception as e:
            return SettleResponse(
                success=False,
                error_reason=ERR_TRANSACTION_FAILED,
                error_message=str(e),
                network=network,
                payer=payer,
                transaction="",
            )
