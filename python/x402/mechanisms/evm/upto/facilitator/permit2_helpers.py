"""Helper functions for facilitator-side upto Permit2 flows."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from eth_utils import to_checksum_address

from .....schemas import PaymentPayload, VerifyResponse
from ...constants import (
    BALANCE_OF_ABI,
    PERMIT2_ADDRESS,
    UPTO_PERMIT2_WITNESS_TYPES,
    X402_UPTO_PERMIT2_PROXY_ABI,
    X402_UPTO_PERMIT2_PROXY_ADDRESS,
    X402_UPTO_PERMIT2_PROXY_SETTLE_WITH_PERMIT_ABI,
)
from ...signer import FacilitatorEvmSigner
from ...types import TypedDataField, UptoPermit2Authorization, UptoPermit2Payload
from ...utils import hex_to_bytes, normalize_address
from .errors import (
    ERR_INSUFFICIENT_BALANCE,
    ERR_PERMIT2612_AMOUNT_MISMATCH,
    ERR_PERMIT2_ALLOWANCE_REQUIRED,
    ERR_PERMIT2_INSUFFICIENT_BALANCE,
    ERR_PERMIT2_INVALID_DESTINATION,
    ERR_PERMIT2_INVALID_NONCE,
    ERR_PERMIT2_INVALID_OWNER,
    ERR_PERMIT2_INVALID_SIGNATURE,
    ERR_PERMIT2_PAYMENT_TOO_EARLY,
    ERR_PERMIT2_PROXY_NOT_DEPLOYED,
    ERR_PERMIT2_SIMULATION_FAILED,
    ERR_UPTO_AMOUNT_EXCEEDS_PERMITTED,
    ERR_UPTO_TRANSACTION_FAILED,
    ERR_UPTO_UNAUTHORIZED_FACILITATOR,
)


@dataclass
class UptoPermit2SettleArgs:
    """Typed settle arguments for upto Permit2 contract calls."""

    permit_tuple: tuple[tuple[Any, int], int, int]
    settlement_amount: int
    owner: str
    witness_tuple: tuple[str, str, int]
    signature: bytes

    def permit_struct(self) -> tuple[tuple[Any, int], int, int]:
        return self.permit_tuple

    def witness_struct(self) -> tuple[str, str, int]:
        return self.witness_tuple


def build_upto_permit2_typed_data(
    permit2_authorization: UptoPermit2Authorization,
    chain_id: int,
) -> tuple[dict[str, Any], dict[str, list[TypedDataField]], str, dict[str, Any]]:
    """Build the EIP-712 payload for upto Permit2 verification."""
    domain_dict: dict[str, Any] = {
        "name": "Permit2",
        "chainId": chain_id,
        "verifyingContract": normalize_address(PERMIT2_ADDRESS),
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


def verify_upto_permit2_signature(
    signer: FacilitatorEvmSigner,
    payer: str,
    permit2_authorization: UptoPermit2Authorization,
    chain_id: int,
    signature: bytes,
) -> bool:
    """Verify an upto Permit2 signature."""
    domain_dict, typed_fields, primary_type, message = build_upto_permit2_typed_data(
        permit2_authorization, chain_id
    )
    return signer.verify_typed_data(
        payer,
        domain_dict,  # type: ignore[arg-type]
        typed_fields,
        primary_type,
        message,
        signature,
    )


def build_upto_permit2_settle_args(
    permit2_payload: UptoPermit2Payload,
    settlement_amount: int,
) -> UptoPermit2SettleArgs:
    """Convert the raw payload into typed contract-call arguments."""
    return UptoPermit2SettleArgs(
        permit_tuple=(
            (
                to_checksum_address(permit2_payload.permit2_authorization.permitted.token),
                int(permit2_payload.permit2_authorization.permitted.amount),
            ),
            int(permit2_payload.permit2_authorization.nonce),
            int(permit2_payload.permit2_authorization.deadline),
        ),
        settlement_amount=settlement_amount,
        owner=to_checksum_address(permit2_payload.permit2_authorization.from_address),
        witness_tuple=(
            to_checksum_address(permit2_payload.permit2_authorization.witness.to),
            to_checksum_address(permit2_payload.permit2_authorization.witness.facilitator),
            int(permit2_payload.permit2_authorization.witness.valid_after),
        ),
        signature=hex_to_bytes(permit2_payload.signature or ""),
    )


def simulate_upto_permit2_settle(
    signer: FacilitatorEvmSigner,
    permit2_payload: UptoPermit2Payload,
    settlement_amount: int,
) -> None:
    """Run settle() via eth_call."""
    args = build_upto_permit2_settle_args(permit2_payload, settlement_amount)
    signer.read_contract(
        X402_UPTO_PERMIT2_PROXY_ADDRESS,
        X402_UPTO_PERMIT2_PROXY_ABI,
        "settle",
        args.permit_struct(),
        args.settlement_amount,
        args.owner,
        args.witness_struct(),
        args.signature,
    )


def simulate_upto_permit2_settle_with_permit(
    signer: FacilitatorEvmSigner,
    permit2_payload: UptoPermit2Payload,
    settlement_amount: int,
    eip2612_info: Any,
) -> None:
    """Run settleWithPermit() via eth_call."""
    args = build_upto_permit2_settle_args(permit2_payload, settlement_amount)
    sig_raw = hex_to_bytes(eip2612_info.signature)
    if len(sig_raw) != 65:
        raise ValueError("EIP-2612 signature must be 65 bytes")
    permit2612_tuple = (
        int(eip2612_info.amount),
        int(eip2612_info.deadline),
        sig_raw[:32],
        sig_raw[32:64],
        sig_raw[64],
    )
    signer.read_contract(
        X402_UPTO_PERMIT2_PROXY_ADDRESS,
        X402_UPTO_PERMIT2_PROXY_SETTLE_WITH_PERMIT_ABI,
        "settleWithPermit",
        permit2612_tuple,
        args.permit_struct(),
        args.settlement_amount,
        args.owner,
        args.witness_struct(),
        args.signature,
    )


def settle_upto_direct(
    signer: FacilitatorEvmSigner,
    permit2_payload: UptoPermit2Payload,
    settlement_amount: int,
) -> str:
    """Send a direct upto settle() transaction."""
    args = build_upto_permit2_settle_args(permit2_payload, settlement_amount)
    return signer.write_contract(
        X402_UPTO_PERMIT2_PROXY_ADDRESS,
        X402_UPTO_PERMIT2_PROXY_ABI,
        "settle",
        args.permit_struct(),
        args.settlement_amount,
        args.owner,
        args.witness_struct(),
        args.signature,
    )


def settle_upto_with_eip2612(
    signer: FacilitatorEvmSigner,
    permit2_payload: UptoPermit2Payload,
    settlement_amount: int,
    eip2612_info: Any,
) -> str:
    """Send an upto settleWithPermit() transaction."""
    args = build_upto_permit2_settle_args(permit2_payload, settlement_amount)
    sig_raw = hex_to_bytes(eip2612_info.signature)
    if len(sig_raw) != 65:
        raise ValueError("EIP-2612 signature must be 65 bytes")
    permit2612_tuple = (
        int(eip2612_info.amount),
        int(eip2612_info.deadline),
        sig_raw[:32],
        sig_raw[32:64],
        sig_raw[64],
    )
    return signer.write_contract(
        X402_UPTO_PERMIT2_PROXY_ADDRESS,
        X402_UPTO_PERMIT2_PROXY_SETTLE_WITH_PERMIT_ABI,
        "settleWithPermit",
        permit2612_tuple,
        args.permit_struct(),
        args.settlement_amount,
        args.owner,
        args.witness_struct(),
        args.signature,
    )


def settle_upto_with_erc20_approval(
    extension_signer: Any,
    permit2_payload: UptoPermit2Payload,
    settlement_amount: int,
    erc20_info: Any,
) -> str:
    """Send the sponsored ERC-20 approval and upto settle bundle."""
    from .....extensions.erc20_approval_gas_sponsoring.types import WriteContractCall

    args = build_upto_permit2_settle_args(permit2_payload, settlement_amount)
    tx_hashes = extension_signer.send_transactions(
        [
            erc20_info.signed_transaction,
            WriteContractCall(
                address=X402_UPTO_PERMIT2_PROXY_ADDRESS,
                abi=X402_UPTO_PERMIT2_PROXY_ABI,
                function="settle",
                args=[
                    args.permit_struct(),
                    args.settlement_amount,
                    args.owner,
                    args.witness_struct(),
                    args.signature,
                ],
            ),
        ]
    )
    return tx_hashes[-1] if tx_hashes else ""


def diagnose_upto_permit2_simulation_failure(
    signer: FacilitatorEvmSigner,
    token_address: str,
    permit2_payload: UptoPermit2Payload,
    amount_required: str,
) -> VerifyResponse:
    """Return the most useful verification error after simulation failure."""
    payer = permit2_payload.permit2_authorization.from_address

    try:
        signer.read_contract(
            X402_UPTO_PERMIT2_PROXY_ADDRESS,
            [{"name": "PERMIT2", "type": "function", "stateMutability": "view", "inputs": [], "outputs": [{"name": "", "type": "address"}]}],
            "PERMIT2",
        )
    except Exception:
        return VerifyResponse(is_valid=False, invalid_reason=ERR_PERMIT2_PROXY_NOT_DEPLOYED, payer=payer)

    try:
        balance = signer.read_contract(token_address, BALANCE_OF_ABI, "balanceOf", payer)
        if int(balance) < int(amount_required):
            return VerifyResponse(
                is_valid=False,
                invalid_reason=ERR_PERMIT2_INSUFFICIENT_BALANCE,
                payer=payer,
            )
    except Exception:
        pass

    try:
        allowance = signer.read_contract(
            token_address,
            [{"name": "allowance", "type": "function", "stateMutability": "view", "inputs": [{"name": "owner", "type": "address"}, {"name": "spender", "type": "address"}], "outputs": [{"name": "", "type": "uint256"}]}],
            "allowance",
            payer,
            PERMIT2_ADDRESS,
        )
        if int(allowance) < int(amount_required):
            return VerifyResponse(
                is_valid=False,
                invalid_reason=ERR_PERMIT2_ALLOWANCE_REQUIRED,
                payer=payer,
            )
    except Exception:
        pass

    return VerifyResponse(is_valid=False, invalid_reason=ERR_PERMIT2_SIMULATION_FAILED, payer=payer)


def check_upto_permit2_prerequisites(
    signer: FacilitatorEvmSigner,
    token_address: str,
    payer: str,
    amount_required: str,
) -> VerifyResponse:
    """Check broad prerequisites when an extension signer lacks simulation support."""
    try:
        signer.read_contract(
            X402_UPTO_PERMIT2_PROXY_ADDRESS,
            [{"name": "PERMIT2", "type": "function", "stateMutability": "view", "inputs": [], "outputs": [{"name": "", "type": "address"}]}],
            "PERMIT2",
        )
    except Exception:
        return VerifyResponse(is_valid=False, invalid_reason=ERR_PERMIT2_PROXY_NOT_DEPLOYED, payer=payer)

    try:
        balance = signer.read_contract(token_address, BALANCE_OF_ABI, "balanceOf", payer)
        if int(balance) < int(amount_required):
            return VerifyResponse(is_valid=False, invalid_reason=ERR_INSUFFICIENT_BALANCE, payer=payer)
    except Exception:
        return VerifyResponse(is_valid=False, invalid_reason=ERR_INSUFFICIENT_BALANCE, payer=payer)

    return VerifyResponse(is_valid=True, payer=payer)


def map_upto_settle_error(error: Exception) -> str:
    """Map contract or RPC failures to stable x402 reason strings."""
    error_msg = str(error)
    if "Permit2612AmountMismatch" in error_msg:
        return ERR_PERMIT2612_AMOUNT_MISMATCH
    if "InvalidAmount" in error_msg:
        return ERR_PERMIT2_INVALID_AMOUNT
    if "InvalidDestination" in error_msg:
        return ERR_PERMIT2_INVALID_DESTINATION
    if "InvalidOwner" in error_msg:
        return ERR_PERMIT2_INVALID_OWNER
    if "PaymentTooEarly" in error_msg:
        return ERR_PERMIT2_PAYMENT_TOO_EARLY
    if "InvalidSignature" in error_msg or "SignatureExpired" in error_msg:
        return ERR_PERMIT2_INVALID_SIGNATURE
    if "InvalidNonce" in error_msg:
        return ERR_PERMIT2_INVALID_NONCE
    if "erc20_approval_tx_failed" in error_msg:
        return "erc20_approval_tx_failed"
    if "AmountExceedsPermitted" in error_msg:
        return ERR_UPTO_AMOUNT_EXCEEDS_PERMITTED
    if "UnauthorizedFacilitator" in error_msg:
        return ERR_UPTO_UNAUTHORIZED_FACILITATOR
    return ERR_UPTO_TRANSACTION_FAILED


__all__ = [
    "UptoPermit2SettleArgs",
    "build_upto_permit2_settle_args",
    "build_upto_permit2_typed_data",
    "check_upto_permit2_prerequisites",
    "diagnose_upto_permit2_simulation_failure",
    "map_upto_settle_error",
    "settle_upto_direct",
    "settle_upto_with_eip2612",
    "settle_upto_with_erc20_approval",
    "simulate_upto_permit2_settle",
    "simulate_upto_permit2_settle_with_permit",
    "verify_upto_permit2_signature",
]
