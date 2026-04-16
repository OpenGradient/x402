"""Facilitator-side upto EVM error constants."""

from ...constants import (
    ERR_INSUFFICIENT_BALANCE,
    ERR_INSUFFICIENT_BALANCE as ERR_PERMIT2_INSUFFICIENT_BALANCE,
    ERR_PERMIT2_ALLOWANCE_REQUIRED,
    ERR_PERMIT2_AMOUNT_MISMATCH,
    ERR_PERMIT2_DEADLINE_EXPIRED,
    ERR_PERMIT2_INVALID_SIGNATURE,
    ERR_PERMIT2_INVALID_SPENDER,
    ERR_PERMIT2_NOT_YET_VALID,
    ERR_PERMIT2_RECIPIENT_MISMATCH,
    ERR_PERMIT2_TOKEN_MISMATCH,
)

ERR_UPTO_INVALID_SCHEME = "invalid_upto_evm_scheme"
ERR_UPTO_NETWORK_MISMATCH = "invalid_upto_evm_network_mismatch"
ERR_UPTO_INVALID_PAYLOAD = "invalid_upto_evm_payload"
ERR_UPTO_SETTLEMENT_EXCEEDS_AMOUNT = "invalid_upto_evm_payload_settlement_exceeds_amount"
ERR_UPTO_AMOUNT_EXCEEDS_PERMITTED = "upto_amount_exceeds_permitted"
ERR_UPTO_UNAUTHORIZED_FACILITATOR = "upto_unauthorized_facilitator"
ERR_UPTO_FACILITATOR_MISMATCH = "upto_facilitator_mismatch"
ERR_UPTO_VERIFICATION_FAILED = "invalid_upto_evm_verification_failed"
ERR_UPTO_FAILED_TO_GET_NETWORK_CONFIG = "invalid_upto_evm_failed_to_get_network_config"
ERR_UPTO_FAILED_TO_GET_RECEIPT = "invalid_upto_evm_failed_to_get_receipt"
ERR_UPTO_TRANSACTION_FAILED = "invalid_upto_evm_transaction_failed"
ERR_INVALID_SIGNATURE_FORMAT = "invalid_upto_evm_signature_format"
ERR_INVALID_REQUIRED_AMOUNT = "invalid_upto_evm_required_amount"
ERR_PERMIT2_INVALID_AMOUNT = "invalid_permit2_amount"
ERR_PERMIT2_INVALID_DESTINATION = "invalid_permit2_destination"
ERR_PERMIT2_INVALID_OWNER = "invalid_permit2_owner"
ERR_PERMIT2_PAYMENT_TOO_EARLY = "permit2_payment_too_early"
ERR_PERMIT2_INVALID_NONCE = "permit2_invalid_nonce"
ERR_PERMIT2612_AMOUNT_MISMATCH = "permit2_2612_amount_mismatch"
ERR_PERMIT2_SIMULATION_FAILED = "permit2_simulation_failed"
ERR_PERMIT2_PROXY_NOT_DEPLOYED = "permit2_proxy_not_deployed"
ERR_ERC20_APPROVAL_INSUFFICIENT_ETH = "erc20_approval_insufficient_eth"
ERR_ERC20_APPROVAL_BROADCAST_FAILED = "erc20_approval_broadcast_failed"

__all__ = [name for name in globals() if name.startswith("ERR_")]
