"""Client-side upto EVM error constants."""

ERR_INVALID_AMOUNT = "invalid_upto_evm_client_amount"
ERR_FAILED_TO_SIGN_PERMIT2_AUTHORIZATION = (
    "invalid_upto_evm_client_failed_to_sign_permit2_authorization"
)
ERR_MISSING_FACILITATOR_ADDRESS = "invalid_upto_evm_client_missing_facilitator_address"

__all__ = [
    "ERR_INVALID_AMOUNT",
    "ERR_FAILED_TO_SIGN_PERMIT2_AUTHORIZATION",
    "ERR_MISSING_FACILITATOR_ADDRESS",
]
