"""Server-side upto EVM error constants."""

ERR_AMOUNT_MUST_BE_STRING = "invalid_upto_evm_server_amount_must_be_string"
ERR_ASSET_ADDRESS_REQUIRED = "invalid_upto_evm_server_asset_address_required"
ERR_FAILED_TO_PARSE_PRICE = "invalid_upto_evm_server_failed_to_parse_price"
ERR_UNSUPPORTED_PRICE_TYPE = "invalid_upto_evm_server_unsupported_price_type"
ERR_FAILED_TO_CONVERT_AMOUNT = "invalid_upto_evm_server_failed_to_convert_amount"
ERR_NO_ASSET_SPECIFIED = "invalid_upto_evm_server_no_asset_specified"
ERR_FAILED_TO_PARSE_AMOUNT = "invalid_upto_evm_server_failed_to_parse_amount"
ERR_INVALID_PAYTO_ADDRESS = "invalid_upto_evm_server_invalid_payto_address"
ERR_AMOUNT_REQUIRED = "invalid_upto_evm_server_amount_required"
ERR_INVALID_AMOUNT = "invalid_upto_evm_server_invalid_amount"
ERR_INVALID_ASSET = "invalid_upto_evm_server_invalid_asset"
ERR_INVALID_TOKEN_AMOUNT = "invalid_upto_evm_server_invalid_token_amount"

__all__ = [name for name in globals() if name.startswith("ERR_")]
