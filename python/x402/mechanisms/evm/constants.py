"""EVM mechanism constants - network configs, ABIs, error codes."""

from typing import TypedDict

# Scheme identifiers
SCHEME_EXACT = "exact"
SCHEME_UPTO = "upto"

# Default token decimals for USDC
DEFAULT_DECIMALS = 6

# Asset transfer methods
ASSET_TRANSFER_METHOD_PERMIT2 = "permit2"
ASSET_TRANSFER_METHOD_EIP3009 = "eip3009"

# Permit2 Canonical Address
# TODO: revert after precompile upgrade
PERMIT2_ADDRESS = "0xA2820a4d4F3A8c5Fa4eaEBF45B093173105a8f8F"

# x402 Permit2 Proxy Addresses (same across all networks)
X402_EXACT_PERMIT2_PROXY_ADDRESS = "0xdB9F7863C9E06Daf21aD43663a06a2f43d303Fa7"
X402_UPTO_PERMIT2_PROXY_ADDRESS = "0xdB9F7863C9E06Daf21aD43663a06a2f43d303Fa7"  # Deploy and update

FUNCTION_TRANSFER_WITH_AUTHORIZATION = "transferWithAuthorization"
FUNCTION_AUTHORIZATION_STATE = "authorizationState"

# Transaction status
TX_STATUS_SUCCESS = 1
TX_STATUS_FAILED = 0

# Default validity period (1 hour in seconds)
DEFAULT_VALIDITY_PERIOD = 3600

# Default validity buffer (30 seconds before now for clock skew)
DEFAULT_VALIDITY_BUFFER = 30

# ERC-6492 magic value (32 bytes)
# bytes32(uint256(keccak256("erc6492.invalid.signature")) - 1)
ERC6492_MAGIC_VALUE = bytes.fromhex(
    "6492649264926492649264926492649264926492649264926492649264926492"
)

# EIP-1271 magic value (returned by isValidSignature on success)
EIP1271_MAGIC_VALUE = bytes.fromhex("1626ba7e")

# Error codes
ERR_INVALID_SIGNATURE = "invalid_exact_evm_payload_signature"
ERR_UNDEPLOYED_SMART_WALLET = "invalid_exact_evm_payload_undeployed_smart_wallet"
ERR_SMART_WALLET_DEPLOYMENT_FAILED = "smart_wallet_deployment_failed"
ERR_RECIPIENT_MISMATCH = "invalid_exact_evm_payload_recipient_mismatch"
ERR_INSUFFICIENT_AMOUNT = "invalid_exact_evm_payload_authorization_value"
ERR_VALID_BEFORE_EXPIRED = "invalid_exact_evm_payload_authorization_valid_before"
ERR_VALID_AFTER_FUTURE = "invalid_exact_evm_payload_authorization_valid_after"
ERR_NONCE_ALREADY_USED = "nonce_already_used"
ERR_INSUFFICIENT_BALANCE = "insufficient_balance"
ERR_MISSING_EIP712_DOMAIN = "missing_eip712_domain"
ERR_NETWORK_MISMATCH = "network_mismatch"
ERR_UNSUPPORTED_SCHEME = "unsupported_scheme"
ERR_FAILED_TO_GET_NETWORK_CONFIG = "invalid_exact_evm_failed_to_get_network_config"
ERR_FAILED_TO_GET_ASSET_INFO = "invalid_exact_evm_failed_to_get_asset_info"
ERR_FAILED_TO_VERIFY_SIGNATURE = "invalid_exact_evm_failed_to_verify_signature"
ERR_TRANSACTION_FAILED = "transaction_failed"

# Upto-specific error codes
ERR_UPTO_INVALID_SPENDER = "invalid_upto_permit2_spender"
ERR_UPTO_RECIPIENT_MISMATCH = "invalid_upto_permit2_recipient_mismatch"
ERR_UPTO_DEADLINE_EXPIRED = "upto_permit2_deadline_expired"
ERR_UPTO_NOT_YET_VALID = "upto_permit2_not_yet_valid"
ERR_UPTO_INSUFFICIENT_AMOUNT = "upto_permit2_insufficient_amount"
ERR_UPTO_TOKEN_MISMATCH = "upto_permit2_token_mismatch"
ERR_UPTO_INVALID_SIGNATURE = "invalid_upto_permit2_signature"
ERR_UPTO_ALLOWANCE_REQUIRED = "upto_permit2_allowance_required"
ERR_UPTO_AMOUNT_EXCEEDS_PERMITTED = "upto_amount_exceeds_permitted"
ERR_UPTO_SESSION_NOT_FOUND = "upto_session_not_found"
ERR_UPTO_SESSION_EXPIRED = "upto_session_expired"
ERR_UPTO_SESSION_CAP_REACHED = "upto_session_cap_reached"


class AssetInfo(TypedDict):
    """Information about a token asset."""

    address: str
    name: str
    version: str
    decimals: int


class NetworkConfig(TypedDict):
    """Configuration for an EVM network."""

    chain_id: int
    default_asset: AssetInfo
    supported_assets: dict[str, AssetInfo]


# Network configurations
NETWORK_CONFIGS: dict[str, NetworkConfig] = {
    # Ethereum Mainnet
    "eip155:1": {
        "chain_id": 1,
        "default_asset": {
            "address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            "name": "USD Coin",
            "version": "2",
            "decimals": 6,
        },
        "supported_assets": {
            "USDC": {
                "address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                "name": "USD Coin",
                "version": "2",
                "decimals": 6,
            },
        },
    },
    # Base Mainnet
    "eip155:8453": {
        "chain_id": 8453,
        "default_asset": {
            "address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            "name": "USD Coin",
            "version": "2",
            "decimals": 6,
        },
        "supported_assets": {
            "USDC": {
                "address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "name": "USD Coin",
                "version": "2",
                "decimals": 6,
            },
        },
    },
    # Base Sepolia (Testnet)
    "eip155:84532": {
        "chain_id": 84532,
        "default_asset": {
            "address": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
            "name": "USDC",
            "version": "2",
            "decimals": 6,
        },
        "supported_assets": {
            "USDC": {
                "address": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
                "name": "USDC",
                "version": "2",
                "decimals": 6,
            },
            "OPG":{
                "address": "0x240b09731D96979f50B2C649C9CE10FcF9C7987F",
                "name": "OPG",
                "version": "2",
                "decimals": 18,
            }
        },
    },
    # Polygon Mainnet
    "eip155:137": {
        "chain_id": 137,
        "default_asset": {
            "address": "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359",
            "name": "USD Coin",
            "version": "2",
            "decimals": 6,
        },
        "supported_assets": {
            "USDC": {
                "address": "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359",
                "name": "USD Coin",
                "version": "2",
                "decimals": 6,
            },
        },
    },
    # Avalanche C-Chain
    "eip155:43114": {
        "chain_id": 43114,
        "default_asset": {
            "address": "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E",
            "name": "USD Coin",
            "version": "2",
            "decimals": 6,
        },
        "supported_assets": {
            "USDC": {
                "address": "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E",
                "name": "USD Coin",
                "version": "2",
                "decimals": 6,
            },
        },
    },
    # MegaETH Mainnet
    "eip155:4326": {
        "chain_id": 4326,
        "default_asset": {
            "address": "0xFAfDdbb3FC7688494971a79cc65DCa3EF82079E7",
            "name": "MegaUSD",
            "version": "1",
            "decimals": 18,
        },
        "supported_assets": {
            "USDM": {
                "address": "0xFAfDdbb3FC7688494971a79cc65DCa3EF82079E7",
                "name": "MegaUSD",
                "version": "1",
                "decimals": 18,
            },
        },
    },
    "eip155:10740": {
        "chain_id": 10740,
        "default_asset": {
            "address": "0x094E464A23B90A71a0894D5D1e5D470FfDD074e1",
            "name": "OUSDC",
            "version": "2",
            "decimals": 6,
        },
        "supported_assets": {
            "OUSDC": {
                "address": "0x094E464A23B90A71a0894D5D1e5D470FfDD074e1",
                "name": "OUSDC",
                "version": "2",
                "decimals": 6,
            },
        },
    },
}

# Network aliases (legacy names to CAIP-2)
NETWORK_ALIASES: dict[str, str] = {
    "base": "eip155:8453",
    "base-mainnet": "eip155:8453",
    "base-sepolia": "eip155:84532",
    "ethereum": "eip155:1",
    "mainnet": "eip155:1",
    "polygon": "eip155:137",
    "avalanche": "eip155:43114",
    "megaeth": "eip155:4326",
    "og-evm": "eip155:10740",
}

# V1 supported networks (legacy name-based)
V1_NETWORKS = [
    "abstract",
    "abstract-testnet",
    "base-sepolia",
    "base",
    "avalanche-fuji",
    "avalanche",
    "iotex",
    "sei",
    "sei-testnet",
    "polygon",
    "polygon-amoy",
    "peaq",
    "story",
    "educhain",
    "skale-base-sepolia",
    "megaeth",
]

# V1 network name to chain ID mapping
V1_NETWORK_CHAIN_IDS: dict[str, int] = {
    "base": 8453,
    "base-sepolia": 84532,
    "ethereum": 1,
    "polygon": 137,
    "polygon-amoy": 80002,
    "avalanche": 43114,
    "avalanche-fuji": 43113,
    "abstract": 2741,
    "abstract-testnet": 11124,
    "iotex": 4689,
    "sei": 1329,
    "sei-testnet": 713715,
    "peaq": 3338,
    "story": 1513,
    "educhain": 656476,
    "skale-base-sepolia": 1444673419,
    "megaeth": 4326,
}

# EIP-3009 ABIs
TRANSFER_WITH_AUTHORIZATION_VRS_ABI = [
    {
        "inputs": [
            {"name": "from", "type": "address"},
            {"name": "to", "type": "address"},
            {"name": "value", "type": "uint256"},
            {"name": "validAfter", "type": "uint256"},
            {"name": "validBefore", "type": "uint256"},
            {"name": "nonce", "type": "bytes32"},
            {"name": "v", "type": "uint8"},
            {"name": "r", "type": "bytes32"},
            {"name": "s", "type": "bytes32"},
        ],
        "name": "transferWithAuthorization",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    }
]

TRANSFER_WITH_AUTHORIZATION_BYTES_ABI = [
    {
        "inputs": [
            {"name": "from", "type": "address"},
            {"name": "to", "type": "address"},
            {"name": "value", "type": "uint256"},
            {"name": "validAfter", "type": "uint256"},
            {"name": "validBefore", "type": "uint256"},
            {"name": "nonce", "type": "bytes32"},
            {"name": "signature", "type": "bytes"},
        ],
        "name": "transferWithAuthorization",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    }
]

AUTHORIZATION_STATE_ABI = [
    {
        "inputs": [
            {"name": "authorizer", "type": "address"},
            {"name": "nonce", "type": "bytes32"},
        ],
        "name": "authorizationState",
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    }
]

BALANCE_OF_ABI = [
    {
        "inputs": [{"name": "account", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    }
]

IS_VALID_SIGNATURE_ABI = [
    {
        "inputs": [
            {"name": "hash", "type": "bytes32"},
            {"name": "signature", "type": "bytes"},
        ],
        "name": "isValidSignature",
        "outputs": [{"name": "magicValue", "type": "bytes4"}],
        "stateMutability": "view",
        "type": "function",
    }
]

# Permit2 Witness Types
PERMIT2_WITNESS_TYPES = {
    "PermitWitnessTransferFrom": [
        {"name": "permitted", "type": "TokenPermissions"},
        {"name": "spender", "type": "address"},
        {"name": "nonce", "type": "uint256"},
        {"name": "deadline", "type": "uint256"},
        {"name": "witness", "type": "Witness"},
    ],
    "TokenPermissions": [
        {"name": "token", "type": "address"},
        {"name": "amount", "type": "uint256"},
    ],
    "Witness": [
        {"name": "to", "type": "address"},
        {"name": "validAfter", "type": "uint256"},
        {"name": "extra", "type": "bytes"},
    ],
}
