NETWORK_TO_ID = {
    "og-devnet": "10744",
}


def get_chain_id(network: str) -> str:
    """Get the chain ID for a given network
    Supports string encoded chain IDs and human readable networks
    """
    try:
        int(network)
        return network
    except ValueError:
        pass
    if network not in NETWORK_TO_ID:
        raise ValueError(f"Unsupported network: {network}")
    return NETWORK_TO_ID[network]


KNOWN_TOKENS = {
    "10744": [
        {
            "human_name": "ousdc",
            "address": "0x48515A4b24f17cadcD6109a9D85a57ba55a619a6",
            "name": "OUSDC",
            "decimals": 6,
            "version": "2",
        }
    ],
}


def get_token_name(chain_id: str, address: str) -> str:
    """Get the token name for a given chain and address"""
    for token in KNOWN_TOKENS[chain_id]:
        if token["address"] == address:
            return token["name"]
    raise ValueError(f"Token not found for chain {chain_id} and address {address}")


def get_token_version(chain_id: str, address: str) -> str:
    """Get the token version for a given chain and address"""
    for token in KNOWN_TOKENS[chain_id]:
        if token["address"] == address:
            return token["version"]
    raise ValueError(f"Token not found for chain {chain_id} and address {address}")


def get_token_decimals(chain_id: str, address: str) -> int:
    """Get the token decimals for a given chain and address"""
    for token in KNOWN_TOKENS[chain_id]:
        if token["address"] == address:
            return token["decimals"]
    raise ValueError(f"Token not found for chain {chain_id} and address {address}")


def get_default_token_address(chain_id: str, token_type: str = "usdc") -> str:
    """Get the default token address for a given chain and token type"""
    for token in KNOWN_TOKENS[chain_id]:
        if token["human_name"] == token_type:
            return token["address"]
    raise ValueError(f"Token type '{token_type}' not found for chain {chain_id}")
