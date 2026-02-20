from typing import Literal


SupportedNetworks = Literal[
    "base", "base-sepolia", "avalanche-fuji", "avalanche", "og-evm"
]

EVM_NETWORK_TO_CHAIN_ID = {
    "og-evm": 10740,
}
