from typing import Literal


SupportedNetworks = Literal[
    "base", "base-sepolia", "avalanche-fuji", "avalanche", "og-devnet"
]

EVM_NETWORK_TO_CHAIN_ID = {
    "og-devnet": 10744,
}
