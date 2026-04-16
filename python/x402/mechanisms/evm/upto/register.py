"""Registration helpers for EVM upto payment schemes."""

from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from x402 import (
        x402Client,
        x402ClientSync,
        x402Facilitator,
        x402FacilitatorSync,
        x402ResourceServer,
        x402ResourceServerSync,
    )

    from ..signer import ClientEvmSigner, FacilitatorEvmSigner

# Type vars for accepting both async and sync variants
ClientT = TypeVar("ClientT", "x402Client", "x402ClientSync")
ServerT = TypeVar("ServerT", "x402ResourceServer", "x402ResourceServerSync")
FacilitatorT = TypeVar("FacilitatorT", "x402Facilitator", "x402FacilitatorSync")


def register_upto_evm_client(
    client: ClientT,
    signer: "ClientEvmSigner",
    networks: str | list[str] | None = None,
    policies: list | None = None,
    rpc_url: str | None = None,
    rpc_by_chain_id: dict[int, str] | None = None,
) -> ClientT:
    """Register EVM upto payment scheme to x402Client.

    Args:
        client: x402Client instance.
        signer: EVM signer for payment authorizations.
        networks: Optional specific network(s) (default: wildcard).
        policies: Optional payment policies.
        rpc_url: Optional fallback RPC URL for on-chain reads (nonces,
            allowances). Required for EIP-2612 gas sponsoring when the
            signer lacks ``read_contract`` capability.
        rpc_by_chain_id: Optional per-chain RPC URLs keyed by chain ID.

    Returns:
        Client for chaining.
    """
    from .client import UptoEvmScheme
    from .client.rpc import UptoEvmSchemeConfig

    config: UptoEvmSchemeConfig | None = None
    if rpc_url or rpc_by_chain_id:
        config = UptoEvmSchemeConfig(
            rpc_url=rpc_url,
            rpc_by_chain_id=rpc_by_chain_id or {},
        )

    scheme = UptoEvmScheme(signer, config=config)

    if networks:
        if isinstance(networks, str):
            networks = [networks]
        for network in networks:
            client.register(network, scheme)
    else:
        client.register("eip155:*", scheme)

    if policies:
        for policy in policies:
            client.register_policy(policy)

    return client


def register_upto_evm_server(
    server: ServerT,
    networks: str | list[str] | None = None,
) -> ServerT:
    """Register EVM upto payment scheme to x402ResourceServer.

    Args:
        server: x402ResourceServer instance.
        networks: Optional specific network(s) (default: wildcard).

    Returns:
        Server for chaining.
    """
    from .server import UptoEvmServerScheme

    scheme = UptoEvmServerScheme()

    if networks:
        if isinstance(networks, str):
            networks = [networks]
        for network in networks:
            server.register(network, scheme)
    else:
        server.register("eip155:*", scheme)

    return server


def register_upto_evm_facilitator(
    facilitator: FacilitatorT,
    signer: "FacilitatorEvmSigner",
    networks: str | list[str],
) -> FacilitatorT:
    """Register EVM upto payment scheme to x402Facilitator.

    Args:
        facilitator: x402Facilitator instance.
        signer: EVM signer for verification/settlement.
        networks: Network(s) to register.

    Returns:
        Facilitator for chaining.
    """
    from .facilitator import UptoEvmFacilitatorScheme

    scheme = UptoEvmFacilitatorScheme(signer)

    if isinstance(networks, str):
        networks = [networks]
    facilitator.register(networks, scheme)

    return facilitator
