"""Client-side upto EVM RPC helpers.

Mirrors TypeScript's ``shared/rpc.ts`` — when the signer lacks on-chain
read capability, an RPC URL from ``UptoEvmSchemeConfig`` is used to
backfill ``read_contract`` so that gas-sponsoring extensions (EIP-2612,
ERC-20 approval) can query nonces and allowances.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ...signer import ClientEvmSigner, ClientEvmSignerWithReadContract, ClientEvmSignerWithSignTransaction


_rpc_read_fn_cache: dict[str, Any] = {}


def _get_rpc_read_contract(rpc_url: str) -> Any:
    """Return a ``read_contract`` callable backed by *rpc_url*, or ``None``.

    Results are cached per URL so we don't spin up a new Web3 instance on
    every call.
    """
    cached = _rpc_read_fn_cache.get(rpc_url)
    if cached is not None:
        return cached

    try:
        from web3 import Web3
    except ImportError:
        return None

    w3 = Web3(Web3.HTTPProvider(rpc_url))

    def read_contract(
        address: str,
        abi: list[dict[str, Any]],
        function_name: str,
        *args: Any,
    ) -> Any:
        contract = w3.eth.contract(
            address=Web3.to_checksum_address(address),
            abi=abi,
        )
        return contract.functions[function_name](*args).call()

    _rpc_read_fn_cache[rpc_url] = read_contract
    return read_contract


class _RpcBackfilledSigner:
    """Wraps a ``ClientEvmSigner`` and adds ``read_contract`` from an RPC URL.

    Satisfies the ``ClientEvmSignerWithReadContract`` runtime-checkable
    protocol so that ``sign_eip2612_permit`` can call both
    ``sign_typed_data`` and ``read_contract`` on the same object.
    """

    def __init__(
        self,
        signer: ClientEvmSigner,
        read_contract_fn: Any,
    ) -> None:
        self._signer = signer
        self._read_contract = read_contract_fn

    @property
    def address(self) -> str:
        return self._signer.address

    def sign_typed_data(
        self,
        domain: Any,
        types: Any,
        primary_type: str,
        message: dict[str, Any],
    ) -> bytes:
        return self._signer.sign_typed_data(domain, types, primary_type, message)

    def read_contract(
        self,
        address: str,
        abi: list[dict[str, Any]],
        function_name: str,
        *args: Any,
    ) -> Any:
        return self._read_contract(address, abi, function_name, *args)


# ---------------------------------------------------------------------------
# Config dataclasses
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class UptoEvmChainConfig:
    """RPC behavior for a single chain."""

    rpc_url: str


@dataclass(slots=True)
class UptoEvmSchemeConfig:
    """RPC behavior for upto EVM clients."""

    rpc_url: str | None = None
    rpc_by_chain_id: dict[int, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Resolution helpers
# ---------------------------------------------------------------------------
def resolve_rpc_url(config: UptoEvmSchemeConfig | None, network: str) -> str | None:
    """Resolve an RPC URL for the requested network."""
    if config is None:
        return None

    try:
        chain_id = int(network.split(":", 1)[1])
    except (IndexError, ValueError):
        chain_id = None

    if chain_id is not None and chain_id in config.rpc_by_chain_id:
        return config.rpc_by_chain_id[chain_id]
    return config.rpc_url


def resolve_read_signer(
    signer: ClientEvmSigner,
    network: str,
    config: UptoEvmSchemeConfig | None = None,
) -> ClientEvmSignerWithReadContract | None:
    """Resolve a signer with read capability.

    If the signer already supports ``read_contract``, return it directly.
    Otherwise, if an RPC URL is configured, backfill ``read_contract``
    via a Web3 public client — matching TypeScript's
    ``resolveExtensionRpcCapabilities``.
    """
    if isinstance(signer, ClientEvmSignerWithReadContract):
        return signer

    rpc_url = resolve_rpc_url(config, network)
    if not rpc_url:
        return None

    read_contract_fn = _get_rpc_read_contract(rpc_url)
    if read_contract_fn is None:
        return None

    return _RpcBackfilledSigner(signer, read_contract_fn)  # type: ignore[return-value]


def resolve_tx_signer(
    signer: ClientEvmSigner,
    network: str,
    config: UptoEvmSchemeConfig | None = None,
) -> ClientEvmSignerWithSignTransaction | None:
    """Resolve a signer with tx-signing capability."""
    if isinstance(signer, ClientEvmSignerWithSignTransaction):
        return signer
    return None


__all__ = [
    "UptoEvmChainConfig",
    "UptoEvmSchemeConfig",
    "resolve_read_signer",
    "resolve_rpc_url",
    "resolve_tx_signer",
]
