"""Client-side upto EVM scheme."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from ....schemas import PaymentRequirements
from ..constants import (
    ERC20_ALLOWANCE_ABI,
    PERMIT2_ADDRESS,
    SCHEME_UPTO,
    UPTO_PERMIT2_WITNESS_TYPES,
    X402_UPTO_PERMIT2_PROXY_ADDRESS,
)
from ..exact.client import _wrap_if_local_account
from ..signer import (
    ClientEvmSigner,
    ClientEvmSignerWithReadContract,
    ClientEvmSignerWithSignTransaction,
)
from ..types import (
    ExactPermit2TokenPermissions,
    TypedDataField,
    UptoPermit2Authorization,
    UptoPermit2Payload,
    UptoPermit2Witness,
)
from ..utils import create_permit2_nonce, get_evm_chain_id, normalize_address

ERR_FAILED_TO_SIGN_PERMIT2_AUTHORIZATION = "invalid_upto_evm_client_failed_to_sign_permit2_authorization"
ERR_MISSING_FACILITATOR_ADDRESS = "invalid_upto_evm_client_missing_facilitator_address"


@dataclass(slots=True)
class UptoEvmChainConfig:
    """RPC behavior for a single chain."""

    rpc_url: str


@dataclass(slots=True)
class UptoEvmSchemeConfig:
    """RPC behavior for upto EVM clients."""

    rpc_url: str | None = None
    rpc_by_chain_id: dict[int, str] = field(default_factory=dict)


class UptoEvmScheme:
    """EVM client implementation for the upto payment scheme."""

    scheme = SCHEME_UPTO

    def __init__(
        self,
        signer: ClientEvmSigner,
        config: UptoEvmSchemeConfig | None = None,
    ):
        self._signer = _wrap_if_local_account(signer)
        self._config = config or UptoEvmSchemeConfig()

    def resolve_rpc_url(self, network: str) -> str | None:
        return resolve_rpc_url(self._config, network)

    def resolve_read_signer(self, network: str):
        return resolve_read_signer(self._signer, network, self._config)

    def resolve_tx_signer(self, network: str):
        return resolve_tx_signer(self._signer, network, self._config)

    def create_payment_payload(
        self,
        requirements: PaymentRequirements,
        extensions: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        result = create_upto_permit2_payload(self._signer, requirements)

        if extensions:
            ext_data = self._try_sign_extensions(requirements, result, extensions)
            if ext_data:
                result["__extensions"] = ext_data

        return result

    def _try_sign_extensions(
        self,
        requirements: PaymentRequirements,
        result: dict[str, Any],
        extensions: dict[str, Any],
    ) -> dict[str, Any] | None:
        eip2612_ext = self._try_sign_eip2612(requirements, result, extensions)
        if eip2612_ext:
            return eip2612_ext

        erc20_ext = self._try_sign_erc20_approval(requirements, extensions)
        if erc20_ext:
            return erc20_ext

        return None

    def _try_sign_eip2612(
        self,
        requirements: PaymentRequirements,
        result: dict[str, Any],
        extensions: dict[str, Any],
    ) -> dict[str, Any] | None:
        from ....extensions.eip2612_gas_sponsoring import EIP2612_GAS_SPONSORING_KEY
        from ....extensions.eip2612_gas_sponsoring.client import sign_eip2612_permit

        if EIP2612_GAS_SPONSORING_KEY not in extensions:
            return None

        read_signer = self.resolve_read_signer(str(requirements.network))
        if read_signer is None:
            return None

        extra = requirements.extra or {}
        token_name = extra.get("name")
        token_version = extra.get("version")
        if not token_name or not token_version:
            return None

        chain_id = get_evm_chain_id(str(requirements.network))
        token_address = normalize_address(requirements.asset)

        try:
            allowance = read_signer.read_contract(
                token_address,
                ERC20_ALLOWANCE_ABI,
                "allowance",
                self._signer.address,
                PERMIT2_ADDRESS,
            )
            if int(allowance) >= int(requirements.amount):
                return None
        except Exception:
            pass

        permit2_auth = result.get("permit2Authorization", {})
        deadline = permit2_auth.get("deadline", "")
        if not deadline:
            deadline = str(int(time.time()) + (requirements.max_timeout_seconds or 3600))
        info = sign_eip2612_permit(
            read_signer,
            token_address,
            str(token_name),
            str(token_version),
            chain_id,
            str(deadline),
            requirements.amount,
        )

        return {EIP2612_GAS_SPONSORING_KEY: {"info": info.to_dict()}}

    def _try_sign_erc20_approval(
        self,
        requirements: PaymentRequirements,
        extensions: dict[str, Any],
    ) -> dict[str, Any] | None:
        from ....extensions.erc20_approval_gas_sponsoring import (
            ERC20_APPROVAL_GAS_SPONSORING_KEY,
        )
        from ....extensions.erc20_approval_gas_sponsoring.client import (
            sign_erc20_approval_transaction,
        )

        if ERC20_APPROVAL_GAS_SPONSORING_KEY not in extensions:
            return None

        tx_signer = self.resolve_tx_signer(str(requirements.network))
        if tx_signer is None:
            return None

        chain_id = get_evm_chain_id(str(requirements.network))
        token_address = normalize_address(requirements.asset)

        read_signer = self.resolve_read_signer(str(requirements.network))
        if read_signer is not None:
            try:
                allowance = read_signer.read_contract(
                    token_address,
                    ERC20_ALLOWANCE_ABI,
                    "allowance",
                    self._signer.address,
                    PERMIT2_ADDRESS,
                )
                if int(allowance) >= int(requirements.amount):
                    return None
            except Exception:
                pass

        info = sign_erc20_approval_transaction(tx_signer, token_address, chain_id)
        return {ERC20_APPROVAL_GAS_SPONSORING_KEY: {"info": info.to_dict()}}


def create_upto_permit2_payload(
    signer: Any,
    requirements: PaymentRequirements,
) -> dict[str, Any]:
    """Create a signed upto Permit2 payload."""
    extra = requirements.extra or {}
    facilitator_address = extra.get("facilitatorAddress")
    if not facilitator_address:
        raise ValueError(
            f"{ERR_MISSING_FACILITATOR_ADDRESS}: "
            "paymentRequirements.extra.facilitatorAddress is required"
        )

    now = int(time.time())
    permit2_authorization = UptoPermit2Authorization(
        from_address=signer.address,
        permitted=ExactPermit2TokenPermissions(
            token=normalize_address(requirements.asset),
            amount=requirements.amount,
        ),
        spender=X402_UPTO_PERMIT2_PROXY_ADDRESS,
        nonce=create_permit2_nonce(),
        deadline=str(now + (requirements.max_timeout_seconds or 3600)),
        witness=UptoPermit2Witness(
            to=normalize_address(requirements.pay_to),
            facilitator=normalize_address(str(facilitator_address)),
            valid_after=str(now - 600),
        ),
    )

    try:
        signature = _sign_upto_permit2_authorization(signer, permit2_authorization, requirements)
    except Exception as exc:
        raise ValueError(f"{ERR_FAILED_TO_SIGN_PERMIT2_AUTHORIZATION}: {exc}") from exc

    return UptoPermit2Payload(
        permit2_authorization=permit2_authorization,
        signature=signature,
    ).to_dict()


def _sign_upto_permit2_authorization(
    signer: Any,
    permit2_authorization: UptoPermit2Authorization,
    requirements: PaymentRequirements,
) -> str:
    chain_id = get_evm_chain_id(str(requirements.network))
    domain_dict, typed_fields, primary_type, message = build_upto_permit2_typed_data(
        permit2_authorization, chain_id
    )
    sig_bytes = signer.sign_typed_data(
        domain_dict,
        typed_fields,
        primary_type,
        message,
    )
    return "0x" + sig_bytes.hex()


def build_upto_permit2_typed_data(
    permit2_authorization: UptoPermit2Authorization,
    chain_id: int,
) -> tuple[dict[str, Any], dict[str, list[TypedDataField]], str, dict[str, Any]]:
    """Build the EIP-712 payload for upto Permit2 signatures."""
    domain_dict: dict[str, Any] = {
        "name": "Permit2",
        "chainId": chain_id,
        "verifyingContract": PERMIT2_ADDRESS,
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
    """Resolve a signer with read capability."""
    _ = resolve_rpc_url(config, network)
    if isinstance(signer, ClientEvmSignerWithReadContract):
        return signer
    return None


def resolve_tx_signer(
    signer: ClientEvmSigner,
    network: str,
    config: UptoEvmSchemeConfig | None = None,
) -> ClientEvmSignerWithSignTransaction | None:
    """Resolve a signer with tx-signing capability."""
    _ = resolve_rpc_url(config, network)
    if isinstance(signer, ClientEvmSignerWithSignTransaction):
        return signer
    return None


__all__ = [
    "ERR_FAILED_TO_SIGN_PERMIT2_AUTHORIZATION",
    "ERR_MISSING_FACILITATOR_ADDRESS",
    "UptoEvmChainConfig",
    "UptoEvmScheme",
    "UptoEvmSchemeConfig",
    "build_upto_permit2_typed_data",
    "create_upto_permit2_payload",
    "resolve_read_signer",
    "resolve_rpc_url",
    "resolve_tx_signer",
]
