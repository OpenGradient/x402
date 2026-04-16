"""Client-side upto EVM scheme."""

from __future__ import annotations

import time
from typing import Any

from .....schemas import PaymentRequirements
from ...constants import ERC20_ALLOWANCE_ABI, PERMIT2_ADDRESS, SCHEME_UPTO
from ...exact.client import _wrap_if_local_account
from ...signer import ClientEvmSigner
from ...utils import get_evm_chain_id, normalize_address
from .permit2 import create_upto_permit2_payload
from .rpc import UptoEvmSchemeConfig, resolve_read_signer, resolve_rpc_url, resolve_tx_signer


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
        from .....extensions.eip2612_gas_sponsoring import EIP2612_GAS_SPONSORING_KEY
        from .....extensions.eip2612_gas_sponsoring.client import sign_eip2612_permit

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
        from .....extensions.erc20_approval_gas_sponsoring import (
            ERC20_APPROVAL_GAS_SPONSORING_KEY,
        )
        from .....extensions.erc20_approval_gas_sponsoring.client import (
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


__all__ = ["UptoEvmScheme"]
