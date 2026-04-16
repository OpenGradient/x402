"""Server-side upto EVM scheme."""

from __future__ import annotations

from .....schemas import AssetAmount, PaymentRequirements, Price, SupportedKind
from ...constants import DEFAULT_DECIMALS, SCHEME_UPTO
from ...exact.server import ExactEvmScheme as _ExactEvmServerScheme
from ...utils import get_asset_info, get_network_config, normalize_address, parse_amount


class UptoEvmScheme(_ExactEvmServerScheme):
    """EVM server implementation for the upto payment scheme."""

    scheme = SCHEME_UPTO

    def get_asset_decimals(self, asset: str, network: str) -> int:
        try:
            return int(get_asset_info(str(network), asset)["decimals"])
        except Exception:
            return DEFAULT_DECIMALS

    def parse_price(self, price: Price, network: str) -> AssetAmount:
        return super().parse_price(price, network)

    def enhance_payment_requirements(
        self,
        requirements: PaymentRequirements,
        supported_kind: SupportedKind,
        extension_keys: list[str],
    ) -> PaymentRequirements:
        config = get_network_config(str(requirements.network))

        if not requirements.asset:
            default = config.get("default_asset")
            if not default or not default.get("address"):
                raise ValueError(
                    f"No default stablecoin configured for network {requirements.network}; "
                    "use register_money_parser or specify an explicit asset address"
                )
            requirements.asset = default["address"]

        try:
            asset_info = get_asset_info(str(requirements.network), requirements.asset)
        except ValueError:
            asset_info = None

        if "." in requirements.amount:
            if asset_info is None:
                raise ValueError(
                    f"Token {requirements.asset} is not a registered asset for network "
                    f"{requirements.network}; provide amount in atomic units"
                )
            requirements.amount = str(parse_amount(requirements.amount, asset_info["decimals"]))

        if requirements.extra is None:
            requirements.extra = {}

        if asset_info is not None:
            if "name" not in requirements.extra:
                requirements.extra["name"] = asset_info["name"]
            if "version" not in requirements.extra:
                requirements.extra["version"] = asset_info["version"]

        requirements.extra["assetTransferMethod"] = "permit2"

        supported_extra = supported_kind.extra or {}
        facilitator_address = supported_extra.get("facilitatorAddress")
        if facilitator_address:
            requirements.extra["facilitatorAddress"] = normalize_address(str(facilitator_address))

        for key in extension_keys:
            if key in supported_extra:
                requirements.extra[key] = supported_extra[key]

        return requirements

    def _default_money_conversion(self, amount: float, network: str) -> AssetAmount:
        config = get_network_config(network)
        asset = config.get("default_asset")

        if not asset or not asset.get("address"):
            raise ValueError(
                f"No default stablecoin configured for network {network}; "
                "use register_money_parser or specify an explicit AssetAmount"
            )

        token_amount = int(amount * (10 ** asset["decimals"]))
        return AssetAmount(
            amount=str(token_amount),
            asset=asset["address"],
            extra={
                "name": asset["name"],
                "version": asset["version"],
                "assetTransferMethod": "permit2",
            },
        )


__all__ = ["UptoEvmScheme"]
