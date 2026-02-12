"""EVM-specific payload and data types."""

from dataclasses import dataclass
from typing import Any


@dataclass
class ExactEIP3009Authorization:
    """EIP-3009 TransferWithAuthorization data."""

    from_address: str  # 'from' is reserved in Python
    to: str
    value: str  # Amount in smallest unit as string
    valid_after: str  # Unix timestamp as string
    valid_before: str  # Unix timestamp as string
    nonce: str  # 32-byte nonce as hex string (0x...)

@dataclass
class Permit2TokenPermissions:
    """Permit2 TokenPermissions struct."""

    token: str
    amount: int


@dataclass
class Permit2Witness:
    """Permit2 Witness struct for x402."""

    to: str
    valid_after: int
    extra: str  # bytes as hex string


@dataclass
class Permit2Authorization:
    """Permit2 Authorization data."""

    permitted: Permit2TokenPermissions
    spender: str
    nonce: int
    deadline: int
    witness: Permit2Witness
    from_address: str  # Not part of the signed message, but needed for payload


@dataclass
class ExactPermit2Payload:
    """Exact payment payload for Permit2."""
    
    permit2_authorization: Permit2Authorization
    signature: str


    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "permit2Authorization": {
                "permitted": {
                    "token": self.permit2_authorization.permitted.token,
                    "amount": str(self.permit2_authorization.permitted.amount),
                },
                "spender": self.permit2_authorization.spender,
                "nonce": str(self.permit2_authorization.nonce),
                "deadline": str(self.permit2_authorization.deadline),
                "witness": {
                    "to": self.permit2_authorization.witness.to,
                    "validAfter": str(self.permit2_authorization.witness.valid_after),
                    "extra": self.permit2_authorization.witness.extra,
                },
                "from": self.permit2_authorization.from_address,
            },
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ExactPermit2Payload":
        """Create from dictionary."""
        auth_data = data["permit2Authorization"]
        permitted_data = auth_data["permitted"]
        witness_data = auth_data["witness"]

        return cls(
            permit2_authorization=Permit2Authorization(
                permitted=Permit2TokenPermissions(
                    token=permitted_data["token"],
                    amount=int(permitted_data["amount"]),
                ),
                spender=auth_data["spender"],
                nonce=int(auth_data["nonce"]),
                deadline=int(auth_data["deadline"]),
                witness=Permit2Witness(
                    to=witness_data["to"],
                    valid_after=int(witness_data["validAfter"]),
                    extra=witness_data["extra"],
                ),
                from_address=auth_data["from"],
            ),
            signature=data["signature"],
        )


@dataclass
class ExactEIP3009Payload:
    """Exact payment payload for EVM networks."""

    authorization: ExactEIP3009Authorization
    signature: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization.

        Returns:
            Dict with authorization and signature fields.
        """
        result: dict[str, Any] = {
            "authorization": {
                "from": self.authorization.from_address,
                "to": self.authorization.to,
                "value": self.authorization.value,
                "validAfter": self.authorization.valid_after,
                "validBefore": self.authorization.valid_before,
                "nonce": self.authorization.nonce,
            }
        }
        if self.signature:
            result["signature"] = self.signature
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ExactEIP3009Payload":
        """Create from dictionary.

        Args:
            data: Dict with authorization and optional signature.

        Returns:
            ExactEIP3009Payload instance.
        """
        auth = data.get("authorization", {})
        return cls(
            authorization=ExactEIP3009Authorization(
                from_address=auth.get("from", ""),
                to=auth.get("to", ""),
                value=auth.get("value", ""),
                valid_after=auth.get("validAfter", ""),
                valid_before=auth.get("validBefore", ""),
                nonce=auth.get("nonce", ""),
            ),
            signature=data.get("signature"),
        )


# Type aliases for V1/V2 compatibility
ExactEvmPayloadV1 = ExactEIP3009Payload
ExactEvmPayloadV2 = ExactEIP3009Payload


@dataclass
class TypedDataDomain:
    """EIP-712 domain separator."""

    name: str
    chain_id: int
    verifying_contract: str
    version: str | None = None


@dataclass
class TypedDataField:
    """Field definition for EIP-712 types."""

    name: str
    type: str


@dataclass
class TransactionReceipt:
    """Transaction receipt from blockchain."""

    status: int
    block_number: int
    tx_hash: str


@dataclass
class ERC6492SignatureData:
    """Parsed ERC-6492 signature components."""

    factory: bytes  # 20-byte factory address (zero if not ERC-6492)
    factory_calldata: bytes  # Deployment calldata (empty if not ERC-6492)
    inner_signature: bytes  # The actual signature (EIP-1271 or EOA)


# EIP-712 authorization types for signing
AUTHORIZATION_TYPES: dict[str, list[dict[str, str]]] = {
    "TransferWithAuthorization": [
        {"name": "from", "type": "address"},
        {"name": "to", "type": "address"},
        {"name": "value", "type": "uint256"},
        {"name": "validAfter", "type": "uint256"},
        {"name": "validBefore", "type": "uint256"},
        {"name": "nonce", "type": "bytes32"},
    ]
}

# EIP-712 domain types
DOMAIN_TYPES: dict[str, list[dict[str, str]]] = {
    "EIP712Domain": [
        {"name": "name", "type": "string"},
        {"name": "version", "type": "string"},
        {"name": "chainId", "type": "uint256"},
        {"name": "verifyingContract", "type": "address"},
    ]
}
