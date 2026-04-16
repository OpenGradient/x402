"""Permit2 verification and settlement for the upto EVM scheme."""

from __future__ import annotations

import time

from .....interfaces import FacilitatorContext
from .....schemas import PaymentPayload, PaymentRequirements, SettleResponse, VerifyResponse
from ...constants import (
    PERMIT2_DEADLINE_BUFFER,
    SCHEME_UPTO,
    TX_STATUS_SUCCESS,
    X402_UPTO_PERMIT2_PROXY_ADDRESS,
)
from ...exact.permit2_utils import _verify_permit2_allowance
from ...signer import FacilitatorEvmSigner
from ...types import UptoPermit2Payload
from ...utils import get_evm_chain_id, hex_to_bytes, normalize_address
from .errors import (
    ERR_INSUFFICIENT_BALANCE,
    ERR_PERMIT2_AMOUNT_MISMATCH,
    ERR_PERMIT2_DEADLINE_EXPIRED,
    ERR_PERMIT2_INVALID_SIGNATURE,
    ERR_PERMIT2_INVALID_SPENDER,
    ERR_PERMIT2_NOT_YET_VALID,
    ERR_PERMIT2_RECIPIENT_MISMATCH,
    ERR_PERMIT2_TOKEN_MISMATCH,
    ERR_UPTO_FAILED_TO_GET_NETWORK_CONFIG,
    ERR_UPTO_FACILITATOR_MISMATCH,
    ERR_UPTO_INVALID_PAYLOAD,
    ERR_UPTO_INVALID_SCHEME,
    ERR_UPTO_NETWORK_MISMATCH,
    ERR_UPTO_SETTLEMENT_EXCEEDS_AMOUNT,
    ERR_UPTO_TRANSACTION_FAILED,
)
from .permit2_helpers import (
    check_upto_permit2_prerequisites,
    diagnose_upto_permit2_simulation_failure,
    map_upto_settle_error,
    settle_upto_direct,
    settle_upto_with_eip2612,
    settle_upto_with_erc20_approval,
    simulate_upto_permit2_settle,
    simulate_upto_permit2_settle_with_permit,
    verify_upto_permit2_signature,
)


def verify_upto_permit2(
    signer: FacilitatorEvmSigner,
    payload: PaymentPayload,
    requirements: PaymentRequirements,
    permit2_payload: UptoPermit2Payload,
    context: FacilitatorContext | None,
    simulate: bool,
) -> VerifyResponse:
    """Verify an upto Permit2 payment payload against the given requirements."""
    payer = permit2_payload.permit2_authorization.from_address

    if payload.accepted.scheme != SCHEME_UPTO or requirements.scheme != SCHEME_UPTO:
        return VerifyResponse(is_valid=False, invalid_reason=ERR_UPTO_INVALID_SCHEME, payer=payer)

    if payload.accepted.network != requirements.network:
        return VerifyResponse(is_valid=False, invalid_reason=ERR_UPTO_NETWORK_MISMATCH, payer=payer)

    try:
        chain_id = get_evm_chain_id(str(requirements.network))
    except Exception as exc:
        return VerifyResponse(
            is_valid=False,
            invalid_reason=ERR_UPTO_FAILED_TO_GET_NETWORK_CONFIG,
            invalid_message=str(exc),
            payer=payer,
        )

    token_address = normalize_address(requirements.asset)

    try:
        spender = normalize_address(permit2_payload.permit2_authorization.spender)
    except Exception:
        return VerifyResponse(is_valid=False, invalid_reason=ERR_PERMIT2_INVALID_SPENDER, payer=payer)

    if spender != normalize_address(X402_UPTO_PERMIT2_PROXY_ADDRESS):
        return VerifyResponse(is_valid=False, invalid_reason=ERR_PERMIT2_INVALID_SPENDER, payer=payer)

    try:
        witness_to = normalize_address(permit2_payload.permit2_authorization.witness.to)
        pay_to = normalize_address(requirements.pay_to)
    except Exception:
        return VerifyResponse(
            is_valid=False,
            invalid_reason=ERR_PERMIT2_RECIPIENT_MISMATCH,
            payer=payer,
        )

    if witness_to != pay_to:
        return VerifyResponse(
            is_valid=False,
            invalid_reason=ERR_PERMIT2_RECIPIENT_MISMATCH,
            payer=payer,
        )

    witness_facilitator = permit2_payload.permit2_authorization.witness.facilitator
    facilitator_match = any(
        normalize_address(address) == normalize_address(witness_facilitator)
        for address in signer.get_addresses()
    )
    if not facilitator_match:
        return VerifyResponse(
            is_valid=False,
            invalid_reason=ERR_UPTO_FACILITATOR_MISMATCH,
            payer=payer,
        )

    now = int(time.time())
    try:
        deadline = int(permit2_payload.permit2_authorization.deadline)
        valid_after = int(permit2_payload.permit2_authorization.witness.valid_after)
        permitted_amount = int(permit2_payload.permit2_authorization.permitted.amount)
        required_amount = int(requirements.amount)
    except (TypeError, ValueError):
        return VerifyResponse(is_valid=False, invalid_reason=ERR_UPTO_INVALID_PAYLOAD, payer=payer)

    if deadline < now + PERMIT2_DEADLINE_BUFFER:
        return VerifyResponse(
            is_valid=False,
            invalid_reason=ERR_PERMIT2_DEADLINE_EXPIRED,
            payer=payer,
        )

    if valid_after > now:
        return VerifyResponse(is_valid=False, invalid_reason=ERR_PERMIT2_NOT_YET_VALID, payer=payer)

    if permitted_amount != required_amount:
        return VerifyResponse(
            is_valid=False,
            invalid_reason=ERR_PERMIT2_AMOUNT_MISMATCH,
            payer=payer,
        )

    try:
        permitted_token = normalize_address(permit2_payload.permit2_authorization.permitted.token)
    except Exception:
        return VerifyResponse(is_valid=False, invalid_reason=ERR_PERMIT2_TOKEN_MISMATCH, payer=payer)

    if permitted_token != token_address:
        return VerifyResponse(is_valid=False, invalid_reason=ERR_PERMIT2_TOKEN_MISMATCH, payer=payer)

    if not permit2_payload.signature:
        return VerifyResponse(
            is_valid=False,
            invalid_reason=ERR_PERMIT2_INVALID_SIGNATURE,
            payer=payer,
        )

    try:
        sig_bytes = hex_to_bytes(permit2_payload.signature)
        if not verify_upto_permit2_signature(
            signer,
            payer,
            permit2_payload.permit2_authorization,
            chain_id,
            sig_bytes,
        ):
            code = signer.get_code(payer)
            if not code:
                return VerifyResponse(
                    is_valid=False,
                    invalid_reason=ERR_PERMIT2_INVALID_SIGNATURE,
                    payer=payer,
                )
    except Exception:
        return VerifyResponse(
            is_valid=False,
            invalid_reason=ERR_PERMIT2_INVALID_SIGNATURE,
            payer=payer,
        )

    if not simulate:
        return VerifyResponse(is_valid=True, payer=payer)

    allowance_result = _verify_permit2_allowance(
        signer,
        payload,
        requirements,
        payer,
        token_address,
        context,
    )
    if allowance_result is not None:
        return allowance_result

    try:
        balance = signer.read_contract(token_address, [{"name": "balanceOf", "type": "function", "stateMutability": "view", "inputs": [{"name": "account", "type": "address"}], "outputs": [{"name": "", "type": "uint256"}]}], "balanceOf", payer)
        if int(balance) < required_amount:
            return VerifyResponse(
                is_valid=False,
                invalid_reason=ERR_INSUFFICIENT_BALANCE,
                payer=payer,
            )
    except Exception:
        return VerifyResponse(
            is_valid=False,
            invalid_reason=ERR_INSUFFICIENT_BALANCE,
            payer=payer,
        )

    try:
        from .....extensions.eip2612_gas_sponsoring import (
            extract_eip2612_gas_sponsoring_info,
            validate_eip2612_permit_for_payment,
        )
        from .....extensions.erc20_approval_gas_sponsoring import (
            ERC20_APPROVAL_GAS_SPONSORING_KEY,
            Erc20ApprovalFacilitatorExtension,
            extract_erc20_approval_gas_sponsoring_info,
            validate_erc20_approval_for_payment,
        )

        eip2612_info = extract_eip2612_gas_sponsoring_info(payload)
        if eip2612_info is not None:
            reason = validate_eip2612_permit_for_payment(eip2612_info, payer, token_address)
            if reason:
                return VerifyResponse(is_valid=False, invalid_reason=reason, payer=payer)
            try:
                simulate_upto_permit2_settle_with_permit(
                    signer,
                    permit2_payload,
                    required_amount,
                    eip2612_info,
                )
            except Exception:
                return diagnose_upto_permit2_simulation_failure(
                    signer,
                    token_address,
                    permit2_payload,
                    requirements.amount,
                )
            return VerifyResponse(is_valid=True, payer=payer)

        erc20_info = extract_erc20_approval_gas_sponsoring_info(payload)
        if erc20_info is not None and context is not None:
            ext = context.get_extension(ERC20_APPROVAL_GAS_SPONSORING_KEY)
            if isinstance(ext, Erc20ApprovalFacilitatorExtension):
                extension_signer = ext.resolve_signer(str(payload.accepted.network))
                if extension_signer is not None:
                    reason, message = validate_erc20_approval_for_payment(
                        erc20_info,
                        payer,
                        token_address,
                    )
                    if reason:
                        return VerifyResponse(
                            is_valid=False,
                            invalid_reason=reason,
                            invalid_message=message,
                            payer=payer,
                        )
                    simulator = getattr(extension_signer, "simulate_transactions", None)
                    if callable(simulator):
                        try:
                            from .....extensions.erc20_approval_gas_sponsoring.types import (
                                TransactionRequest,
                                WriteContractCall,
                            )
                            from .permit2_helpers import build_upto_permit2_settle_args

                            args = build_upto_permit2_settle_args(permit2_payload, required_amount)
                            ok = simulator(
                                [
                                    TransactionRequest(serialized=erc20_info.signed_transaction),
                                    TransactionRequest(
                                        call=WriteContractCall(
                                            address=X402_UPTO_PERMIT2_PROXY_ADDRESS,
                                            abi=[],
                                            function="settle",
                                            args=[
                                                args.permit_struct(),
                                                args.settlement_amount,
                                                args.owner,
                                                args.witness_struct(),
                                                args.signature,
                                            ],
                                        )
                                    ),
                                ]
                            )
                            if ok:
                                return VerifyResponse(is_valid=True, payer=payer)
                        except Exception:
                            return diagnose_upto_permit2_simulation_failure(
                                signer,
                                token_address,
                                permit2_payload,
                                requirements.amount,
                            )

                    return check_upto_permit2_prerequisites(
                        signer,
                        token_address,
                        payer,
                        requirements.amount,
                    )

        simulate_upto_permit2_settle(signer, permit2_payload, required_amount)
    except Exception:
        return diagnose_upto_permit2_simulation_failure(
            signer,
            token_address,
            permit2_payload,
            requirements.amount,
        )

    return VerifyResponse(is_valid=True, payer=payer)


def settle_upto_permit2(
    signer: FacilitatorEvmSigner,
    payload: PaymentPayload,
    requirements: PaymentRequirements,
    permit2_payload: UptoPermit2Payload,
    context: FacilitatorContext | None,
    simulate_in_settle: bool,
) -> SettleResponse:
    """Settle an upto Permit2 payment."""
    payer = permit2_payload.permit2_authorization.from_address
    network = str(payload.accepted.network)

    try:
        settlement_amount = int(requirements.amount)
    except (TypeError, ValueError):
        return SettleResponse(
            success=False,
            error_reason=ERR_UPTO_INVALID_PAYLOAD,
            network=network,
            payer=payer,
            transaction="",
        )

    verify_requirements = requirements.model_copy(
        update={"amount": permit2_payload.permit2_authorization.permitted.amount},
        deep=True,
    )
    verify_result = verify_upto_permit2(
        signer,
        payload,
        verify_requirements,
        permit2_payload,
        context,
        simulate=simulate_in_settle,
    )
    if not verify_result.is_valid:
        return SettleResponse(
            success=False,
            error_reason=verify_result.invalid_reason,
            error_message=verify_result.invalid_message,
            network=network,
            payer=verify_result.payer or payer,
            transaction="",
        )

    if settlement_amount == 0:
        return SettleResponse(
            success=True,
            transaction="",
            network=network,
            payer=verify_result.payer,
            amount="0",
        )

    permitted_amount = int(permit2_payload.permit2_authorization.permitted.amount)
    if settlement_amount > permitted_amount:
        return SettleResponse(
            success=False,
            error_reason=ERR_UPTO_SETTLEMENT_EXCEEDS_AMOUNT,
            network=network,
            payer=payer,
            transaction="",
        )

    try:
        from .....extensions.eip2612_gas_sponsoring import extract_eip2612_gas_sponsoring_info
        from .....extensions.erc20_approval_gas_sponsoring import (
            ERC20_APPROVAL_GAS_SPONSORING_KEY,
            Erc20ApprovalFacilitatorExtension,
            extract_erc20_approval_gas_sponsoring_info,
        )

        eip2612_info = extract_eip2612_gas_sponsoring_info(payload)
        erc20_info = extract_erc20_approval_gas_sponsoring_info(payload)

        tx_hash = ""
        used_extension_signer = None
        if eip2612_info is not None:
            tx_hash = settle_upto_with_eip2612(
                signer,
                permit2_payload,
                settlement_amount,
                eip2612_info,
            )
        elif erc20_info is not None and context is not None:
            ext = context.get_extension(ERC20_APPROVAL_GAS_SPONSORING_KEY)
            if isinstance(ext, Erc20ApprovalFacilitatorExtension):
                used_extension_signer = ext.resolve_signer(str(payload.accepted.network))
            if used_extension_signer is not None:
                tx_hash = settle_upto_with_erc20_approval(
                    used_extension_signer,
                    permit2_payload,
                    settlement_amount,
                    erc20_info,
                )
            else:
                tx_hash = settle_upto_direct(signer, permit2_payload, settlement_amount)
        else:
            tx_hash = settle_upto_direct(signer, permit2_payload, settlement_amount)

        receipt_signer = used_extension_signer or signer
        receipt = receipt_signer.wait_for_transaction_receipt(tx_hash)
        if receipt.status != TX_STATUS_SUCCESS:
            return SettleResponse(
                success=False,
                error_reason=ERR_UPTO_TRANSACTION_FAILED,
                transaction=tx_hash,
                network=network,
                payer=payer,
            )

        return SettleResponse(
            success=True,
            transaction=tx_hash,
            network=network,
            payer=verify_result.payer,
            amount=str(settlement_amount),
        )
    except Exception as exc:
        return SettleResponse(
            success=False,
            error_reason=map_upto_settle_error(exc),
            error_message=str(exc)[:500],
            network=network,
            payer=payer,
            transaction="",
        )


__all__ = [
    "settle_upto_permit2",
    "verify_upto_permit2",
]
