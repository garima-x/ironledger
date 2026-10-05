"""
Sepolia/web3 anchoring layer (garima's clean modular version).
Degrades gracefully to local mode if Sepolia is not configured.
"""
import json
import logging
from typing import Optional

from .config import settings

logger = logging.getLogger("ironledger.blockchain")

_web3 = None
_contract = None
_account = None
_init_error: Optional[str] = None


def _init():
    global _web3, _contract, _account, _init_error
    if _web3 is not None or _init_error is not None:
        return
    if not settings.chain_configured:
        _init_error = (
            "Sepolia not configured (SEPOLIA_RPC_URL / PRIVATE_KEY / CONTRACT_ADDRESS)"
            " — running in local mode."
        )
        return
    try:
        from web3 import Web3

        w3 = Web3(Web3.HTTPProvider(settings.sepolia_rpc_url))
        if not w3.is_connected():
            _init_error = "Could not reach Sepolia RPC — check SEPOLIA_RPC_URL."
            return
        abi = json.loads(settings.contract_abi_path.read_text())
        contract = w3.eth.contract(
            address=Web3.to_checksum_address(settings.contract_address), abi=abi
        )
        account = w3.eth.account.from_key(settings.private_key)
        _web3, _contract, _account = w3, contract, account
    except Exception as exc:
        _init_error = f"Sepolia initialization failed: {exc}"
        logger.warning(_init_error)


def chain_status() -> dict:
    _init()
    return {
        "configured": settings.chain_configured,
        "connected": _web3 is not None,
        "detail": _init_error or "connected",
    }


def anchor_on_chain(
    hash_hex: str, prev_hash_hex: str
) -> tuple[Optional[str], Optional[int], Optional[str]]:
    """Returns (tx_hash, onchain_index, error)."""
    _init()
    if _web3 is None:
        return None, None, _init_error

    try:
        from web3 import Web3

        hash_bytes = bytes.fromhex(hash_hex)
        prev_bytes = bytes.fromhex(prev_hash_hex)
        nonce = _web3.eth.get_transaction_count(_account.address)
        tx = _contract.functions.anchor(hash_bytes, prev_bytes).build_transaction(
            {"from": _account.address, "nonce": nonce, "chainId": 11155111}
        )
        signed = _account.sign_transaction(tx)
        tx_hash = _web3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = _web3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        onchain_index = None
        try:
            logs = _contract.events.Anchored().process_receipt(receipt)
            if logs:
                onchain_index = int(logs[0]["args"]["index"])
        except Exception:
            pass
        return tx_hash.hex(), onchain_index, None
    except Exception as exc:
        return None, None, f"Anchor transaction failed: {exc}"
