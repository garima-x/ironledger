"""SHA-256 hash-chaining logic (from garima's modular backend)."""
import hashlib
import json

GENESIS_HASH = "0" * 64


def compute_hash(
    source: str, command: str, entity: str, params: dict, prev_hash: str
) -> tuple[str, str]:
    """Returns (preimage_string, sha256_hex_digest)."""
    params_str = json.dumps(params, sort_keys=True, separators=(",", ":"))
    preimage = f"{source}|{command}|{entity}|{params_str}|{prev_hash}"
    digest = hashlib.sha256(preimage.encode("utf-8")).hexdigest()
    return preimage, digest
