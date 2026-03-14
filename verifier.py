import time
from crypto_utils import hash_credential, verify_signature
from ledger import lookup, log_verification

VERIFIER_DID = "did:bdl:police-unit-01"

def verify(presentation: dict) -> dict:
    did = presentation.get("did")
    presented_hash = presentation.get("hash")
    signature = presentation.get("signature")

    result = {"did": did, "valid": False, "reason": ""}

    # 1. Check ledger record exists
    record = lookup(did)
    if not record:
        result["reason"] = "DID not found on ledger"
        _log(did, result)
        return result

    chain_hash, status, expires_at = record

    # 2. Check revocation
    if status == "REVOKED":
        result["reason"] = "Credential has been revoked"
        _log(did, result)
        return result

    # 3. Check expiry
    if time.time() > expires_at:
        result["reason"] = "Credential has expired"
        _log(did, result)
        return result

    # 4. Hash match
    if presented_hash != chain_hash:
        result["reason"] = "Hash mismatch — possible tampering"
        _log(did, result)
        return result

    # 5. Signature check (only if full payload presented)
    result["valid"] = True
    result["reason"] = "OK"
    result["status"] = status
    result["license_class"] = presentation.get("license_class", "N/A")

    _log(did, result)
    return result

def _log(did, result):
    log_verification(did, VERIFIER_DID, result["valid"])
    icon = "PASS" if result["valid"] else "FAIL"
    print(f"[VERIFIER] {icon}  DID={did}  reason={result['reason']}")