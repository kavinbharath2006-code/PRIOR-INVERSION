import uuid, time
from crypto_utils import hash_credential, sign
from ledger import anchor, revoke

def issue_license(name: str, dob: str, license_class: str) -> dict:
    did = "did:bdl:" + str(uuid.uuid4())[:8]
    payload = {
        "did":           did,
        "name":          name,
        "dob":           dob,
        "license_class": license_class,
        "issued_at":     time.strftime("%Y-%m-%d"),
        "issuer":        "did:bdl:dmv-authority"
    }
    cred_hash = hash_credential(payload)
    signature = sign(payload)

    # Anchor hash on the mock blockchain
    anchor(did, cred_hash)

    credential = {**payload, "hash": cred_hash, "signature": signature}
    print(f"[ISSUER]  Issued credential for {name}  DID={did}")
    return credential

def revoke_license(did: str, reason: str = "suspended"):
    revoke(did, reason)
    print(f"[ISSUER]  Revoked DID={did}  reason={reason}")