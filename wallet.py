import json, os

WALLET_FILE = "wallet.json"

def store(credential: dict):
    wallet = _load()
    wallet[credential["did"]] = credential
    _save(wallet)
    print(f"[WALLET]  Stored credential DID={credential['did']}")

def present(did: str, disclose_fields=None) -> dict:
    """
    Selective disclosure: only share requested fields.
    Default: share did + hash + signature (no PII).
    """
    wallet = _load()
    cred = wallet.get(did)
    if not cred:
        raise ValueError(f"No credential found for DID={did}")

    if disclose_fields is None:
        disclose_fields = ["did", "license_class", "hash", "signature"]

    presentation = {k: cred[k] for k in disclose_fields if k in cred}
    print(f"[WALLET]  Presenting fields: {list(presentation.keys())}")
    return presentation

def _load():
    if os.path.exists(WALLET_FILE):
        with open(WALLET_FILE) as f:
            return json.load(f)
    return {}

def _save(wallet):
    with open(WALLET_FILE, "w") as f:
        json.dump(wallet, f, indent=2)