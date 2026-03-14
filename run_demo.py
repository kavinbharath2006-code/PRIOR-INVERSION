from ledger import init
import issuer, wallet, verifier

def main():
    print("=" * 50)
    print("  BDL PROTOTYPE — Full demo flow")
    print("=" * 50)

    # Boot the mock ledger
    init()

    # --- STEP 1: DMV issues a license ---
    print("\n--- 1. Issuing license ---")
    cred = issuer.issue_license(
        name="Arjun Sharma",
        dob="1995-06-15",
        license_class="B"
    )
    did = cred["did"]

    # --- STEP 2: Citizen stores it in wallet ---
    print("\n--- 2. Storing in wallet ---")
    wallet.store(cred)

    # --- STEP 3: Citizen presents to police (selective disclosure) ---
    print("\n--- 3. Presenting credential (no DOB/address shared) ---")
    presentation = wallet.present(did, disclose_fields=[
        "did", "license_class", "hash", "signature"
    ])

    # --- STEP 4: Police verify ---
    print("\n--- 4. Verifying ---")
    result = verifier.verify(presentation)
    print(f"    Result: {result}")

    # --- STEP 5: Tamper test ---
    print("\n--- 5. Tamper test (bad hash) ---")
    tampered = {**presentation, "hash": "000deadbeef"}
    result2 = verifier.verify(tampered)
    print(f"    Result: {result2}")

    # --- STEP 6: Revocation test ---
    print("\n--- 6. Revocation test ---")
    issuer.revoke_license(did, reason="DUI offence")
    result3 = verifier.verify(presentation)
    print(f"    Result: {result3}")

    print("\n" + "=" * 50)
    print("  Demo complete. Check bdl_ledger.db for full log.")
    print("=" * 50)

if __name__ == "__main__":
    main()