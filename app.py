from flask import Flask, request, jsonify, render_template, send_file
from flask_cors import CORS
import sqlite3, io, qrcode, json, os
from ledger import init, anchor, revoke, lookup, log_verification, DB
from crypto_utils import hash_credential, sign
from issuer import issue_license, revoke_license
from wallet import store, present
from verifier import verify

app = Flask(__name__)
CORS(app)
init()

# ── Pages ──────────────────────────────────────────
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/issuer")
def issuer_page():
    return render_template("issuer.html")

@app.route("/wallet")
def wallet_page():
    return render_template("wallet.html")

@app.route("/verifier")
def verifier_page():
    return render_template("verifier.html")

@app.route("/explorer")
def explorer_page():
    return render_template("explorer.html")

# ── API: Issue ──────────────────────────────────────
@app.route("/api/issue", methods=["POST"])
def api_issue():
    data = request.json
    try:
        cred = issue_license(
            name=data["name"],
            dob=data["dob"],
            license_class=data["license_class"]
        )
        store(cred)
        return jsonify({"success": True, "credential": cred})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

# ── API: Verify ─────────────────────────────────────
@app.route("/api/verify", methods=["POST"])
def api_verify():
    data = request.json
    did = data.get("did")
    try:
        presentation = present(did, disclose_fields=[
            "did", "license_class", "hash", "signature"
        ])
        result = verify(presentation)
        return jsonify({"success": True, "result": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

# ── API: Revoke ─────────────────────────────────────
@app.route("/api/revoke", methods=["POST"])
def api_revoke():
    data = request.json
    did = data.get("did")
    reason = data.get("reason", "suspended")
    try:
        revoke_license(did, reason)
        return jsonify({"success": True, "message": f"DID {did} revoked"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

# ── API: Wallet list ────────────────────────────────
@app.route("/api/wallet", methods=["GET"])
def api_wallet():
    try:
        if not os.path.exists("wallet.json"):
            return jsonify({"credentials": []})
        with open("wallet.json") as f:
            wallet_data = json.load(f)
        creds = list(wallet_data.values())
        return jsonify({"credentials": creds})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# ── API: Ledger events ──────────────────────────────
@app.route("/api/events", methods=["GET"])
def api_events():
    con = sqlite3.connect(DB)
    rows = con.execute(
        "SELECT event, did, timestamp, detail FROM events ORDER BY id DESC LIMIT 50"
    ).fetchall()
    con.close()
    events = [
        {"event": r[0], "did": r[1], "timestamp": r[2], "detail": r[3]}
        for r in rows
    ]
    return jsonify({"events": events})

# ── API: QR code ────────────────────────────────────
@app.route("/api/qr/<did>")
def api_qr(did):
    img = qrcode.make(did)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")

if __name__ == "__main__":
    app.run(debug=True, port=5000)