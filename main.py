
import os
import json
import hashlib
import sqlite3
import base64
import threading
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)

app = Flask(__name__)
DB = os.environ.get("DB_PATH", "mailroom.db")
PROFILE = "ga5-mailroom-action-gate/v2"
LOCK = threading.RLock()

ACTIONS = {
    "create_draft", "update_internal_record",
    "send_approved_notice", "request_confirmation",
    "quarantine_item", "no_action",
}


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False
    ).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def init_db():
    with sqlite3.connect(DB) as db:
        db.execute("""
        CREATE TABLE IF NOT EXISTS evaluations (
            evaluation_id TEXT PRIMARY KEY,
            input_digest TEXT NOT NULL,
            request_json TEXT NOT NULL,
            verifier_json TEXT NOT NULL,
            proposals_json TEXT NOT NULL,
            response_json TEXT NOT NULL,
            commit_json TEXT
        )
        """)
        db.execute("""
        CREATE TABLE IF NOT EXISTS decisions (
            fingerprint TEXT PRIMARY KEY,
            proposal_json TEXT NOT NULL
        )
        """)


def error(message, code):
    return jsonify({"error": message, "code": code}), 400


def make_call_id(dossier):
    fingerprint = digest(dossier)
    return "mail-" + fingerprint[:32]


def decide(dossier):
    # Conservative baseline. Replace with AI-assisted decisions
    # and validate its result against the frozen action schemas.
    text = " ".join(
        str(line.get("text", ""))
        for source in dossier.get("sources", [])
        for line in source.get("lines", [])
    ).lower()

    reference = dossier["dossierId"]

    if any(word in text for word in (
        "ignore previous instructions", "reveal secret",
        "send confidential", "prompt injection"
    )):
        return {
            "action": "quarantine_item",
            "target": {"kind": "security_queue", "id": "mailroom"},
            "payload": {
                "artifactId": reference,
                "reasonCode": "INDIRECT_PROMPT_INJECTION"
            },
        }

    return {
        "action": "request_confirmation",
        "target": {"kind": "approval_queue", "id": "mailroom"},
        "payload": {
            "claimedSender": "unknown",
            "questionCode": "VERIFY_REQUEST",
            "referenceId": reference,
        },
    }


def verify_receipt(receipt, evaluation_id, input_digest):
    verifier = _current_verifier
    if not verifier:
        return False

    signed_object = {
        "profile": PROFILE,
        "evaluationId": evaluation_id,
        "inputDigest": input_digest,
        "receipt": {
            key: value for key, value in receipt.items()
            if key != "receiptSignature"
        },
    }

    try:
        jwk = verifier["publicKeyJwk"]
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            return False

        x = jwk["x"]
        raw_key = base64.urlsafe_b64decode(
            x + "=" * (-len(x) % 4)
        )
        public_key = Ed25519PublicKey.from_public_bytes(raw_key)
        signature = base64.b64decode(
            receipt["receiptSignature"], validate=True
        )
        public_key.verify(signature, canonical(signed_object))
        return True
    except Exception:
        return False


_current_verifier = None


@app.get("/")
def home():
    return jsonify({"service": "Safe AI Mailroom", "status": "ready"})


@app.post("/")
def mailroom():
    global _current_verifier

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return error("Invalid JSON body", "INVALID_JSON")

    if body.get("profile") != PROFILE:
        return error("Unsupported profile", "INVALID_PROFILE")

    operation = body.get("operation")
    if operation not in ("propose", "commit"):
        return error("Invalid operation", "INVALID_OPERATION")

    if operation == "propose":
        evaluation_id = body.get("evaluationId")
        dossiers = body.get("dossiers")
        verifier = body.get("receiptVerifier")
        corpus = body.get("corpus")

        if (
            not isinstance(evaluation_id, str) or not evaluation_id
            or not isinstance(dossiers, list)
            or not isinstance(verifier, dict)
            or not isinstance(corpus, dict)
        ):
            return error("Invalid request fields", "INVALID_SCHEMA")

        ids = [d.get("dossierId") for d in dossiers
               if isinstance(d, dict)]
        if len(ids) != len(dossiers) or len(set(ids)) != len(ids):
            return error("Invalid or duplicate dossier IDs", "INVALID_DOSSIERS")

        input_digest = digest(dossiers)

        with LOCK, sqlite3.connect(DB) as db:
            old = db.execute(
                "SELECT input_digest,response_json FROM evaluations "
                "WHERE evaluation_id=?", (evaluation_id,)
            ).fetchone()

            if old:
                if old[0] != input_digest:
                    return jsonify({
                        "error": "Evaluation content conflict",
                        "code": "IDEMPOTENCY_CONFLICT"
                    }), 409
                return jsonify(json.loads(old[1]))

            proposals = []
            for dossier in dossiers:
                fingerprint = digest(dossier)
                row = db.execute(
                    "SELECT proposal_json FROM decisions WHERE fingerprint=?",
                    (fingerprint,)
                ).fetchone()

                if row:
                    proposal = json.loads(row[0])
                else:
                    decision = decide(dossier)
                    lines = [
                        line["lineId"]
                        for source in dossier.get("sources", [])
                        for line in source.get("lines", [])
                        if isinstance(line, dict) and "lineId" in line
                    ]
                    proposal = {
                        "dossierId": dossier["dossierId"],
                        "callId": make_call_id(dossier),
                        "action": decision["action"],
                        "target": decision["target"],
                        "payload": decision["payload"],
                        "evidence": lines[:1],
                    }
                    db.execute(
                        "INSERT OR IGNORE INTO decisions VALUES (?,?)",
                        (fingerprint, json.dumps(proposal))
                    )

                # Bind the current dossier ID even for cached decisions.
                proposal["dossierId"] = dossier["dossierId"]
                proposals.append(proposal)

            response = {
                "profile": PROFILE,
                "evaluationId": evaluation_id,
                "status": "awaiting_receipts",
                "inputDigest": input_digest,
                "proposals": proposals,
            }

            db.execute(
                "INSERT INTO evaluations VALUES (?,?,?,?,?,?,NULL)",
                (evaluation_id, input_digest, json.dumps(body),
                 json.dumps(verifier), json.dumps(proposals),
                 json.dumps(response))
            )
            db.commit()
            return jsonify(response)

    evaluation_id = body.get("evaluationId")
    input_digest = body.get("inputDigest")
    receipts = body.get("receipts")

    if not isinstance(receipts, list):
        return error("Invalid receipts", "INVALID_RECEIPTS")

    with LOCK, sqlite3.connect(DB) as db:
        row = db.execute(
            "SELECT input_digest,request_json,verifier_json,"
            "proposals_json,commit_json FROM evaluations "
            "WHERE evaluation_id=?", (evaluation_id,)
        ).fetchone()

        if not row:
            return jsonify({"error": "Unknown evaluation"}), 404

        stored_digest, req_json, verifier_json, proposals_json, old_commit = row

        if stored_digest != input_digest:
            return error("Digest mismatch", "DIGEST_MISMATCH")

        if old_commit:
            old_body = json.loads(old_commit)
            if canonical(old_body) == canonical(body):
                return jsonify(old_body)
            return jsonify({"error": "Commit conflict"}), 409

        proposals = json.loads(proposals_json)
        expected = {p["dossierId"]: p for p in proposals}

        if len(receipts) != len(expected):
            return error("Receipt count mismatch", "INVALID_RECEIPTS")

        receipt_ids = [r.get("receiptId") for r in receipts
                       if isinstance(r, dict)]
        if len(receipt_ids) != len(receipts) or len(set(receipt_ids)) != len(receipts):
            return error("Duplicate receipt", "INVALID_RECEIPTS")

        _current_verifier = json.loads(verifier_json)
        outcomes = []

        # Validate every receipt before recording any outcome.
        for receipt in receipts:
            if not isinstance(receipt, dict):
                _current_verifier = None
                return error("Invalid receipt", "INVALID_RECEIPTS")

            proposal = expected.get(receipt.get("dossierId"))
            if not proposal:
                _current_verifier = None
                return error("Unknown receipt dossier", "INVALID_RECEIPTS")

            normalized = {
                key: proposal[key]
                for key in ("dossierId", "callId", "action",
                            "target", "payload", "evidence")
            }
            normalized["evidence"] = sorted(normalized["evidence"])
            proposal_digest = digest(normalized)

            if (
                receipt.get("callId") != proposal["callId"]
                or receipt.get("action") != proposal["action"]
                or receipt.get("proposalDigest") != proposal_digest
                or not verify_receipt(receipt, evaluation_id, input_digest)
            ):
                _current_verifier = None
                return error("Receipt verification failed", "INVALID_SIGNATURE")

            outcomes.append({
                "dossierId": proposal["dossierId"],
                "callId": proposal["callId"],
                "action": proposal["action"],
                "proposalDigest": proposal_digest,
                "receiptId": receipt["receiptId"],
                "status": "executed" if receipt["accepted"] is True
                          else "rejected",
            })

        _current_verifier = None

        response = {
            "profile": PROFILE,
            "evaluationId": evaluation_id,
            "status": "completed",
            "inputDigest": input_digest,
            "outcomes": outcomes,
        }

        db.execute(
            "UPDATE evaluations SET commit_json=? WHERE evaluation_id=?",
            (json.dumps(response), evaluation_id)
        )
        db.commit()
        return jsonify(response)


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
