import os
import json
import hashlib
import secrets
import time
from copy import deepcopy
from flask import Flask, request, jsonify

# IMPORTANT:
# This is a transport-correct starter for the Observable Incident Triage assignment.
# It fixes the "app is not defined" deployment error and provides the required routes.
# It does NOT implement the complete AI planning / tool lifecycle / OTLP rubric by itself.

app = Flask(__name__)
PROFILE = "ga5-incident-agent/v2"
MODEL = os.getenv("MODEL_NAME", "gemini-2.5-flash")
runs = {}
receipts_by_id = {}

def json_error(message, status):
    return jsonify({"error": message}), status

def canonical_digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def is_object(value):
    return isinstance(value, dict)

@app.get("/")
def home():
    return jsonify({"service": "Observable Incident Triage",
        "status": "ready",
        "profile": PROFILE
    }), 200

@app.post("/v2/incidents")
def create_incident():
    body = request.get_json(silent=True)
    if not is_object(body):
        return json_error("Request body must be a JSON object", 400)

    if body.get("profile") != PROFILE:
        return json_error("Unsupported profile", 422)

    required = ["runId", "agentName", "publicMarker", "incident",
                "toolCatalog", "policy"]
    missing = [key for key in required if key not in body]
    if missing:
        return jsonify({"error": "Missing required fields", "missing": missing}), 400

    run_id = body.get("runId")
    if not isinstance(run_id, str) or not run_id.strip():
        return json_error("runId must be a non-empty string", 400)

    # Replaying the exact same request returns the stored response.
    request_digest = canonical_digest(body)
    if run_id in runs:
        old = runs[run_id]
        if old["requestDigest"] != request_digest:
            return json_error("runId already exists with different content", 409)
        return jsonify(deepcopy(old["response"])), 200

    incident = body.get("incident")
    if not is_object(incident):
        return json_error("incident must be a JSON object", 400)

    allowed = incident.get("allowedRootCauses", [])
    if not isinstance(allowed, list) or not allowed:
        return json_error("incident.allowedRootCauses must be a non-empty list", 422)

    # Safe transport fallback: do not pretend that an AI diagnosis or tool execution
    # happened. Replace this block with the assignment's actual model-planning logic.
    cause = allowed[0]
    transcript = incident.get("transcript", "")
    evidence_ids = []
    if isinstance(transcript, str):
        import re
        evidence_ids = re.findall(r"\[(ev_[A-Za-z0-9_-]+)\]", transcript)[:4]

    response = {
        "profile": PROFILE,
        "runId": run_id,
        "status": "waiting",
        "diagnosis": {
            "rootCause": cause,
            "evidence": evidence_ids,
            "summary": "Starter response only: connect the required model-planning logic before submitting to the grader."
        },
        "dispatches": [],
        "approvals": []
    }

    runs[run_id] = {
        "requestDigest": request_digest,
        "originalRequest": deepcopy(body),
        "response": deepcopy(response),
        "actionLog": [],
        "receiptLog": [],
        "pending": {},
        "createdAt": int(time.time())
    }
    return jsonify(response), 200

@app.post("/v2/incidents/<run_id>/receipts")
def add_receipts(run_id):
    if run_id not in runs:
        return json_error("Unknown runId", 404)

    body = request.get_json(silent=True)
    if not is_object(body):
        return json_error("Request body must be a JSON object", 400)

    items = body.get("receipts")
    if not isinstance(items, list):
        # Also accept a single receipt object for easier testing.
        items = [body] if body.get("receiptId") else None
    if not isinstance(items, list):
        return json_error("Body must contain a receipts array or a receipt object", 400)

    state = runs[run_id]
    for receipt in items:
        if not is_object(receipt):
            return json_error("Each receipt must be a JSON object", 400)
        receipt_id = receipt.get("receiptId")
        if not isinstance(receipt_id, str) or not receipt_id:
            return json_error("Every receipt needs receiptId", 422)
        digest = canonical_digest(receipt)
        if receipt_id in receipts_by_id:
            if receipts_by_id[receipt_id] != digest:
                return json_error("receiptId already exists with different content", 409)
            continue
        receipts_by_id[receipt_id] = digest
        state["receiptLog"].append(deepcopy(receipt))

    # This starter records receipts but does not fabricate tool results or retries.
    return jsonify({
        "runId": run_id,
        "status": "waiting",
        "acceptedReceipts": len(items),
        "dispatches": [],
        "approvals": []
    }), 200

@app.get("/v2/incidents/<run_id>")
def get_incident(run_id):
    if run_id not in runs:
        return json_error("Unknown runId", 404)

    state = runs[run_id]
    result = deepcopy(state["response"])
    result["actionLog"] = deepcopy(state["actionLog"])
    result["receiptLog"] = deepcopy(state["receiptLog"])
    # Keep the expected telemetry field present; full OTLP spans must be implemented.
    result["resourceSpans"] = []
    return jsonify(result), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
 
