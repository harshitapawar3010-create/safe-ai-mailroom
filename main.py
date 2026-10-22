@app.get("/")
def home():
    return jsonify({"service": "Safe AI Mailroom", "status": "ready", "profile": PROFILE})


@app.post("/")
def mailroom():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return fail("Invalid JSON body", "INVALID_JSON")
    if body.get("profile") != PROFILE:
        return fail("Unsupported profile", "INVALID_PROFILE")
    operation = body.get("operation")
    if operation not in ("propose", "commit"):
        return fail("Invalid operation", "INVALID_OPERATION")

    if operation == "propose":
        problem = validate_propose(body)
        if problem:
            return fail(problem, "INVALID_SCHEMA", 422)
        evaluation_id = body["evaluationId"]
        dossiers = body["dossiers"]
        input_digest = digest(dossiers)

        with db_connect() as db:
            old = db.execute("SELECT input_digest,response_json FROM evaluations WHERE evaluation_id=?", (evaluation_id,)).fetchone()
            if old:
                if old["input_digest"] != input_digest:
                    return fail("Evaluation content conflict", "IDEMPOTENCY_CONFLICT", 409)
                return jsonify(json.loads(old["response_json"]))

            proposals = []
            for dossier in dossiers:
                fingerprint = digest(dossier)
                cached = db.execute("SELECT proposal_json FROM decisions WHERE fingerprint=?", (fingerprint,)).fetchone()
                if cached:
                    proposal = json.loads(cached["proposal_json"])
                    proposal["dossierId"] = dossier["dossierId"]
                else:
                    proposal = make_proposal(dossier)
                    db.execute("INSERT OR IGNORE INTO decisions(fingerprint,proposal_json) VALUES (?,?)", (fingerprint, json.dumps(proposal, ensure_ascii=False, separators=(",", ":"))))
                    # In a simultaneous first request, always use the canonical stored result.
                    saved = db.execute("SELECT proposal_json FROM decisions WHERE fingerprint=?", (fingerprint,)).fetchone()
                    proposal = json.loads(saved["proposal_json"])
                    proposal["dossierId"] = dossier["dossierId"]
                proposals.append(proposal)

            response = {"profile": PROFILE, "evaluationId": evaluation_id, "status": "awaiting_receipts", "inputDigest": input_digest, "proposals": proposals}
            db.execute(
                "INSERT INTO evaluations(evaluation_id,input_digest,request_json,verifier_json,proposals_json,response_json) VALUES (?,?,?,?,?,?)",
                (evaluation_id, input_digest, canonical(body).decode("utf-8"),
                 canonical(body["receiptVerifier"]).decode("utf-8"),
                 canonical(proposals).decode("utf-8"), canonical(response).decode("utf-8"))
            )
            db.commit()
            return jsonify(response)

    evaluation_id = body.get("evaluationId")
    input_digest = body.get("inputDigest")
    receipts = body.get("receipts")
    if not is_nonempty_string(evaluation_id, 200) or not is_nonempty_string(input_digest, 64) or not isinstance(receipts, list):
        return fail("Invalid commit request", "INVALID_SCHEMA", 422)

    with db_connect() as db:
        row = db.execute("SELECT input_digest,verifier_json,proposals_json,commit_request_json,commit_response_json FROM evaluations WHERE evaluation_id=?", (evaluation_id,)).fetchone()
        if not row:
            return fail("Unknown evaluation", "UNKNOWN_EVALUATION", 404)
        if row["input_digest"] != input_digest:
            return fail("Digest mismatch", "DIGEST_MISMATCH", 409)
        if row["commit_response_json"] is not None:
            if canonical(body).decode("utf-8") == row["commit_request_json"]:
                return jsonify(json.loads(row["commit_response_json"]))
            return fail("Commit conflict", "COMMIT_CONFLICT", 409)

        proposals = json.loads(row["proposals_json"])
        verifier = json.loads(row["verifier_json"])
        expected = {p["dossierId"]: p for p in proposals}
        if len(receipts) != len(expected):
            return fail("Receipt count mismatch", "INVALID_RECEIPTS", 422)
        if any(not valid_receipt_shape(r) for r in receipts):
            return fail("Malformed receipt", "INVALID_RECEIPTS", 422)
        if len({r["dossierId"] for r in receipts}) != len(receipts) or len({r["receiptId"] for r in receipts}) != len(receipts):
            return fail("Duplicate receipt or dossier", "INVALID_RECEIPTS", 422)

        # Validate all receipts before producing/persisting any outcomes.
        outcomes = []
        for receipt in receipts:
            proposal = expected.get(receipt["dossierId"])
            if proposal is None:
                return fail("Unknown receipt dossier", "INVALID_RECEIPTS", 422)
            pdigest = proposal_digest(proposal)
            if (
                receipt["callId"] != proposal["callId"]
                or receipt["action"] != proposal["action"]
                or receipt["proposalDigest"] != pdigest
                or not verify_receipt(receipt, evaluation_id, input_digest, verifier)
            ):
                return fail("Receipt verification failed", "INVALID_RECEIPT", 422)
            outcomes.append({
                "dossierId": proposal["dossierId"], "callId": proposal["callId"],
                "action": proposal["action"], "proposalDigest": pdigest,
                "receiptId": receipt["receiptId"],
                "status": "executed" if receipt["accepted"] else "rejected",
            })

        response = {"profile": PROFILE, "evaluationId": evaluation_id, "status": "completed", "inputDigest": input_digest, "outcomes": outcomes}
        db.execute("UPDATE evaluations SET commit_request_json=?,commit_response_json=? WHERE evaluation_id=?",
                   (canonical(body).decode("utf-8"), canonical(response).decode("utf-8"), evaluation_id))
        db.commit()
        return jsonify(response)


@app.errorhandler(413)
def too_large(_):
    return fail("Request body too large", "REQUEST_TOO_LARGE", 413)


@app.errorhandler(500)
def server_error(_):
    return fail("Internal server error", "INTERNAL_ERROR", 500)


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "10000")))
