#!/usr/bin/env python3
"""
proxy.py — Drop-in replacement for: python3 -m http.server 8000

Run:  python3 proxy.py
Then: open http://localhost:8000 in your browser

The browser calls /api/token and /api/iam on THIS server.
This server calls sso.dynatrace.com and api.dynatrace.com.
No CORS. No CSP. The browser never touches Dynatrace URLs directly.

Install once:  pip install flask requests
"""

import json
import threading
import time

import requests
from flask import Flask, jsonify, request, send_from_directory

# ── Config ────────────────────────────────────────────────────────────────────
STATIC_DIR = "."          # folder containing iam-manager.html
PORT       = 8000
SSO_URL    = "https://sso.dynatrace.com/sso/oauth2/token"
API_BASE   = "https://api.dynatrace.com"
SCOPES     = (
    "account-idm-read account-idm-write "
    "iam-policies-management iam:bindings:read iam:effective-permissions:read"
)

app = Flask(__name__, static_folder=STATIC_DIR)

# ── Server-side token cache ───────────────────────────────────────────────────
# Keyed by client_id so multiple credential sets work in the same session.
_token_cache: dict[str, dict] = {}   # { client_id: { token, expires_at } }
_cache_lock = threading.Lock()


def _get_token(client_id: str, client_secret: str, account_id: str) -> str:
    """Return a cached token, or fetch a fresh one from Dynatrace SSO."""
    now = time.time()
    with _cache_lock:
        cached = _token_cache.get(client_id)
        if cached and cached["expires_at"] - 60 > now:   # 60 s safety margin
            return cached["token"]

    resp = requests.post(
        SSO_URL,
        data={
            "grant_type":    "client_credentials",
            "client_id":     client_id,
            "client_secret": client_secret,
            "scope":         SCOPES,
            "resource":      f"urn:dtaccount:{account_id}",
        },
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    token = data["access_token"]
    # Dynatrace tokens live 3 600 s; cache for 50 min
    expires_at = now + 50 * 60

    with _cache_lock:
        _token_cache[client_id] = {"token": token, "expires_at": expires_at}

    return token


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the main HTML page."""
    return send_from_directory(STATIC_DIR, "iam-manager.html")


@app.route("/<path:filename>")
def static_files(filename):
    """Serve any other static asset (JS, CSS, etc.)."""
    return send_from_directory(STATIC_DIR, filename)


@app.route("/api/token", methods=["POST"])
def api_token():
    """
    Fetch (or return cached) OAuth token.

    Request body (JSON):
      { "clientId": "...", "clientSecret": "...", "accountId": "..." }

    Response (JSON):
      { "access_token": "..." }
    """
    body = request.get_json(force=True) or {}
    client_id     = body.get("clientId", "").strip()
    client_secret = body.get("clientSecret", "").strip()
    account_id    = body.get("accountId", "").strip()

    if not (client_id and client_secret and account_id):
        return jsonify({"error": "clientId, clientSecret, and accountId are required."}), 400

    try:
        token = _get_token(client_id, client_secret, account_id)
        return jsonify({"access_token": token})
    except requests.HTTPError as exc:
        return jsonify({"error": f"SSO error {exc.response.status_code}: {exc.response.text}"}), 401
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/iam", methods=["POST"])
def api_iam():
    """
    Proxy an authenticated request to api.dynatrace.com.

    Request body (JSON):
      {
        "clientId":     "...",
        "clientSecret": "...",
        "accountId":    "...",
        "path":         "/iam/v1/accounts/.../users/...",
        "method":       "GET" | "POST" | "PUT" | "DELETE",   // default GET
        "body":         { ... }                               // optional
      }

    Response: the raw JSON from api.dynatrace.com, same HTTP status.
    """
    body = request.get_json(force=True) or {}
    client_id     = body.get("clientId", "").strip()
    client_secret = body.get("clientSecret", "").strip()
    account_id    = body.get("accountId", "").strip()
    path          = body.get("path", "").strip()
    method        = body.get("method", "GET").upper()
    payload       = body.get("body")

    if not (client_id and client_secret and account_id and path):
        return jsonify({"error": "clientId, clientSecret, accountId, and path are required."}), 400

    # Fetch / reuse token
    try:
        token = _get_token(client_id, client_secret, account_id)
    except requests.HTTPError as exc:
        return jsonify({"error": f"Token error {exc.response.status_code}: {exc.response.text}"}), 401
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    # Forward to Dynatrace
    url = f"{API_BASE}{path}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
        "Accept":        "application/json",
    }

    try:
        dt_resp = requests.request(
            method,
            url,
            headers=headers,
            json=payload if payload is not None else None,
            timeout=30,
        )
    except Exception as exc:
        return jsonify({"error": str(exc)}), 502

    if dt_resp.status_code == 204:
        return ("", 204)

    # Return whatever Dynatrace returned, preserving the status code
    try:
        return (jsonify(dt_resp.json()), dt_resp.status_code)
    except ValueError:
        return (dt_resp.text, dt_resp.status_code, {"Content-Type": "text/plain"})


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"\n  IAM Manager proxy running → http://localhost:{PORT}\n")
    app.run(host="0.0.0.0", port=PORT, debug=False, use_reloader=False)
