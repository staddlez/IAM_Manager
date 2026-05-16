#!/usr/bin/env python3
"""
proxy.py — Drop-in replacement for: python3 -m http.server 8000

Run:  python3 proxy.py
Then: open http://localhost:8000 in your browser

The browser calls /api/token and /api/iam on THIS server.
This server calls sso.dynatrace.com and api.dynatrace.com, or the hardening API
when the UI sends apiBase=https://INTERNAL.com.
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
API_BASE_HARDENING = "https://INTERNAL.com"
DQL_PATH_BASE = "/platform/storage/query/v1"
ALLOWED_API_BASES = {API_BASE, API_BASE_HARDENING}
ALLOWED_ORIGINS = {
    f"http://localhost:{PORT}",
    f"http://127.0.0.1:{PORT}",
}
ALLOWED_HOSTS = {
    f"localhost:{PORT}",
    f"127.0.0.1:{PORT}",
}
SCOPES     = (
    "account-idm-read account-idm-write "
    "iam-policies-management iam:bindings:read iam:effective-permissions:read"
)

app = Flask(__name__, static_folder=STATIC_DIR)


@app.before_request
def _protect_local_api_routes():
    """Restrict API routes to the local IAM Manager page.

    This prevents the proxy from being used as a local open proxy by another site.
    Same-origin requests from http://localhost:8000 or http://127.0.0.1:8000 are allowed.
    """
    if not request.path.startswith("/api/"):
        return None

    host = request.host.split("@")[-1]
    if host not in ALLOWED_HOSTS:
        return jsonify({"error": "Blocked request: invalid Host header."}), 403

    origin = request.headers.get("Origin")
    referer = request.headers.get("Referer")

    if origin and origin.rstrip("/") not in ALLOWED_ORIGINS:
        return jsonify({"error": "Blocked request: invalid Origin header."}), 403

    if referer:
        allowed_ref = any(referer.startswith(o + "/") or referer == o for o in ALLOWED_ORIGINS)
        if not allowed_ref:
            return jsonify({"error": "Blocked request: invalid Referer header."}), 403

    return None

# ── Server-side token cache ───────────────────────────────────────────────────
# Keyed by client_id + account_id so multiple credential sets work in the same session.
_token_cache: dict[str, dict] = {}   # { cache_key: { token, expires_at } }
_cache_lock = threading.Lock()


def _cache_key(client_id: str, account_id: str) -> str:
    return f"{client_id}|{account_id}"


def _get_token(client_id: str, client_secret: str, account_id: str, force_refresh: bool = False) -> tuple[str, int]:
    """Return a cached token, or fetch a fresh one from Dynatrace SSO."""
    now = time.time()
    key = _cache_key(client_id, account_id)
    with _cache_lock:
        cached = _token_cache.get(key)
        if not force_refresh and cached and cached["expires_at"] - 60 > now:   # 60 s safety margin
            return cached["token"], int(cached.get("expires_in", 3600))

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
    expires_in = int(data.get("expires_in", 3600))
    expires_at = now + max(60, expires_in - 60)

    with _cache_lock:
        _token_cache[key] = {"token": token, "expires_at": expires_at, "expires_in": expires_in}

    return token, expires_in


def _safe_api_base(value: str | None) -> str:
    """Allow only known Dynatrace API bases so the proxy cannot be used as an open proxy."""
    base = (value or API_BASE).strip().rstrip("/")
    if base not in ALLOWED_API_BASES:
        raise ValueError(f"Unsupported apiBase: {base}")
    return base


def _forward_to_dynatrace(method: str, url: str, token: str, payload):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
        "Accept":        "application/json",
    }
    return requests.request(
        method,
        url,
        headers=headers,
        json=payload if payload is not None else None,
        timeout=30,
    )


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
      { "clientId": "...", "clientSecret": "...", "accountId": "...", "forceRefresh": true|false }

    Response (JSON):
      { "access_token": "...", "expires_in": 3600 }
    """
    body = request.get_json(force=True) or {}
    client_id     = body.get("clientId", "").strip()
    client_secret = body.get("clientSecret", "").strip()
    account_id    = body.get("accountId", "").strip()
    force_refresh = bool(body.get("forceRefresh", False))

    if not (client_id and client_secret and account_id):
        return jsonify({"error": "clientId, clientSecret, and accountId are required."}), 400

    try:
        token, expires_in = _get_token(client_id, client_secret, account_id, force_refresh=force_refresh)
        return jsonify({"access_token": token, "expires_in": expires_in})
    except requests.HTTPError as exc:
        return jsonify({"error": f"SSO error {exc.response.status_code}: {exc.response.text}"}), 401
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/iam", methods=["POST"])
def api_iam():
    """
    Proxy an authenticated request to Dynatrace Account/IAM API.

    Request body (JSON):
      {
        "clientId":     "...",
        "clientSecret": "...",
        "accountId":    "...",
        "accessToken":  "...",       // optional; UI refreshed token
        "apiBase":      "https://api.dynatrace.com" | "https://api-hardening.internal.dynatracelabs.com",
        "path":         "/iam/v1/accounts/.../users/...",
        "method":       "GET" | "POST" | "PUT" | "DELETE",   // default GET
        "body":         { ... }                               // optional
      }

    Response: the raw JSON from Dynatrace, same HTTP status.
    """
    body = request.get_json(force=True) or {}
    client_id     = body.get("clientId", "").strip()
    client_secret = body.get("clientSecret", "").strip()
    account_id    = body.get("accountId", "").strip()
    path          = body.get("path", "").strip()
    method        = body.get("method", "GET").upper()
    payload       = body.get("body")
    access_token  = body.get("accessToken", "").strip()

    if not (client_id and client_secret and account_id and path):
        return jsonify({"error": "clientId, clientSecret, accountId, and path are required."}), 400
    if not path.startswith("/"):
        return jsonify({"error": "path must start with /."}), 400

    try:
        api_base = _safe_api_base(body.get("apiBase"))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    # Prefer the UI-provided token so a forced refresh in the browser is actually used.
    token = access_token
    if not token:
        try:
            token, _ = _get_token(client_id, client_secret, account_id)
        except requests.HTTPError as exc:
            return jsonify({"error": f"Token error {exc.response.status_code}: {exc.response.text}"}), 401
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    url = f"{api_base}{path}"

    try:
        dt_resp = _forward_to_dynatrace(method, url, token, payload)

        # If the UI did not pass a token and our cached token failed, force-refresh and retry once.
        if dt_resp.status_code in (401, 403) and not access_token:
            fresh_token, _ = _get_token(client_id, client_secret, account_id, force_refresh=True)
            dt_resp = _forward_to_dynatrace(method, url, fresh_token, payload)
    except Exception as exc:
        return jsonify({"error": str(exc), "apiBase": api_base, "path": path}), 502

    if dt_resp.status_code == 204:
        return ("", 204)

    # Return whatever Dynatrace returned, preserving the status code
    try:
        return (jsonify(dt_resp.json()), dt_resp.status_code)
    except ValueError:
        return (dt_resp.text, dt_resp.status_code, {"Content-Type": "text/plain"})



@app.route("/api/dql", methods=["POST"])
def api_dql():
    """
    Proxy an authenticated DQL request to Dynatrace Apps/Grail Query API.

    Request body (JSON):
      {
        "clientId": "...",
        "clientSecret": "...",
        "accountId": "...",
        "accessToken": "...",
        "envId": "abc12345",
        "path": "/query:execute",
        "method": "POST",
        "body": { "query": "fetch logs | limit 10", "defaultScanLimitGbytes": 100 }
      }

    Default target:
      https://{envId}.apps.dynatrace.com/platform/storage/query/v1{path}

    In debug mode, if apiBase is set to the hardening base, target:
      https://api-hardening.internal.dynatracelabs.com/platform/storage/query/v1{path}
    """
    body = request.get_json(force=True) or {}
    client_id     = body.get("clientId", "").strip()
    client_secret = body.get("clientSecret", "").strip()
    account_id    = body.get("accountId", "").strip()
    env_id        = body.get("envId", "").strip()
    path          = body.get("path", "").strip()
    method        = body.get("method", "POST").upper()
    payload       = body.get("body")
    access_token  = body.get("accessToken", "").strip()

    if not (client_id and client_secret and account_id and path):
        return jsonify({"error": "clientId, clientSecret, accountId, and path are required."}), 400
    if not path.startswith("/"):
        return jsonify({"error": "path must start with /."}), 400
    if not path.startswith("/query:"):
        return jsonify({"error": "Only /query:* DQL paths are supported by /api/dql."}), 400

    # Prefer the UI-provided token so forced browser refreshes are honored.
    token = access_token
    if not token:
        try:
            token, _ = _get_token(client_id, client_secret, account_id)
        except requests.HTTPError as exc:
            return jsonify({"error": f"Token error {exc.response.status_code}: {exc.response.text}"}), 401
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    try:
        api_base = _safe_api_base(body.get("apiBase"))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    if api_base == API_BASE_HARDENING:
        url = f"{API_BASE_HARDENING}{DQL_PATH_BASE}{path}"
    else:
        if not env_id:
            return jsonify({"error": "envId is required for DQL requests when not using hardening apiBase."}), 400
        # Keep this constrained to Dynatrace app domains; do not accept arbitrary hosts.
        safe_env = ''.join(ch for ch in env_id.lower() if ch.isalnum() or ch in ('-', '_'))
        if safe_env != env_id.lower():
            return jsonify({"error": "envId contains unsupported characters."}), 400
        url = f"https://{safe_env}.apps.dynatrace.com{DQL_PATH_BASE}{path}"

    try:
        dt_resp = _forward_to_dynatrace(method, url, token, payload)

        if dt_resp.status_code in (401, 403) and not access_token:
            fresh_token, _ = _get_token(client_id, client_secret, account_id, force_refresh=True)
            dt_resp = _forward_to_dynatrace(method, url, fresh_token, payload)
    except Exception as exc:
        return jsonify({"error": str(exc), "url": url}), 502

    if dt_resp.status_code == 204:
        return ("", 204)

    try:
        return (jsonify(dt_resp.json()), dt_resp.status_code)
    except ValueError:
        return (dt_resp.text, dt_resp.status_code, {"Content-Type": "text/plain"})


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"\n  IAM Manager proxy running → http://127.0.0.1:{PORT}")
    print(f"  API bases allowed:")
    for base in sorted(ALLOWED_API_BASES):
        print(f"    - {base}")
    print()
    app.run(host="127.0.0.1", port=PORT, debug=False, use_reloader=False)
