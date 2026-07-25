import ipaddress
import os
import posixpath
import socket
from urllib.parse import urlsplit, urljoin

import requests
from fastapi import FastAPI

app = FastAPI()

SANDBOX_ROOT = os.path.realpath(
    os.path.join(os.path.dirname(os.path.realpath(__file__)), "sandbox-f007a281e1")
)
ALLOWED_HOSTS = {"example.com", "www.iana.org"}
MAX_REDIRECTS = 5
FETCH_TIMEOUT = 5
MAX_RESULT_CHARS = 20000


# ---------------- read_file ----------------

def resolve_sandbox_path(path: str) -> str:
    """Normalize a path relative to the sandbox root WITHOUT url-decoding.
    Literal '%2e%2e' or '..'-looking filenames are treated as plain text,
    matching real filesystem semantics."""
    if path.startswith("/"):
        candidate = path
    else:
        candidate = posixpath.join(SANDBOX_ROOT, path)
    return posixpath.normpath(candidate)


def is_within_sandbox(normalized: str) -> bool:
    return normalized == SANDBOX_ROOT or normalized.startswith(SANDBOX_ROOT + "/")


def handle_read_file(path: str):
    if not path:
        return {"action": "block", "reason": "No path provided."}

    normalized = resolve_sandbox_path(path)
    if not is_within_sandbox(normalized):
        return {"action": "block", "reason": "Path resolves outside the permitted sandbox directory."}

    try:
        real = os.path.realpath(normalized)
    except Exception:
        return {"action": "block", "reason": "Could not resolve path."}

    if not is_within_sandbox(real):
        return {"action": "block", "reason": "Resolved (real) path escapes the sandbox (possible symlink)."}

    try:
        with open(real, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except FileNotFoundError:
        return {"action": "block", "reason": "File does not exist."}
    except IsADirectoryError:
        return {"action": "block", "reason": "Path is a directory, not a file."}
    except Exception as e:
        return {"action": "block", "reason": f"Could not read file: {type(e).__name__}"}

    return {"action": "allow", "reason": "Path is within the permitted sandbox directory.", "result": content}


# ---------------- fetch_url ----------------

def host_is_public_ip(host: str) -> bool:
    """Resolve host and ensure every resolved address is a public, routable IP
    (rejects private, loopback, link-local/metadata, reserved, multicast)."""
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return False
    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return False
    return True


def validate_url(url: str):
    try:
        parsed = urlsplit(url)
    except Exception:
        return False, "URL could not be parsed."

    if parsed.scheme not in ("http", "https"):
        return False, "Only http/https URLs are permitted."

    if parsed.username is not None or parsed.password is not None:
        return False, "URLs with embedded userinfo are not permitted."

    host = (parsed.hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        return False, "Host is not on the exact allowlist (example.com, www.iana.org only)."

    if not host_is_public_ip(host):
        return False, "Host resolves to a non-public address."

    return True, None


def handle_fetch_url(url: str):
    if not url:
        return {"action": "block", "reason": "No url provided."}

    current_url = url
    for _ in range(MAX_REDIRECTS + 1):
        ok, reason = validate_url(current_url)
        if not ok:
            return {"action": "block", "reason": reason}

        try:
            resp = requests.get(current_url, timeout=FETCH_TIMEOUT, allow_redirects=False)
        except Exception as e:
            return {"action": "block", "reason": f"Fetch failed: {type(e).__name__}"}

        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location")
            if not location:
                break
            current_url = urljoin(current_url, location)
            continue

        text = resp.text[:MAX_RESULT_CHARS]
        return {
            "action": "allow",
            "reason": "Host is on the exact allowlist and resolves to a public address.",
            "result": text,
        }

    return {"action": "block", "reason": "Too many redirects or redirect target failed validation."}


@app.post("/check")
def check(payload: dict):
    tool = payload.get("tool")
    args = payload.get("arguments", {}) or {}

    if tool == "read_file":
        return handle_read_file(args.get("path", ""))
    if tool == "fetch_url":
        return handle_fetch_url(args.get("url", ""))

    return {"action": "block", "reason": "Unrecognized tool."}


@app.get("/")
def health():
    return {"status": "ok"}
