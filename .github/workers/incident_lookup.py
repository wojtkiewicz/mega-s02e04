#!/usr/bin/env python3
"""GitHub Actions worker for the MEGA.dev S02E04 incident-lookup job."""

import base64
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


URL = os.environ.get("JOB_1_MCP_URL", "")
PROTOCOL_VERSION = "2025-03-26"
SESSION_ID = None
REQUEST_ID = 0
TRANSCRIPT = []


def collect_step_tokens(value, found=None):
    if found is None:
        found = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower().replace("_", "") in {"step", "steptoken"} and isinstance(item, str):
                found.add(item)
            collect_step_tokens(item, found)
    elif isinstance(value, list):
        for item in value:
            collect_step_tokens(item, found)
    elif isinstance(value, str):
        try:
            collect_step_tokens(json.loads(value), found)
        except (json.JSONDecodeError, TypeError):
            pass
    return found


def mask(value, step_tokens=None):
    """Mask step tokens, including tokens embedded in JSON text content."""
    if step_tokens is None:
        step_tokens = collect_step_tokens(value)
    if isinstance(value, dict):
        return {
            key: (
                "[MASKED]"
                if key.lower().replace("_", "") in {"step", "steptoken"}
                else mask(item, step_tokens)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [mask(item, step_tokens) for item in value]
    if isinstance(value, str):
        for token in step_tokens:
            value = value.replace(token, "[MASKED]")
    return value


def log_record(kind, value):
    safe_record = mask(value)
    TRANSCRIPT.append({"kind": kind, "record": safe_record})
    if kind == "REQUEST":
        method = value.get("body", {}).get("method", "unknown")
        print(f"MCP_LOG REQUEST {method}", flush=True)
    else:
        print(f"MCP_LOG REPLY HTTP {value.get('status', 'unknown')}", flush=True)


def emit_private_log(extra=None):
    payload = {"transcript": TRANSCRIPT}
    if extra:
        payload.update(extra)
    plaintext = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    aes_key = secrets.token_bytes(32)
    iv = secrets.token_bytes(16)
    encrypted = subprocess.run(
        ["openssl", "enc", "-aes-256-cbc", "-nosalt", "-K", aes_key.hex(), "-iv", iv.hex()],
        input=plaintext,
        capture_output=True,
        check=True,
    ).stdout
    wrapped_key = subprocess.run(
        [
            "openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey",
            os.path.join(os.path.dirname(__file__), "job1_public.pem"),
            "-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256",
        ],
        input=aes_key,
        capture_output=True,
        check=True,
    ).stdout
    mac = hmac.new(aes_key, iv + encrypted, hashlib.sha256).digest()
    envelope = {
        "key": base64.b64encode(wrapped_key).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
        "ciphertext": base64.b64encode(encrypted).decode("ascii"),
        "hmac": base64.b64encode(mac).decode("ascii"),
    }
    encoded = base64.b64encode(json.dumps(envelope, separators=(",", ":")).encode("utf-8")).decode("ascii")
    print("MEGA_JOB1_PRIVATE_LOG_B64=" + encoded, flush=True)


def parse_response(response):
    body = response.read().decode("utf-8")
    content_type = response.headers.get("Content-Type", "")
    if "text/event-stream" in content_type:
        messages = []
        for event in body.split("\n\n"):
            data = "\n".join(line[5:].lstrip() for line in event.splitlines() if line.startswith("data:"))
            if data:
                messages.append(json.loads(data))
        if not messages:
            raise RuntimeError("MCP returned an empty event stream")
        return messages[-1]
    if not body:
        return None
    return json.loads(body)


def rpc(method, params=None, notification=False):
    global REQUEST_ID, SESSION_ID
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": PROTOCOL_VERSION,
        "User-Agent": "curl/8.5.0",
    }
    if SESSION_ID:
        headers["Mcp-Session-Id"] = SESSION_ID
    request = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        request["params"] = params
    if not notification:
        REQUEST_ID += 1
        request["id"] = REQUEST_ID
    log_record("REQUEST", {"endpoint": "[JOB_1_MCP_URL secret]", "body": request})
    http_request = Request(URL, data=json.dumps(request).encode("utf-8"), headers=headers, method="POST")
    try:
        with urlopen(http_request, timeout=30) as response:
            if response.headers.get("Mcp-Session-Id"):
                SESSION_ID = response.headers["Mcp-Session-Id"]
            parsed = parse_response(response)
            log_record("REPLY", {"status": response.status, "body": parsed})
            return parsed
    except HTTPError as error:
        body = error.read().decode("utf-8", errors="replace")
        log_record("REPLY", {"status": error.code, "body": body})
        raise RuntimeError(f"MCP HTTP error {error.code}") from error
    except URLError as error:
        raise RuntimeError("Could not reach the job MCP endpoint") from error


def tool_call(name, arguments):
    response = rpc("tools/call", {"name": name, "arguments": arguments})
    if not isinstance(response, dict) or "error" in response:
        raise RuntimeError("MCP call failed")
    result = response.get("result", {})
    if result.get("isError"):
        raise RuntimeError(f"Job tool {name} rejected the call")
    if "structuredContent" in result:
        return result["structuredContent"]
    blocks = result.get("content", [])
    texts = [item.get("text", "") for item in blocks if item.get("type") == "text"]
    text = "\n".join(texts)
    if not text:
        return result
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def find_step(value):
    if isinstance(value, dict):
        for key in ("step", "stepToken", "step_token"):
            if isinstance(value.get(key), str):
                return value[key]
        for child in value.values():
            found = find_step(child)
            if found:
                return found
    elif isinstance(value, list):
        for child in value:
            found = find_step(child)
            if found:
                return found
    return None


def find_entry(value):
    candidates = []

    def walk(item):
        if isinstance(item, dict):
            if isinstance(item.get("id"), str):
                candidates.append(item)
            for child in item.values():
                walk(child)
        elif isinstance(item, list):
            for child in item:
                walk(child)

    walk(value)
    matches = []
    for item in candidates:
        serialized = json.dumps(item, ensure_ascii=False).lower()
        if "tram-3" in serialized:
            matches.append(item)
    if len(matches) == 1:
        return matches[0]
    if not matches and len(candidates) == 1:
        return candidates[0]
    raise RuntimeError(f"Expected one tram-3 incident entry, found {len(matches)}")


def text_value(value):
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("text", "result", "redacted"):
            if isinstance(value.get(key), str):
                return value[key]
    raise RuntimeError("The redact tool did not return text")


def main():
    if not URL:
        raise RuntimeError("JOB_1_MCP_URL secret is missing")

    initialized = rpc(
        "initialize",
        {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "mega-s02e04-github-worker", "version": "1"},
        },
    )
    if "error" in initialized:
        raise RuntimeError("MCP initialization failed")
    rpc("notifications/initialized", notification=True)

    search_result = tool_call("search", {"query": "tram-3", "scope": "ops/live"})
    step = find_step(search_result)
    if not step:
        raise RuntimeError("search did not return its required step token")

    entry = find_entry(search_result)
    read_result = tool_call(
        "read",
        {
            "id": entry["id"],
            "fields": ["date", "time", "clock", "line", "cause"],
            "step": step,
        },
    )
    step = find_step(read_result)
    if not step:
        raise RuntimeError("read did not return its required step token")

    record = read_result
    for container in ("record", "entry", "fields"):
        if isinstance(record, dict) and isinstance(record.get(container), dict):
            record = record[container]
    fields = ["date", "time", "clock", "line", "cause"]
    missing = [field for field in fields if not isinstance(record, dict) or field not in record]
    if missing:
        raise RuntimeError("read omitted required fields: " + ", ".join(missing))
    handin = "\n".join(f"{field}: {record[field]}" for field in fields)

    redact_result = tool_call("redact", {"text": handin, "step": step})
    step = find_step(redact_result)
    if not step:
        raise RuntimeError("redact did not return its required step token")
    redacted = text_value(redact_result)

    submitted = tool_call("submit", {"result": redacted, "skillVersion": "1", "step": step})
    result = submitted.get("result") if isinstance(submitted, dict) else None
    receipt = submitted.get("receipt") if isinstance(submitted, dict) else None
    if not isinstance(result, str) or not isinstance(receipt, str):
        raise RuntimeError("submit did not return both result and receipt")

    emit_private_log({"result": result, "receipt": receipt, "submitted": True})
    print("Job 1 submitted; encrypted result, receipt, and masked trace emitted.", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:  # Fail closed; do not print secrets or raw tool tokens.
        print(f"Worker failed: {error}", file=sys.stderr, flush=True)
        try:
            emit_private_log({"submitted": False, "failure": str(error)})
        except Exception:
            print("Could not emit encrypted worker log.", file=sys.stderr, flush=True)
        sys.exit(1)
