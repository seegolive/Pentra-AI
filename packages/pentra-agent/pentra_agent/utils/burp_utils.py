"""Burp MCP encoding / decoding utilities for agent nodes.

These helpers leverage Burp Suite's built-in encoding tools via BurpMCPClient
rather than Python's standard library, ensuring byte-exact consistency with
what Burp's Decoder, Intruder, and Repeater would produce.

Usage::

    from pentra_agent.utils.burp_utils import encode_payload_for_injection, \
        decode_interesting_value, generate_unique_marker

    async def test_waf_bypass(burp, payload):
        for enc in ("url", "double_url", "base64"):
            encoded = await encode_payload_for_injection(burp, payload, enc)
            # ... send and check response ...
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)


async def encode_payload_for_injection(
    burp: "BurpMCPClient",
    payload: str,
    encoding: str,
) -> str:
    """Encode *payload* using Burp's encoding tools.

    Args:
        burp:     An active BurpMCPClient instance.
        payload:  The raw payload string to encode.
        encoding: One of ``"url"``, ``"base64"``, ``"double_url"``.
                  Falls back to returning *payload* unchanged for unknown encodings.

    Returns:
        The encoded payload string.

    Use for WAF-bypass variant generation::

        variants = [
            await encode_payload_for_injection(burp, "' OR 1=1--", enc)
            for enc in ("url", "double_url", "base64")
        ]
    """
    if encoding == "url":
        return await burp.url_encode(payload)
    elif encoding == "base64":
        return await burp.base64_encode(payload)
    elif encoding == "double_url":
        single_encoded = await burp.url_encode(payload)
        return await burp.url_encode(single_encoded)
    elif encoding == "url_decode":
        return await burp.url_decode(payload)
    elif encoding == "base64_decode":
        return await burp.base64_decode(payload)
    else:
        log.debug("[burp_utils] Unknown encoding %r — returning payload unchanged", encoding)
        return payload


async def decode_interesting_value(
    burp: "BurpMCPClient",
    value: str,
) -> dict:
    """Auto-detect and decode a potentially-encoded value.

    Tries Base64 decode and URL decode in sequence.  Results where the
    decoded form differs from the input are returned in the dict.

    Useful for analysing cookies, JWT tokens, API keys, and opaque parameters
    found in proxy history.

    Args:
        burp:  An active BurpMCPClient instance.
        value: The value to decode (e.g. a cookie value or query-param value).

    Returns:
        Dict with keys: ``original``, and optionally ``base64_decoded``,
        ``url_decoded``.

    Example::

        result = await decode_interesting_value(burp, "aGVsbG8gd29ybGQ=")
        # → {"original": "aGVsbG8gd29ybGQ=", "base64_decoded": "hello world"}
    """
    results: dict = {"original": value}

    # Try base64 decode
    try:
        decoded = await burp.base64_decode(value)
        if decoded and decoded != value and len(decoded) > 0:
            results["base64_decoded"] = decoded
    except Exception:
        pass

    # Try URL decode
    try:
        url_decoded = await burp.url_decode(value)
        if url_decoded and url_decoded != value:
            results["url_decoded"] = url_decoded
    except Exception:
        pass

    return results


async def generate_unique_marker(burp: "BurpMCPClient") -> str:
    """Generate a unique random marker string for injection testing.

    The marker is used to identify reflected / stored responses and
    to tie Burp Collaborator interactions back to specific test payloads.

    Returns a string of the form ``"PENTRA<12-char-random>MARKER"``.

    Example::

        marker = await generate_unique_marker(burp)
        payload = f"<img src='https://{collab_host}/{marker}' />"
    """
    random_str = await burp.generate_random_string(12)
    return f"PENTRA{random_str}MARKER"
