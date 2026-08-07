"""Alexa custom-skill endpoint.

The endpoint deliberately does very little: it validates the caller, queues a
ring request, and answers Alexa well within the eight-second response window.
Apple/iCloud work happens in the worker Lambda.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any


RING_INTENTS = {"RingPhoneIntent"}
STOP_INTENTS = {"AMAZON.CancelIntent", "AMAZON.StopIntent"}


class RingRequestNotQueued(RuntimeError):
    """The linked-user ring request could not be safely queued."""


def _application_id(event: dict[str, Any]) -> str:
    session_id = (
        event.get("session", {}).get("application", {}).get("applicationId", "")
    )
    context_id = (
        event.get("context", {})
        .get("System", {})
        .get("application", {})
        .get("applicationId", "")
    )
    return session_id or context_id


def _response(text: str, *, end_session: bool = True) -> dict[str, Any]:
    return {
        "version": "1.0",
        "response": {
            "outputSpeech": {"type": "PlainText", "text": text},
            "shouldEndSession": end_session,
        },
    }


def _linked_access_token(event: dict[str, Any]) -> str:
    return str(
        event.get("context", {})
        .get("System", {})
        .get("user", {})
        .get("accessToken", "")
    )


def _requested_device_name(event: dict[str, Any]) -> str:
    slot = (
        event.get("request", {})
        .get("intent", {})
        .get("slots", {})
        .get("deviceName", {})
    )
    resolutions = (
        slot.get("resolutions", {})
        .get("resolutionsPerAuthority", [])
    )
    for authority in resolutions:
        values = authority.get("values", [])
        if values:
            resolved = values[0].get("value", {}).get("name")
            if resolved:
                return str(resolved).strip()
    return str(slot.get("value") or "").strip()


def _queue_cloudflare_ring_request(event: dict[str, Any]) -> str | None:
    api_base_url = os.environ.get("FIND_MY_API_BASE_URL", "").rstrip("/")
    if not api_base_url:
        return False
    access_token = _linked_access_token(event)
    if not access_token:
        raise RingRequestNotQueued(
            "Please link your Alexa account to Device Finder before ringing your Apple device."
        )

    device_name = _requested_device_name(event)
    body = json.dumps(
        {"source": "alexa", **({"deviceName": device_name} if device_name else {})},
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{api_base_url}/api/ring/request",
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=4) as response:
            if 200 <= response.status < 300:
                try:
                    payload = json.loads(response.read().decode("utf-8"))
                except (AttributeError, TypeError, ValueError):
                    payload = {}
                return str(payload.get("deviceLabel") or device_name or "your Apple device")
    except urllib.error.HTTPError as exc:
        if exc.code in {401, 403}:
            raise RingRequestNotQueued(
                "Please link your Alexa account to Device Finder again."
            ) from None
        if exc.code == 409:
            raise RingRequestNotQueued(
                "Your Apple setup needs renewal. Open Device Finder to update the Apple login."
            ) from None
        if exc.code == 404:
            raise RingRequestNotQueued(
                f"I couldn't find {device_name or 'that device'}. Check its Alexa name in Device Finder."
            ) from None
        raise RingRequestNotQueued(
            "I couldn't queue the ring. Open Device Finder to check your setup."
        ) from None
    except (OSError, urllib.error.URLError):
        raise RingRequestNotQueued(
            "I couldn't reach Device Finder. Open the app to check your setup."
        ) from None
    raise RingRequestNotQueued(
        "I couldn't queue the ring. Open Device Finder to check your setup."
    )


def _queue_ring_request(event: dict[str, Any]) -> str:
    cloudflare_device = _queue_cloudflare_ring_request(event)
    if cloudflare_device:
        return cloudflare_device

    queue_url = os.environ["RING_QUEUE_URL"]
    request = event.get("request", {})
    body = json.dumps(
        {
            "action": "ring",
            "requestId": request.get("requestId", "unknown"),
        },
        separators=(",", ":"),
    )

    # boto3 is provided by the AWS Lambda runtime.
    import boto3

    boto3.client("sqs").send_message(
        QueueUrl=queue_url,
        MessageBody=body,
        MessageGroupId="find-my-alexa",
    )
    return os.environ.get("PHONE_SPOKEN_NAME", "your Apple device")


def _ring_response(event: dict[str, Any]) -> dict[str, Any]:
    try:
        phone_name = _queue_ring_request(event)
    except RingRequestNotQueued as exc:
        return _response(str(exc))
    return _response(f"Okay, ringing {phone_name}.")


def lambda_handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    """Handle LaunchRequest and RingPhoneIntent requests."""
    expected_skill_id = os.environ.get("EXPECTED_SKILL_ID", "")
    if not expected_skill_id or _application_id(event) != expected_skill_id:
        raise PermissionError("Request did not come from the configured Alexa skill")

    request = event.get("request", {})
    request_type = request.get("type", "")

    if request_type == "SessionEndedRequest":
        return {"version": "1.0", "response": {}}

    if request_type == "LaunchRequest":
        return _ring_response(event)

    if request_type == "IntentRequest":
        intent_name = request.get("intent", {}).get("name", "")
        if intent_name in RING_INTENTS:
            return _ring_response(event)
        if intent_name in STOP_INTENTS:
            return _response("Okay.")
        if intent_name == "AMAZON.HelpIntent":
            return _response(
                "Say ring my phone, or say ring followed by a device's Alexa name.",
                end_session=False,
            )

    return _response("I didn't understand that. Say ring the phone.", end_session=False)
