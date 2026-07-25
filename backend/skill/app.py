"""Alexa custom-skill endpoint.

The endpoint deliberately does very little: it validates the caller, queues a
ring request, and answers Alexa well within the eight-second response window.
Apple/iCloud work happens in the worker Lambda.
"""

from __future__ import annotations

import json
import os
from typing import Any


RING_INTENTS = {"RingPhoneIntent"}
STOP_INTENTS = {"AMAZON.CancelIntent", "AMAZON.StopIntent"}


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


def _queue_ring_request(event: dict[str, Any]) -> None:
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
        _queue_ring_request(event)
        phone_name = os.environ.get("PHONE_SPOKEN_NAME", "your phone")
        return _response(f"Okay, ringing {phone_name}.")

    if request_type == "IntentRequest":
        intent_name = request.get("intent", {}).get("name", "")
        if intent_name in RING_INTENTS:
            _queue_ring_request(event)
            phone_name = os.environ.get("PHONE_SPOKEN_NAME", "your phone")
            return _response(f"Okay, ringing {phone_name}.")
        if intent_name in STOP_INTENTS:
            return _response("Okay.")
        if intent_name == "AMAZON.HelpIntent":
            return _response(
                "Say ring the phone, or use your where is Basil's phone routine.",
                end_session=False,
            )

    return _response("I didn't understand that. Say ring the phone.", end_session=False)
