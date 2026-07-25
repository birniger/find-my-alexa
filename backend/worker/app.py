"""SQS worker that invokes Apple's Find My play-sound operation."""

from __future__ import annotations

import json
import os
from typing import Any

from find_my import ring_device
from session_store import S3SessionStore


def lambda_handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    records = event.get("Records", [])
    if len(records) != 1:
        raise ValueError("Expected exactly one SQS record")

    message = json.loads(records[0]["body"])
    if message.get("action") != "ring":
        raise ValueError("Unsupported action")

    store = S3SessionStore(
        bucket=os.environ["SESSION_BUCKET"],
        prefix=os.environ.get("SESSION_PREFIX", "session/"),
    )
    try:
        session_directory = store.download()

        ring_device(
            apple_id=os.environ["APPLE_ID"],
            target_name=os.environ["DEVICE_NAME"],
            session_directory=session_directory,
        )

        # Persist refreshed cookies after a successful operation. Failure here
        # is logged but must not cause SQS to retry and ring the phone twice.
        try:
            store.upload()
        except Exception as exc:  # noqa: BLE001
            print(f"Session refresh upload failed: {type(exc).__name__}")
    finally:
        store.cleanup()

    print("Find My sound request completed")
    return {"processed": 1}
