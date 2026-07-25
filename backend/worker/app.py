"""SQS worker that invokes Apple's Find My play-sound operation."""

from __future__ import annotations

import contextlib
import json
import os
import signal
from typing import Any

from find_my import DeviceNotFound, ReauthenticationRequired, ring_device
from session_store import S3SessionStore, SessionStoreError


class WorkerOperationError(RuntimeError):
    """A sanitized retryable failure safe to emit to Lambda logs."""


class WorkerOperationDeadline(RuntimeError):
    """The Apple operation exceeded its application-level deadline."""


def _failure_category(exc: Exception) -> str:
    if isinstance(exc, ReauthenticationRequired):
        return "reauthentication_required"
    if isinstance(exc, DeviceNotFound):
        return "device_unavailable"
    if isinstance(exc, SessionStoreError):
        return "session_unavailable"
    if isinstance(exc, WorkerOperationDeadline):
        return "operation_deadline"
    return "operation_failed"


@contextlib.contextmanager
def _operation_deadline(
    context: Any,
    *,
    max_seconds: float,
    reserve_ms: int,
):
    """Bound one phase while reserving Lambda time for cleanup."""
    remaining_ms = 45_000
    get_remaining = getattr(context, "get_remaining_time_in_millis", None)
    if callable(get_remaining):
        remaining_ms = get_remaining()
    available_seconds = (remaining_ms - reserve_ms) / 1_000
    if available_seconds <= 0:
        raise WorkerOperationDeadline("Not enough Lambda time remains")
    seconds = min(max_seconds, available_seconds)

    def deadline_reached(_signum, _frame):
        raise WorkerOperationDeadline("The Find My operation timed out")

    previous_handler = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, deadline_reached)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
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
        # Bound download and every Apple request before the external side
        # effect, while reserving seven seconds for persistence and cleanup.
        with _operation_deadline(context, max_seconds=35.0, reserve_ms=7_000):
            session_directory = store.download()
            ring_device(
                apple_id=os.environ["APPLE_ID"],
                target_name=os.environ["DEVICE_NAME"],
                session_directory=session_directory,
            )

        # Persist refreshed cookies after a successful operation. Failure here
        # is logged but must not cause SQS to retry and ring the phone twice.
        try:
            with _operation_deadline(context, max_seconds=3.0, reserve_ms=3_000):
                store.upload()
        except Exception:  # noqa: BLE001
            print("Find My worker warning: session_refresh_failed")
    except Exception as exc:  # noqa: BLE001
        category = _failure_category(exc)
        print(f"Find My worker failed: {category}")
        raise WorkerOperationError(f"Find My worker failed: {category}") from None
    finally:
        store.cleanup()

    print("Find My sound request completed")
    return {"processed": 1}
