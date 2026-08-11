"""SQS worker that invokes Apple's Find My play-sound operation."""

from __future__ import annotations

import contextlib
import json
import os
import re
import signal
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from find_my import DeviceNotFound, ReauthenticationRequired, check_device, ring_device
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


def _message_value(
    message: dict[str, Any],
    key: str,
    *,
    env_key: str | None = None,
    default: str = "",
    max_length: int = 500,
) -> str:
    value = message.get(key)
    if value is None and env_key:
        value = os.environ.get(env_key)
    if value is None:
        value = default
    if not isinstance(value, str):
        raise ValueError(f"Invalid {key}")
    value = value.strip()
    if not value or len(value) > max_length:
        raise ValueError(f"Invalid {key}")
    return value


def _safe_local_directory(message: dict[str, Any]) -> Path:
    raw = str(message.get("jobId") or message.get("requestId") or "request")
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", raw).strip(".-")[:80] or "request"
    return Path(f"/tmp/find-my-alexa-session-{slug}")


SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")


def _password_parameter_name(message: dict[str, Any]) -> str | None:
    """Derive the parameter path rather than trusting one from the message."""
    if not message.get("storedApplePassword"):
        return None
    account_id = str(message.get("accountId") or "")
    if not SAFE_IDENTIFIER.match(account_id):
        return None
    # One Apple sign-in covers every device it selected, so the setup worker
    # holds a single credential per account.
    return f"/find-my/{account_id}/apple-password"


def _stored_password(message: dict[str, Any]) -> str | None:
    """Read the Apple password of an account that opted into unattended renewal.

    Only called after a session has already failed, so accounts that never
    opted in cause no lookup and the password stays out of memory on the
    overwhelming majority of invocations.
    """
    name = _password_parameter_name(message)
    if not name:
        return None

    # boto3 is provided by the AWS Lambda runtime.
    import boto3

    try:
        response = boto3.client("ssm").get_parameter(Name=name, WithDecryption=True)
    except Exception:  # noqa: BLE001
        print("Find My worker warning: stored_password_unavailable")
        return None
    value = response.get("Parameter", {}).get("Value")
    return value if isinstance(value, str) and value else None


def _run_operation(
    action: str,
    apple_id: str,
    device_name: str,
    session_directory: Path,
    password: str | None = None,
) -> None:
    operation = check_device if action == "health_check" else ring_device
    operation(
        apple_id=apple_id,
        target_name=device_name,
        session_directory=session_directory,
        password=password,
    )


def _post_runner_event(message: dict[str, Any], status: str, detail: str = "") -> None:
    callback_url = message.get("callbackUrl")
    token = os.environ.get("RUNNER_API_TOKEN", "").strip()
    if not isinstance(callback_url, str) or not callback_url or not token:
        return

    payload = {
        "jobId": message.get("jobId", ""),
        "accountId": message.get("accountId", ""),
        "deviceId": message.get("deviceId", ""),
        "status": status,
        "message": detail,
    }
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        callback_url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Runner-Token": token,
            "User-Agent": "DeviceFinderRunner/1.0",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=3):
            pass
    except (OSError, urllib.error.URLError):
        print("Find My worker warning: callback_failed")


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
    action = message.get("action")
    if action not in {"ring", "health_check"}:
        raise ValueError("Unsupported action")

    store = S3SessionStore(
        bucket=_message_value(message, "sessionBucket", env_key="SESSION_BUCKET"),
        prefix=_message_value(
            message,
            "sessionPrefix",
            env_key="SESSION_PREFIX",
            default="session/",
        ),
        local_directory=_safe_local_directory(message),
    )
    try:
        # Bound download and every Apple request before the external side
        # effect, while reserving seven seconds for persistence and cleanup.
        with _operation_deadline(context, max_seconds=35.0, reserve_ms=7_000):
            session_directory = store.download()
            apple_id = _message_value(message, "appleId", env_key="APPLE_ID")
            device_name = _message_value(message, "deviceName", env_key="DEVICE_NAME")
            try:
                _run_operation(action, apple_id, device_name, session_directory)
            except ReauthenticationRequired:
                # Accounts that opted in get one unattended retry: pyicloud
                # sends the stored password with the trust token Apple issued
                # at setup, so no verification code is needed until that token
                # expires too.
                password = _stored_password(message)
                if not password:
                    raise
                print("Find My worker: retrying with the stored Apple password")
                _run_operation(
                    action, apple_id, device_name, session_directory, password
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
        # The exception class name is safe to log and is the only clue to what
        # the catch-all category actually was. Class names never contain Apple
        # IDs, device IDs, cookies, passwords, or locations, and the setup
        # worker already logs failures this way.
        print(f"Find My worker failed: {category} ({type(exc).__name__})")
        _post_runner_event(message, category, category)
        if action == "health_check" and category == "reauthentication_required":
            return {"processed": 1}
        raise WorkerOperationError(f"Find My worker failed: {category}") from None
    finally:
        store.cleanup()

    print("Find My sound request completed")
    _post_runner_event(message, "healthy" if action == "health_check" else "succeeded")
    return {"processed": 1}
