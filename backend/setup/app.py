"""Interactive Apple setup worker for the private friends beta."""

from __future__ import annotations

import io
import hashlib
import json
import os
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any


SESSION_BUNDLE_NAME = "session-bundle.zip"
POLL_SECONDS = 2.0
SETUP_TIMEOUT_SECONDS = 9 * 60


class SetupFailed(RuntimeError):
    """A sanitized setup failure safe for Lambda logs."""


def _runner_token() -> str:
    token = os.environ.get("RUNNER_API_TOKEN", "").strip()
    if not token:
        raise SetupFailed("The runner callback credential is not configured")
    return token


def _runner_headers() -> dict[str, str]:
    token = _runner_token()
    return {
        "Authorization": f"Bearer {token}",
        "X-Runner-Token": token,
        "User-Agent": "DeviceFinderRunner/1.0",
    }


def _post_event(message: dict[str, Any], status: str, detail: str = "", **extra: Any) -> None:
    callback = str(message["callbackBaseUrl"]).rstrip("/") + "/api/runner/events"
    body = json.dumps(
        {
            "setupId": message["setupId"],
            "accountId": message["accountId"],
            "deviceId": message["deviceId"],
            "setupStatus": status,
            "message": detail,
            **extra,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        callback,
        data=body,
        method="POST",
        headers={**_runner_headers(), "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=5):
        pass


def _poll_setup(message: dict[str, Any]) -> dict[str, Any]:
    url = str(message["callbackBaseUrl"]).rstrip("/") + f"/api/runner/setup/{message['setupId']}"
    request = urllib.request.Request(
        url,
        headers=_runner_headers(),
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def _wait_for(message: dict[str, Any], key: str, predicate) -> Any:
    deadline = time.monotonic() + SETUP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        state = _poll_setup(message)
        if state.get("status") in ("failed", "expired"):
            raise SetupFailed("The setup session was cancelled or expired")
        value = state.get(key)
        if predicate(value):
            return value
        time.sleep(POLL_SECONDS)
    raise SetupFailed("The setup session expired while waiting for user input")


def _stop_device_monitor(manager: Any) -> None:
    stop_event = getattr(manager, "stop_event", None)
    monitor = getattr(manager, "_monitor", None)
    if stop_event is not None:
        stop_event.set()
    if monitor is not None:
        monitor.join(timeout=1.0)
        if monitor.is_alive():
            raise SetupFailed("The Find My background monitor did not stop")


def _safe_device_summary(device: Any) -> dict[str, str]:
    status = device.status()
    model = str(status.get("deviceDisplayName") or "Apple device")
    battery = status.get("batteryLevel")
    summary = model
    if isinstance(battery, (int, float)) and 0 <= battery <= 1:
        summary = f"{model}, battery {round(battery * 100)}%"
    return {
        "name": str(status.get("name") or model),
        "summary": summary,
    }


def _create_session_bundle(paths: list[Path]) -> io.BytesIO:
    bundle = io.BytesIO()
    with zipfile.ZipFile(bundle, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in paths:
            if not path.is_file():
                raise SetupFailed("pyicloud did not create a complete session")
            archive.write(path, arcname=path.name)
    bundle.seek(0)
    return bundle


def _upload_session(
    message: dict[str, Any],
    directory: str,
    api: Any,
    apple_device_id: str,
    session_bucket: str,
    session_prefix: str,
) -> None:
    target_path = Path(directory) / "target.json"
    target_path.write_text(
        json.dumps({"version": 1, "device_id": apple_device_id}, separators=(",", ":")),
        encoding="utf-8",
    )
    session_files = [
        Path(api.session.session_path),
        Path(api.session.cookiejar_path),
        target_path,
    ]

    import boto3

    boto3.client("s3").upload_fileobj(
        _create_session_bundle(session_files),
        session_bucket,
        f"{session_prefix.rstrip('/')}/{SESSION_BUNDLE_NAME}",
        ExtraArgs={"ServerSideEncryption": "AES256"},
    )


def _request_2fa(api: Any, preferred_method: str) -> tuple[bool, str]:
    from pyicloud.exceptions import (
        PyiCloudNoTrustedNumberAvailable,
        PyiCloudTrustedDevicePromptException,
    )

    if preferred_method == "sms":
        request_sms = getattr(api, "_request_sms_2fa_code", None)
        if request_sms is not None:
            try:
                if request_sms():
                    return True, "sms"
            except PyiCloudNoTrustedNumberAvailable:
                pass
            except Exception:  # noqa: BLE001
                print("Find My setup warning: sms_delivery_unavailable")

    try:
        requested = bool(api.request_2fa_code())
        method = str(getattr(api, "two_factor_delivery_method", "trusted_device"))
        return requested, method
    except PyiCloudTrustedDevicePromptException:
        set_delivery_state = getattr(api, "_set_two_factor_delivery_state", None)
        if set_delivery_state is None:
            raise
        set_delivery_state(
            "trusted_device",
            "The trusted-device bridge timed out; enter the code Apple already displayed.",
        )
        return True, "trusted_device"


MAX_BUNDLE_FILE_SIZE = 5 * 1024 * 1024


def _extract_session_bundle(bundle_path: Path, directory: Path) -> None:
    """Unpack a stored session bundle, rejecting anything but the three expected files."""
    try:
        with zipfile.ZipFile(bundle_path) as archive:
            members = archive.infolist()
            names = [member.filename for member in members]
            if (
                len(members) != 3
                or any(Path(name).name != name for name in names)
                or len([name for name in names if name.endswith(".session")]) != 1
                or len([name for name in names if name.endswith(".cookiejar")]) != 1
                or names.count("target.json") != 1
                or any(member.file_size > MAX_BUNDLE_FILE_SIZE for member in members)
            ):
                raise SetupFailed("The saved Apple session is unusable")
            for member in members:
                destination = directory / member.filename
                destination.write_bytes(archive.read(member))
                destination.chmod(0o600)
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as exc:
        raise SetupFailed("The saved Apple session is unusable") from exc


def _open_saved_session(message: dict[str, Any], directory: str) -> Any:
    """Reuse a stored Find My session so adding devices needs no Apple sign-in."""
    bucket = str(message.get("reuseSessionBucket") or "")
    prefix = str(message.get("reuseSessionPrefix") or "").rstrip("/")
    if not bucket or not prefix:
        raise SetupFailed("No saved Apple session is available")

    import boto3

    bundle_path = Path(directory) / SESSION_BUNDLE_NAME
    try:
        boto3.client("s3").download_file(bucket, f"{prefix}/{SESSION_BUNDLE_NAME}", str(bundle_path))
    except Exception as exc:  # noqa: BLE001
        print(f"Find My setup warning: saved_session_unavailable:{type(exc).__name__}")
        raise SetupFailed(
            "The saved Apple session could not be opened. Choose Set up devices to sign in to Apple again."
        ) from None
    _extract_session_bundle(bundle_path, Path(directory))
    bundle_path.unlink(missing_ok=True)

    from pyicloud import PyiCloudService

    api = PyiCloudService(
        message["appleId"],
        password=None,
        cookie_directory=directory,
        with_family=False,
        authenticate=False,
    )
    auth_status = api.get_auth_status()
    if not auth_status.get("authenticated") or auth_status.get("requires_2fa"):
        raise SetupFailed(
            "The saved Apple session expired. Choose Set up devices to sign in to Apple again."
        )
    return api


def _create_api(message: dict[str, Any], directory: str, password: str) -> Any:
    from pyicloud import PyiCloudService

    api = PyiCloudService(
        message["appleId"],
        password,
        cookie_directory=directory,
        with_family=False,
        authenticate=False,
    )
    api.authenticate()
    return api


def _candidate_id(device: Any) -> str:
    apple_device_id = str(device.data.get("id") or "")
    if not apple_device_id:
        raise SetupFailed("Apple did not return a device ID")
    return hashlib.sha256(apple_device_id.encode("utf-8")).hexdigest()[:32]


def _public_failure_message(exc: Exception) -> str:
    if isinstance(exc, SetupFailed):
        return str(exc)
    if type(exc).__name__ == "PyiCloudFailedLoginException":
        return "Apple did not accept this sign-in. Check the Apple email and password, then try again in a few minutes."
    return "Apple setup could not connect. Please try again in a few minutes."


def _run_setup(message: dict[str, Any]) -> None:
    with tempfile.TemporaryDirectory(prefix="find-my-friends-setup-") as directory:
        reusing_session = message.get("mode") == "reuse_session"
        if reusing_session:
            _post_event(message, "awaiting_credentials", "Opening your saved Apple session...")
            api = _open_saved_session(message, directory)
        else:
            _post_event(message, "awaiting_credentials", "Signing in to Apple...")
            password = message.pop("password", "")
            if not password:
                raise SetupFailed("The Apple password was not provided")
            api = _create_api(message, directory, password)
            del password
        if not reusing_session and api.requires_2fa:
            requested, delivery_method = _request_2fa(
                api, str(message.get("verificationMethod") or "trusted_device")
            )
            if not requested:
                raise SetupFailed("Apple did not offer a code-based verification challenge")
            delivery_message = (
                "Apple sent a text message. Ignore any code shown by an automatic device prompt and use the SMS code."
                if delivery_method == "sms"
                else "Approve the sign-in notification and use the code shown on that Apple device."
            )
            _post_event(
                message,
                "awaiting_2fa",
                delivery_message,
                verificationMethod=delivery_method,
            )
            code = _wait_for(message, "verification_code", lambda value: isinstance(value, str) and bool(value.strip()))
            if not api.validate_2fa_code(str(code)):
                if delivery_method == "sms":
                    raise SetupFailed(
                        "Apple rejected that SMS code. If you approved a device prompt, it may have replaced the SMS challenge. Start again and use one method only."
                    )
                raise SetupFailed("Apple rejected that device code. Start again and use the newest code shown after tapping Allow.")

        manager = api.devices
        try:
            devices = list(manager)
            candidates = []
            devices_by_candidate: dict[str, Any] = {}
            for device in devices:
                summary = _safe_device_summary(device)
                candidate_id = _candidate_id(device)
                devices_by_candidate[candidate_id] = device
                candidates.append({"id": candidate_id, **summary})
            if not candidates:
                raise SetupFailed("Apple returned no Find My devices")
            _post_event(message, "select_device", "Choose one or more Apple devices to test.", devices=candidates)
            selected_devices = _wait_for(
                message,
                "selected_devices_json",
                lambda value: isinstance(value, str) and value not in ("", "[]"),
            )
            selections = json.loads(selected_devices)
            if not isinstance(selections, list) or not selections:
                raise SetupFailed("No Apple device was selected")
            selected_pairs: list[tuple[dict[str, Any], Any]] = []
            for selection in selections:
                if not isinstance(selection, dict):
                    continue
                device = devices_by_candidate.get(str(selection.get("candidateId") or ""))
                if device is not None:
                    selected_pairs.append((selection, device))
            if not selected_pairs:
                raise SetupFailed("The selected Apple devices are no longer available")

            for _, device in selected_pairs:
                device.play_sound(subject="Device Finder setup test")
            count = len(selected_pairs)
            _post_event(
                message,
                "test_ring_sent",
                f"Confirm that {'the selected Apple device played a sound' if count == 1 else f'all {count} selected Apple devices played a sound'}.",
            )
            _wait_for(message, "confirmed_test_ring", lambda value: value in (1, True))
            completed_device_ids = []
            for selection, device in selected_pairs:
                apple_device_id = str(device.data.get("id") or "")
                _upload_session(
                    message,
                    directory,
                    api,
                    apple_device_id,
                    str(selection.get("sessionBucket") or message["sessionBucket"]),
                    str(selection.get("sessionPrefix") or message["sessionPrefix"]),
                )
                completed_device_ids.append(str(selection.get("deviceId") or ""))
        finally:
            if "manager" in locals():
                _stop_device_monitor(manager)

    _post_event(
        message,
        "completed",
        "Find My setup completed.",
        deviceIds=[device_id for device_id in completed_device_ids if device_id],
    )


def lambda_handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    records = event.get("Records", [])
    if len(records) != 1:
        raise ValueError("Expected exactly one SQS record")
    message = json.loads(records[0]["body"])
    records[0]["body"] = ""
    if message.get("action") != "setup":
        raise ValueError("Unsupported action")
    try:
        _run_setup(message)
    except Exception as exc:  # noqa: BLE001
        failure_kind = f"http_{exc.code}" if isinstance(exc, urllib.error.HTTPError) else type(exc).__name__
        try:
            _post_event(message, "failed", _public_failure_message(exc))
        except (OSError, urllib.error.URLError, KeyError):
            print("Find My setup warning: callback_failed")
            raise SetupFailed("Find My setup failed before its callback completed") from None
        print(f"Find My setup failed: {failure_kind}")
        return {"processed": 1, "status": "failed"}
    return {"processed": 1}
