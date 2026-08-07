"""Ring exactly one allowlisted Apple device using a persisted iCloud session."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any


HTTP_TIMEOUT = (5.0, 12.0)


class ReauthenticationRequired(RuntimeError):
    """The saved iCloud session is absent, expired, or no longer trusted."""


class DeviceNotFound(RuntimeError):
    """The configured device was not returned by Find My."""


class MonitorShutdownError(RuntimeError):
    """The pyicloud background monitor did not stop safely."""


def _install_http_timeout(api: Any) -> None:
    """Apply a bounded default to every request made by this pyicloud session."""
    original_request = api.session.request

    def request_with_timeout(method, url, **kwargs):
        if kwargs.get("timeout") is None:
            kwargs["timeout"] = HTTP_TIMEOUT
        return original_request(method, url, **kwargs)

    api.session.request = request_with_timeout


def _stop_device_monitor(manager: Any) -> None:
    """Stop pyicloud 2.6.5's private daemon monitor before returning to Lambda."""
    stop_event = getattr(manager, "stop_event", None)
    monitor = getattr(manager, "_monitor", None)
    if stop_event is None and monitor is None:
        return
    if stop_event is not None:
        stop_event.set()
    if monitor is not None:
        monitor.join(timeout=1.0)
        if monitor.is_alive():
            raise MonitorShutdownError("The Find My background monitor did not stop")


def _normalise_name(value: str) -> str:
    value = value.replace("’", "'").replace("‘", "'").replace("ʼ", "'")
    return re.sub(r"\s+", " ", value).strip().casefold()


def _configured_device_id(session_directory: Path) -> str | None:
    path = session_directory / "target.json"
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        raise DeviceNotFound("The encrypted device selection is invalid") from exc
    device_id = payload.get("device_id")
    if not isinstance(device_id, str) or not device_id:
        raise DeviceNotFound("The encrypted device selection has no device ID")
    return device_id


def _matching_devices(devices: list[Any], target_name: str, session_directory: Path) -> list[Any]:
    target_id = _configured_device_id(session_directory)
    if target_id:
        return [
            device
            for device in devices
            if str(device.data.get("id") or "") == target_id
        ]

    # Backward-compatible fallback for sessions created before target.json.
    wanted = _normalise_name(target_name)
    matches = []
    for device in devices:
        name = str(device.status().get("name") or "")
        if _normalise_name(name) == wanted:
            matches.append(device)
    return matches


def check_device(apple_id: str, target_name: str, session_directory: Path) -> None:
    """Validate that the cached session can still see the configured device."""
    logging.getLogger("pyicloud").setLevel(logging.CRITICAL)

    from pyicloud import PyiCloudService

    api = PyiCloudService(
        apple_id,
        password=None,
        cookie_directory=str(session_directory),
        with_family=False,
        authenticate=False,
    )
    _install_http_timeout(api)
    auth_status = api.get_auth_status()
    if not auth_status.get("authenticated") or auth_status.get("requires_2fa"):
        raise ReauthenticationRequired(
            "The iCloud session expired; renew the Apple setup"
        )

    manager = api.devices
    try:
        devices = list(manager)
        if len(_matching_devices(devices, target_name, session_directory)) != 1:
            raise DeviceNotFound(
                "The configured Find My device was not returned exactly once"
            )
    finally:
        _stop_device_monitor(manager)


def ring_device(apple_id: str, target_name: str, session_directory: Path) -> None:
    """Validate the cached session and ring the exact configured device.

    Authentication is intentionally disabled. If the cached token has expired,
    the worker fails instead of attempting a login with a password stored in AWS.
    """
    # Third-party diagnostics can contain account or HTTP response details.
    logging.getLogger("pyicloud").setLevel(logging.CRITICAL)

    from pyicloud import PyiCloudService

    api = PyiCloudService(
        apple_id,
        password=None,
        cookie_directory=str(session_directory),
        with_family=False,
        authenticate=False,
    )
    _install_http_timeout(api)
    auth_status = api.get_auth_status()
    if not auth_status.get("authenticated") or auth_status.get("requires_2fa"):
        raise ReauthenticationRequired(
            "The iCloud session expired; rerun scripts/authenticate.py"
        )

    manager = api.devices
    try:
        devices = list(manager)
        matches = _matching_devices(devices, target_name, session_directory)

        if len(matches) != 1:
            raise DeviceNotFound(
                "The configured Find My device was not returned exactly once"
            )

        matches[0].play_sound(subject="Find My alert requested through Alexa")
    finally:
        # Device properties can restart pyicloud's daemon monitor, so stop and
        # join it only after every Find My operation has finished.
        _stop_device_monitor(manager)
