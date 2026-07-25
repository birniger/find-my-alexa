"""Ring exactly one allowlisted Apple device using a persisted iCloud session."""

from __future__ import annotations

import json
import re
from pathlib import Path


class ReauthenticationRequired(RuntimeError):
    """The saved iCloud session is absent, expired, or no longer trusted."""


class DeviceNotFound(RuntimeError):
    """The configured device was not returned by Find My."""


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


def ring_device(apple_id: str, target_name: str, session_directory: Path) -> None:
    """Validate the cached session and ring the exact configured device.

    Authentication is intentionally disabled. If the cached token has expired,
    the worker fails instead of attempting a login with a password stored in AWS.
    """
    from pyicloud import PyiCloudService

    api = PyiCloudService(
        apple_id,
        password=None,
        cookie_directory=str(session_directory),
        with_family=False,
        authenticate=False,
    )
    auth_status = api.get_auth_status()
    if not auth_status.get("authenticated") or auth_status.get("requires_2fa"):
        raise ReauthenticationRequired(
            "The iCloud session expired; rerun scripts/authenticate.py"
        )

    target_id = _configured_device_id(session_directory)
    if target_id:
        matches = [
            device
            for device in api.devices
            if str(device.data.get("id") or "") == target_id
        ]
    else:
        # Backward-compatible fallback for sessions created before target.json.
        wanted = _normalise_name(target_name)
        matches = []
        for device in api.devices:
            name = str(device.status().get("name") or "")
            if _normalise_name(name) == wanted:
                matches.append(device)

    if len(matches) != 1:
        raise DeviceNotFound(
            "The configured Find My device was not returned exactly once"
        )

    matches[0].play_sound(subject="Find My alert requested through Alexa")
