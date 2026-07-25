#!/usr/bin/env python3
"""Create a trusted pyicloud session locally and upload only its session files."""

from __future__ import annotations

import argparse
import getpass
import json
import re
import tempfile
from pathlib import Path


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apple-id", required=True)
    parser.add_argument("--bucket", help="SessionBucketName stack output")
    parser.add_argument("--stack-name", help="Resolve the bucket from this stack")
    parser.add_argument("--region", default="eu-west-1")
    parser.add_argument(
        "--device-name",
        required=True,
        help="Select a Find My device with this name before upload",
    )
    parser.add_argument(
        "--test-ring",
        action="store_true",
        help="Ring --device-name once after authentication",
    )
    return parser.parse_args()


def _resolve_bucket(args: argparse.Namespace, boto3_module) -> str:
    if args.bucket:
        return args.bucket
    if not args.stack_name:
        raise SystemExit("Pass either --bucket or --stack-name")

    response = boto3_module.client(
        "cloudformation", region_name=args.region
    ).describe_stacks(StackName=args.stack_name)
    outputs = response["Stacks"][0].get("Outputs", [])
    for output in outputs:
        if output["OutputKey"] == "SessionBucketName":
            return output["OutputValue"]
    raise SystemExit("The stack has no SessionBucketName output")


def _normalise_name(value: str) -> str:
    value = value.replace("’", "'").replace("‘", "'").replace("ʼ", "'")
    return re.sub(r"\s+", " ", value).strip().casefold()


def _safe_device_summary(device) -> str:
    status = device.status()
    model = str(status.get("deviceDisplayName") or "iPhone")
    battery = status.get("batteryLevel")
    if isinstance(battery, (int, float)) and 0 <= battery <= 1:
        return f"{model}, battery {round(battery * 100)}%"
    return model


def _select_device(matches):
    if len(matches) == 1:
        return matches[0]

    print("Multiple Find My devices have that name:")
    for index, device in enumerate(matches, start=1):
        print(f"  {index}. {_safe_device_summary(device)}")

    for attempts_left in (3, 2, 1):
        choice = input("Select the iPhone to ring: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(matches):
            return matches[int(choice) - 1]
        if attempts_left == 1:
            raise SystemExit("No valid device selection was entered")
        print(f"Invalid selection; {attempts_left - 1} attempt(s) remain")

    raise AssertionError("unreachable")


def _confirm_test_ring() -> None:
    confirmation = input("Did the intended device ring? [y/N]: ").strip().casefold()
    if confirmation not in {"y", "yes"}:
        raise SystemExit(
            "Device selection was not confirmed; no session was uploaded"
        )


def _complete_2fa(api) -> None:
    from pyicloud.exceptions import (
        PyiCloudNoTrustedNumberAvailable,
        PyiCloudTrustedDevicePromptException,
    )

    if not api.requires_2fa:
        return
    if getattr(api, "security_key_names", []):
        raise SystemExit(
            "This account requires a hardware security key. "
            "Use the pyicloud CLI to authenticate, then rerun with a code-based account."
        )

    bridge_timed_out = False
    try:
        requested = api.request_2fa_code()
    except PyiCloudTrustedDevicePromptException:
        # Apple's trusted-device route depends on an APNS-style websocket. It
        # can time out after Apple has already displayed a valid code. With no
        # bridge state, pyicloud's validator uses Apple's legacy trusted-device
        # code endpoint, so preserve that delivery method and prompt for the
        # code the user already received.
        set_delivery_state = getattr(api, "_set_two_factor_delivery_state", None)
        if set_delivery_state is None:
            raise SystemExit(
                "Apple's trusted-device prompt timed out and this pyicloud "
                "version cannot recover the delivered code"
            )
        set_delivery_state(
            "trusted_device",
            "The trusted-device bridge timed out; enter the code Apple already displayed.",
        )
        bridge_timed_out = True
        requested = True

    if not requested:
        raise SystemExit("Apple did not offer a trusted-device or SMS 2FA challenge")

    method = getattr(api, "two_factor_delivery_method", "unknown")
    notice = getattr(api, "two_factor_delivery_notice", None)
    if notice:
        print(notice)
    print(f"Apple requested a verification code via: {method}")
    for attempts_left in (3, 2, 1):
        code = getpass.getpass("Apple verification code: ")
        if api.validate_2fa_code(code):
            break

        # If Apple's legacy endpoint rejects the bridge-delivered code, use
        # pyicloud's built-in SMS endpoint for the next attempt when possible.
        if bridge_timed_out:
            request_sms = getattr(api, "_request_sms_2fa_code", None)
            if request_sms is not None:
                try:
                    if request_sms(
                        notice="Trusted-device code was rejected; using SMS instead."
                    ):
                        bridge_timed_out = False
                        print("Apple sent a new verification code via SMS.")
                        continue
                except PyiCloudNoTrustedNumberAvailable:
                    pass

        if attempts_left == 1:
            raise SystemExit("Apple rejected the verification code")
        print(f"Invalid code; {attempts_left - 1} attempt(s) remain")

    if not api.is_trusted_session and not api.trust_session():
        raise SystemExit("Apple accepted 2FA but did not trust the browser session")


def main() -> None:
    args = _parse_args()

    import boto3
    from pyicloud import PyiCloudService

    bucket = _resolve_bucket(args, boto3)
    password = getpass.getpass(
        "Apple password (used only in this process; never uploaded): "
    )

    with tempfile.TemporaryDirectory(prefix="find-my-alexa-auth-") as directory:
        api = PyiCloudService(
            args.apple_id,
            password,
            cookie_directory=directory,
            with_family=False,
        )
        _complete_2fa(api)

        # Force Find My initialization and show names only, never IDs or locations.
        devices = list(api.devices)
        device_names = [str(device.status().get("name") or "") for device in devices]
        print("Find My devices:")
        for name in sorted(device_names, key=str.casefold):
            print(f"  - {name}")

        if args.device_name:
            matches = [
                device
                for device in devices
                if _normalise_name(str(device.status().get("name") or ""))
                == _normalise_name(args.device_name)
            ]
            if not matches:
                raise SystemExit(
                    "--device-name did not match a Find My device"
                )
            selected_device = _select_device(matches)
            device_id = str(selected_device.data.get("id") or "")
            if not device_id:
                raise SystemExit("Apple did not return an ID for the selected device")

            if args.test_ring:
                selected_device.play_sound(
                    subject="Find My Alexa authentication test"
                )
                print(f"Sent one test sound to {args.device_name}")
                _confirm_test_ring()

            target_path = Path(directory) / "target.json"
            target_path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "device_id": device_id,
                    },
                    separators=(",", ":"),
                ),
                encoding="utf-8",
            )

        session_files = [
            Path(api.session.session_path),
            Path(api.session.cookiejar_path),
            Path(directory) / "target.json",
        ]
        s3 = boto3.client("s3", region_name=args.region)
        for path in session_files:
            if not path.is_file():
                raise SystemExit(f"pyicloud did not create {path.name}")
            s3.upload_file(
                str(path),
                bucket,
                f"session/{path.name}",
                ExtraArgs={"ServerSideEncryption": "AES256"},
            )

    print("Uploaded the trusted iCloud session. The Apple password was not stored.")


if __name__ == "__main__":
    main()
