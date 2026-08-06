import importlib.util
import hashlib
import json
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class SetupWorkerTests(unittest.TestCase):
    def test_reported_setup_failure_is_acknowledged_without_queue_retry(self):
        setup_app = load_module("setup_app_failure_test_module", ROOT / "backend/setup/app.py")
        event = {"Records": [{"body": json.dumps({"action": "setup", "setupId": "failed"})}]}
        with (
            patch.object(setup_app, "_run_setup", side_effect=setup_app.SetupFailed("Apple rejected the code")),
            patch.object(setup_app, "_post_event") as post_event,
        ):
            result = setup_app.lambda_handler(event, None)
        self.assertEqual(result, {"processed": 1, "status": "failed"})
        self.assertEqual(event["Records"][0]["body"], "")
        post_event.assert_called_once()

    def test_trusted_device_choice_does_not_request_sms(self):
        setup_app = load_module("setup_app_delivery_test_module", ROOT / "backend/setup/app.py")
        fake_exceptions = types.ModuleType("pyicloud.exceptions")
        fake_exceptions.PyiCloudTrustedDevicePromptException = type(
            "PyiCloudTrustedDevicePromptException", (RuntimeError,), {}
        )
        fake_exceptions.PyiCloudNoTrustedNumberAvailable = type(
            "PyiCloudNoTrustedNumberAvailable", (RuntimeError,), {}
        )
        api = types.SimpleNamespace(
            _request_sms_2fa_code=Mock(return_value=True),
            request_2fa_code=Mock(return_value=True),
            two_factor_delivery_method="trusted_device",
        )
        with patch.dict(sys.modules, {"pyicloud.exceptions": fake_exceptions}):
            self.assertEqual(setup_app._request_2fa(api, "trusted_device"), (True, "trusted_device"))
        api.request_2fa_code.assert_called_once_with()
        api._request_sms_2fa_code.assert_not_called()

    def test_wait_for_stops_when_setup_is_replaced(self):
        setup_app = load_module("setup_app_cancel_test_module", ROOT / "backend/setup/app.py")
        with patch.object(setup_app, "_poll_setup", return_value={"status": "expired"}):
            with self.assertRaisesRegex(setup_app.SetupFailed, "cancelled or expired"):
                setup_app._wait_for({"setupId": "old"}, "verification_code", bool)

    def test_runner_token_ignores_deployment_whitespace(self):
        setup_app = load_module("setup_app_token_test_module", ROOT / "backend/setup/app.py")
        with patch.dict("os.environ", {"RUNNER_API_TOKEN": "  token-with-newline\n"}):
            self.assertEqual(setup_app._runner_token(), "token-with-newline")
            self.assertEqual(setup_app._runner_headers()["X-Runner-Token"], "token-with-newline")

    def test_setup_flow_uploads_confirmed_session_bundle(self):
        setup_app = load_module("setup_app_test_module", ROOT / "backend/setup/app.py")

        class Response:
            status = 200

            def __init__(self, payload=None):
                self.payload = payload or {}

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return json.dumps(self.payload).encode("utf-8")

        posted_events = []

        candidate_id = hashlib.sha256(b"apple-device-id").hexdigest()[:32]

        def urlopen(request, timeout=0):
            if request.get_method() == "POST":
                posted_events.append(json.loads(request.data.decode("utf-8")))
                return Response()
            return Response(
                {
                    "verification_code": "123456",
                    "selected_devices_json": json.dumps([
                        {
                            "candidateId": candidate_id,
                            "deviceId": "device-1",
                            "label": "Kitchen iPad",
                            "model": "iPad Pro",
                            "sessionBucket": "bucket",
                            "sessionPrefix": "accounts/account-1/devices/device-1/",
                        }
                    ]),
                    "confirmed_test_ring": 1,
                }
            )

        device = Mock()
        device.status.return_value = {
            "name": "Kitchen iPad",
            "deviceDisplayName": "iPad Pro",
            "batteryLevel": 0.5,
        }
        device.data = {"id": "apple-device-id"}

        class Api:
            requires_2fa = True
            devices = [device]
            two_factor_delivery_method = "sms"
            sms_requests = 0

            def __init__(self, directory):
                session_path = Path(directory) / "account.session"
                cookie_path = Path(directory) / "account.cookiejar"
                session_path.write_text("session", encoding="utf-8")
                cookie_path.write_text("cookie", encoding="utf-8")
                self.session = types.SimpleNamespace(
                    session_path=str(session_path),
                    cookiejar_path=str(cookie_path),
                )

            @staticmethod
            def authenticate():
                return None

            @classmethod
            def _request_sms_2fa_code(cls):
                cls.sms_requests += 1
                return True

            @staticmethod
            def request_2fa_code():
                return True

            @staticmethod
            def validate_2fa_code(code):
                return code == "123456"

        fake_pyicloud = types.ModuleType("pyicloud")
        fake_pyicloud.PyiCloudService = Mock(side_effect=lambda *_args, cookie_directory, **_kwargs: Api(cookie_directory))
        fake_exceptions = types.ModuleType("pyicloud.exceptions")
        fake_exceptions.PyiCloudTrustedDevicePromptException = type(
            "PyiCloudTrustedDevicePromptException",
            (RuntimeError,),
            {},
        )
        fake_exceptions.PyiCloudNoTrustedNumberAvailable = type(
            "PyiCloudNoTrustedNumberAvailable",
            (RuntimeError,),
            {},
        )
        uploaded = {}
        fake_boto3 = types.ModuleType("boto3")
        fake_boto3.client = Mock(
            return_value=types.SimpleNamespace(
                upload_fileobj=lambda fileobj, bucket, key, ExtraArgs: uploaded.update(
                    {"body": fileobj.read(), "bucket": bucket, "key": key, "extra": ExtraArgs}
                )
            )
        )

        event = {
            "Records": [
                {
                    "body": json.dumps(
                        {
                            "action": "setup",
                            "setupId": "setup-1",
                            "accountId": "account-1",
                            "deviceId": "device-1",
                            "callbackBaseUrl": "https://find.example",
                            "appleId": "friend@example.com",
                            "password": "not-stored",
                            "verificationMethod": "sms",
                            "sessionBucket": "bucket",
                            "sessionPrefix": "accounts/account-1/devices/device-1/",
                        }
                    )
                }
            ]
        }

        with (
            patch.dict(sys.modules, {"pyicloud": fake_pyicloud, "pyicloud.exceptions": fake_exceptions, "boto3": fake_boto3}),
            patch.dict("os.environ", {"RUNNER_API_TOKEN": "token"}),
            patch("urllib.request.urlopen", side_effect=urlopen),
        ):
            response = setup_app.lambda_handler(event, None)

        self.assertEqual(response, {"processed": 1})
        self.assertEqual(event["Records"][0]["body"], "")
        self.assertEqual(Api.sms_requests, 1)
        device.play_sound.assert_called_once()
        self.assertEqual(uploaded["bucket"], "bucket")
        self.assertEqual(uploaded["key"], "accounts/account-1/devices/device-1/session-bundle.zip")
        self.assertEqual(uploaded["extra"], {"ServerSideEncryption": "AES256"})
        self.assertIn("completed", [event["setupStatus"] for event in posted_events])


class SavedSessionReuseTests(unittest.TestCase):
    @staticmethod
    def _bundle(directory: Path, names=("account.session", "account.cookiejar", "target.json")) -> bytes:
        import io
        import zipfile

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, mode="w") as archive:
            for name in names:
                archive.writestr(name, "{}" if name == "target.json" else "stored")
        return buffer.getvalue()

    def _open(self, setup_app, tmp, bundle_bytes, auth_status):
        def download_file(_bucket, _key, destination):
            Path(destination).write_bytes(bundle_bytes)

        api = types.SimpleNamespace(get_auth_status=lambda: auth_status)
        fake_boto3 = types.ModuleType("boto3")
        fake_boto3.client = Mock(return_value=types.SimpleNamespace(download_file=download_file))
        fake_pyicloud = types.ModuleType("pyicloud")
        fake_pyicloud.PyiCloudService = Mock(return_value=api)
        message = {
            "appleId": "friend@example.com",
            "reuseSessionBucket": "bucket",
            "reuseSessionPrefix": "accounts/account-1/devices/device-1/",
        }
        with patch.dict(sys.modules, {"boto3": fake_boto3, "pyicloud": fake_pyicloud}):
            return setup_app._open_saved_session(message, str(tmp)), fake_pyicloud.PyiCloudService

    def test_saved_session_is_opened_without_a_password(self):
        import tempfile

        setup_app = load_module("setup_app_reuse_test_module", ROOT / "backend/setup/app.py")
        with tempfile.TemporaryDirectory() as directory:
            api, service = self._open(
                setup_app, Path(directory), self._bundle(Path(directory)), {"authenticated": True, "requires_2fa": False}
            )
            self.assertIsNotNone(api)
            self.assertIsNone(service.call_args.kwargs["password"])
            self.assertFalse(service.call_args.kwargs["authenticate"])
            self.assertTrue((Path(directory) / "account.session").is_file())
            self.assertFalse((Path(directory) / "session-bundle.zip").exists())

    def test_expired_saved_session_asks_for_a_fresh_sign_in(self):
        import tempfile

        setup_app = load_module("setup_app_reuse_expired_test_module", ROOT / "backend/setup/app.py")
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(setup_app.SetupFailed, "sign in to Apple again"):
                self._open(
                    setup_app,
                    Path(directory),
                    self._bundle(Path(directory)),
                    {"authenticated": True, "requires_2fa": True},
                )

    def test_tampered_bundle_is_rejected(self):
        import tempfile

        setup_app = load_module("setup_app_reuse_bundle_test_module", ROOT / "backend/setup/app.py")
        with tempfile.TemporaryDirectory() as directory:
            tampered = self._bundle(Path(directory), names=("../escape.session", "account.cookiejar", "target.json"))
            with self.assertRaisesRegex(setup_app.SetupFailed, "unusable"):
                self._open(setup_app, Path(directory), tampered, {"authenticated": True, "requires_2fa": False})

    def test_reuse_mode_skips_credentials_and_two_factor(self):
        setup_app = load_module("setup_app_reuse_flow_test_module", ROOT / "backend/setup/app.py")
        api = types.SimpleNamespace(requires_2fa=True, devices=[])
        message = {"action": "setup", "setupId": "s", "mode": "reuse_session", "appleId": "friend@example.com"}
        with (
            patch.object(setup_app, "_open_saved_session", return_value=api) as open_saved,
            patch.object(setup_app, "_create_api") as create_api,
            patch.object(setup_app, "_request_2fa") as request_2fa,
            patch.object(setup_app, "_post_event"),
            patch.object(setup_app, "_stop_device_monitor"),
        ):
            with self.assertRaisesRegex(setup_app.SetupFailed, "no Find My devices"):
                setup_app._run_setup(message)
        open_saved.assert_called_once()
        create_api.assert_not_called()
        request_2fa.assert_not_called()


if __name__ == "__main__":
    unittest.main()
