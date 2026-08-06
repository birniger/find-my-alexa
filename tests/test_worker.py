import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
import types
import unittest
import zipfile
from contextlib import redirect_stdout
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


class FindMyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.find_my = load_module(
            "find_my_test_module", ROOT / "backend/worker/find_my.py"
        )

    def test_exact_normalised_device_name_rings(self):
        device = Mock()
        device.status.return_value = {"name": "Basil’s iPhone"}
        api = Mock()
        api.get_auth_status.return_value = {
            "authenticated": True,
            "requires_2fa": False,
        }
        api.devices = [device]

        fake_pyicloud = Mock()
        fake_pyicloud.PyiCloudService.return_value = api
        with patch.dict(sys.modules, {"pyicloud": fake_pyicloud}):
            self.find_my.ring_device(
                "basil@example.com", "  basil’s   iphone ", Path("/tmp/session")
            )
        device.play_sound.assert_called_once()

    def test_encrypted_target_id_selects_one_of_duplicate_names(self):
        first = Mock()
        first.data = {"id": "old-phone"}
        first.status.return_value = {"name": "Basil’s iPhone"}
        second = Mock()
        second.data = {"id": "current-phone"}
        second.status.return_value = {"name": "Basil’s iPhone"}
        api = Mock()
        api.get_auth_status.return_value = {
            "authenticated": True,
            "requires_2fa": False,
        }
        api.devices = [first, second]

        fake_pyicloud = Mock()
        fake_pyicloud.PyiCloudService.return_value = api
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "target.json").write_text(
                json.dumps({"device_id": "current-phone"}),
                encoding="utf-8",
            )
            with patch.dict(sys.modules, {"pyicloud": fake_pyicloud}):
                self.find_my.ring_device(
                    "basil@example.com",
                    "Basil's iPhone",
                    Path(directory),
                )

        first.play_sound.assert_not_called()
        second.play_sound.assert_called_once()

    def test_expired_session_never_attempts_password_login(self):
        api = Mock()
        api.get_auth_status.return_value = {"authenticated": False}
        fake_pyicloud = Mock()
        fake_pyicloud.PyiCloudService.return_value = api

        with patch.dict(sys.modules, {"pyicloud": fake_pyicloud}):
            with self.assertRaises(self.find_my.ReauthenticationRequired):
                self.find_my.ring_device(
                    "basil@example.com", "Basil’s iPhone", Path("/tmp/session")
                )
        _, kwargs = fake_pyicloud.PyiCloudService.call_args
        self.assertFalse(kwargs["authenticate"])
        self.assertIsNone(kwargs["password"])

    def test_monitor_stays_active_for_sound_then_stops_before_return(self):
        class Manager:
            def __init__(self):
                self.alive = True
                self.restart_count = 0
                self.stop_event = types.SimpleNamespace(
                    set=Mock(side_effect=self._stop)
                )
                self._monitor = Mock()
                self._monitor.is_alive.side_effect = lambda: self.alive

            def _stop(self):
                self.alive = False

            def __iter__(self):
                return iter([device])

        manager = Manager()

        class RestartingDevice:
            sound_calls = 0

            @property
            def data(self):
                if not manager.alive:
                    manager.alive = True
                    manager.restart_count += 1
                return {"id": "phone"}

            def status(self):
                return {"name": "Basil's iPhone"}

            def play_sound(self, **_kwargs):
                _ = self.data
                self.sound_calls += 1

        device = RestartingDevice()
        api = Mock()
        api.get_auth_status.return_value = {
            "authenticated": True,
            "requires_2fa": False,
        }
        api.devices = manager
        original_request = api.session.request

        fake_pyicloud = Mock()
        fake_pyicloud.PyiCloudService.return_value = api
        with patch.dict(sys.modules, {"pyicloud": fake_pyicloud}):
            self.find_my.ring_device(
                "basil@example.com", "Basil's iPhone", Path("/tmp/session")
            )

        manager.stop_event.set.assert_called_once_with()
        manager._monitor.join.assert_called_once_with(timeout=1.0)
        self.assertFalse(manager.alive)
        self.assertEqual(manager.restart_count, 0)
        self.assertEqual(device.sound_calls, 1)

        api.session.request("GET", "https://example.invalid")
        original_request.assert_called_once_with(
            "GET",
            "https://example.invalid",
            timeout=self.find_my.HTTP_TIMEOUT,
        )

    def test_monitor_shutdown_failure_is_reported_after_sound(self):
        device = Mock()
        device.data = {"id": "phone"}

        class Manager:
            stop_event = Mock()
            _monitor = Mock()

            def __iter__(self):
                return iter([device])

        Manager._monitor.is_alive.return_value = True
        api = Mock()
        api.get_auth_status.return_value = {
            "authenticated": True,
            "requires_2fa": False,
        }
        api.devices = Manager()

        fake_pyicloud = Mock()
        fake_pyicloud.PyiCloudService.return_value = api
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "target.json").write_text(
                json.dumps({"device_id": "phone"}),
                encoding="utf-8",
            )
            with patch.dict(sys.modules, {"pyicloud": fake_pyicloud}):
                with self.assertRaises(self.find_my.MonitorShutdownError):
                    self.find_my.ring_device(
                        "basil@example.com",
                        "Basil's iPhone",
                        Path(directory),
                    )
        device.play_sound.assert_called_once()


class SessionStoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store_module = load_module(
            "session_store_test_module",
            ROOT / "backend/worker/session_store.py",
        )

    def test_refuses_unsafe_local_path(self):
        store = self.store_module.S3SessionStore(
            "bucket", local_directory=Path("/")
        )
        with self.assertRaises(self.store_module.SessionStoreError):
            store.download()

    def test_refuses_path_that_escapes_tmp_with_parent_segments(self):
        store = self.store_module.S3SessionStore(
            "bucket", local_directory=Path("/tmp/../etc/find-my-alexa")
        )
        with self.assertRaises(self.store_module.SessionStoreError):
            store.download()

    def test_legacy_download_migrates_to_one_atomic_bundle(self):
        class Paginator:
            @staticmethod
            def paginate(**_kwargs):
                return [
                    {
                        "Contents": [
                            {"Key": "session/account.session"},
                            {"Key": "session/account.cookiejar"},
                            {"Key": "session/target.json"},
                        ]
                    }
                ]

        class S3:
            def __init__(self):
                self.bundle = None
                self.deleted = []

            @staticmethod
            def get_paginator(_name):
                return Paginator()

            @staticmethod
            def download_file(_bucket, key, destination):
                Path(destination).write_text(key, encoding="utf-8")

            def put_object(self, **request):
                self.bundle = request["Body"]
                self.put_request = request
                return {"ETag": '"new-etag"'}

            def delete_object(self, *, Bucket, Key):
                self.deleted.append((Bucket, Key))

        directory = Path("/tmp/find-my-alexa-session-store-test")
        shutil.rmtree(directory, ignore_errors=True)
        s3 = S3()
        store = self.store_module.S3SessionStore(
            "bucket", local_directory=directory, client=s3
        )

        downloaded = store.download()
        self.assertEqual(
            {path.name for path in downloaded.iterdir()},
            {"account.session", "account.cookiejar", "target.json"},
        )
        store.upload()
        with zipfile.ZipFile(io.BytesIO(s3.bundle)) as archive:
            self.assertEqual(
                set(archive.namelist()),
                {"account.session", "account.cookiejar", "target.json"},
            )
        self.assertEqual(s3.put_request["ServerSideEncryption"], "AES256")
        self.assertEqual(s3.put_request["IfNoneMatch"], "*")
        self.assertEqual(
            {key for _bucket, key in s3.deleted},
            {
                "session/account.session",
                "session/account.cookiejar",
                "session/target.json",
            },
        )
        store.upload()
        self.assertEqual(len(s3.deleted), 3)
        self.assertEqual(s3.put_request["IfMatch"], '"new-etag"')
        store.cleanup()
        self.assertFalse(downloaded.exists())

    def test_downloads_and_safely_extracts_atomic_bundle(self):
        source = Path("/tmp/find-my-alexa-source-bundle-test")
        destination = Path("/tmp/find-my-alexa-bundle-download-test")
        shutil.rmtree(source, ignore_errors=True)
        shutil.rmtree(destination, ignore_errors=True)
        source.mkdir(mode=0o700)
        for name in ("account.session", "account.cookiejar", "target.json"):
            (source / name).write_text(name, encoding="utf-8")
        bundle = self.store_module.create_session_bundle(source).read()

        class Paginator:
            @staticmethod
            def paginate(**_kwargs):
                return [
                    {
                        "Contents": [
                            {
                                "Key": "session/session-bundle.zip",
                                "ETag": '"current-etag"',
                            }
                        ]
                    }
                ]

        class S3:
            def __init__(self):
                self.put_request = None
                self.deleted = []

            @staticmethod
            def get_paginator(_name):
                return Paginator()

            @staticmethod
            def download_file(_bucket, _key, local_path):
                Path(local_path).write_bytes(bundle)

            def put_object(self, **request):
                self.put_request = request
                return {"ETag": '"next-etag"'}

            def delete_object(self, **request):
                self.deleted.append(request)

        s3 = S3()
        store = self.store_module.S3SessionStore(
            "bucket", local_directory=destination, client=s3
        )
        downloaded = store.download()
        self.assertEqual(
            {path.name for path in downloaded.iterdir()},
            {"account.session", "account.cookiejar", "target.json"},
        )
        self.assertFalse((downloaded / "session-bundle.zip").exists())
        store.upload()
        self.assertEqual(s3.put_request["IfMatch"], '"current-etag"')
        self.assertEqual(s3.deleted, [])
        store.cleanup()
        shutil.rmtree(source, ignore_errors=True)

    def test_rejects_bundle_with_path_traversal_member(self):
        bundle_buffer = io.BytesIO()
        with zipfile.ZipFile(bundle_buffer, mode="w") as archive:
            archive.writestr("../account.session", "session")
            archive.writestr("account.cookiejar", "cookies")
            archive.writestr("target.json", "{}")
        bundle = bundle_buffer.getvalue()

        class Paginator:
            @staticmethod
            def paginate(**_kwargs):
                return [
                    {
                        "Contents": [
                            {
                                "Key": "session/session-bundle.zip",
                                "ETag": '"current-etag"',
                            }
                        ]
                    }
                ]

        class S3:
            @staticmethod
            def get_paginator(_name):
                return Paginator()

            @staticmethod
            def download_file(_bucket, _key, local_path):
                Path(local_path).write_bytes(bundle)

        destination = Path("/tmp/find-my-alexa-malicious-bundle-test")
        shutil.rmtree(destination, ignore_errors=True)
        store = self.store_module.S3SessionStore(
            "bucket", local_directory=destination, client=S3()
        )
        with self.assertRaisesRegex(
            self.store_module.SessionStoreError, "bundle is invalid"
        ):
            store.download()
        store.cleanup()


class WorkerHandlerTests(unittest.TestCase):
    def test_cleanup_runs_when_ring_fails(self):
        find_my_module = types.ModuleType("find_my")
        find_my_module.ring_device = Mock(side_effect=RuntimeError("ring failed"))
        find_my_module.check_device = Mock()
        find_my_module.DeviceNotFound = type("DeviceNotFound", (RuntimeError,), {})
        find_my_module.ReauthenticationRequired = type(
            "ReauthenticationRequired", (RuntimeError,), {}
        )

        store = Mock()
        store.download.return_value = Path("/tmp/find-my-alexa-session")
        session_store_module = types.ModuleType("session_store")
        session_store_module.S3SessionStore = Mock(return_value=store)
        session_store_module.SessionStoreError = type(
            "SessionStoreError", (RuntimeError,), {}
        )

        with patch.dict(
            sys.modules,
            {
                "find_my": find_my_module,
                "session_store": session_store_module,
            },
        ):
            worker_app = load_module(
                "worker_app_cleanup_test_module",
                ROOT / "backend/worker/app.py",
            )

        environment = {
            "APPLE_ID": "basil@example.com",
            "DEVICE_NAME": "Basil's iPhone",
            "SESSION_BUCKET": "bucket",
        }
        event = {"Records": [{"body": json.dumps({"action": "ring"})}]}
        with patch.dict(os.environ, environment, clear=True):
            with self.assertRaisesRegex(
                worker_app.WorkerOperationError, "operation_failed"
            ):
                worker_app.lambda_handler(event, None)

        store.cleanup.assert_called_once_with()
        store.upload.assert_not_called()

    def test_third_party_error_text_is_not_logged_or_raised(self):
        secret = "basil@example.com: full private response body"
        find_my_module = types.ModuleType("find_my")
        find_my_module.ring_device = Mock(side_effect=RuntimeError(secret))
        find_my_module.check_device = Mock()
        find_my_module.DeviceNotFound = type("DeviceNotFound", (RuntimeError,), {})
        find_my_module.ReauthenticationRequired = type(
            "ReauthenticationRequired", (RuntimeError,), {}
        )

        store = Mock()
        store.download.return_value = Path("/tmp/find-my-alexa-session")
        session_store_module = types.ModuleType("session_store")
        session_store_module.S3SessionStore = Mock(return_value=store)
        session_store_module.SessionStoreError = type(
            "SessionStoreError", (RuntimeError,), {}
        )

        with patch.dict(
            sys.modules,
            {
                "find_my": find_my_module,
                "session_store": session_store_module,
            },
        ):
            worker_app = load_module(
                "worker_app_redaction_test_module",
                ROOT / "backend/worker/app.py",
            )

        environment = {
            "APPLE_ID": "basil@example.com",
            "DEVICE_NAME": "Basil's iPhone",
            "SESSION_BUCKET": "bucket",
        }
        event = {"Records": [{"body": json.dumps({"action": "ring"})}]}
        output = io.StringIO()
        with (
            patch.dict(os.environ, environment, clear=True),
            redirect_stdout(output),
            self.assertRaises(worker_app.WorkerOperationError) as raised,
        ):
            worker_app.lambda_handler(event, None)

        self.assertNotIn(secret, output.getvalue())
        self.assertNotIn(secret, str(raised.exception))
        self.assertTrue(raised.exception.__suppress_context__)

        context = Mock()
        context.get_remaining_time_in_millis.return_value = 2_000
        with self.assertRaises(worker_app.WorkerOperationDeadline):
            with worker_app._operation_deadline(
                context,
                max_seconds=35.0,
                reserve_ms=7_000,
            ):
                self.fail("deadline should reject before entering the operation")

    def test_message_can_select_account_scoped_session_prefix(self):
        find_my_module = types.ModuleType("find_my")
        find_my_module.ring_device = Mock()
        find_my_module.check_device = Mock()
        find_my_module.DeviceNotFound = type("DeviceNotFound", (RuntimeError,), {})
        find_my_module.ReauthenticationRequired = type(
            "ReauthenticationRequired", (RuntimeError,), {}
        )

        store = Mock()
        store.download.return_value = Path("/tmp/find-my-alexa-session-job-1")
        session_store_module = types.ModuleType("session_store")
        session_store_module.S3SessionStore = Mock(return_value=store)
        session_store_module.SessionStoreError = type(
            "SessionStoreError", (RuntimeError,), {}
        )

        with patch.dict(
            sys.modules,
            {
                "find_my": find_my_module,
                "session_store": session_store_module,
            },
        ):
            worker_app = load_module(
                "worker_app_multi_user_test_module",
                ROOT / "backend/worker/app.py",
            )

        event = {
            "Records": [
                {
                    "body": json.dumps(
                        {
                            "action": "ring",
                            "jobId": "job/1",
                            "appleId": "friend@example.com",
                            "deviceName": "Friend's iPhone",
                            "sessionPrefix": "accounts/account-1/devices/device-1/",
                            "sessionBucket": "friend-bucket",
                        }
                    )
                }
            ]
        }
        with patch.dict(os.environ, {}, clear=True):
            response = worker_app.lambda_handler(event, None)

        self.assertEqual(response, {"processed": 1})
        session_store_module.S3SessionStore.assert_called_once_with(
            bucket="friend-bucket",
            prefix="accounts/account-1/devices/device-1/",
            local_directory=Path("/tmp/find-my-alexa-session-job-1"),
        )
        find_my_module.ring_device.assert_called_once_with(
            apple_id="friend@example.com",
            target_name="Friend's iPhone",
            session_directory=Path("/tmp/find-my-alexa-session-job-1"),
        )

    def test_health_check_uses_no_ring_validation(self):
        find_my_module = types.ModuleType("find_my")
        find_my_module.ring_device = Mock()
        find_my_module.check_device = Mock()
        find_my_module.DeviceNotFound = type("DeviceNotFound", (RuntimeError,), {})
        find_my_module.ReauthenticationRequired = type(
            "ReauthenticationRequired", (RuntimeError,), {}
        )

        store = Mock()
        store.download.return_value = Path("/tmp/find-my-alexa-session-health-1")
        session_store_module = types.ModuleType("session_store")
        session_store_module.S3SessionStore = Mock(return_value=store)
        session_store_module.SessionStoreError = type(
            "SessionStoreError", (RuntimeError,), {}
        )

        with patch.dict(
            sys.modules,
            {
                "find_my": find_my_module,
                "session_store": session_store_module,
            },
        ):
            worker_app = load_module(
                "worker_app_health_check_test_module",
                ROOT / "backend/worker/app.py",
            )

        event = {
            "Records": [
                {
                    "body": json.dumps(
                        {
                            "action": "health_check",
                            "jobId": "health-1",
                            "appleId": "friend@example.com",
                            "deviceName": "Friend's iPhone",
                            "sessionPrefix": "accounts/account-1/devices/device-1/",
                            "sessionBucket": "friend-bucket",
                        }
                    )
                }
            ]
        }
        with patch.dict(os.environ, {}, clear=True):
            response = worker_app.lambda_handler(event, None)

        self.assertEqual(response, {"processed": 1})
        find_my_module.check_device.assert_called_once_with(
            apple_id="friend@example.com",
            target_name="Friend's iPhone",
            session_directory=Path("/tmp/find-my-alexa-session-health-1"),
        )
        find_my_module.ring_device.assert_not_called()


if __name__ == "__main__":
    unittest.main()
