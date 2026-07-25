import importlib.util
import json
import os
import shutil
import sys
import tempfile
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

    def test_download_requires_all_three_encrypted_files_and_cleanup(self):
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
            @staticmethod
            def get_paginator(_name):
                return Paginator()

            @staticmethod
            def download_file(_bucket, key, destination):
                Path(destination).write_text(key, encoding="utf-8")

        directory = Path("/tmp/find-my-alexa-session-store-test")
        shutil.rmtree(directory, ignore_errors=True)
        store = self.store_module.S3SessionStore(
            "bucket", local_directory=directory, client=S3()
        )

        downloaded = store.download()
        self.assertEqual(
            {path.name for path in downloaded.iterdir()},
            {"account.session", "account.cookiejar", "target.json"},
        )
        store.cleanup()
        self.assertFalse(downloaded.exists())


class WorkerHandlerTests(unittest.TestCase):
    def test_cleanup_runs_when_ring_fails(self):
        find_my_module = types.ModuleType("find_my")
        find_my_module.ring_device = Mock(side_effect=RuntimeError("ring failed"))

        store = Mock()
        store.download.return_value = Path("/tmp/find-my-alexa-session")
        session_store_module = types.ModuleType("session_store")
        session_store_module.S3SessionStore = Mock(return_value=store)

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
            with self.assertRaisesRegex(RuntimeError, "ring failed"):
                worker_app.lambda_handler(event, None)

        store.cleanup.assert_called_once_with()
        store.upload.assert_not_called()


if __name__ == "__main__":
    unittest.main()
