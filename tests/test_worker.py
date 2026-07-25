import importlib.util
import json
import os
import sys
import tempfile
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


if __name__ == "__main__":
    unittest.main()
