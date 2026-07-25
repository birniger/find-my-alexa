import importlib.util
import io
import sys
import tempfile
import types
import unittest
import zipfile
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


class TrustedDevicePromptError(Exception):
    pass


class NoTrustedNumberError(Exception):
    pass


class FakeApi:
    requires_2fa = True
    security_key_names = []
    is_trusted_session = True
    two_factor_delivery_method = "unknown"
    two_factor_delivery_notice = None

    def request_2fa_code(self):
        raise TrustedDevicePromptError()

    def _set_two_factor_delivery_state(self, method, notice):
        self.two_factor_delivery_method = method
        self.two_factor_delivery_notice = notice

    def validate_2fa_code(self, code):
        self.validated_code = code
        return True


class AuthenticationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.auth = load_module(
            "authenticate_script", ROOT / "scripts/authenticate.py"
        )

    def test_bridge_timeout_accepts_already_delivered_code(self):
        fake_exceptions = types.SimpleNamespace(
            PyiCloudNoTrustedNumberAvailable=NoTrustedNumberError,
            PyiCloudTrustedDevicePromptException=TrustedDevicePromptError,
        )
        api = FakeApi()
        with (
            patch.dict(
                sys.modules,
                {
                    "pyicloud": types.SimpleNamespace(),
                    "pyicloud.exceptions": fake_exceptions,
                },
            ),
            patch.object(self.auth.getpass, "getpass", return_value="123456"),
        ):
            self.auth._complete_2fa(api)

        self.assertEqual(api.two_factor_delivery_method, "trusted_device")
        self.assertEqual(api.validated_code, "123456")

    def test_duplicate_device_selection_uses_numbered_choice(self):
        first = object()
        second = object()
        with (
            patch("builtins.input", return_value="2"),
            patch.object(self.auth, "_safe_device_summary", return_value="iPhone"),
        ):
            selected = self.auth._select_device([first, second])
        self.assertIs(selected, second)

    def test_unconfirmed_test_ring_aborts_before_upload(self):
        with patch("builtins.input", return_value="no"):
            with self.assertRaises(SystemExit):
                self.auth._confirm_test_ring()

    def test_session_bundle_contains_exactly_the_required_files(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = [
                Path(directory, "account.session"),
                Path(directory, "account.cookiejar"),
                Path(directory, "target.json"),
            ]
            for path in paths:
                path.write_text(path.name, encoding="utf-8")

            bundle = self.auth._create_session_bundle(paths)

        with zipfile.ZipFile(io.BytesIO(bundle.read())) as archive:
            self.assertEqual(
                set(archive.namelist()),
                {"account.session", "account.cookiejar", "target.json"},
            )

    def test_local_authentication_monitor_is_stopped(self):
        manager = types.SimpleNamespace(
            stop_event=Mock(),
            _monitor=Mock(),
        )
        manager._monitor.is_alive.return_value = False

        self.auth._stop_device_monitor(manager)

        manager.stop_event.set.assert_called_once_with()
        manager._monitor.join.assert_called_once_with(timeout=1.0)


if __name__ == "__main__":
    unittest.main()
