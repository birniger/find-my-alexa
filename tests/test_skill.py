import importlib.util
import io
import json
import os
import sys
import types
import unittest
import urllib.error
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


class SkillTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = load_module("skill_app", ROOT / "backend/skill/app.py")

    def setUp(self):
        os.environ["EXPECTED_SKILL_ID"] = "amzn1.ask.skill.test"
        os.environ["RING_QUEUE_URL"] = "https://sqs.example/queue"
        os.environ["PHONE_SPOKEN_NAME"] = "Basil's phone"
        os.environ.pop("FIND_MY_API_BASE_URL", None)

    @staticmethod
    def event(request):
        return {
            "session": {
                "application": {"applicationId": "amzn1.ask.skill.test"}
            },
            "request": {"requestId": "request-1", **request},
        }

    def test_launch_queues_ring(self):
        sqs = Mock()
        fake_boto3 = types.SimpleNamespace(client=lambda _name: sqs)
        with patch.dict(sys.modules, {"boto3": fake_boto3}):
            response = self.app.lambda_handler(
                self.event({"type": "LaunchRequest"}), None
            )
        self.assertEqual(
            response["response"]["outputSpeech"]["text"],
            "Okay, ringing Basil's phone.",
        )
        sqs.send_message.assert_called_once()
        self.assertEqual(
            sqs.send_message.call_args.kwargs["MessageGroupId"],
            "find-my-alexa",
        )

    def test_wrong_skill_is_rejected(self):
        event = self.event({"type": "LaunchRequest"})
        event["session"]["application"]["applicationId"] = "wrong"
        with self.assertRaises(PermissionError):
            self.app.lambda_handler(event, None)

    def test_help_does_not_queue(self):
        response = self.app.lambda_handler(
            self.event(
                {
                    "type": "IntentRequest",
                    "intent": {"name": "AMAZON.HelpIntent"},
                }
            ),
            None,
        )
        self.assertFalse(response["response"]["shouldEndSession"])

    def test_account_linked_user_posts_to_cloudflare(self):
        event = self.event({"type": "LaunchRequest"})
        event["context"] = {
            "System": {"user": {"accessToken": "auth0-token"}}
        }
        opened = Mock()
        opened.__enter__ = Mock(return_value=types.SimpleNamespace(status=202))
        opened.__exit__ = Mock(return_value=None)

        with (
            patch.dict(os.environ, {"FIND_MY_API_BASE_URL": "https://find.example"}),
            patch("urllib.request.urlopen", return_value=opened) as urlopen,
        ):
            response = self.app.lambda_handler(event, None)

        self.assertEqual(
            response["response"]["outputSpeech"]["text"],
            "Okay, ringing your Apple device.",
        )
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "https://find.example/api/ring/request")
        self.assertEqual(request.headers["Authorization"], "Bearer auth0-token")

    def test_cloudflare_failure_does_not_fall_back_to_legacy_queue(self):
        event = self.event({"type": "LaunchRequest"})
        event["context"] = {
            "System": {"user": {"accessToken": "auth0-token"}}
        }
        sqs = Mock()
        fake_boto3 = types.SimpleNamespace(client=lambda _name: sqs)
        with (
            patch.dict(os.environ, {"FIND_MY_API_BASE_URL": "https://find.example"}),
            patch("urllib.request.urlopen", side_effect=urllib.error.URLError("down")),
            patch.dict(sys.modules, {"boto3": fake_boto3}),
        ):
            response = self.app.lambda_handler(event, None)

        self.assertEqual(
            response["response"]["outputSpeech"]["text"],
            "I couldn't reach Device Finder. Open the app to check your setup.",
        )
        sqs.send_message.assert_not_called()

    def test_named_phone_is_forwarded_and_confirmed(self):
        event = self.event(
            {
                "type": "IntentRequest",
                "intent": {
                    "name": "RingPhoneIntent",
                    "slots": {"deviceName": {"value": "work iPhone"}},
                },
            }
        )
        event["context"] = {"System": {"user": {"accessToken": "auth0-token"}}}

        class Response:
            status = 202

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            @staticmethod
            def read():
                return json.dumps({"deviceLabel": "Work iPhone"}).encode("utf-8")

        with (
            patch.dict(os.environ, {"FIND_MY_API_BASE_URL": "https://find.example"}),
            patch("urllib.request.urlopen", return_value=Response()) as urlopen,
        ):
            response = self.app.lambda_handler(event, None)

        request = urlopen.call_args.args[0]
        # "source" lets the hosted app record that Alexa account linking works.
        self.assertEqual(json.loads(request.data), {"source": "alexa", "deviceName": "work iPhone"})
        self.assertEqual(response["response"]["outputSpeech"]["text"], "Okay, ringing Work iPhone.")

    def test_cloudflare_needs_renewal_does_not_fall_back_to_legacy_queue(self):
        event = self.event({"type": "LaunchRequest"})
        event["context"] = {
            "System": {"user": {"accessToken": "auth0-token"}}
        }
        sqs = Mock()
        fake_boto3 = types.SimpleNamespace(client=lambda _name: sqs)

        def raise_conflict(*_args, **_kwargs):
            error = urllib.error.HTTPError(
                "https://find.example/api/ring/request",
                409,
                "Conflict",
                {},
                io.BytesIO(b""),
            )
            error.close()
            raise error

        with (
            patch.dict(os.environ, {"FIND_MY_API_BASE_URL": "https://find.example"}),
            patch("urllib.request.urlopen", side_effect=raise_conflict),
            patch.dict(sys.modules, {"boto3": fake_boto3}),
        ):
            response = self.app.lambda_handler(event, None)

        self.assertEqual(
            response["response"]["outputSpeech"]["text"],
            "Your Apple setup needs renewal. Open Device Finder to update the Apple login.",
        )
        sqs.send_message.assert_not_called()

    def test_cloudflare_configured_requires_account_linking(self):
        sqs = Mock()
        fake_boto3 = types.SimpleNamespace(client=lambda _name: sqs)
        with (
            patch.dict(os.environ, {"FIND_MY_API_BASE_URL": "https://find.example"}),
            patch.dict(sys.modules, {"boto3": fake_boto3}),
        ):
            response = self.app.lambda_handler(
                self.event({"type": "LaunchRequest"}), None
            )

        self.assertEqual(
            response["response"]["outputSpeech"]["text"],
            "Please link your Alexa account to Device Finder before ringing your Apple device.",
        )
        sqs.send_message.assert_not_called()


if __name__ == "__main__":
    unittest.main()
