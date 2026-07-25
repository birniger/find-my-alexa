import importlib.util
import os
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


class SkillTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = load_module("skill_app", ROOT / "backend/skill/app.py")

    def setUp(self):
        os.environ["EXPECTED_SKILL_ID"] = "amzn1.ask.skill.test"
        os.environ["RING_QUEUE_URL"] = "https://sqs.example/queue"
        os.environ["PHONE_SPOKEN_NAME"] = "Basil's phone"

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


if __name__ == "__main__":
    unittest.main()
