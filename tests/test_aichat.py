import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

import requests


MODULE_PATH = Path(__file__).resolve().parents[1] / "aichat" / "aichat.py"
SPEC = importlib.util.spec_from_file_location("aichat_module", MODULE_PATH)
aichat = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(aichat)


class AichatTests(TestCase):
    def make_args(self, **overrides):
        base = {
            "base_url": "https://openrouter.ai/api/v1",
            "api_key": "test-key",
            "temperature": None,
            "max_tokens": None,
            "timeout": 10,
            "retry_count": 1,
            "retry_backoff": 0,
            "fallback_model": "",
            "json": False,
        }
        base.update(overrides)
        return SimpleNamespace(**base)

    def test_analyze_command_risk_detects_high_risk(self):
        risk = aichat.analyze_command_risk("sudo rm -rf /tmp/demo")
        self.assertTrue(risk["is_risky"])
        self.assertEqual(risk["level"], "high")
        self.assertIn("needs-sudo", risk["tags"])
        self.assertIn("recursive-delete", risk["tags"])

    def test_enforce_command_quality_repairs_multiline_response(self):
        args = self.make_args()
        messages = [{"role": "system", "content": "cmd"}]
        with patch.object(aichat, "request_completion", return_value=("echo repaired", "model")):
            fixed = aichat.enforce_command_quality(args, "model", messages, "echo one\necho two")
        self.assertEqual(fixed, "echo repaired")

    def test_request_completion_falls_back_to_secondary_model(self):
        args = self.make_args(retry_count=1, fallback_model="fallback-model")
        seen_models = []

        def fake_chat_completion(**kwargs):
            seen_models.append(kwargs["model"])
            if kwargs["model"] == "google/gemini-2.5-flash-lite":
                raise requests.RequestException("primary failed")
            return "ok"

        with patch.object(aichat, "chat_completion", side_effect=fake_chat_completion):
            output, used_model = aichat.request_completion(
                args,
                "google/gemini-2.5-flash-lite",
                [{"role": "user", "content": "hi"}],
            )

        self.assertEqual(output, "ok")
        self.assertEqual(used_model, "fallback-model")
        self.assertEqual(
            seen_models,
            ["google/gemini-2.5-flash-lite", "google/gemini-2.5-flash-lite", "fallback-model"],
        )

    def test_execute_or_refine_uses_feedback_then_executes(self):
        args = self.make_args()
        messages = [{"role": "system", "content": "cmd"}]

        with (
            patch("builtins.input", side_effect=["needs more input", "y"]),
            patch.object(aichat, "request_completion", return_value=("echo fixed", "model")),
            patch.object(aichat, "enforce_command_quality", return_value="echo fixed"),
            patch.object(aichat.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run_mock,
            patch.object(aichat, "emit_model_output"),
        ):
            aichat.execute_or_refine_command(args, "model", messages, "echo wrong")

        run_mock.assert_called_once_with("echo fixed", shell=True, check=False)

    def test_execute_or_refine_risky_command_requires_extra_confirmation(self):
        args = self.make_args()
        messages = [{"role": "system", "content": "cmd"}]

        with (
            patch("builtins.input", side_effect=["y", "no"]),
            patch.object(aichat.subprocess, "run") as run_mock,
        ):
            aichat.execute_or_refine_command(args, "model", messages, "sudo rm -rf /tmp/demo")

        run_mock.assert_not_called()

    def test_classify_command_exit_treats_grep_no_match_as_non_error(self):
        status, note = aichat.classify_command_exit('grep -r "blaat" .', 1)
        self.assertEqual(status, "executed-no-match")
        self.assertEqual(note, "No matches found.")

    def test_execute_or_refine_non_error_exit_does_not_print_failed(self):
        args = self.make_args()
        messages = [{"role": "system", "content": "cmd"}]

        with (
            patch("builtins.input", side_effect=["y"]),
            patch.object(
                aichat.subprocess,
                "run",
                return_value=SimpleNamespace(returncode=1),
            ) as run_mock,
            patch.object(aichat, "emit_exec_event") as emit_exec_event_mock,
            patch("sys.stderr"),
        ):
            aichat.execute_or_refine_command(args, "model", messages, 'grep -r "blaat" .')

        run_mock.assert_called_once_with('grep -r "blaat" .', shell=True, check=False)
        emit_exec_event_mock.assert_called_once_with(
            args,
            'grep -r "blaat" .',
            "executed-no-match",
            aichat.analyze_command_risk('grep -r "blaat" .'),
            1,
        )
