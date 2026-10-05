"""Isolated guard tests: no application database or model download required."""
import ast
import math
from pathlib import Path
import re
from types import SimpleNamespace
import unittest
from unittest.mock import Mock
import time

source = ast.parse((Path(__file__).resolve().parents[1] / "app.py").read_text())
names = {"provider_chat", "parse_llama_guard", "llama_guard_settings",
         "llama_guard_threshold_result", "llama_guard_evaluate"}
namespace = dict(math=math, re=re, time=time)
exec(compile(ast.Module(body=[n for n in source.body if isinstance(n, ast.FunctionDef)
                             and n.name in names], type_ignores=[]), "app.py", "exec"), namespace)


class GuardTests(unittest.TestCase):
    def test_settings(self):
        for device, layers in (("auto", -1), ("cpu", 0), ("gpu", 999)):
            self.assertEqual(namespace["llama_guard_settings"](device, 0),
                             ({"num_gpu": layers}, 0.0))
        for threshold in (-1, 2, "nan", "inf"):
            with self.assertRaises(ValueError):
                namespace["llama_guard_settings"]("auto", threshold)
        with self.assertRaises(ValueError):
            namespace["llama_guard_settings"]("invalid")
        self.assertIsNone(namespace["llama_guard_settings"]("auto", "")[1])

    def test_threshold(self):
        response = SimpleNamespace(text="safe", raw={"logprobs": [
            {"token": "safe", "logprob": math.log(.7),
             "top_logprobs": [{"token": "unsafe", "logprob": math.log(.3)}]}]})
        classify = namespace["llama_guard_threshold_result"]
        result = classify(response, .2)
        self.assertEqual(result["label"], "unsafe")
        self.assertEqual(result["model_label"], "safe")
        self.assertAlmostEqual(result["malicious_score"], .3)
        self.assertEqual(classify(response, .5)["label"], "safe")
        self.assertEqual(classify(response, 0)["label"], "unsafe")
        self.assertEqual(classify(response, 1)["label"], "safe")

    def test_unsupported_and_default(self):
        response = SimpleNamespace(text="unsafe\nS1", raw={})
        classify = namespace["llama_guard_threshold_result"]
        self.assertEqual(classify(response, None)["categories"], ["S1"])
        with self.assertRaisesRegex(ValueError, "did not return"):
            classify(response, .5)

    def test_payload_and_both_stages(self):
        post = Mock()
        post.return_value.json.return_value = {"message": {"content": "safe"}, "done": True}
        namespace.update(requests=SimpleNamespace(post=post), decrypt_secret=lambda _: "",
                         extra_headers=lambda _: {}, uses_custom_endpoint=lambda _: False,
                         join_url=lambda base, path: base + path,
                         ProviderResponse=lambda *args: SimpleNamespace(text=args[0], raw=args[1]))
        profile = SimpleNamespace(api_key_enc="", timeout_seconds=120, verify_tls=True,
                                  adapter="ollama", base_url="http://test")
        result = namespace["llama_guard_evaluate"]({"text": "hello"}, "hi", profile,
                                                   "guard", device="cpu", timeout_seconds=42)
        self.assertEqual(post.call_count, 2)
        self.assertEqual(result["output"]["label"], "safe")
        payload = post.call_args.kwargs["json"]
        self.assertEqual(payload["options"]["num_gpu"], 0)
        self.assertEqual(post.call_args.kwargs["timeout"], 42)
        self.assertEqual(payload["messages"][-1]["role"], "assistant")
        self.assertNotIn("logprobs", payload)
        with self.assertRaises(ValueError):
            namespace["llama_guard_evaluate"]({"text": "hi"}, "", profile, "guard",
                                               mode="input", threshold=.5)
        self.assertTrue(post.call_args.kwargs["json"]["logprobs"])
        self.assertEqual(post.call_args.kwargs["json"]["top_logprobs"], 20)


if __name__ == "__main__":
    unittest.main()
