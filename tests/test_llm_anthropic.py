"""Anthropic tool-use path of the agent loop, against a fake API (no key, no network)."""
import os
import unittest
from unittest import mock

from guardian import llm

CFG = {"llm": {"provider": "anthropic", "model": "claude-haiku-4-5", "base_url": ""}}
TOOLS = [{"type": "function", "function": {"name": "read_file", "description": "d",
                                           "parameters": {"type": "object", "properties": {"path": {"type": "string"}}}}}]


class AnthropicLoop(unittest.TestCase):
    def test_tool_call_then_answer(self):
        sent = []
        replies = [
            {"model": "m", "content": [{"type": "text", "text": "looking"},
                                       {"type": "tool_use", "id": "t1", "name": "read_file", "input": {"path": "a.js"}}]},
            {"model": "m", "content": [{"type": "text", "text": "done. VERDICT: unclear"}]},
        ]

        def fake_post(url, body, headers, timeout, retries=2):
            sent.append(body)
            return replies[len(sent) - 1]

        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "x"}), mock.patch.object(llm, "_post", fake_post):
            self.assertTrue(llm.agentic_ok(CFG))
            text, calls = llm.run_loop(CFG, "sys", "user", TOOLS, lambda n, a: f"contents of {a['path']}")
        self.assertEqual(text, "done. VERDICT: unclear")
        self.assertEqual(calls, [{"tool": "read_file", "args": {"path": "a.js"}}])
        self.assertEqual(sent[0]["system"], "sys")
        self.assertEqual(sent[0]["tools"][0]["input_schema"]["type"], "object")
        result = sent[1]["messages"][-1]["content"][0]   # tool output goes back as a tool_result, wrapped as untrusted DATA
        self.assertEqual((result["type"], result["tool_use_id"]), ("tool_result", "t1"))
        self.assertIn("<DATA>", result["content"])
        self.assertEqual(sent[1]["messages"][-2]["content"][1]["type"], "tool_use")


if __name__ == "__main__":
    unittest.main()
