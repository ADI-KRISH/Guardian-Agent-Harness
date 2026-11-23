"""Failover between OpenAI-compatible endpoints on 429 / credit / outage (fake _post, no network)."""
import os
import unittest
from unittest import mock

from guardian import llm

CFG = {"llm": {"provider": "openai", "model": "big", "base_url": "https://a.example/v1"}}
OK = {"model": "small", "choices": [{"message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}]}
ENV = {"GUARDIAN_API_KEY": "k1", "GUARDIAN_FALLBACK_1": "https://b.example/v1|small|k2", "GUARDIAN_FALLBACK_2": "http://localhost:11434/v1|llama3.2|ollama"}


class Failover(unittest.TestCase):
    def setUp(self):
        llm._COOLDOWN.clear()

    def _run(self, failing, bad="HTTP 429 rate_limit_exceeded: slow down"):
        urls = []

        def fake_post(url, body, headers, timeout, retries=2):
            urls.append((url.split("/v1")[0], body["model"], headers["Authorization"]))
            if url.split("/v1")[0] in failing:
                raise llm.LLMError(bad)
            return OK
        with mock.patch.dict(os.environ, ENV), mock.patch.object(llm, "_post", fake_post):
            m, _ = llm.chat(CFG, [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}], None)
            m2, _ = llm.chat(CFG, [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}], None)
        return urls, m

    def test_429_moves_to_next_endpoint_with_its_own_model_and_key(self):
        urls, m = self._run({"https://a.example"})
        self.assertEqual(urls[0], ("https://a.example", "big", "Bearer k1"))
        self.assertEqual(urls[1], ("https://b.example", "small", "Bearer k2"))
        self.assertEqual(m["content"], "hi")

    def test_failed_endpoint_is_skipped_during_cooldown(self):
        urls, _ = self._run({"https://a.example"})
        self.assertEqual([u[0] for u in urls], ["https://a.example", "https://b.example", "https://b.example"])   # 2nd call goes straight to b

    def test_chain_ends_at_local_ollama(self):
        urls, _ = self._run({"https://a.example", "https://b.example"}, bad="HTTP 402 insufficient_quota: no credits")
        self.assertEqual(urls[2][:2], ("http://localhost:11434", "llama3.2"))

    def test_bad_request_is_not_failed_over(self):
        with self.assertRaises(llm.LLMError):
            self._run({"https://a.example"}, bad="HTTP 400 invalid_request: bad body")


if __name__ == "__main__":
    unittest.main()
