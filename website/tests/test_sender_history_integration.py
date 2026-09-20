import asyncio
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app
from sender_history import SenderHistoryResult, canonicalize_sender_address


class _FakeHistoryStore:
    def __init__(self, *, lookup_result=None, observe_result=None):
        self.lookup_result = lookup_result or SenderHistoryResult(status="not_seen")
        self.observe_result = observe_result or SenderHistoryResult(
            status="first_seen",
            first_seen_at="2026-09-20T00:00:00Z",
            last_seen_at="2026-09-20T00:00:00Z",
            seen_count=1,
        )
        self.lookup_calls = []
        self.observe_calls = []

    async def lookup(self, address):
        self.lookup_calls.append(address)
        return self.lookup_result

    async def observe(self, address):
        self.observe_calls.append(address)
        return self.observe_result


class SenderHistoryIntegrationTests(unittest.TestCase):
    def analyze_sender(self, address):
        return json.loads(asyncio.run(
            app.analyze_email(app.EmailRequest(email=address))
        ).body)

    def analyze_raw(self, raw_email):
        return json.loads(asyncio.run(
            app.analyze_content_endpoint(app.ContentRequest(raw_email=raw_email))
        ).body)

    def test_sender_only_analysis_is_read_only_and_risk_neutral(self):
        store = _FakeHistoryStore()
        baseline = app._analyze_sender_address("alice@gmail.com")

        with patch.object(app, "_sender_history_store", store):
            result = self.analyze_sender("alice@gmail.com")

        self.assertEqual(store.lookup_calls, ["alice@gmail.com"])
        self.assertEqual(store.observe_calls, [])
        self.assertEqual(result["risk_score"], baseline["risk_score"])
        self.assertEqual(
            result["account_observability"],
            "provider_account_unverifiable",
        )
        self.assertEqual(result["sender_history_status"], "not_seen")
        self.assertEqual(result["sender_history_scope"], "this_deployment_only")

    def test_sender_history_uses_the_accepted_idna_and_root_dot_normalization(self):
        store = _FakeHistoryStore()

        with patch.object(app, "_sender_history_store", store):
            self.analyze_sender("user@éxample.com")
            self.analyze_sender("alice@gmail.com.")

        self.assertEqual(store.lookup_calls, [
            "user@xn--xample-9ua.com",
            "alice@gmail.com",
        ])

    def test_raw_email_records_canonical_aliases_once(self):
        store = _FakeHistoryStore()
        raw_email = """From: Alice <a.lice+shopping@gmail.com>, Alice Alias <alice@gmail.com>
To: user@example.com
Subject: Project update

Here is the requested update.
"""

        with patch.object(app, "_sender_history_store", store):
            result = self.analyze_raw(raw_email)

        self.assertEqual(len(store.observe_calls), 1)
        self.assertEqual(
            canonicalize_sender_address(store.observe_calls[0]),
            "alice@gmail.com",
        )
        self.assertEqual(store.lookup_calls, [])
        self.assertEqual(result["sender_analysis"]["sender_history_status"], "first_seen")
        self.assertEqual(result["sender_analysis"]["sender_seen_count"], 1)
        self.assertEqual(result["total_score"], 0)

    def test_ambiguous_from_headers_observe_only_the_selected_riskiest_sender(self):
        store = _FakeHistoryStore()
        raw_email = """From: Alice <alice@example.com>
From: Security <notice@paypa1-verify.example>
To: user@example.com
Subject: Account update

Review the attached notice.
"""

        with patch.object(app, "_sender_history_store", store):
            result = self.analyze_raw(raw_email)

        self.assertEqual(store.observe_calls, ["notice@paypa1-verify.example"])
        self.assertEqual(
            result["sender_analysis"]["email"],
            "notice@paypa1-verify.example",
        )

    def test_nested_messages_do_not_amplify_sender_history_requests(self):
        store = _FakeHistoryStore()
        raw_email = """From: Outer Sender <outer@example.com>
To: user@example.com
Subject: Forwarded message
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="outer-boundary"

--outer-boundary
Content-Type: text/plain; charset=utf-8

See the attached message.
--outer-boundary
Content-Type: message/rfc822

From: Nested Sender <nested@paypa1-verify.example>
To: outer@example.com
Subject: Urgent verification

Verify your password now.
--outer-boundary--
"""

        with patch.object(app, "_sender_history_store", store):
            self.analyze_raw(raw_email)

        self.assertEqual(store.observe_calls, ["outer@example.com"])
        self.assertEqual(store.lookup_calls, [])

    def test_missing_sender_does_not_create_history(self):
        store = _FakeHistoryStore()
        raw_email = """To: user@example.com
Subject: Project update

Here is the requested update.
"""

        with patch.object(app, "_sender_history_store", store):
            result = self.analyze_raw(raw_email)

        self.assertEqual(store.observe_calls, [])
        self.assertNotIn("sender_analysis", result)

    def test_previously_seen_history_never_suppresses_phishing_evidence(self):
        store = _FakeHistoryStore(observe_result=SenderHistoryResult(
            status="previously_seen",
            first_seen_at="2026-09-01T00:00:00Z",
            last_seen_at="2026-09-20T00:00:00Z",
            seen_count=50,
        ))
        raw_email = """From: Security <alice@outlook.com>
To: user@example.com
Subject: Urgent account verification

Your mailbox will be suspended. Confirm your password now at http://paypa1-secure.example/login
"""

        with patch.object(app, "_sender_history_store", store):
            result = self.analyze_raw(raw_email)

        self.assertIn(result["risk_level"], {"high", "critical"})
        self.assertEqual(
            result["sender_analysis"]["sender_history_status"],
            "previously_seen",
        )
        self.assertEqual(result["sender_analysis"]["sender_seen_count"], 50)

    def test_disposable_and_privacy_relay_categories_are_not_account_age_claims(self):
        store = _FakeHistoryStore()
        with patch.object(app, "_sender_history_store", store):
            disposable = self.analyze_sender("user@mailinator.com")
            relay = self.analyze_sender("user@simplelogin.com")

        self.assertEqual(disposable["account_observability"], "not_applicable")
        self.assertEqual(relay["account_observability"], "not_applicable")

    def test_public_capability_output_is_secret_free(self):
        health = json.loads(asyncio.run(app.health()).body)
        config = json.loads(asyncio.run(app.get_public_config()).body)

        for payload in (health, config):
            self.assertIn("sender_history_enabled", payload)
            self.assertIn("sender_history_available", payload)
            serialized = json.dumps(payload)
            self.assertNotIn("UPSTASH_REDIS_REST_TOKEN", serialized)
            self.assertNotIn("SENDER_HISTORY_HMAC_KEY", serialized)


if __name__ == "__main__":
    unittest.main()
