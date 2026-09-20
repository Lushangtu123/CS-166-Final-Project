import asyncio
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from urllib.error import URLError


WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

from config import load_settings
from sender_history import (
    DisabledSenderHistoryStore,
    SenderHistoryResult,
    UpstashSenderHistoryStore,
    build_sender_history_store,
    canonicalize_sender_address,
    sender_history_key,
)


class _Response:
    def __init__(self, payload):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps(self._payload).encode("utf-8")


class SenderIdentityTests(unittest.TestCase):
    def test_canonicalization_matches_existing_alias_rules(self):
        self.assertEqual(
            canonicalize_sender_address("A.Lice+shopping@GMAIL.com"),
            "alice@gmail.com",
        )
        self.assertEqual(
            canonicalize_sender_address("alice+shopping@outlook.com"),
            "alice@outlook.com",
        )
        self.assertEqual(
            canonicalize_sender_address("alice+bad tag@outlook.com"),
            "alice+bad tag@outlook.com",
        )

    def test_custom_domains_do_not_assume_plus_addressing(self):
        self.assertEqual(
            canonicalize_sender_address("alice+sales@example.com"),
            "alice+sales@example.com",
        )
        self.assertNotEqual(
            sender_history_key("alice+sales@example.com", "a" * 32),
            sender_history_key("alice@example.com", "a" * 32),
        )

    def test_googlemail_aliases_follow_gmail_canonicalization(self):
        self.assertEqual(
            canonicalize_sender_address("A.Lice+shopping@googlemail.com"),
            "alice@googlemail.com",
        )

    def test_hmac_key_is_deterministic_secret_scoped_and_opaque(self):
        address = "alice.smith@gmail.com"
        first = sender_history_key(address, "a" * 32)
        equivalent = sender_history_key("a.licesmith+tag@gmail.com", "a" * 32)
        other_secret = sender_history_key(address, "b" * 32)

        self.assertEqual(first, equivalent)
        self.assertNotEqual(first, other_secret)
        self.assertTrue(first.startswith("sender-history:v1:"))
        self.assertNotIn("alice", first)
        self.assertNotIn("gmail", first)

    def test_public_history_contract_is_coarse_and_service_scoped(self):
        payload = SenderHistoryResult(
            status="previously_seen",
            first_seen_at="2026-09-01T00:00:00Z",
            last_seen_at="2026-09-20T00:00:00Z",
            seen_count=12,
        ).as_dict()

        self.assertEqual(payload, {
            "sender_history_status": "previously_seen",
            "sender_history_scope": "this_service_history",
        })


class SenderHistoryStoreTests(unittest.TestCase):
    def settings(self):
        return load_settings({
            "APP_ENV": "test",
            "SENDER_HISTORY_ENABLED": "true",
            "UPSTASH_REDIS_REST_URL": "https://example.upstash.io",
            "UPSTASH_REDIS_REST_TOKEN": "token-value",
            "SENDER_HISTORY_HMAC_KEY": "k" * 32,
            "SENDER_HISTORY_RETENTION_DAYS": "90",
            "SENDER_HISTORY_TIMEOUT_SECONDS": "0.5",
        })

    def test_disabled_store_never_performs_network_io(self):
        store = DisabledSenderHistoryStore()

        lookup = asyncio.run(store.lookup("alice@gmail.com"))
        observed = asyncio.run(store.observe("alice@gmail.com"))

        self.assertEqual(lookup.status, "disabled")
        self.assertEqual(observed.status, "disabled")
        self.assertIsNone(lookup.seen_count)

    def test_default_http_client_disables_redirects_to_protect_bearer_token(self):
        with patch("sender_history.build_opener") as build_opener:
            secure_opener = build_opener.return_value
            store = UpstashSenderHistoryStore(self.settings())

        build_opener.assert_called_once()
        handler = build_opener.call_args.args[0]
        self.assertEqual(type(handler).__name__, "_NoRedirectHandler")
        self.assertIs(store._opener, secure_opener.open)

    def test_atomic_observation_uses_only_hmac_key_and_returns_first_seen(self):
        captured = []

        def opener(request, timeout):
            captured.append((request, timeout))
            return _Response([{"result": [1, 1789862400, 1789862400, 1]}])

        store = UpstashSenderHistoryStore(
            self.settings(),
            opener=opener,
            clock=lambda: 1789862400,
        )
        result = asyncio.run(store.observe("alice.smith@gmail.com"))

        self.assertEqual(result.status, "first_seen")
        self.assertEqual(result.seen_count, 1)
        self.assertEqual(result.first_seen_at, "2026-09-20T00:00:00Z")
        request, timeout = captured[0]
        body = request.data.decode("utf-8")
        self.assertEqual(timeout, 0.5)
        self.assertIn('"EVAL"', body)
        self.assertIn("math.min", body)
        self.assertIn("math.max", body)
        self.assertIn(str(90 * 86400), body)
        self.assertNotIn("alice", body)
        self.assertNotIn("gmail", body)
        self.assertEqual(request.full_url, "https://example.upstash.io/pipeline")
        self.assertEqual(request.headers["Authorization"], "Bearer token-value")

    def test_read_only_lookup_does_not_use_mutating_redis_commands(self):
        captured = []

        def opener(request, timeout):
            captured.append(json.loads(request.data.decode("utf-8")))
            return _Response([{"result": [1789862400, 1789948800, 2]}])

        store = UpstashSenderHistoryStore(
            self.settings(), opener=opener, clock=lambda: 1789948800,
        )
        result = asyncio.run(store.lookup("alice@gmail.com"))

        self.assertEqual(result.status, "previously_seen")
        self.assertEqual(result.seen_count, 2)
        commands = captured[0]
        self.assertEqual(commands[0][0], "HMGET")
        self.assertNotIn("HINCRBY", json.dumps(commands))
        self.assertNotIn("EXPIRE", json.dumps(commands))

    def test_missing_record_is_not_seen(self):
        store = UpstashSenderHistoryStore(
            self.settings(),
            opener=lambda *_args, **_kwargs: _Response([
                {"result": [None, None, None]}
            ]),
        )

        result = asyncio.run(store.lookup("nobody@gmail.com"))

        self.assertEqual(result.status, "not_seen")
        self.assertIsNone(result.seen_count)

    def test_corrupt_existing_record_fails_open_instead_of_showing_false_history(self):
        cases = (
            [1789948800, 1789862400, 1],
            [1789862400, 1789948800, 0],
        )
        for values in cases:
            with self.subTest(values=values):
                store = UpstashSenderHistoryStore(
                    self.settings(),
                    opener=lambda *_args, **_kwargs: _Response([
                        {"result": values}
                    ]),
                )

                result = asyncio.run(store.lookup("alice@gmail.com"))

                self.assertEqual(result.status, "unavailable")
                self.assertIsNone(result.seen_count)

    def test_network_and_malformed_responses_fail_open_without_secrets(self):
        cases = (
            lambda *_args, **_kwargs: (_ for _ in ()).throw(URLError("token-value")),
            lambda *_args, **_kwargs: _Response({"unexpected": "token-value"}),
        )
        for opener in cases:
            with self.subTest(opener=opener):
                store = UpstashSenderHistoryStore(self.settings(), opener=opener)
                result = asyncio.run(store.observe("alice@gmail.com"))
                self.assertEqual(result.status, "unavailable")
                self.assertIsNone(result.seen_count)
                self.assertNotIn("token-value", result.error or "")
                self.assertNotIn("alice", result.error or "")

    def test_distributed_rate_limit_uses_an_opaque_key_and_returns_retry_after(self):
        captured = []
        responses = iter((
            _Response([{"result": [1, 60]}]),
            _Response([{"result": [11, 37]}]),
        ))

        def opener(request, timeout):
            captured.append((json.loads(request.data.decode("utf-8")), timeout))
            return next(responses)

        store = UpstashSenderHistoryStore(self.settings(), opener=opener)
        allowed = asyncio.run(store.check_rate_limit(
            "203.0.113.9:/api/analyze-content", limit=10, window_seconds=60,
        ))
        blocked = asyncio.run(store.check_rate_limit(
            "203.0.113.9:/api/analyze-content", limit=10, window_seconds=60,
        ))

        self.assertTrue(allowed.allowed)
        self.assertEqual(allowed.retry_after, 0)
        self.assertFalse(blocked.allowed)
        self.assertEqual(blocked.retry_after, 37)
        body = json.dumps(captured[0][0])
        self.assertIn('"EVAL"', body)
        self.assertIn('"10"', body)
        self.assertIn('"60"', body)
        self.assertNotIn("203.0.113.9", body)
        self.assertNotIn("analyze-content", body)
        self.assertEqual(captured[0][1], 0.5)

    def test_distributed_rate_limit_fails_open_when_upstash_is_unavailable(self):
        store = UpstashSenderHistoryStore(
            self.settings(),
            opener=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                URLError("token-value")
            ),
        )

        decision = asyncio.run(store.check_rate_limit(
            "203.0.113.9:/api/analyze-content", limit=10, window_seconds=60,
        ))

        self.assertIsNone(decision)

    def test_disabled_store_skips_distributed_rate_limiting(self):
        decision = asyncio.run(DisabledSenderHistoryStore().check_rate_limit(
            "203.0.113.9:/api/analyze-content", limit=10, window_seconds=60,
        ))

        self.assertIsNone(decision)

    def test_builder_uses_disabled_store_for_missing_or_invalid_configuration(self):
        disabled = build_sender_history_store(load_settings({"APP_ENV": "test"}))
        partial = build_sender_history_store(load_settings({
            "APP_ENV": "test",
            "SENDER_HISTORY_ENABLED": "true",
            "UPSTASH_REDIS_REST_URL": "https://example.upstash.io",
        }))

        self.assertIsInstance(disabled, DisabledSenderHistoryStore)
        self.assertIsInstance(partial, DisabledSenderHistoryStore)
        self.assertEqual(asyncio.run(disabled.lookup("alice@gmail.com")).status, "disabled")
        self.assertEqual(asyncio.run(partial.lookup("alice@gmail.com")).status, "unavailable")


if __name__ == "__main__":
    unittest.main()
