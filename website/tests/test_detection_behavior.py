import asyncio
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app
import content_model
from config import Settings


class SenderRiskAnalysisTests(unittest.TestCase):
    def test_equivalent_idn_and_trailing_dot_use_identical_sender_rules(self):
        for domain in ('secure-例子.xyz', 'gmail.com'):
            encoded = domain.encode('idna').decode()
            scores = [self.analyze('billing@' + variant)['risk_score']
                      for variant in (domain, encoded, encoded + '.')]
            self.assertEqual(len(set(scores)), 1)

    def test_sender_endpoint_rejects_non_address_input(self):
        for value in ("hello", "Full email authenticity verification is disabled.",
                      "a@@example.com", "a b@example.com", "a..b@example.com", "a@example"):
            with self.subTest(value=value):
                with self.assertRaises(app.HTTPException) as error:
                    self.analyze(value)
                self.assertEqual(error.exception.status_code, 400)
                self.assertIn("email address", error.exception.detail.lower())

    def test_sender_endpoint_accepts_supported_address_patterns(self):
        for value in ("alice+shopping@gmail.com", "admin99@192.168.1.1", "user@例子.com"):
            with self.subTest(value=value):
                self.assertIn("risk_score", self.analyze(value))

    def analyze(self, address: str) -> dict:
        response = asyncio.run(app.analyze_email(app.EmailRequest(email=address)))
        return json.loads(response.body)

    def test_sender_analysis_is_honest_heuristic_not_uci_probability(self):
        result = self.analyze("security-alert@paypa1-verify.xyz")

        self.assertEqual(result["analysis_method"], "sender-domain-heuristics")
        self.assertNotIn("phishing_probability", result)
        self.assertGreaterEqual(result["risk_score"], 60)
        self.assertIn(result["verdict"], {"high", "critical"})

    def test_known_provider_has_low_sender_risk(self):
        result = self.analyze("alice@gmail.com")

        self.assertLess(result["risk_score"], 20)
        self.assertEqual(result["verdict"], "low")

    def test_digit_substitution_brand_domains_are_high_risk_by_themselves(self):
        for domain in (
            "paypa1.com",
            "g00gle.com",
            "app1e.com",
            "n3tflix.com",
            "micro5oft.com",
            "6oogle.com",
            "p4ypal.com",
        ):
            with self.subTest(domain=domain):
                result = self.analyze(f"alice@{domain}")
                self.assertIn(result["verdict"], {"high", "critical"})
                self.assertTrue(any(
                    "impersonate" in indicator["msg"].lower()
                    for indicator in result["risk_indicators"]
                ))

    def test_plain_brand_substring_keeps_its_existing_non_decisive_score(self):
        result = self.analyze("alice@paypalcommunity.com")

        self.assertNotIn(result["verdict"], {"high", "critical"})
        self.assertLess(result["risk_score"], 60)
        self.assertFalse(any(
            "character substitution" in indicator["msg"].lower()
            for indicator in result["risk_indicators"]
        ))

    def test_public_suffix_parsing_uses_the_registrable_domain(self):
        ordinary = self.analyze("alice@mail.company.co.uk")
        ordinary_messages = [item["msg"] for item in ordinary["risk_indicators"]]
        self.assertTrue(any("company.co.uk" in message for message in ordinary_messages))
        self.assertFalse(any("Domain (co.uk)" in message for message in ordinary_messages))
        self.assertFalse(any("subdomain levels" in message for message in ordinary_messages))
        self.assertFalse(any("TLD '.uk' is uncommon" in message for message in ordinary_messages))

        lookalike = self.analyze("alice@paypa1.co.uk")
        self.assertIn(lookalike["verdict"], {"high", "critical"})
        self.assertTrue(any(
            "impersonate 'paypal'" in indicator["msg"].lower()
            for indicator in lookalike["risk_indicators"]
        ))


class DisposableEmailClassificationTests(unittest.TestCase):
    def analyze(self, address: str) -> dict:
        return app._analyze_sender_address(address)

    def assert_status(self, result: dict, expected: str) -> None:
        self.assertIn("disposable_status", result)
        self.assertEqual(result["disposable_status"], expected)

    def test_multilabel_disposable_domains_are_confirmed(self):
        for address, matched_domain in (
            ("user@10minutemail.co.uk", "10minutemail.co.uk"),
            ("user@guerrillamail.co.uk", "guerrillamail.co.uk"),
            ("user@inbound.mailinator.com", "mailinator.com"),
        ):
            with self.subTest(address=address):
                result = self.analyze(address)
                self.assert_status(result, "known_disposable_provider")
                self.assertEqual(result["disposable_confidence"], "confirmed")
                self.assertEqual(result["matched_provider_domain"], matched_domain)
                self.assertTrue(result["is_disposable"])
                self.assertFalse(result["is_suspected_disposable"])

    def test_random_major_provider_mailbox_is_suspicious_not_confirmed(self):
        for address in (
            "xq7m9v2k4p8z@gmail.com",
            "xq7m9v2k4p8z@outlook.com",
        ):
            with self.subTest(address=address):
                result = self.analyze(address)
                self.assert_status(result, "suspicious_mailbox_pattern")
                self.assertEqual(result["disposable_confidence"], "heuristic")
                self.assertFalse(result["is_disposable"])
                self.assertTrue(result["is_suspected_disposable"])
                self.assertNotIn(result["verdict"], {"high", "critical"})
                self.assertEqual(result["med_risk_count"], 1)
                self.assertEqual(result["risk_score"], 10)

    def test_confirmed_provider_is_context_not_phishing_evidence(self):
        for address in ("user@mailinator.com", "xq7m9v2k4p8z@mailinator.com"):
            with self.subTest(address=address):
                result = self.analyze(address)
                self.assert_status(result, "known_disposable_provider")
                self.assertEqual(result["high_risk_count"], 0)
                self.assertEqual(result["med_risk_count"], 0)
                self.assertEqual(result["risk_score"], 0)
                provider_indicators = [r for r in result["risk_indicators"]
                                       if "disposable-email provider" in r["msg"]]
                self.assertEqual(len(provider_indicators), 1)
                self.assertEqual(provider_indicators[0]["level"], "info")

    def test_apple_private_relay_domains_are_recognized_without_guessing_icloud(self):
        for domain in ("privaterelay.appleid.com", "private.icloud.com"):
            result = self.analyze(f"user@{domain}")
            self.assert_status(result, "privacy_relay")
            self.assertEqual(result["risk_score"], 0)
            self.assert_status(self.analyze(f"user@{domain}.evil.example"), "no_known_match")
        self.assert_status(self.analyze("user@icloud.com"), "no_known_match")

    def test_disposable_provider_does_not_suppress_other_sender_risks(self):
        result = self.analyze("user@one.two.three.mailinator.com")
        self.assert_status(result, "known_disposable_provider")
        self.assertGreater(result["risk_score"], 0)
        self.assertTrue(any("subdomain levels" in r["msg"] for r in result["risk_indicators"]))

    def test_ordinary_major_provider_mailboxes_remain_unconfirmed(self):
        for address in ("alice.smith@gmail.com", "alice.smith@outlook.com"):
            with self.subTest(address=address):
                result = self.analyze(address)
                self.assert_status(result, "no_known_match")
                self.assertEqual(result["disposable_confidence"], "unknown")
                self.assertFalse(result["is_disposable"])
                self.assertFalse(result["is_suspected_disposable"])
                self.assertEqual(result["verdict"], "low")
                self.assertEqual(result["risk_score"], 0)

    def test_privacy_relays_are_informational_not_phishing_evidence(self):
        for matched_domain in sorted(app.PRIVACY_RELAY_DOMAINS):
            address = f"user@{matched_domain}"
            with self.subTest(address=address):
                result = self.analyze(address)
                self.assert_status(result, "privacy_relay")
                self.assertEqual(result["matched_provider_domain"], matched_domain)
                self.assertFalse(result["is_disposable"])
                self.assertFalse(result["is_suspected_disposable"])
                self.assertEqual(result["risk_score"], 0)

        for address in (
            "xq7m9v2k4p8z@relay.firefox.com",
            "user@sub.relay.firefox.com",
        ):
            with self.subTest(address=address):
                result = self.analyze(address)
                self.assert_status(result, "privacy_relay")
                self.assertEqual(result["risk_score"], 0)
                self.assertEqual(result["phish_feature_count"], 0)

    def test_simplelogin_alias_domains_are_privacy_relays(self):
        for domain in (
            "simplelogin.com",
            "simplelogin.co",
            "simplelogin.fr",
            "simplelogin.io",
            "aleeas.com",
            "slmails.com",
            "silomails.com",
            "slmail.me",
        ):
            with self.subTest(domain=domain):
                result = self.analyze(f"user@{domain}")
                self.assert_status(result, "privacy_relay")
                self.assertEqual(result["matched_provider_domain"], domain)
                self.assertEqual(result["risk_score"], 0)

    def test_subaddressing_does_not_increase_sender_risk(self):
        base = self.analyze("alice.smith@outlook.com")
        for address in (
            "alice.smith+shopping@outlook.com",
            "alice.smith+http@outlook.com",
            "alice.smith+sale%2026@outlook.com",
            "alice.smith+this-is-a-very-long-but-benign-routing-tag@outlook.com",
        ):
            with self.subTest(address=address):
                tagged = self.analyze(address)
                self.assertIn("address_alias_type", tagged)
                self.assertEqual(tagged["address_alias_type"], "subaddress")
                self.assertEqual(tagged["risk_score"], base["risk_score"])
                self.assertEqual(tagged["disposable_status"], base["disposable_status"])

    def test_custom_domain_plus_local_part_is_not_claimed_as_an_alias(self):
        result = self.analyze("alice+sales@example.com")

        self.assertIsNone(result["address_alias_type"])

    def test_gmail_dot_variant_uses_the_same_sender_risk(self):
        for compact_address, dotted_address in (
            ("alicesmith@gmail.com", "alice.smith@gmail.com"),
            ("andrewburns@gmail.com", "andrew.burns@gmail.com"),
            (
                "christopherrichardson@gmail.com",
                "c.h.r.i.s.t.o.p.h.e.r.r.i.c.h.a.r.d.s.o.n@gmail.com",
            ),
        ):
            with self.subTest(dotted_address=dotted_address):
                compact = self.analyze(compact_address)
                dotted = self.analyze(dotted_address)

                self.assertEqual(dotted["risk_score"], compact["risk_score"])
                self.assertEqual(dotted["disposable_status"], "no_known_match")
                self.assertEqual(dotted["verdict"], "low")

    def test_composite_randomness_does_not_duplicate_component_indicators(self):
        result = self.analyze("zzzzzzz1a2b3@example.com")
        messages = [indicator["msg"].lower() for indicator in result["risk_indicators"]]

        self.assert_status(result, "suspicious_mailbox_pattern")
        self.assertEqual(sum("randomness factors" in msg for msg in messages), 1)
        self.assertFalse(any("repeated characters" in msg for msg in messages))

    def test_disposable_substrings_do_not_confirm_unrelated_domains(self):
        for address in (
            "user@discardrecords.com",
            "user@lastmailbox.com",
            "user@jetableconsulting.com",
            "user@mailinator.com.evil.example",
            "user@relay.firefox.com.evil.example",
        ):
            with self.subTest(address=address):
                result = self.analyze(address)
                self.assert_status(result, "no_known_match")
                self.assertFalse(result["is_disposable"])
                self.assertNotIn(result["verdict"], {"high", "critical"})

    def test_anchored_temporary_domain_pattern_is_heuristic_only(self):
        for address in (
            "user@tempmail2026.example",
            "user@temp-mail2026.example",
            "user@temporary-email2026.example",
            "user@trash-mail2026.example",
            "user@fake-inbox2026.example",
        ):
            with self.subTest(address=address):
                result = self.analyze(address)
                self.assert_status(result, "suspicious_domain_pattern")
                self.assertEqual(result["disposable_confidence"], "heuristic")
                self.assertFalse(result["is_disposable"])
                self.assertTrue(result["is_suspected_disposable"])

    def test_domain_registries_are_normalized_and_disjoint(self):
        privacy_relays = getattr(app, "PRIVACY_RELAY_DOMAINS", set())

        self.assertTrue(privacy_relays)
        self.assertTrue(all(domain == domain.strip().lower().rstrip(".")
                            for domain in app._DISPOSABLE_DOMAIN_SOURCE))
        self.assertTrue(all(app._REGISTRY_DOMAIN_RE.fullmatch(domain)
                            for domain in app._DISPOSABLE_DOMAIN_SOURCE))
        self.assertTrue(all(domain == domain.lower() for domain in app.DISPOSABLE_DOMAINS))
        self.assertTrue(all(domain == domain.lower() for domain in privacy_relays))
        self.assertTrue(app.DISPOSABLE_DOMAINS.isdisjoint(privacy_relays))

    def test_disposable_registry_has_versioned_provenance(self):
        metadata = getattr(app, "DISPOSABLE_REGISTRY_METADATA", None)
        self.assertIsNotNone(metadata, "disposable registry metadata is missing")
        self.assertEqual(metadata.get("schema"), "phishguard-disposable-domains-v1")
        self.assertRegex(metadata.get("version", ""), r"^\d{4}\.\d{2}\.\d{2}$")
        self.assertEqual(metadata.get("domain_count"), len(app._DISPOSABLE_DOMAIN_SOURCE))
        self.assertTrue(metadata.get("provenance"))


class ContentRuleRobustnessTests(unittest.TestCase):
    def test_insufficient_context_keeps_rules_and_marks_clean_result_incomplete(self):
        abstention = {
            "ml_status": "insufficient_context",
            "ml_phishing_probability": None,
            "ml_legitimate_probability": None,
            "ml_label": None,
            "ml_prediction": None,
            "ml_decision_threshold": 35.1,
            "ml_top_contributors": [],
        }
        with patch.object(app, "_content_pipeline", {
            "decision_threshold": 0.351,
            "metrics": {},
        }), patch.object(app, "predict_content", return_value=abstention):
            result = json.loads(asyncio.run(app.analyze_content_endpoint(
                app.ContentRequest(subject="Meeting notes", body="")
            )).body)

        self.assertEqual(result["ml_status"], "insufficient_context")
        self.assertFalse(result["analysis_complete"])
        self.assertEqual(result["risk_level"], "unknown")
        self.assertIsNone(result["combined_phishing_score"])
        self.assertTrue(any(
            "too little text" in warning.lower()
            for warning in result["analysis_warnings"]
        ))

    def test_insufficient_context_does_not_erase_independent_link_risk(self):
        abstention = {
            "ml_status": "insufficient_context",
            "ml_phishing_probability": None,
            "ml_legitimate_probability": None,
            "ml_label": None,
            "ml_prediction": None,
            "ml_decision_threshold": 35.1,
            "ml_top_contributors": [],
        }
        with patch.object(app, "_content_pipeline", {
            "decision_threshold": 0.351,
            "metrics": {},
        }), patch.object(app, "predict_content", return_value=abstention):
            result = json.loads(asyncio.run(app.analyze_content_endpoint(
                app.ContentRequest(
                    subject="Review",
                    body='<a href="https://paypal.com.login.example">Continue</a>',
                )
            )).body)

        self.assertEqual(result["ml_status"], "insufficient_context")
        self.assertIn(result["risk_level"], {"high", "critical"})
        self.assertIsNotNone(result["combined_phishing_score"])
        self.assertFalse(result["analysis_complete"])

    def test_ml_abstention_keeps_rules_and_marks_clean_result_incomplete(self):
        abstention = {
            "ml_status": "insufficient_feature_coverage",
            "ml_phishing_probability": None,
            "ml_legitimate_probability": None,
            "ml_label": None,
            "ml_prediction": None,
            "ml_decision_threshold": 35.1,
            "ml_top_contributors": [],
        }
        with patch.object(app, "_content_pipeline", {
            "decision_threshold": 0.351,
            "metrics": {},
        }), patch.object(app, "predict_content", return_value=abstention):
            result = json.loads(asyncio.run(app.analyze_content_endpoint(
                app.ContentRequest(subject="会议提醒", body="明天下午三点开会。")
            )).body)

        self.assertEqual(result["ml_status"], "insufficient_feature_coverage")
        self.assertFalse(result["analysis_complete"])
        self.assertEqual(result["risk_level"], "unknown")
        self.assertIsNone(result["combined_phishing_score"])
        self.assertTrue(any(
            "coverage" in warning.lower()
            for warning in result["analysis_warnings"]
        ))

    def test_malformed_link_retains_medium_floor_without_lowering_high_evidence(self):
        malformed = '<a href="https://[broken">Continue</a>'
        for body, expected in ((malformed, 'medium'),
                               (malformed + '<a href="//paypa1.example/">Go</a>', 'high')):
            result = json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(body=body))).body)
            self.assertEqual(result['risk_level'], expected)
            self.assertEqual(result['risk_floor'], expected)

    def test_relative_targets_use_the_first_base_in_the_same_document(self):
        for body, expected in (
            ('<base href="//paypa1.example/"><a href="collect">Continue</a>', 'high'),
            ('<base href="//paypa1.example/"><form action="/collect"></form>', 'high'),
            ('<base href="//paypa1.example/"><form><button formaction="collect">Go</button></form>', 'high'),
            ('<base href="//example.org/"><a href="collect">Continue</a>', 'safe'),
            ('<base href="//example.org/"><base href="//paypa1.example/"><a href="collect">Continue</a>', 'safe'),
            ('<base href="//paypa1.example/"><a href="https://example.org/">Continue</a>', 'safe'),
            ('<a href="collect">Continue</a>', 'safe'),
        ):
            with self.subTest(body=body):
                result = json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(body=body))).body)
                self.assertEqual(result['risk_level'], expected)

    def test_form_targets_and_password_controls_are_inspected(self):
        samples = (
            ('<form action="//paypa1.example/"><input type="password"></form>', 'high'),
            ('<form action="/local"><input type="password"><button formaction="//paypa1.example/">Go</button></form>', 'high'),
            ('<form action="https://example.net/"><input type="password"></form>', 'medium'),
            ('<form action="https://example.net/"><input type="text" name="search"></form>', 'safe'),
        )
        for body, expected in samples:
            with self.subTest(body=body):
                result = json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(body=body))).body)
                self.assertEqual(result['risk_level'], expected)
                if 'password' in body:
                    self.assertTrue(any('password' in i['msg'].lower() for i in result['extra_indicators']))

    def test_shorteners_match_decoded_destination_hosts_only(self):
        for body, expected in (
            ('<a href="https://bit.ly/demo">Review</a>', True),
            ('<a href="https://b&#105;t.ly/demo">Review</a>', True),
            ('<a href="//bit.ly/demo">Review</a>', True),
            ('Read https://bit.ly/demo', True),
            ('We discuss bit.ly without any hyperlinks.', False),
            ('https://notbit.ly.example.com/', False),
            ('https://example.com/?redirect=bit.ly', False),
        ):
            with self.subTest(body=body):
                result = app.analyze_email_content('Note', body)
                self.assertEqual(result['has_shortener'], expected)
                self.assertEqual(any('shortened URLs' in i['msg'] for i in result['extra_indicators']), expected)

    def test_pressure_and_direct_credential_request_set_high_floor(self):
        for body in (
            'Your account has been suspended. Act now, click here and enter your password to verify your account: https://example.net/',
            'URGENT: account suspended. Please provide your password.',
            'Your account has been suspended. Do not delay, enter your password immediately.',
        ):
            with self.subTest(body=body):
                result = json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(body=body))).body)
                self.assertIn(result['risk_level'], {'high', 'critical'})
                self.assertTrue(any('credential request' in i['msg'].lower() for i in result['extra_indicators']))
        for body in (
            'You requested a password reset. Reset your password at https://example.com/reset.',
            'Security reminder: never enter your password from an email link. If your account has been suspended, do not act immediately.',
            'URGENT account suspended. Do not provide your password to anyone.',
        ):
            with self.subTest(negative=body):
                result = json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(body=body))).body)
                self.assertNotIn(result['risk_level'], {'high', 'critical'})

    def test_positive_rule_evidence_never_becomes_no_indicators_verdict(self):
        result = json.loads(asyncio.run(app.analyze_content_endpoint(
            app.ContentRequest(body='Please enter your password.')
        )).body)
        self.assertTrue(result['category_results'])
        self.assertNotEqual(result['risk_level'], 'safe')
        self.assertNotIn('No Phishing Indicators', result['risk_label'])

    def test_html_visible_text_preserves_credential_phrases(self):
        variants = ('Please enter your password.', 'Please enter your <b>password</b>.',
                    'Please enter your p&#97;ssword.', 'Please enter&nbsp;your\npassword.',
                    '<p>Please enter your</p><p>password.</p>')
        for body in variants:
            with self.subTest(body=body):
                result = app.analyze_email_content('Note', body)
                self.assertTrue(any(c['key'] == 'credential' for c in result['category_results']))
        for body in ('<style>.password:after {content: "enter your password"}</style>Hello',
                     '<script>const text = "enter your password";</script>Hello',
                     '<!-- enter your password -->Hello', 'Please enter your name.'):
            with self.subTest(negative=body):
                result = app.analyze_email_content('Note', body)
                self.assertFalse(any(c['key'] == 'credential' for c in result['category_results']))

    def test_generic_login_hostname_alone_does_not_force_high_risk(self):
        for host in ('login.example.com', 'account.example.com', 'secure.example.com'):
            with self.subTest(host=host):
                result = app.analyze_email_content('Note', f'<a href="https://{host}/">Open portal</a>')
                self.assertNotIn(result['risk_level'], {'high', 'critical'})
                self.assertFalse(any(i['level'] == 'high' for i in result['extra_indicators']))
        for destination in ('https://login.paypa1.example/', 'https://paypal.com@account.example.com/',
                            'https://credential-capture.example/'):
            with self.subTest(strong_evidence=destination):
                result = app.analyze_email_content('Note', f'<a href="{destination}">Open portal</a>')
                self.assertIn(result['risk_level'], {'high', 'critical'})

    def test_ip_link_formats_keep_the_same_evidence(self):
        destinations = (
            'http://192.0.2.10/', 'http://[2001:db8::10]/',
            'http://3221225994/', 'http://0xc000020a/', 'http://0300.0.2.012/',
            'http://&#49;&#57;&#50;.0.2.10/', 'http://%31%39%32.0.2.10/',
            '//192.0.2.10/',
        )
        for destination in destinations:
            with self.subTest(destination=destination):
                result = app.analyze_email_content(
                    'Note', f'<a href="{destination}">Review document</a>',
                )
                self.assertTrue(result['has_ip_url'])
                self.assertIn(result['risk_level'], {'high', 'critical'})
                self.assertEqual(sum('IP address' in i['msg'] for i in result['extra_indicators']), 1)
        for destination in ('https://192.0.2.10.example.com/', 'http://4294967296/',
                            'https://example.com/192.0.2.10'):
            with self.subTest(negative_control=destination):
                result = app.analyze_email_content('Note', destination)
                self.assertFalse(result['has_ip_url'])

    def test_protocol_relative_links_keep_destination_evidence(self):
        for ending in ('</a>', ''):
            for prefix in ('https:', ''):
                with self.subTest(ending=ending, prefix=prefix):
                    result = app.analyze_email_content(
                        'Note', f'<a href="{prefix}//paypa1.example/">Review document{ending}',
                    )
                    self.assertIn(result['risk_level'], {'high', 'critical'})
                    self.assertTrue(any('lookalike' in i['msg'] for i in result['extra_indicators']))

    def test_attacker_supplied_footer_does_not_reduce_risk(self):
        lure = (
            "URGENT: account suspended\n"
            "Verify your password immediately by clicking the link below."
        )
        base = app.analyze_email_content("Action required", lure)
        padded = app.analyze_email_content(
            "Action required",
            lure + "\nUnsubscribe | Privacy Policy | All rights reserved",
        )

        self.assertEqual(padded["total_score"], base["total_score"])
        self.assertGreater(len(padded["safety_signals"]), 0)

    def test_html_link_text_mismatch_is_detected(self):
        result = app.analyze_email_content(
            "Shared document",
            '<a href="https://credential-capture.example/login">https://docs.google.com</a>',
        )

        messages = [item["msg"] for item in result["extra_indicators"]]
        self.assertTrue(any("does not match" in message for message in messages))

    def test_suspicious_destination_is_analyzed_without_visible_url(self):
        result = app.analyze_email_content(
            "Document shared",
            '<a href="https://credential-capture.example/view">Review document</a>',
        )

        messages = [item["msg"].lower() for item in result["extra_indicators"]]
        self.assertIn(result["risk_level"], {"high", "critical"})
        self.assertTrue(any("destination" in message for message in messages))

    def test_plain_text_suspicious_url_is_analyzed(self):
        result = app.analyze_email_content(
            "Document shared",
            "Review it at https://credential-capture.example/view",
        )

        self.assertIn(result["risk_level"], {"high", "critical"})

    def test_hxxp_scheme_obfuscation_is_high_risk(self):
        result = app.analyze_email_content(
            "Document shared",
            "Review it at hxxps://credential-capture.example/view",
        )

        messages = [item["msg"].lower() for item in result["extra_indicators"]]
        self.assertIn(result["risk_level"], {"high", "critical"})
        self.assertTrue(any("obfuscated" in message for message in messages))

    def test_zero_width_characters_do_not_hide_credential_phrase(self):
        result = app.analyze_email_content(
            "Account notice",
            "Click here to v\u200berify your acc\u200bount.",
        )

        categories = [item["key"] for item in result["category_results"]]
        self.assertIn("credential", categories)

    def test_bare_visible_domain_mismatch_is_detected(self):
        result = app.analyze_email_content(
            "Receipt",
            '<a href="https://evil.example/view">paypal.com</a>',
        )

        messages = [item["msg"].lower() for item in result["extra_indicators"]]
        self.assertTrue(any("does not match" in message for message in messages))

    def test_idn_confusable_link_destination_is_high_risk(self):
        result = app.analyze_email_content(
            "Document shared",
            '<a href="https://xn--pple-43d.com/view">Review document</a>',
        )

        messages = [item["msg"].lower() for item in result["extra_indicators"]]
        self.assertIn(result["risk_level"], {"high", "critical"})
        self.assertTrue(any("idn" in message or "confusable" in message for message in messages))

    def test_ascii_digit_brand_lookalike_destination_is_high_risk(self):
        result = app.analyze_email_content(
            "Document shared",
            '<a href="https://paypa1.com/view">Review document</a>',
        )

        messages = [item["msg"].lower() for item in result["extra_indicators"]]
        self.assertIn(result["risk_level"], {"high", "critical"})
        self.assertTrue(any("lookalike" in message for message in messages))

    def test_url_userinfo_destination_is_high_risk(self):
        result = app.analyze_email_content(
            "Document shared",
            '<a href="https://paypal.com@evil.example/view">Review document</a>',
        )

        messages = [item["msg"].lower() for item in result["extra_indicators"]]
        self.assertIn(result["risk_level"], {"high", "critical"})
        self.assertTrue(any("userinfo" in message for message in messages))

    def test_empty_url_userinfo_is_not_high_risk(self):
        result = app.analyze_email_content(
            "Document shared",
            '<a href="https://@example.com/view">Review document</a>',
        )

        messages = [item["msg"].lower() for item in result["extra_indicators"]]
        self.assertNotIn(result["risk_level"], {"high", "critical"})
        self.assertFalse(any("userinfo" in message for message in messages))

    def test_brand_in_deceptive_subdomain_is_high_risk(self):
        result = app.analyze_email_content(
            "Document shared",
            '<a href="https://paypal.com.evil.example/view">Review document</a>',
        )

        messages = [item["msg"].lower() for item in result["extra_indicators"]]
        self.assertIn(result["risk_level"], {"high", "critical"})
        self.assertTrue(any("lookalike" in message for message in messages))

    def test_concatenated_brand_lure_destination_is_high_risk(self):
        for destination in (
            "https://securepaypal.example/view",
            "https://paypalverify.example/view",
            "https://paypalservice.example/view",
            "https://paypalconfirm.example/view",
            "https://paypalportal.example/view",
            "https://pay-pal.example/view",
            "https://paypa-l.example/view",
        ):
            with self.subTest(destination=destination):
                result = app.analyze_email_content(
                    "Document shared",
                    f'<a href="{destination}">Review document</a>',
                )
                messages = [
                    item["msg"].lower() for item in result["extra_indicators"]
                ]
                self.assertIn(result["risk_level"], {"high", "critical"})
                self.assertTrue(any("lookalike" in message for message in messages))

    def test_canonical_brand_destination_is_not_a_lookalike(self):
        for destination in (
            "https://paypal.com/view",
            "https://www.paypal.com/view",
            "https://pineapple.com/view",
            "https://googleusercontent.com/view",
            "https://amazon.co.uk/view",
            "https://amazon.de/view",
            "https://google.co.uk/view",
        ):
            with self.subTest(destination=destination):
                result = app.analyze_email_content(
                    "Document shared",
                    f'<a href="{destination}">Review document</a>',
                )
                messages = [
                    item["msg"].lower() for item in result["extra_indicators"]
                ]
                self.assertFalse(any("lookalike" in message for message in messages))
                self.assertFalse(any("userinfo" in message for message in messages))

    def test_malformed_link_destination_does_not_abort_analysis(self):
        result = app.analyze_email_content(
            "Document shared",
            '<a href="http://[invalid">Review document</a>',
        )

        self.assertIsInstance(result, dict)
        self.assertIn("risk_level", result)

    def test_plain_security_words_are_not_character_obfuscation(self):
        for text in ("login", "verify", "account", "password", "bank", "Microsoft"):
            with self.subTest(text=text):
                self.assertEqual(app._detect_obfuscation(text), [])

    def test_later_obfuscated_word_is_not_hidden_by_plain_occurrence(self):
        self.assertIn("login", app._detect_obfuscation("login or l0gin"))

    def test_ip_destination_sets_high_risk_floor(self):
        result = app.analyze_email_content(
            "Document shared",
            "Review it at http://203.0.113.10/view",
        )

        self.assertIn(result["risk_level"], {"high", "critical"})

    def test_high_risk_floor_does_not_downgrade_critical_score(self):
        result = app.analyze_email_content(
            "URGENT final warning: account suspended",
            (
                "Legal action and criminal charges. You have won free money. "
                "Verify your account and reset your password. PayPal Amazon. "
                "Keep this confidential and click the link below. "
                "See the attached file and enable macros. Technical support. "
                "Work from home. I am the CEO. "
                "https://credential-capture.example/view"
            ),
        )

        self.assertGreater(result["total_score"], 15)
        self.assertEqual(result["risk_level"], "critical")

    def test_keyword_matching_respects_word_boundaries(self):
        subjects = (
            "First quarterly report",
            "Who should review this?",
            "Real estate newsletter",
        )
        for subject in subjects:
            with self.subTest(subject=subject):
                result = app.analyze_email_content(
                    subject,
                    "Here is the requested update.",
                )
                self.assertEqual(result["total_score"], 0)

    def test_strong_structural_evidence_is_not_averaged_away(self):
        fused = app.fuse_content_risk(
            ml_phishing_probability=0.02,
            ml_decision_threshold=0.45,
            heuristic_score=16,
        )

        self.assertEqual(fused["risk_level"], "critical")
        self.assertGreaterEqual(fused["combined_phishing_score"], 80)

    def test_model_only_high_score_is_not_labeled_critical(self):
        fused = app.fuse_content_risk(
            ml_phishing_probability=0.842,
            ml_decision_threshold=0.3736,
            heuristic_score=0,
        )
        self.assertEqual(fused['risk_level'], 'high')
        self.assertEqual(fused['fusion_basis'], 'model_only')
        self.assertEqual(fused['combined_phishing_score'], 84.2)

    def test_high_model_score_with_independent_evidence_can_be_critical(self):
        fused = app.fuse_content_risk(
            ml_phishing_probability=0.90,
            ml_decision_threshold=0.3736,
            heuristic_score=9,
        )
        self.assertEqual(fused['risk_level'], 'critical')
        self.assertEqual(fused['fusion_basis'], 'corroborated')

    def test_four_weak_rule_points_do_not_corroborate_critical_model_verdict(self):
        fused = app.fuse_content_risk(
            ml_phishing_probability=0.90,
            ml_decision_threshold=0.3736,
            heuristic_score=4,
        )
        self.assertEqual(fused['risk_level'], 'high')
        self.assertEqual(fused['fusion_basis'], 'model_led')

    def test_one_weak_rule_does_not_claim_model_is_corroborated(self):
        fused = app.fuse_content_risk(
            ml_phishing_probability=0.958,
            ml_decision_threshold=0.3736,
            heuristic_score=1,
        )
        self.assertEqual(fused['risk_level'], 'high')
        self.assertEqual(fused['fusion_basis'], 'model_led')
        self.assertIn('Model Signal Needs Review', fused['risk_label'])

    def test_regional_english_phrasing_is_not_scored_as_phishing(self):
        result = app.analyze_email_content("Follow up", "Kindly revert at the earliest.")

        self.assertEqual(result["total_score"], 0)


class RawEmailAnalysisTests(unittest.TestCase):
    def test_recipient_headers_are_preserved_and_self_addressing_is_low_risk(self):
        raw_email = """From: Alice <alice@gmail.com>
To: Alice <alice@gmail.com>
Cc: Bob <bob@outlook.com>
Subject: Project update

Here is the requested update.
"""

        result = json.loads(asyncio.run(app.analyze_content_endpoint(
            app.ContentRequest(raw_email=raw_email)
        )).body)

        headers = result["message_structure"]["header_candidates"]
        self.assertEqual(headers["To"], ["Alice <alice@gmail.com>"])
        self.assertEqual(headers["Cc"], ["Bob <bob@outlook.com>"])
        self.assertEqual(result["structure_score"], 1)
        self.assertNotIn(result["risk_level"], {"high", "critical"})
        self.assertTrue(any(
            "self-addressed" in item["msg"].lower()
            for item in result["extra_indicators"]
        ))

    def test_missing_visible_recipient_is_informational_only(self):
        raw_email = """From: Alice <alice@gmail.com>
Subject: Project update

Here is the requested update.
"""

        result = json.loads(asyncio.run(app.analyze_content_endpoint(
            app.ContentRequest(raw_email=raw_email)
        )).body)

        self.assertEqual(result["structure_score"], 0)
        self.assertNotIn(result["risk_level"], {"high", "critical"})
        self.assertTrue(any(
            "no visible to or cc" in item["msg"].lower()
            for item in result["extra_indicators"]
        ))

    def test_missing_visible_recipient_is_reported_without_a_from_header(self):
        raw_email = """Subject: Project update

Here is the requested update.
"""

        result = json.loads(asyncio.run(app.analyze_content_endpoint(
            app.ContentRequest(raw_email=raw_email)
        )).body)

        self.assertEqual(result["structure_score"], 0)
        self.assertTrue(any(
            "no visible to or cc" in item["msg"].lower()
            for item in result["extra_indicators"]
        ))

    def test_transfer_encoded_attached_email_is_not_silently_marked_complete(self):
        import base64
        import quopri
        inner = b'From: Apple <service@unrelated.example>\n\nHello'
        for kind in ('message/rfc822', 'message/global'):
            for encoding, payload in (('base64', base64.b64encode(inner)),
                                      ('quoted-printable', quopri.encodestring(inner))):
                with self.subTest(kind=kind, encoding=encoding):
                    raw = (f'Content-Type: {kind}\nContent-Disposition: attachment; filename=forwarded.eml\n'
                           f'Content-Transfer-Encoding: {encoding}\n\n\n').encode() + payload
                    result = self.upload([raw])
                    self.assertFalse(result['analysis_complete'])
                    self.assertTrue(result['message_structure']['parse_warnings'])

    def test_opaque_eml_attachment_reports_uninspected_content(self):
        from email.message import EmailMessage
        message = EmailMessage()
        message.set_content('Hello')
        message.add_attachment(b'From: alice@gmail.com\n\nHello', maintype='application',
                               subtype='octet-stream', filename='forwarded.eml')
        result = self.upload([message.as_bytes()])
        self.assertFalse(result['analysis_complete'])
        self.assertEqual(result['risk_level'], 'unknown')

    def test_attached_messages_are_bounded_and_benign_or_empty_content_is_honest(self):
        from email.message import EmailMessage
        def wrap(inner):
            outer = EmailMessage()
            outer.set_content('Hello')
            outer.add_attachment(inner, filename='forwarded.eml')
            return outer
        clean = EmailMessage()
        clean['From'] = 'alice@gmail.com'
        clean.set_content('Hello')
        self.assertEqual(self.upload([wrap(clean).as_bytes()])['risk_level'], 'safe')
        empty = self.upload([wrap(EmailMessage()).as_bytes()])
        self.assertFalse(empty['analysis_complete'])
        deep = clean
        for _ in range(5):
            deep = wrap(deep)
        result = self.upload([deep.as_bytes()])
        self.assertFalse(result['analysis_complete'])
        self.assertTrue(any('limit' in s for s in result['message_structure']['parse_warnings']))
        self.assertEqual(result['message_structure']['attachments'][0]['inspection_status'], 'metadata_only')
        many = EmailMessage()
        many.set_content('Hello')
        for index in range(22):
            many.add_attachment(clean, filename=f'forwarded-{index}.eml')
        result = self.upload([many.as_bytes()])
        self.assertFalse(result['analysis_complete'])
        self.assertEqual(len(result['message_structure']['nested_messages']), 20)
        self.assertEqual(
            [item['inspection_status'] for item in result['message_structure']['attachments']],
            ['message_analyzed'] * 20 + ['metadata_only'] * 2,
        )

    def test_attached_email_retains_identity_evidence_without_trusting_inner_auth(self):
        from email.message import EmailMessage
        inner = EmailMessage()
        inner['From'] = 'Apple <service@unrelated.example>'
        inner['Authentication-Results'] = 'trusted.example; dmarc=pass'
        inner.set_content('Hello')
        outer = EmailMessage()
        outer['From'] = 'alice@gmail.com'
        outer.set_content('Hello')
        outer.add_attachment(inner, filename='forwarded.eml')
        with patch.object(app, 'SETTINGS', Settings(app_env='test', enable_email_verification=False,
                                                  trusted_authserv_ids=frozenset({'trusted.example'}))):
            result = self.upload([outer.as_bytes()])
        self.assertIn(result['risk_level'], {'high', 'critical'})
        self.assertEqual(result['message_structure']['attachments'][0]['filename'], 'forwarded.eml')
        nested = result['message_structure']['nested_messages'][0]
        self.assertFalse(nested['authentication_results_trusted'])
        self.assertTrue(any('Attached message' in i['msg'] and 'apple' in i['msg'].lower()
                            for i in result['extra_indicators']))

    def test_idn_sender_is_checked_in_both_raw_input_modes(self):
        from email.message import EmailMessage
        from email import policy
        for domain in ('secure-例子.xyz', 'secure-例子.xyz'.encode('idna').decode()):
            message = EmailMessage(policy=policy.SMTPUTF8)
            message['From'] = 'billing@' + domain
            message.set_content('Hello')
            for result in (self.upload([message.as_bytes()]), json.loads(asyncio.run(
                    app.analyze_content_endpoint(app.ContentRequest(raw_email=message.as_string()))).body)):
                self.assertIn('sender_analysis', result)
                self.assertEqual(result['risk_level'], 'high')

    def test_plain_mime_preserves_urls_and_whitespace_without_interpreting_markup(self):
        raw = b'Content-Type: text/plain\n\nSee <https://bit.ly>'
        self.assertTrue(self.upload([raw])['has_shortener'])
        raw = (b'Content-Type: text/plain\n\nYour account has been suspended. '
               b'Act now and enter\n your\tpassword.')
        self.assertEqual(self.upload([raw])['risk_level'], 'high')
        raw = b'Content-Type: text/plain\n\n<form><input type="password"></form>'
        self.assertFalse(any('Embedded HTML form' in i['msg'] for i in self.upload([raw])['extra_indicators']))

    def test_html_base_and_form_state_do_not_cross_mime_parts(self):
        from email.message import EmailMessage
        message = EmailMessage()
        message.make_mixed()
        for html in ('<base href="//paypa1.example/"><form id="a">',
                     '<a href="collect">Continue</a><input type="password" form="a">'):
            part = EmailMessage()
            part.set_content(html, subtype='html')
            message.attach(part)
        result = self.upload([message.as_bytes()])
        self.assertEqual(result['risk_level'], 'safe')
        self.assertTrue(result['analysis_complete'])

    def test_mime_defects_report_incomplete_instead_of_clean_verdict(self):
        raw = (b'Content-Type: multipart/mixed; boundary=declared\n\n'
               b'--different\nContent-Type: text/plain\n\nHello\n--different--\n')
        for result in (self.upload([raw]), json.loads(asyncio.run(
                app.analyze_content_endpoint(app.ContentRequest(raw_email=raw.decode()))).body)):
            self.assertFalse(result['analysis_complete'])
            self.assertEqual(result['risk_level'], 'unknown')
            self.assertIn('Incomplete', result['risk_label'])
            self.assertIsNone(result['combined_phishing_score'])
            self.assertTrue(result['message_structure']['parse_warnings'])
        truncated = (b'Content-Type: multipart/mixed; boundary=x\n\n--x\n'
                     b'Content-Type: text/html\n\n<a href="https://paypa1.example/">Go</a>')
        result = self.upload([truncated])
        self.assertFalse(result['analysis_complete'])
        self.assertEqual(result['risk_level'], 'high')
        clean = self.upload([b'Content-Type: text/plain\n\nHello'])
        self.assertTrue(clean['analysis_complete'])
        self.assertEqual(clean['risk_level'], 'safe')

    def test_mime_parts_cannot_hide_each_others_visible_text(self):
        from email.message import EmailMessage
        lure = 'Your account has been suspended. Act now and enter your password.'
        for prefix in ('Hello', '<style>', '<script>', '<head>'):
            with self.subTest(prefix=prefix):
                message = EmailMessage()
                message['From'] = 'alice@gmail.com'
                message.set_content(prefix)
                message.add_alternative('<p>' + lure + '</p>', subtype='html')
                for result in (self.upload([message.as_bytes()]), json.loads(asyncio.run(
                        app.analyze_content_endpoint(app.ContentRequest(raw_email=message.as_string()))).body)):
                    self.assertEqual(result['risk_level'], 'high')
        for subtype, expected in (('plain', 'high'), ('html', 'safe')):
            message = EmailMessage()
            message.set_content('<style>' + lure + '</style>', subtype=subtype)
            self.assertEqual(self.upload([message.as_bytes()])['risk_level'], expected)

    def upload(self, chunks, content_type='message/rfc822'):
        iterator = iter(chunks)
        async def receive():
            chunk = next(iterator, None)
            return {'type': 'http.request', 'body': chunk or b'', 'more_body': chunk is not None}
        request = app.Request({'type': 'http', 'headers': [(b'content-type', content_type.encode())]}, receive)
        return json.loads(asyncio.run(app.analyze_eml_endpoint(request)).body)

    def test_binary_upload_runs_full_message_analysis(self):
        raw = ('From: alice@gmail.com\nContent-Type: text/html; charset=iso-8859-1\n\n'
               'Hébergement <a href="//paypa1.example/">Open</a>').encode('iso-8859-1')
        result = self.upload([raw[:40], raw[40:]])
        self.assertEqual(result['input_mode'], 'raw-email')
        self.assertEqual(result['message_structure']['parse_warnings'], [])
        self.assertEqual(result['risk_level'], 'high')

    def test_encoded_mime_and_invalid_byte_warnings(self):
        import base64
        import quopri
        body = '您的账户异常：enter your password'
        for encoding, encoded in (('base64', base64.b64encode(body.encode('gb18030'))),
                                  ('quoted-printable', quopri.encodestring(body.encode('gb18030')))):
            with self.subTest(encoding=encoding):
                headers = f'Content-Type: text/plain; charset=gb18030\nContent-Transfer-Encoding: {encoding}\n\n'
                self.assertEqual(app.analyze_raw_email(headers.encode() + encoded)['body'], body)
                self.assertEqual(app.analyze_raw_email(headers + encoded.decode('ascii'))['body'], body)
        damaged = app.analyze_raw_email(b'Content-Type: text/plain; charset=utf-8\n\n\xff enter your password')
        self.assertTrue(damaged['parse_warnings'])
        self.assertIn('enter your password', damaged['body'])

    def test_binary_upload_rejects_oversize_empty_and_wrong_media(self):
        for chunks, media, status in (([b'x' * 30_000, b'x' * 30_001], 'message/rfc822', 413),
                                      ([b'   '], 'message/rfc822', 400),
                                      ([b'hello'], 'text/plain', 415)):
            with self.subTest(status=status):
                with self.assertRaises(app.HTTPException) as error:
                    self.upload(chunks, media)
                self.assertEqual(error.exception.status_code, status)
        self.assertIn('risk_level', self.upload([b'x' * 60_000]))

    def test_mime_bytes_and_legacy_unicode_preserve_decoded_text(self):
        for charset, body in [('utf-8', '您的账户存在异常'),
                              ('gb18030', '您的账户存在异常'),
                              ('iso-8859-1', 'Voici votre hébergement')]:
            with self.subTest(charset=charset):
                headers = (f'Subject: Note\nContent-Type: text/plain; charset={charset}\n'
                           'Content-Transfer-Encoding: 8bit\n\n')
                raw = headers.encode('ascii') + body.encode(charset)
                result = app.analyze_raw_email(raw)
                self.assertEqual(result['body'], body)
                self.assertEqual(result['parse_warnings'], [])
                self.assertEqual(app.analyze_raw_email(headers + body)['body'], body)

    def test_attachment_only_email_can_return_a_verdict(self):
        for filename, expected in (('invoice.exe', 'high'), ('invoice.zip', 'medium'),
                                   ('notes.txt', 'unknown')):
            with self.subTest(filename=filename):
                raw = ('Content-Type: application/octet-stream\n'
                       f'Content-Disposition: attachment; filename="{filename}"\n\npayload')
                result = json.loads(asyncio.run(app.analyze_content_endpoint(
                    app.ContentRequest(raw_email=raw)
                )).body)
                self.assertEqual(result['risk_level'], expected)
                self.assertEqual(result['message_structure']['attachments'][0]['filename'], filename)
                self.assertEqual(result['message_structure']['attachments'][0]['inspection_status'], 'metadata_only')
                self.assertFalse(result['analysis_complete'])
                self.assertTrue(any('attachment content' in warning.lower()
                                    for warning in result['analysis_warnings']))
        for request in (app.ContentRequest(), app.ContentRequest(raw_email='\n\n')):
            with self.assertRaises(app.HTTPException) as error:
                asyncio.run(app.analyze_content_endpoint(request))
            self.assertEqual(error.exception.status_code, 400)

    def test_benign_image_attachment_is_incomplete_not_safe(self):
        from email.message import EmailMessage
        message = EmailMessage()
        message.set_content('Hello team. ' * 30)
        message.add_attachment(b'opaque image bytes', maintype='image', subtype='png', filename='chart.png')
        with patch.object(app, '_content_pipeline', None):
            result = self.upload([message.as_bytes()])
        self.assertEqual(result['risk_level'], 'unknown')
        self.assertIsNone(result['combined_phishing_score'])
        self.assertFalse(result['analysis_complete'])
        self.assertEqual(result['message_structure']['attachments'], [
            {'filename': 'chart.png', 'content_type': 'image/png', 'inspection_status': 'metadata_only'}
        ])
        self.assertEqual(result['message_structure']['parse_warnings'], [])
        self.assertEqual(sum('attachment content' in warning.lower()
                             for warning in result['analysis_warnings']), 1)

    def test_inline_non_text_part_without_filename_has_coverage_status(self):
        raw = (b'Content-Type: multipart/mixed; boundary=x\n\n'
               b'--x\nContent-Type: text/plain\n\nHello team.\n'
               b'--x\nContent-Type: image/png\nContent-Disposition: inline\n\nopaque\n--x--\n')
        with patch.object(app, '_content_pipeline', None):
            result = self.upload([raw])
        self.assertEqual(result['risk_level'], 'unknown')
        self.assertFalse(result['analysis_complete'])
        self.assertEqual(result['message_structure']['attachments'], [
            {'filename': 'unnamed', 'content_type': 'image/png', 'inspection_status': 'metadata_only'}
        ])

    def test_nested_message_inspection_status_reflects_success_and_ambiguity(self):
        from email.message import EmailMessage
        inner = EmailMessage()
        inner.set_content('Hello team.')
        outer = EmailMessage()
        outer.set_content('Hello team.')
        outer.add_attachment(inner, filename='forwarded.eml')
        with patch.object(app, '_content_pipeline', None):
            clean = self.upload([outer.as_bytes()])
        self.assertEqual(clean['message_structure']['attachments'][0]['inspection_status'], 'message_analyzed')
        self.assertTrue(clean['analysis_complete'])
        self.assertFalse(any('attachment content' in warning.lower()
                             for warning in clean['analysis_warnings']))

        outer.add_attachment(inner, filename='forwarded.eml')
        with patch.object(app, '_content_pipeline', None):
            ambiguous = self.upload([outer.as_bytes()])
        self.assertEqual(ambiguous['message_structure']['attachments'][0]['inspection_status'], 'metadata_only')
        self.assertFalse(ambiguous['analysis_complete'])
        self.assertEqual(ambiguous['risk_level'], 'unknown')

    def test_unparsed_attached_message_keeps_metadata_only_status(self):
        raw = (b'Content-Type: message/rfc822\nContent-Disposition: attachment; filename=forwarded.eml\n'
               b'Content-Transfer-Encoding: base64\n\nRm9ybTogYWxpY2VAZXhhbXBsZS5jb20K')
        with patch.object(app, '_content_pipeline', None):
            result = self.upload([raw])
        self.assertEqual(result['message_structure']['attachments'][0]['inspection_status'], 'metadata_only')
        self.assertFalse(result['analysis_complete'])
        self.assertTrue(result['message_structure']['parse_warnings'])

    def test_ambiguous_mime_interpretation_cannot_claim_attached_message_was_analyzed(self):
        raw = (b'Content-Type: message/rfc822\nContent-Type: text/plain\n'
               b'Content-Disposition: attachment; filename=forwarded.eml\n\n'
               b'From: alice@gmail.com\n\nHello')
        with patch.object(app, '_content_pipeline', None):
            result = self.upload([raw])
        self.assertFalse(result['analysis_complete'])
        self.assertTrue(result['message_structure']['parse_warnings'])
        self.assertTrue(all(item['inspection_status'] == 'metadata_only'
                            for item in result['message_structure']['attachments']))

    def test_opaque_child_of_parsed_attached_message_keeps_outer_result_incomplete(self):
        from email.message import EmailMessage
        inner = EmailMessage()
        inner.set_content('Hello team.')
        inner.add_attachment(b'opaque', maintype='image', subtype='png', filename='chart.png')
        outer = EmailMessage()
        outer.set_content('Hello team.')
        outer.add_attachment(inner, filename='forwarded.eml')
        with patch.object(app, '_content_pipeline', None):
            result = self.upload([outer.as_bytes()])
        self.assertEqual(result['message_structure']['attachments'][0]['inspection_status'], 'message_analyzed')
        self.assertFalse(result['analysis_complete'])
        self.assertEqual(result['risk_level'], 'unknown')
        self.assertTrue(any('attached message: attachment content' in warning.lower()
                            for warning in result['analysis_warnings']))

    def test_unknown_charset_keeps_evidence_and_reports_fallback(self):
        for charset in ('utf-8', 'x-unknown-charset'):
            with self.subTest(charset=charset):
                raw = ('From: alice@gmail.com\nSubject: Note\n'
                       f'Content-Type: text/html; charset={charset}\n\n'
                       '<a href="https://paypa1.example/">Review document</a>')
                result = json.loads(asyncio.run(app.analyze_content_endpoint(
                    app.ContentRequest(raw_email=raw)
                )).body)
                self.assertIn(result['risk_level'], {'high', 'critical'})
                warnings = result['message_structure'].get('parse_warnings', [])
                self.assertEqual(bool(warnings), charset != 'utf-8')
                if warnings:
                    self.assertTrue(any('decoding' in i['msg'].lower()
                                        for i in result['extra_indicators']))

    def test_uploaded_message_is_authoritative_over_manual_text(self):
        raw = ('From: alice@gmail.com\nSubject: Note\n'
               'Content-Type: text/html; charset=utf-8\n\n'
               '<a href="https://paypa1.example/">Review document</a>')
        for manual_body in ('', 'Hi, meeting is at noon.'):
            with self.subTest(manual_body=manual_body):
                result = json.loads(asyncio.run(app.analyze_content_endpoint(
                    app.ContentRequest(raw_email=raw, subject='Old subject', body=manual_body)
                )).body)
                self.assertEqual(result['input_mode'], 'raw-email')
                self.assertIn(result['risk_level'], {'high', 'critical'})
                self.assertTrue(any('lookalike' in item['msg']
                                    for item in result['extra_indicators']))

    def test_disposable_context_does_not_score_but_dangerous_links_still_do(self):
        for body, dangerous in (("Lunch is at noon.", False),
                                ("Visit http://192.0.2.10/login", True)):
            raw = f"From: user@mailinator.com\nSubject: Note\n\n{body}"
            result = json.loads(asyncio.run(app.analyze_content_endpoint(
                app.ContentRequest(raw_email=raw)
            )).body)
            self.assertEqual(result["sender_score"], 0)
            self.assertEqual(result["sender_analysis"]["disposable_status"], "known_disposable_provider")
            if dangerous:
                self.assertIn(result["risk_level"], {"high", "critical"})
            else:
                self.assertEqual(result["total_score"], 0)

    def test_raw_email_fuses_suspicious_sender_analysis(self):
        raw_email = """From: billing@secure-account.xyz
To: user@example.com
Subject: Notice

Please review.
"""

        response = asyncio.run(
            app.analyze_content_endpoint(app.ContentRequest(raw_email=raw_email))
        )
        result = json.loads(response.body)
        messages = [item["msg"].lower() for item in result["extra_indicators"]]

        self.assertIn("sender_analysis", result)
        self.assertEqual(result["sender_analysis"]["risk_score"], 100)
        self.assertEqual(result["sender_analysis"]["verdict"], "critical")
        self.assertIn(result["risk_level"], {"high", "critical"})
        self.assertTrue(any("sender:" in message for message in messages))

    def test_raw_email_fuses_highest_risk_from_multiple_mailboxes(self):
        raw_email = """From: Alice <alice@gmail.com>, billing@secure-account.xyz
To: user@example.com
Subject: Notice

Please review.
"""

        response = asyncio.run(
            app.analyze_content_endpoint(app.ContentRequest(raw_email=raw_email))
        )
        result = json.loads(response.body)

        self.assertEqual(result["sender_analysis"]["risk_score"], 100)
        self.assertEqual(result["sender_analysis"]["verdict"], "critical")
        self.assertIn(result["risk_level"], {"high", "critical"})

    def test_raw_email_marks_malformed_quoted_from_value_incomplete(self):
        raw_email = """From: "quoted@display"
To: user@example.com
Subject: Project update

Here is the requested update.
"""

        response = asyncio.run(
            app.analyze_content_endpoint(app.ContentRequest(raw_email=raw_email))
        )
        result = json.loads(response.body)

        self.assertNotIn("sender_analysis", result)
        self.assertEqual(result["risk_level"], "unknown")
        self.assertFalse(result['analysis_complete'])
        self.assertTrue(result['message_structure']['parse_warnings'])

    def test_raw_email_keeps_known_provider_sender_benign(self):
        raw_email = """From: Alice <alice@gmail.com>
To: user@example.com
Subject: Project update

Here is the requested update.
"""

        response = asyncio.run(
            app.analyze_content_endpoint(app.ContentRequest(raw_email=raw_email))
        )
        result = json.loads(response.body)

        self.assertIn("sender_analysis", result)
        self.assertLess(result["sender_analysis"]["risk_score"], 20)
        self.assertEqual(result["total_score"], 0)
        self.assertEqual(result["risk_level"], "safe")

    def test_protected_brand_display_name_requires_a_canonical_domain(self):
        samples = (
            "From: PayPal <billing@gmail.com>\nSubject: Receipt\n\nReview receipt.",
            "From: Microsoft Security <alert@outlook.com>\nSubject: Alert\n\nReview alert.",
        )

        for raw_email in samples:
            with self.subTest(raw_email=raw_email):
                structure = app.analyze_raw_email(raw_email)
                messages = [item["msg"].lower() for item in structure["indicators"]]
                self.assertTrue(any("brand identity" in message for message in messages))
                self.assertGreaterEqual(structure["structure_score"], 4)

    def test_idn_confusable_brand_domain_is_detected(self):
        raw_email = """From: Apple <service@xn--pple-43d.com>
Subject: Account notice

Review the notice.
"""

        structure = app.analyze_raw_email(raw_email)

        messages = [item["msg"].lower() for item in structure["indicators"]]
        self.assertTrue(any("confusable" in message for message in messages))
        self.assertGreaterEqual(structure["structure_score"], 4)

    def test_canonical_brand_sender_is_not_flagged(self):
        raw_email = """From: PayPal <service@paypal.com>
Subject: Receipt

Your receipt is ready.
"""

        structure = app.analyze_raw_email(raw_email)

        messages = [item["msg"].lower() for item in structure["indicators"]]
        self.assertFalse(any("brand identity" in message for message in messages))
        self.assertFalse(any("confusable" in message for message in messages))
        self.assertEqual(structure["structure_score"], 0)

    def test_attacker_authentication_header_is_not_trusted_by_default(self):
        raw_email = """From: Support <notice@example.com>
Subject: Security notice
Authentication-Results: attacker.example; spf=fail; dkim=fail; dmarc=pass

Review the attached notice.
"""

        structure = app.analyze_raw_email(raw_email)

        self.assertFalse(structure["authentication_trusted"])
        self.assertEqual(structure["auth_results"], {})
        self.assertEqual(structure["structure_score"], 0)
        self.assertTrue(structure["untrusted_authentication_claims"])

    def test_configured_authentication_service_results_are_honored(self):
        raw_email = """From: Support <notice@example.com>
Subject: Security notice
Authentication-Results: mx.receiver.example; spf=fail; dkim=fail; dmarc=fail

Review the attached notice.
"""

        structure = app.analyze_raw_email(
            raw_email,
            trusted_authserv_ids={"mx.receiver.example"},
        )

        self.assertFalse(structure["authentication_trusted"])
        self.assertEqual(
            structure["auth_results"],
            {"spf": "fail", "dkim": "fail", "dmarc": "fail"},
        )
        self.assertGreaterEqual(structure["structure_score"], 6)
        self.assertEqual(structure["untrusted_authentication_claims"], [])

    def test_raw_email_uses_authentication_and_identity_mismatch_signals(self):
        raw_email = """From: PayPal <service@paypal.com>
Reply-To: collections@paypa1-support.example
Return-Path: <bounce@paypa1-support.example>
Subject: Updated document
Authentication-Results: mx.example; spf=fail; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<p>Please review the updated document.</p>
<a href="https://paypa1-support.example/login">https://paypal.com</a>
"""
        trusted_settings = Settings(
            app_env="test",
            enable_email_verification=False,
            content_model_enabled=False,
            trusted_authserv_ids=frozenset({"mx.example"}),
        )
        with patch.object(app, "SETTINGS", trusted_settings):
            response = asyncio.run(
                app.analyze_content_endpoint(app.ContentRequest(raw_email=raw_email))
            )
        result = json.loads(response.body)

        self.assertEqual(result["input_mode"], "raw-email")
        self.assertGreaterEqual(result["structure_score"], 8)
        messages = [item["msg"] for item in result["extra_indicators"]]
        self.assertTrue(any("authentication failed" in message.lower() for message in messages))
        self.assertTrue(any("reply-to" in message.lower() for message in messages))

    def test_multipart_html_links_are_scanned_even_with_plain_alternative(self):
        raw_email = """From: Service <notice@example.com>
Subject: Updated document
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary=demo

--demo
Content-Type: text/plain; charset=utf-8

Please review the document.
--demo
Content-Type: text/html; charset=utf-8

<a href="https://capture.example/login">https://docs.google.com</a>
--demo--
"""
        response = asyncio.run(
            app.analyze_content_endpoint(app.ContentRequest(raw_email=raw_email))
        )
        result = json.loads(response.body)

        messages = [item["msg"] for item in result["extra_indicators"]]
        self.assertTrue(any("does not match" in message for message in messages))

    def test_dmarc_pass_prevents_forwarding_spf_failure_from_being_high_risk(self):
        raw_email = """From: Newsletter <news@example.com>
Subject: Weekly update
Authentication-Results: mx.example; spf=fail; dkim=pass; dmarc=pass

Here is this week's project update.
"""
        structure = app.analyze_raw_email(
            raw_email,
            trusted_authserv_ids={"mx.example"},
        )

        self.assertEqual(structure["structure_score"], 0)
        self.assertTrue(structure["authentication_trusted"])

    def test_archive_and_macro_attachments_are_flagged(self):
        samples = (
            ("invoice.zip", "application/zip"),
            (
                "invoice.docm",
                "application/vnd.ms-word.document.macroEnabled.12",
            ),
        )
        for filename, content_type in samples:
            raw_email = f"""From: Service <notice@example.com>
Subject: Updated files
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary=x

--x
Content-Type: text/plain

Please review.
--x
Content-Type: {content_type}
Content-Disposition: attachment; filename="{filename}"

payload
--x--
"""
            with self.subTest(filename=filename):
                structure = app.analyze_raw_email(raw_email)
                messages = [item["msg"].lower() for item in structure["indicators"]]
                self.assertGreater(structure["structure_score"], 0)
                self.assertTrue(any("attachment" in message for message in messages))

    def test_extensionless_executable_mime_attachment_is_high_risk(self):
        for content_type in ("application/x-msdownload", "application/x-java-archive"):
            raw_email = f"""From: Service <notice@example.com>
Subject: Updated files
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary=x

--x
Content-Type: text/plain

Please review.
--x
Content-Type: {content_type}
Content-Disposition: attachment; filename="invoice"

payload
--x--
"""
            with self.subTest(content_type=content_type):
                structure = app.analyze_raw_email(raw_email)
                messages = [item["msg"].lower() for item in structure["indicators"]]

                self.assertEqual(structure["risk_floor"], "high")
                self.assertTrue(any("attachment" in message for message in messages))

    def test_dangerous_mime_leaf_is_high_risk_without_attachment_metadata(self):
        for disposition in ("", "Content-Disposition: inline\n"):
            raw_email = f"""From: Service <notice@example.com>
Subject: Updated files
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary=x

--x
Content-Type: text/plain

Please review.
--x
Content-Type: application/x-msdownload
{disposition}
payload
--x--
"""

            with self.subTest(disposition=disposition or "missing"):
                structure = app.analyze_raw_email(raw_email)
                messages = [item["msg"].lower() for item in structure["indicators"]]
                self.assertEqual(structure["risk_floor"], "high")
                self.assertTrue(any("attachment" in message for message in messages))

    def test_extensionless_macro_office_mime_attachments_are_high_risk(self):
        content_types = (
            "application/vnd.ms-word.template.macroEnabled.12",
            "application/vnd.ms-excel.template.macroEnabled.12",
            "application/vnd.ms-powerpoint.slideshow.macroEnabled.12",
        )
        for content_type in content_types:
            raw_email = f"""From: Service <notice@example.com>
Subject: Updated files
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary=x

--x
Content-Type: text/plain

Please review.
--x
Content-Type: {content_type}
Content-Disposition: attachment; filename="invoice"

payload
--x--
"""
            with self.subTest(content_type=content_type):
                structure = app.analyze_raw_email(raw_email)
                self.assertEqual(structure["risk_floor"], "high")

    def test_extensionless_archive_mime_attachment_is_medium_risk(self):
        for content_type in ("application/zip", "application/x-zip-compressed"):
            raw_email = f"""From: Service <notice@example.com>
Subject: Updated files
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary=x

--x
Content-Type: text/plain

Please review.
--x
Content-Type: {content_type}
Content-Disposition: attachment; filename="invoice"

payload
--x--
"""
            with self.subTest(content_type=content_type):
                structure = app.analyze_raw_email(raw_email)
                messages = [item["msg"].lower() for item in structure["indicators"]]

                self.assertEqual(structure["risk_floor"], "medium")
                self.assertTrue(any("archive attachment" in message for message in messages))

    def test_pdf_mime_attachment_without_dangerous_extension_is_not_flagged(self):
        raw_email = """From: Service <notice@example.com>
Subject: Updated files
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary=x

--x
Content-Type: text/plain

Please review.
--x
Content-Type: application/pdf
Content-Disposition: attachment; filename="invoice.pdf"

payload
--x--
"""

        structure = app.analyze_raw_email(raw_email)
        messages = [item["msg"].lower() for item in structure["indicators"]]

        self.assertEqual(structure["structure_score"], 0)
        self.assertFalse(any("attachment" in message for message in messages))

    def test_decisive_authentication_failure_sets_high_risk_floor(self):
        raw_email = """From: Service <notice@example.com>
Subject: Updated document
Authentication-Results: mx.example; spf=fail; dkim=fail; dmarc=fail

Please review the updated document.
"""
        trusted_settings = Settings(
            app_env="test",
            enable_email_verification=False,
            content_model_enabled=False,
            trusted_authserv_ids=frozenset({"mx.example"}),
        )
        with patch.object(app, "SETTINGS", trusted_settings):
            response = asyncio.run(
                app.analyze_content_endpoint(app.ContentRequest(raw_email=raw_email))
            )
        result = json.loads(response.body)

        self.assertIn(result["risk_level"], {"high", "critical"})
        self.assertIn("untrusted_authentication_claims", result["message_structure"])


class ContentModelEvaluationTests(unittest.TestCase):
    def test_offline_builder_does_not_load_pickle_cache_by_default(self):
        with patch.dict(content_model.os.environ, {}, clear=True):
            with patch.object(
                content_model,
                "build_content_pipeline",
                return_value={},
            ) as build:
                content_model.build_content_pipeline_from_env(seed=7)

        self.assertFalse(build.call_args.kwargs["use_cache"])

    def test_fallback_grouping_collapses_volatile_urls_addresses_and_numbers(self):
        first = (
            "Invoice 12345 is ready. Visit https://capture.example/a?token=abc "
            "or contact jane@example.com."
        )
        second = (
            "Invoice 98765 is ready. Visit https://other.example/b?token=xyz "
            "or contact bob@example.org."
        )

        self.assertEqual(
            content_model._text_group(first, "fixture.csv"),
            content_model._text_group(second, "fixture.csv"),
        )

    def test_fallback_grouping_is_source_agnostic(self):
        text = "Invoice 12345 is ready at https://capture.example/a."

        self.assertEqual(
            content_model._text_group(text, "first.csv"),
            content_model._text_group(text, "second.csv"),
        )

    def test_cross_source_duplicates_are_removed_before_splitting(self):
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory)
            first = data_dir / "first.csv"
            second = data_dir / "second.csv"
            content_model.pd.DataFrame([
                {
                    "subject": "Invoice 12345",
                    "body": "Review https://capture.example/a for account details.",
                    "label": 1,
                },
            ]).to_csv(first, index=False)
            content_model.pd.DataFrame([
                {
                    "subject": "Invoice 98765",
                    "body": "Review https://other.example/b for account details.",
                    "label": 1,
                },
            ]).to_csv(second, index=False)
            datasets = [
                ("first.csv", None, "champa_csv"),
                ("second.csv", None, "champa_csv"),
            ]
            with patch.object(content_model, "_DATASETS", datasets):
                texts, labels, groups, _ = content_model.load_real_corpus(
                    csv_path=data_dir / "anchor.csv"
                )

        self.assertEqual(len(texts), 1)
        self.assertEqual(labels, [1])
        self.assertEqual(len(set(groups)), 1)

    def test_phishnchips_variants_with_the_same_url_share_a_group(self):
        rows = [
            {
                "id": "variant-1",
                "url_raw": "https://same-campaign.example/login",
                "phish_label": 1,
                "email_content": json.dumps({"subject": "One", "body": "A" * 30}),
            },
            {
                "id": "variant-2",
                "url_raw": "https://same-campaign.example/login",
                "phish_label": 1,
                "email_content": json.dumps({"subject": "Two", "body": "B" * 30}),
            },
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "phishnchips.csv"
            content_model.pd.DataFrame(rows).to_csv(path, index=False)
            _, _, groups = content_model._load_one_corpus(path, "phishnchips_csv")

        self.assertEqual(groups[0], groups[1])

    def test_evaluation_is_group_isolated_and_reports_detection_metrics(self):
        pipeline = content_model.build_content_pipeline(
            use_real=False,
            augment_synthetic=True,
            n_variants=2,
            auto_download=False,
            use_cache=False,
            fast_mode=True,
        )
        metrics = pipeline["metrics"]

        self.assertEqual(metrics["split_strategy"], "stratified-group-5-fold")
        self.assertEqual(metrics["group_overlap"], 0)
        self.assertIn("campaign URL", metrics["grouping_policy"])
        self.assertIn("Phishing_Recall", metrics)
        self.assertIn("False_Negative_Rate", metrics)
        self.assertIn("PR_AUC", metrics)
        self.assertIn("Brier", metrics)
        self.assertIn("Default_Threshold_Phishing_Recall", metrics)
        self.assertIn("Recall_Gain_vs_0_5", metrics)
        self.assertIn("source_sample_counts", metrics)
        self.assertTrue(metrics["source_sample_counts"])
        self.assertEqual(metrics["model_selection_metric"], "average_precision")
        self.assertGreater(pipeline["decision_threshold"], 0)
        self.assertLess(pipeline["decision_threshold"], 1)


class DeploymentModeTests(unittest.TestCase):
    def test_health_is_ready_with_validated_heuristic_detectors_only(self):
        response = asyncio.run(app.health())
        payload = json.loads(response.body)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["sender_analysis_method"], "sender-domain-heuristics")

    def test_rules_only_lifespan_skips_model_training(self):
        rules_only = Settings(
            app_env="demo",
            enable_email_verification=False,
            content_model_enabled=False,
        )

        async def run_lifespan():
            async with app.lifespan(app.app):
                return json.loads((await app.health()).body)

        with patch.object(app, "SETTINGS", rules_only):
            with patch.object(
                content_model,
                "build_content_pipeline_from_env",
                side_effect=AssertionError("rules-only mode must not train a model"),
            ):
                payload = asyncio.run(run_lifespan())

        self.assertEqual(payload["status"], "ok")
        self.assertFalse(payload["content_model_loaded"])

    def test_metrics_endpoint_scopes_uci_results_to_websites(self):
        payload = json.loads(asyncio.run(app.get_metrics()).body)

        self.assertEqual(payload["benchmark_scope"], "uci-phishing-websites-only")
        self.assertNotIn("feature_importances", payload)


if __name__ == "__main__":
    unittest.main()
