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


class ContentRuleRobustnessTests(unittest.TestCase):
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

    def test_regional_english_phrasing_is_not_scored_as_phishing(self):
        result = app.analyze_email_content("Follow up", "Kindly revert at the earliest.")

        self.assertEqual(result["total_score"], 0)


class RawEmailAnalysisTests(unittest.TestCase):
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

    def test_raw_email_ignores_malformed_quoted_from_value(self):
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
        self.assertEqual(result["risk_level"], "safe")

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
