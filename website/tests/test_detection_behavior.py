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
