import hashlib
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import pandas as pd
from scipy.sparse import csr_matrix


WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import content_model


class SpaPhishCorpusTests(unittest.TestCase):
    def test_training_module_prediction_uses_runtime_abstention_contract(self):
        vectorizer = Mock()
        vectorizer.transform.return_value = csr_matrix((1, 2))
        classifier = Mock()
        classifier.predict_proba.side_effect = AssertionError(
            "classifier must not run for zero-feature text"
        )

        result = content_model.predict_content(
            {
                "vectorizer": vectorizer,
                "clf": classifier,
                "decision_threshold": 0.4,
            },
            "Detailed project planning notes",
            "Please review this complete coordination summary before tomorrow's meeting.",
        )

        self.assertEqual(result["ml_status"], "insufficient_feature_coverage")
        self.assertIsNone(result["ml_prediction"])

    def test_hard_negative_corpus_contains_only_grouped_legitimate_messages(self):
        texts, labels, groups = content_model.generate_hard_negative_corpus(
            seed=42,
            variants_per_template=3,
        )

        template_count = len(content_model._LEGIT_TEMPLATES) + len(
            content_model._PERSONAL_HARD_NEGATIVE_TEMPLATES
        ) + len(content_model._WORKPLACE_HARD_NEGATIVE_TEMPLATES)
        self.assertEqual(len(texts), len(set(texts)))
        self.assertGreaterEqual(len(texts), template_count)
        self.assertEqual(labels, [0] * len(texts))
        self.assertEqual(len(set(groups)), template_count)
        self.assertTrue(any("planning meeting" in text.lower() for text in texts))
        self.assertTrue(
            {
                f"synthetic:legitimate:{index}"
                for index in range(len(content_model._LEGIT_TEMPLATES))
            }.issubset(set(groups))
        )

    def test_synthetic_build_excludes_hard_negatives_from_held_out_families(self):
        pipeline = content_model.build_content_pipeline(
            use_real=False,
            n_variants=4,
            auto_download=False,
            use_cache=False,
            fast_mode=True,
        )

        match = re.search(
            r"(\d+) held-out template variants",
            pipeline["metrics"]["data_source"],
        )
        self.assertIsNotNone(match)
        self.assertGreater(int(match.group(1)), 0)
        self.assertEqual(pipeline["metrics"]["group_overlap"], 0)

    def test_hard_negative_corpus_covers_personal_social_correspondence(self):
        texts, labels, groups = content_model.generate_hard_negative_corpus(
            seed=42,
            variants_per_template=2,
        )
        normalized = "\n".join(texts).lower()

        self.assertEqual(labels, [0] * len(texts))
        self.assertIn("vacation pictures", normalized)
        self.assertIn("next weekend", normalized)
        self.assertIn("family photos", normalized)
        self.assertGreaterEqual(
            len({group for group in groups if ":personal-social:" in group}),
            4,
        )
        self.assertNotIn(
            "Hey\n\nI loved the photos from the trip. See you this weekend.",
            texts,
        )

    def test_hard_negative_corpus_covers_routine_monthly_reporting(self):
        texts, labels, groups = content_model.generate_hard_negative_corpus(
            seed=42,
            variants_per_template=2,
        )
        normalized = "\n".join(texts).lower()

        self.assertEqual(labels, [0] * len(texts))
        self.assertIn("monthly report", normalized)
        self.assertIn("revenue", normalized)
        self.assertIn("scheduled maintenance", normalized)
        self.assertGreaterEqual(
            len({group for group in groups if ":workplace:" in group}),
            7,
        )

    def test_legitimate_synthetic_rows_do_not_receive_threat_filler(self):
        texts, labels, _groups = content_model.generate_content_corpus(
            seed=42,
            n_variants=3,
            return_groups=True,
        )
        legitimate = "\n".join(
            text.lower() for text, label in zip(texts, labels) if label == 0
        )

        self.assertNotIn("failure to comply will result", legitimate)
        self.assertNotIn("immediate attention to this matter", legitimate)

    def test_appended_sources_exclude_reserved_normalized_families(self):
        texts, labels, groups, excluded = content_model._exclude_reserved_families(
            [
                "Invoice 123 at https://one.example/pay",
                "Ordinary team lunch tomorrow",
            ],
            [0, 0],
            ["duplicate", "unique"],
            reserved_texts=["Invoice 999 at https://two.example/pay"],
        )

        self.assertEqual(texts, ["Ordinary team lunch tomorrow"])
        self.assertEqual(labels, [0])
        self.assertEqual(groups, ["unique"])
        self.assertEqual(excluded, 1)

    def test_partition_reserves_future_mail_and_removes_family_overlap(self):
        rows = [
            {
                "hash": "early-phish",
                "subject": "Early phishing",
                "body": "Verify the older account at https://old.example/123 now.",
                "date": "2023-06-01",
                "Label": 1,
            },
            {
                "hash": "undated-legit",
                "subject": "Team notes",
                "body": "The project discussion is attached for tomorrow's meeting.",
                "date": "",
                "Label": 0,
            },
            {
                "hash": "undated-duplicate",
                "subject": "Future phishing",
                "body": "Reset account 999 at https://copy.example/other immediately.",
                "date": "",
                "Label": 1,
            },
            {
                "hash": "validation-phish",
                "subject": "Future phishing",
                "body": "Reset account 123 at https://validation.example/login immediately.",
                "date": "2024-02-01",
                "Label": 1,
            },
            {
                "hash": "validation-legit",
                "subject": "Validation meeting",
                "body": "The agenda for the 2024 planning meeting is ready.",
                "date": "2024-03-01",
                "Label": 0,
            },
            {
                "hash": "holdout-phish",
                "subject": "Holdout phishing",
                "body": "Confirm the 2025 account at https://holdout.example/login.",
                "date": "2025-03-01",
                "Label": 1,
            },
            {
                "hash": "holdout-legit",
                "subject": "Holdout meeting",
                "body": "The agenda for the 2025 quarterly planning meeting is ready.",
                "date": "2025-04-01",
                "Label": 0,
            },
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "SpaPhish.csv"
            pd.DataFrame(rows).to_csv(
                path,
                sep=";",
                index=False,
                encoding="utf-8-sig",
            )
            partitions = content_model._load_spaphish_partitions(
                path,
                verify_sha256=False,
            )

        train_texts, train_labels, train_groups = partitions["train"]
        validation_texts, validation_labels, validation_groups = partitions["validation"]
        holdout_texts, holdout_labels, holdout_groups = partitions["holdout"]
        self.assertEqual(train_labels, [1, 0])
        self.assertEqual(validation_labels, [1, 0])
        self.assertEqual(holdout_labels, [1, 0])
        self.assertEqual(len(train_texts), 2)
        self.assertEqual(len(validation_texts), 2)
        self.assertEqual(len(holdout_texts), 2)
        self.assertFalse(set(train_groups) & (set(validation_groups) | set(holdout_groups)))
        self.assertFalse(set(validation_groups) & set(holdout_groups))
        self.assertEqual(partitions["metadata"]["cutoff"], "2024-01-01")
        self.assertEqual(partitions["metadata"]["holdout_start"], "2025-01-01")
        self.assertEqual(partitions["metadata"]["excluded_family_overlap"], 1)
        self.assertEqual(partitions["metadata"]["temporal_assurance"], "partial")

    def test_validation_threshold_maximizes_recall_under_false_positive_cap(self):
        threshold = content_model._select_threshold_at_fpr(
            [1, 1, 0, 0],
            [0.9, 0.4, 0.35, 0.1],
            max_false_positive_rate=0.20,
        )

        self.assertEqual(threshold, 0.4)

    def test_validation_threshold_replaces_lower_oof_threshold(self):
        threshold = content_model._effective_decision_threshold(
            oof_threshold=0.20,
            validation_threshold=0.40,
        )

        self.assertEqual(threshold, 0.40)

    def test_validation_threshold_is_not_lowered_by_a_safety_clamp(self):
        threshold = content_model._effective_decision_threshold(
            oof_threshold=0.20,
            validation_threshold=0.99,
        )

        self.assertEqual(threshold, 0.99)

    def test_no_positive_threshold_remains_above_one(self):
        validation_threshold = content_model._select_threshold_at_fpr(
            [1, 0],
            [1.0, 1.0],
            max_false_positive_rate=0.0,
        )

        self.assertGreater(validation_threshold, 1.0)
        self.assertEqual(
            content_model._effective_decision_threshold(
                oof_threshold=0.5,
                validation_threshold=validation_threshold,
            ),
            validation_threshold,
        )

    def test_wilson_interval_reports_small_sample_uncertainty(self):
        lower, upper = content_model._wilson_interval(10, 55)

        self.assertAlmostEqual(lower, 0.1019, places=4)
        self.assertAlmostEqual(upper, 0.3033, places=4)

    def test_wilson_interval_handles_zero_and_all_success_boundaries(self):
        zero_lower, zero_upper = content_model._wilson_interval(0, 10)
        all_lower, all_upper = content_model._wilson_interval(10, 10)

        self.assertEqual(zero_lower, 0.0)
        self.assertAlmostEqual(zero_upper, 0.2775, places=4)
        self.assertAlmostEqual(all_lower, 0.7225, places=4)
        self.assertEqual(all_upper, 1.0)

    def test_wilson_interval_rejects_invalid_counts(self):
        for successes, total in ((0, 0), (-1, 10), (11, 10)):
            with self.subTest(successes=successes, total=total):
                with self.assertRaises(ValueError):
                    content_model._wilson_interval(successes, total)

    def test_download_checksum_failure_preserves_existing_file(self):
        expected = hashlib.sha256(b"trusted dataset").hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "dataset.csv"
            destination.write_bytes(b"trusted dataset")

            def fake_retrieve(_url, temporary_path):
                Path(temporary_path).write_bytes(b"tampered dataset")

            with patch.object(content_model.urllib.request, "urlretrieve", fake_retrieve):
                downloaded = content_model._download(
                    "https://datasets.example/corpus.csv",
                    destination,
                    expected_sha256=expected,
                )

            self.assertFalse(downloaded)
            self.assertEqual(destination.read_bytes(), b"trusted dataset")
            self.assertFalse(destination.with_suffix(".csv.part").exists())

    def test_partition_rejects_a_file_that_does_not_match_published_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / content_model._SPAPHISH_FILENAME
            path.write_bytes(b"not the published corpus")

            with self.assertRaisesRegex(ValueError, "SHA-256"):
                content_model._load_spaphish_partitions(path)

    def test_spaphish_source_digest_is_pinned(self):
        self.assertEqual(
            content_model._SPAPHISH_SHA256,
            "fdd74842d0a19fd4332bd91f90b0bcb06e045ceb2b599051b4598b65055a9cc5",
        )

    def test_cache_key_includes_temporal_policy(self):
        baseline = content_model._cache_key(
            use_real=True,
            augment_synthetic=False,
            n_variants=1,
            max_real_rows=100,
            fast_mode=True,
            seed=42,
        )
        with patch.object(content_model, "_SPAPHISH_HOLDOUT_START", "2026-01-01"):
            changed = content_model._cache_key(
                use_real=True,
                augment_synthetic=False,
                n_variants=1,
                max_real_rows=100,
                fast_mode=True,
                seed=42,
            )

        self.assertNotEqual(baseline, changed)

    def test_pipeline_reports_separate_dated_holdout_metrics(self):
        texts = [
            f"Urgent credential reset phishing sample topic{chr(97 + index % 26)}{chr(97 + index // 26)}"
            if index % 2 else f"Routine project meeting notes topic{chr(97 + index % 26)}{chr(97 + index // 26)}"
            for index in range(30)
        ]
        labels = [index % 2 for index in range(30)]
        groups = [f"group-{index}" for index in range(30)]
        holdout = (
            [
                "Urgente: confirme su contraseña y cuenta ahora",
                "Agenda normal para la reunión del equipo mañana",
            ],
            [1, 0],
            ["holdout-phish", "holdout-legit"],
        )
        partitions = {
            "train": (
                [
                    "Confirme su cuenta histórica inmediatamente",
                    "Notas normales del equipo para el proyecto",
                ],
                [1, 0],
                ["train-phish", "train-legit"],
            ),
            "validation": (
                [
                    "Verifique su contraseña histórica ahora",
                    "Resumen normal de la reunión del proyecto",
                ],
                [1, 0],
                ["validation-phish", "validation-legit"],
            ),
            "holdout": holdout,
            "metadata": {
                "cutoff": "2024-01-01",
                "holdout_start": "2025-01-01",
                "temporal_assurance": "partial",
                "excluded_family_overlap": 0,
                "undated_training_rows": 0,
            },
        }
        with patch.object(
            content_model,
            "load_real_corpus",
            return_value=(texts, labels, groups, "fixture corpus"),
        ), patch.object(
            content_model,
            "_load_spaphish_partitions",
            return_value=partitions,
        ):
            pipeline = content_model.build_content_pipeline(
                use_real=True,
                auto_download=False,
                use_cache=False,
                fast_mode=True,
            )

        temporal = pipeline["metrics"]["temporal_holdout"]
        self.assertEqual(temporal["dataset"], "SpaPhish v1")
        self.assertEqual(temporal["cutoff"], "2025-01-01")
        self.assertEqual(temporal["n_test"], 2)
        self.assertEqual(temporal["group_overlap"], 0)
        self.assertEqual(temporal["temporal_assurance"], "partial")
        self.assertEqual(temporal["evaluation_role"], "regression-slice")
        self.assertEqual(
            pipeline["metrics"]["temporal_validation"]["status"],
            "used-for-threshold-selection",
        )
        self.assertIn(
            "False_Positive_Rate_95_CI",
            pipeline["metrics"]["temporal_validation"],
        )
        self.assertIn(
            "Phishing_Recall_95_CI",
            pipeline["metrics"]["temporal_holdout"],
        )
        self.assertEqual(
            pipeline["metrics"]["source_sample_counts"]["SpaPhish-training"],
            2,
        )
        self.assertEqual(pipeline["metrics"]["normalized_family_overlap"], 0)
        self.assertEqual(pipeline["metrics"]["build_provenance"]["seed"], 42)
        self.assertEqual(
            pipeline["metrics"]["build_provenance"]["cache_version"],
            content_model._CACHE_VERSION,
        )
        package_versions = pipeline["metrics"]["build_provenance"]["package_versions"]
        self.assertEqual(
            set(package_versions),
            {"numpy", "scipy", "scikit-learn", "joblib", "threadpoolctl", "pandas"},
        )
        self.assertTrue(pipeline["metrics"]["build_provenance"]["python_version"])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "new-model.pkl"
            digest = content_model.save_content_pipeline_artifact(pipeline, path)
            from content_inference import load_content_pipeline_artifact
            loaded = load_content_pipeline_artifact(path, digest)
        self.assertEqual(
            loaded["metrics"]["build_provenance"]["package_versions"],
            package_versions,
        )
        self.assertGreater(
            pipeline["metrics"]["source_sample_counts"]["hard-negative-synthetic"],
            0,
        )
        expected_templates = len(content_model._LEGIT_TEMPLATES) + len(
            content_model._PERSONAL_HARD_NEGATIVE_TEMPLATES
        ) + len(content_model._WORKPLACE_HARD_NEGATIVE_TEMPLATES)
        self.assertIn(
            f"templates={expected_templates}",
            pipeline["metrics"]["data_source"],
        )


if __name__ == "__main__":
    unittest.main()
