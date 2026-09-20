import json
import subprocess
import tempfile
from pathlib import Path
import sys
import unittest


WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import disposable_registry
from disposable_registry import load_disposable_registry


class DisposableRegistryBuilderTests(unittest.TestCase):
    def test_versioned_privacy_relay_registry_has_source_metadata(self):
        loader = getattr(disposable_registry, "load_privacy_relay_registry", None)
        self.assertIsNotNone(loader, "privacy-relay registry loader is missing")

        domains, metadata = loader()
        self.assertEqual(metadata["schema"], "phishguard-privacy-relay-domains-v1")
        self.assertIn("simplelogin.com", domains)
        self.assertIn("retrieved", metadata["provenance"].lower())
        self.assertIn("https://", metadata["provenance"])

    def test_loader_rejects_invalid_metadata_types_and_version(self):
        base = {
            "schema": "phishguard-disposable-domains-v1",
            "version": "2026.09.18",
            "domain_count": 1,
            "provenance": "fixture source",
            "domains": ["mailinator.com"],
        }
        invalid_values = (
            ("version", 123),
            ("version", "garbage"),
            ("provenance", True),
            ("provenance", "   "),
            ("domain_count", 1.0),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "registry.json"
            for field, value in invalid_values:
                with self.subTest(field=field, value=value):
                    payload = {**base, field: value}
                    path.write_text(json.dumps(payload), encoding="utf-8")
                    with self.assertRaises(ValueError):
                        load_disposable_registry(path)

    def test_builder_cli_does_not_replace_output_for_empty_source(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "domains.txt"
            output = Path(directory) / "registry.json"
            source.write_text("# comments only\n", encoding="utf-8")
            output.write_text("sentinel\n", encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(WEBSITE_DIR / "tools" / "build_disposable_registry.py"),
                    "--input", str(source),
                    "--output", str(output),
                    "--version", "2026.09.18",
                    "--provenance", "fixture source",
                ],
                cwd=WEBSITE_DIR.parent,
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output.read_text(encoding="utf-8"), "sentinel\n")

    def test_builder_cli_runs_from_the_project_root(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "domains.txt"
            output = Path(directory) / "registry.json"
            source.write_text("mailinator.com\n", encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(WEBSITE_DIR / "tools" / "build_disposable_registry.py"),
                    "--input", str(source),
                    "--output", str(output),
                    "--version", "2026.09.18",
                    "--provenance", "fixture source",
                ],
                cwd=WEBSITE_DIR.parent,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(output.read_text())["domain_count"], 1)

    def test_builder_normalizes_and_deduplicates_line_sources(self):
        try:
            from tools.build_disposable_registry import build_registry
        except ImportError:
            build_registry = None
        self.assertIsNotNone(build_registry, "offline registry builder is missing")

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "domains.txt"
            source.write_text(
                "# source comment\nMailinator.COM\nmailinator.com\nTEMP-MAIL.org.\n",
                encoding="utf-8",
            )
            payload = build_registry(
                [source],
                version="2026.09.18",
                provenance="fixture source",
            )

        self.assertEqual(payload["domains"], ["mailinator.com", "temp-mail.org"])
        self.assertEqual(payload["domain_count"], 2)
        self.assertEqual(payload["provenance"], "fixture source")


if __name__ == "__main__":
    unittest.main()
