import base64
import hashlib
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.build_private_cohort import build_cohort, main as cohort_main, read_private_jsonl, write_cohort
from tools.case_archive import _canonical, write_private_bytes
from tools.evaluate_serving_pipeline import _validated_record


def draft(number, *, mode='content', reviewer='alice'):
    case_id = f'00000000-0000-4000-8000-{number:012d}'
    raw = (b'Subject: Synthetic\n\nBody' if mode == 'eml' else
           _canonical({'subject': 'Synthetic', 'body': 'Body'}))
    source = ({'eml_base64': base64.b64encode(raw).decode()} if mode == 'eml' else
              {'subject': 'Synthetic', 'body': 'Body'})
    return {'schema': 'reviewed-feedback-draft-v1', 'id': case_id, 'label': 'legitimate',
            'input_mode': mode, 'content_sha256': hashlib.sha256(mode.encode() + b'\0' + raw).hexdigest(),
            'review_reason': 'false_alert', 'evidence_basis': 'retained_message',
            'reviewed_by': reviewer, 'case_reviewer_ids': [reviewer],
            'source_consent': True, 'evaluation_consent': True, **source}


def annotation(item, *, role='development', family='family-one', reviewer='bob'):
    return {'id': item['id'], 'label': 'legitimate', 'provider': 'gmail',
            'received_at': '2026-09-21', 'language': 'en', 'family_id': family,
            'cohort_role': role, 'independent_reviewer': reviewer}


class PrivateCohortTests(unittest.TestCase):
    def test_old_draft_cannot_evaluate_a_possibly_generated_feedback_subject(self):
        item = draft(1)
        item['subject'] = 'User feedback · false_positive'
        item['content_sha256'] = hashlib.sha256(b'content\0' + _canonical({'subject': item['subject'], 'body': item['body']})).hexdigest()
        with self.assertRaisesRegex(ValueError, 'ambiguous legacy feedback subject'):
            build_cohort([item], [annotation(item)])
        item['source_schema'] = 2
        self.assertEqual(build_cohort([item], [annotation(item)])['development'][0]['subject'], item['subject'])

    def test_private_cohort_creates_evaluator_inputs_and_lineage(self):
        content = draft(1)
        eml = draft(2, mode='eml')
        cohort = build_cohort([content, eml], [annotation(content),
            annotation(eml, role='holdout', family='family-two')])
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'cohort'
            counts = write_cohort(output, cohort, draft_sha256='a' * 64, annotations_sha256='b' * 64)
            self.assertEqual(counts, {'development': 1, 'holdout': 1})
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            development = read_private_jsonl(output / 'development.jsonl')[0]
            holdout = read_private_jsonl(output / 'holdout.jsonl')[0]
            self.assertEqual(development['body'], 'Body')
            self.assertEqual(holdout['provider'], 'gmail')
            self.assertEqual(_validated_record(development, 1)['id'], content['id'])
            self.assertEqual(_validated_record(holdout, 2)['id'], eml['id'])
            self.assertEqual(Path(holdout['eml_path']).read_bytes(), b'Subject: Synthetic\n\nBody')
            self.assertEqual(Path(holdout['eml_path']).stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads((output / 'lineage.json').read_text())['independence'],
                             'self_attested_not_verified')

    def test_separate_reviewer_and_family_boundary_are_required(self):
        first, second = draft(1), draft(2, mode='eml')
        with self.assertRaisesRegex(ValueError, 'independent reviewer'):
            build_cohort([first], [annotation(first, reviewer='alice')])
        first['case_reviewer_ids'].append('charlie')
        with self.assertRaisesRegex(ValueError, 'independent reviewer'):
            build_cohort([first], [annotation(first, reviewer='charlie')])
        with self.assertRaisesRegex(ValueError, 'family cannot occur'):
            build_cohort([first, second], [annotation(first), annotation(second, role='holdout')])
        with self.assertRaisesRegex(ValueError, 'disagrees'):
            build_cohort([first], [{**annotation(first), 'label': 'phishing'}])
        duplicate = {**second, 'content_sha256': first['content_sha256']}
        with self.assertRaisesRegex(ValueError, 'fingerprints'):
            build_cohort([first, duplicate], [annotation(first)])

    def test_private_input_and_fingerprint_validation(self):
        item = draft(1)
        with tempfile.TemporaryDirectory() as tmp:
            private = write_private_bytes(Path(tmp) / 'draft.jsonl', _canonical(item) + b'\n')
            self.assertEqual(read_private_jsonl(private)[0]['id'], item['id'])
            private.chmod(0o644)
            with self.assertRaisesRegex(ValueError, 'private regular'):
                read_private_jsonl(private)
        item['body'] = 'Altered'
        with self.assertRaisesRegex(ValueError, 'fingerprint'):
            build_cohort([item], [annotation(item)])

    def test_cli_builds_private_files_without_exposing_message_in_stdout(self):
        item = draft(1)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            draft_path = write_private_bytes(root / 'draft.jsonl', _canonical(item) + b'\n')
            annotation_path = write_private_bytes(root / 'annotations.jsonl',
                                                  _canonical(annotation(item)) + b'\n')
            output = io.StringIO()
            with redirect_stdout(output):
                cohort_main(['--draft', str(draft_path), '--annotations', str(annotation_path),
                             '--output-dir', str(root / 'cohort')])
            self.assertEqual(read_private_jsonl(root / 'cohort' / 'development.jsonl')[0]['body'], 'Body')
            self.assertNotIn('Synthetic', output.getvalue())


if __name__ == '__main__':
    unittest.main()
