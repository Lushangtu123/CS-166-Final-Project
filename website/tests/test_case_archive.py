import base64
import copy
from datetime import date
import hashlib
import io
import json
import os
from contextlib import redirect_stdout
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from case_cloud import SUMMARY_FIELDS
from case_store import CaseStore
from tools.case_archive import (create_archive, read_archive, restore_local,
                                validate_archive, validate_namespace, write_archive)
from tools.export_reviewed_feedback import build_reviewed_draft
from tools.case_retention import PURGE_SCRIPT, main as retention_main, purge_one, retention_candidates


STAMP = '2026-09-22T20:00:00Z'


def record(number, *, feedback=False, consent=True, verdict='legitimate', status='closed'):
    case_id = f'00000000-0000-4000-8000-{number:012d}'
    return {
        'id': case_id, 'title': 'Synthetic email', 'risk': 'high',
        'status': status, 'verdict': verdict, 'version': 2, 'created_at': STAMP,
        'updated_at': STAMP, 'created_by': 'user_feedback' if feedback else 'analyst',
        'input_sha256': hashlib.sha256(case_id.encode()).hexdigest(),
        'source': {'subject': 'Synthetic mail', 'body': 'Synthetic body'},
        'analysis': {'risk_level': 'high', 'model_id': 'test-model'},
        'provenance': ({'record_kind': 'user_feedback', 'source_consent': consent,
                        'evaluation_consent': consent, 'input_mode': 'content',
                        'report_type': 'false_positive'} if feedback else {}),
        'events': [
            {'actor': 'user_feedback' if feedback else 'analyst', 'happened_at': STAMP,
             'action': 'created', 'changes': {'status': {'from': None, 'to': 'pending'}}, 'note': ''},
            {'actor': 'analyst', 'happened_at': STAMP, 'action': 'reviewed',
             'changes': {'status': {'from': 'pending', 'to': status},
                         'feedback_reason': {'from': None, 'to': 'false_alert'},
                         'evidence_basis': {'from': None, 'to': 'retained_message'}} if feedback
                        else {'status': {'from': 'pending', 'to': status}},
             'note': 'Reviewed synthetic mail'},
        ],
    }


def fields(*records):
    result = {}
    for item in records:
        case_id = item['id']
        result['r:' + case_id] = json.dumps(item)
        result['s:' + case_id] = json.dumps({key: item[key] for key in SUMMARY_FIELDS})
        result['q:' + hashlib.sha256(case_id.encode()).hexdigest()] = json.dumps({
            'id': case_id, 'digest': item['input_sha256']})
    return result


class _Store:
    def __init__(self, key, values):
        self.key = key
        self.values = values

    def execute(self, command, key, field=None):
        if key != self.key:
            raise AssertionError('wrong namespace')
        if command == 'HKEYS':
            return list(self.values)
        if command == 'HGET':
            return self.values.get(field)
        raise AssertionError('unexpected Redis command')


def archive_with(case_fields=None, feedback_fields=None):
    return create_archive(
        _Store('phishguard:cases:v1:production-cases', case_fields or {}),
        _Store('phishguard:cases:v1:production-cases-feedback', feedback_fields or {}),
        created_at=STAMP)


class CaseArchiveTests(unittest.TestCase):
    def test_private_archive_round_trip_and_isolated_sqlite_recovery(self):
        original_case = record(1)
        original_feedback = record(2, feedback=True)
        archive = archive_with(fields(original_case), fields(original_feedback))
        with tempfile.TemporaryDirectory() as tmp:
            path = write_archive(Path(tmp) / 'private.json', archive)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            loaded = read_archive(path)
            self.assertEqual(loaded, archive)
            with self.assertRaises(FileExistsError):
                write_archive(path, archive)
            counts = restore_local(loaded, Path(tmp) / 'restore')
            self.assertEqual(counts, {'case': 1, 'feedback': 1})
            self.assertEqual(CaseStore(Path(tmp) / 'restore' / 'case.sqlite3').get(original_case['id']), original_case)
            self.assertEqual(CaseStore(Path(tmp) / 'restore' / 'feedback.sqlite3').get(original_feedback['id']), original_feedback)

    def test_invalid_or_tampered_archive_fails_before_recovery(self):
        archive = archive_with(fields(record(1)), fields(record(2, feedback=True)))
        tampered = copy.deepcopy(archive)
        tampered['namespaces']['case']['r:' + record(1)['id']] = '{}'
        with self.assertRaisesRegex(ValueError, 'checksum'):
            validate_archive(tampered)
        broken = archive_with(fields(record(1)))
        broken['namespaces']['case'].pop('s:' + record(1)['id'])
        with self.assertRaisesRegex(ValueError, 'checksum'):
            validate_archive(broken)
        with self.assertRaisesRegex(ValueError, 'do not match'):
            validate_namespace(broken['namespaces']['case'])
        with tempfile.TemporaryDirectory() as tmp:
            path = write_archive(Path(tmp) / 'archive.json', archive)
            os.chmod(path, 0o644)
            with self.assertRaisesRegex(ValueError, '0600'):
                read_archive(path)

    def test_cloud_export_rejects_missing_field(self):
        incomplete = fields(record(1))
        class ChangingStore(_Store):
            def execute(self, command, key, field=None):
                if command == 'HGET' and field.startswith('r:'):
                    return None
                return super().execute(command, key, field)
        with self.assertRaisesRegex(ValueError, 'changed during export'):
            create_archive(ChangingStore('phishguard:cases:v1:one', incomplete),
                           _Store('phishguard:cases:v1:two', {}))

    def test_cloud_export_rejects_invalid_final_index_response(self):
        class InvalidFinalList(_Store):
            def __init__(self, key, values):
                super().__init__(key, values)
                self.reads = 0

            def execute(self, command, key, field=None):
                if command == 'HKEYS':
                    self.reads += 1
                    if self.reads == 2:
                        return None
                return super().execute(command, key, field)

        with self.assertRaisesRegex(ValueError, 'changed during export'):
            create_archive(InvalidFinalList('phishguard:cases:v1:one', fields(record(1))),
                           _Store('phishguard:cases:v1:two', {}))

    def test_reviewed_draft_requires_separate_consent_and_closed_human_label(self):
        consented = record(1, feedback=True)
        not_consented = record(2, feedback=True, consent=False)
        pending = record(3, feedback=True, status='in_progress')
        draft, counts = build_reviewed_draft(archive_with(feedback_fields=fields(
            consented, not_consented, pending)))
        self.assertEqual(len(draft), 1)
        self.assertEqual(draft[0]['label'], 'legitimate')
        self.assertEqual(draft[0]['body'], 'Synthetic body')
        self.assertEqual(draft[0]['review_reason'], 'false_alert')
        self.assertEqual(draft[0]['reviewed_by'], 'analyst')
        self.assertEqual(draft[0]['case_reviewer_ids'], ['analyst'])
        self.assertTrue(draft[0]['evaluation_consent'])
        self.assertNotIn('events', draft[0])
        self.assertEqual(counts['no_evaluation_consent'], 1)
        self.assertEqual(counts['not_closed_or_labeled'], 1)

    def test_conflicting_labels_are_not_exported_as_truth(self):
        first = record(1, feedback=True, verdict='phishing')
        second = record(2, feedback=True, verdict='legitimate')
        rows, counts = build_reviewed_draft(archive_with(feedback_fields=fields(first, second)))
        self.assertEqual(rows, [])
        self.assertEqual(counts['conflicting_labels'], 2)

    def test_original_eml_is_a_draft_but_legacy_consent_is_not(self):
        eml = record(1, feedback=True)
        eml['provenance']['input_mode'] = 'eml'
        eml['source'] = {'eml_base64': base64.b64encode(b'Subject: Synthetic\n\nBody').decode(),
                         'body': 'Subject: Synthetic\n\nBody'}
        legacy = record(2, feedback=True)
        legacy['provenance'].pop('evaluation_consent')
        rows, counts = build_reviewed_draft(archive_with(feedback_fields=fields(eml, legacy)))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['input_mode'], 'eml')
        self.assertEqual(base64.b64decode(rows[0]['eml_base64']), b'Subject: Synthetic\n\nBody')
        self.assertEqual(counts['no_evaluation_consent'], 1)

    def test_body_only_feedback_can_enter_curation_draft(self):
        item = record(1, feedback=True)
        item['source'] = {'body': 'Synthetic body'}
        rows, _counts = build_reviewed_draft(archive_with(feedback_fields=fields(item)))
        self.assertEqual(rows[0]['subject'], '')
        self.assertEqual(rows[0]['body'], 'Synthetic body')

    def test_legacy_or_report_only_review_is_not_exported(self):
        legacy = record(1, feedback=True)
        legacy['events'][1]['changes'].pop('feedback_reason')
        report_only = record(2, feedback=True)
        report_only['events'][1]['changes']['evidence_basis']['to'] = 'report_only'
        rows, counts = build_reviewed_draft(archive_with(feedback_fields=fields(legacy, report_only)))
        self.assertEqual(rows, [])
        self.assertEqual(counts['unstructured_review'], 2)

    def test_retention_selects_only_closed_records_before_cutoff(self):
        old = record(1, feedback=True)
        open_record = record(2, feedback=True, status='in_progress')
        archive = archive_with(feedback_fields=fields(old, open_record))
        self.assertEqual(retention_candidates(archive, 'feedback', date(2026, 9, 23)), [old['id']])
        self.assertEqual(retention_candidates(archive, 'feedback', date(2026, 9, 22)), [])
        with tempfile.TemporaryDirectory() as tmp:
            path = write_archive(Path(tmp) / 'archive.json', archive)
            output = io.StringIO()
            with redirect_stdout(output):
                retention_main(['--archive', str(path), '--kind', 'feedback', '--before', '2026-09-23'])
            self.assertIn(old['id'], output.getvalue())

    def test_cloud_purge_compares_all_three_archived_fields_before_deletion(self):
        item = record(1, feedback=True)
        archive = archive_with(feedback_fields=fields(item))
        class FakeStore:
            key = archive['source_keys']['feedback']
            def __init__(self):
                self.fields = dict(archive['namespaces']['feedback'])
                self.commands = []
            def execute(self, *command):
                self.commands.append(command)
                if command[0] == 'HGET':
                    return self.fields.get(command[2])
                self.assertion = command[1] == PURGE_SCRIPT and command[2] == 1
                names, expected = command[4:7], command[7:10]
                if any(self.fields.get(name) != raw for name, raw in zip(names, expected)):
                    return 'changed'
                for name in names:
                    del self.fields[name]
                return 'deleted'
        store = FakeStore()
        names = purge_one(store, archive, kind='feedback', case_id=item['id'], before=date(2026, 9, 23))
        self.assertTrue(store.assertion)
        self.assertEqual(len(names), 3)
        self.assertEqual(store.fields, {})
        changed = FakeStore()
        changed.fields['r:' + item['id']] = '{}'
        with self.assertRaisesRegex(ValueError, 'changed after archiving'):
            purge_one(changed, archive, kind='feedback', case_id=item['id'], before=date(2026, 9, 23))
        self.assertEqual(len(changed.fields), 3)
        with self.assertRaisesRegex(ValueError, 'not older'):
            purge_one(FakeStore(), archive, kind='feedback', case_id=item['id'], before=date(2026, 9, 22))


if __name__ == '__main__':
    unittest.main()
