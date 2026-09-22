import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from manage_case_access import main, merge_credential, parse_existing_mapping


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


class CaseAccessManagerTests(unittest.TestCase):
    def test_existing_mapping_is_validated_and_preserved_when_adding_an_analyst(self):
        current = parse_existing_mapping(json.dumps({'alice': digest('alice-token')}))

        merged, changed = merge_credential(current, 'bob', digest('bob-token'))

        self.assertTrue(changed)
        self.assertEqual(merged, {
            'alice': digest('alice-token'),
            'bob': digest('bob-token'),
        })
        self.assertEqual(current, {'alice': digest('alice-token')})

    def test_existing_actor_cannot_be_rotated_without_explicit_confirmation(self):
        current = {'alice': digest('old-token')}

        with self.assertRaisesRegex(ValueError, 'ROTATE'):
            merge_credential(current, 'alice', digest('new-token'))

        merged, changed = merge_credential(
            current, 'alice', digest('new-token'), allow_rotation=True)
        self.assertTrue(changed)
        self.assertEqual(merged['alice'], digest('new-token'))

    def test_reusing_the_same_actor_and_token_is_a_noop(self):
        current = {'alice': digest('same-token')}

        merged, changed = merge_credential(current, 'alice', digest('same-token'))

        self.assertFalse(changed)
        self.assertEqual(merged, current)

    def test_invalid_maps_and_duplicate_credentials_are_rejected(self):
        for raw in ('', '[]', '{"bad actor":"' + 'a' * 64 + '"}',
                    '{"alice":"NOT-A-HASH"}'):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    parse_existing_mapping(raw)

        with self.assertRaisesRegex(ValueError, 'already belongs'):
            merge_credential({'alice': digest('shared-token')},
                             'bob', digest('shared-token'))

    def test_invalid_existing_json_stops_before_new_token_is_generated(self):
        with patch('manage_case_access.sys.stdin.isatty', return_value=True), \
             patch('manage_case_access.sys.stdout.isatty', return_value=True), \
             patch('builtins.input', return_value='alice'), \
             patch('manage_case_access.getpass', return_value='invalid JSON'), \
             patch('manage_case_access.secrets.token_urlsafe') as generate:
            with self.assertRaisesRegex(SystemExit, 'JSON object'):
                main()
        generate.assert_not_called()

    def test_existing_actor_requires_rotation_before_generating_a_new_token(self):
        current = json.dumps({'alice': digest('old-token')})
        with patch('manage_case_access.sys.stdin.isatty', return_value=True), \
             patch('manage_case_access.sys.stdout.isatty', return_value=True), \
             patch('builtins.input', side_effect=['alice', 'n', '']), \
             patch('manage_case_access.getpass', return_value=current), \
             patch('manage_case_access.secrets.token_urlsafe') as generate:
            with self.assertRaisesRegex(SystemExit, 'not changed'):
                main()
        generate.assert_not_called()

    def test_interactive_output_contains_the_complete_merged_mapping(self):
        current = json.dumps({'alice': digest('alice-token')})
        existing_token = 'synthetic-bob-token-with-at-least-32-characters'
        with patch('manage_case_access.sys.stdin.isatty', return_value=True), \
             patch('manage_case_access.sys.stdout.isatty', return_value=True), \
             patch('builtins.input', side_effect=['bob', 'y']), \
             patch('manage_case_access.getpass', side_effect=[current, existing_token]), \
             patch('builtins.print') as output:
            main()
        emitted = [call.args[0] for call in output.call_args_list
                   if len(call.args) == 1 and call.args[0].startswith('{')]
        self.assertEqual(len(emitted), 1)
        self.assertEqual(json.loads(emitted[0]), {
            'alice': digest('alice-token'),
            'bob': digest(existing_token),
        })


if __name__ == '__main__':
    unittest.main()
