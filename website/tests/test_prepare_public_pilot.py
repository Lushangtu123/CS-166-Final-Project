"""Pinned research download preparation, exercised entirely with synthetic bytes."""
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import prepare_public_pilot as pilot
from tools.evaluation_data import load_corpus


def archive_bytes():
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w:bz2') as archive:
        for name, raw in [('easy_ham/0001.normal', b'Subject: Notes\n\nMeeting tomorrow.'),
                          ('../../0002.escape', b'Subject: Notes\n\nBring your notes.'),
                          ('easy_ham/0003.large', b'x' * (pilot.MAX_MAIL + 1))]:
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
        link = tarfile.TarInfo('../../0004.link')
        link.type = tarfile.SYMTYPE
        link.linkname = '/private/sensitive'
        archive.addfile(link)
    return buffer.getvalue()


class PreparePublicPilotTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.archive = archive_bytes()
        self.messages = {f'email/{number}.eml': f'Subject: Suspicious {number}\n\nVerify your password.'.encode() for number in range(3)}
        self.tree = {'truncated': False, 'tree': [
            {'path': path, 'type': 'blob', 'size': len(raw),
             'sha': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}
            for path, raw in self.messages.items()]}

    def download(self, url, limit):
        if url == pilot.HAM_URL:
            return self.archive
        if url == f'https://api.github.com/repos/{pilot.POT_REPO}/git/trees/{pilot.POT_REV}?recursive=1':
            return json.dumps(self.tree).encode()
        prefix = f'https://raw.githubusercontent.com/{pilot.POT_REPO}/{pilot.POT_REV}/'
        if url.startswith(prefix):
            self.assertEqual(limit, pilot.MAX_MAIL)
            return self.messages[url[len(prefix):]]
        self.fail('Unexpected URL')

    def prepare(self, output, count=2):
        with patch.object(pilot, 'download', side_effect=self.download), \
             patch.object(pilot, 'HAM_SHA', hashlib.sha256(self.archive).hexdigest()):
            return pilot.prepare(output, count, 42)

    def test_checksum_rejected_before_archive_parsing(self):
        with patch.object(pilot.tarfile, 'open') as read_archive:
            with self.assertRaisesRegex(ValueError, 'pinned version'):
                pilot.ham_candidates(b'not the pinned archive')
            read_archive.assert_not_called()

    def test_existing_output_never_overwritten_and_counts_bounded_before_download(self):
        output = self.root / 'existing'
        output.mkdir()
        sentinel = output / 'keep.txt'
        sentinel.write_text('unchanged')
        with patch.object(pilot, 'download') as download:
            with self.assertRaisesRegex(ValueError, 'already exists'):
                pilot.prepare(output, 1, 42)
            for count in (0, -1, 501):
                with self.subTest(count=count), self.assertRaises(ValueError):
                    pilot.prepare(self.root / 'new', count, 42)
            download.assert_not_called()
        self.assertEqual(sentinel.read_text(), 'unchanged')

    def test_mocked_prepare_verifies_git_blobs_and_writes_loadable_exploratory_manifest(self):
        output = self.root / 'pilot'
        result = self.prepare(output)
        self.assertEqual(result['records'], 4)
        self.assertEqual(result['excluded_size']['spamassassin-easy-ham'], 1)
        manifest = json.loads((output / 'manifest.json').read_text())
        self.assertIs(manifest['exploratory_only'], True)
        self.assertIs(manifest['study_notes']['labels_human_reviewed'], False)
        corpus = load_corpus(output / 'manifest.json')
        self.assertEqual(len(corpus.records), 4)
        self.assertTrue(all(row['provider'] == 'unknown' and row['received_at'] is None for row in corpus.records))
        self.assertEqual({row['label'] for row in corpus.records}, {'legitimate', 'phishing'})
        for row in json.loads('[' + ','.join((output / 'records.jsonl').read_text().splitlines()) + ']'):
            self.assertEqual(hashlib.sha256((output / row['eml_path']).read_bytes()).hexdigest(), row['content_sha256'])
        # Malicious archive names and link targets are never used for local writes.
        self.assertFalse((self.root / '0002.escape').exists())
        self.assertFalse((output / '0004.link').exists())
        self.assertEqual(len(list(output.rglob('*.eml'))), 4)
        self.assertFalse(any(path.is_symlink() for path in output.rglob('*')))

    def test_git_blob_tampering_fails_before_any_output_is_written(self):
        for row in self.tree['tree']:
            row['sha'] = '0' * 40
        output = self.root / 'bad'
        with self.assertRaisesRegex(ValueError, 'Git object'):
            self.prepare(output)
        self.assertFalse(output.exists())

    def test_truncated_or_insufficient_inventory_does_not_write_partial_dataset(self):
        output = self.root / 'bad'
        self.tree['truncated'] = True
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            self.prepare(output)
        self.tree['truncated'] = False
        self.tree['tree'] = self.tree['tree'][:1]
        with self.assertRaisesRegex(ValueError, 'Not enough'):
            self.prepare(output)
        self.assertFalse(output.exists())

    def test_seeded_sampling_is_reproducible(self):
        self.prepare(self.root / 'first')
        self.prepare(self.root / 'second')
        one = load_corpus(self.root / 'first/manifest.json')
        two = load_corpus(self.root / 'second/manifest.json')
        self.assertEqual(one.dataset_sha256, two.dataset_sha256)

    def test_network_reader_enforces_bounded_download(self):
        response = io.BytesIO(b'123456')
        with patch.object(pilot.urllib.request, 'urlopen', return_value=response) as urlopen:
            with self.assertRaisesRegex(ValueError, 'budget'):
                pilot.download('https://example.org/fixed', 5)
            self.assertEqual(urlopen.call_args.kwargs['timeout'], 30)


if __name__ == '__main__':
    unittest.main()
