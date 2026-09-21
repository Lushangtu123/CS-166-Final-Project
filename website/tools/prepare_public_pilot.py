"""Prepare a pinned, noncommercial research pilot. Never follow links in messages.

Downloads public mail only when explicitly run. Raw data stays under the caller's
local output directory; repository labels are not human-reviewed phishing labels.
"""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
from pathlib import Path
import random
import tarfile
import urllib.request

POT_REV = '49f63777126b0bdb9eb1f6e770a5c3f9df2b0306'
POT_REPO = 'rf-peixoto/phishing_pot'
HAM_URL = 'https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2'
HAM_SHA = '2b7b65904bcfcc31d2b5f51946f2d261370b257402cbbd62930b46ab83367438'
MAX_MAIL = 60000  # existing original-EML serving evaluation limit


def download(url, limit):
    request = urllib.request.Request(url, headers={'User-Agent': 'PhishGuard-personal-research'})
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Source exceeds download budget')
    return data


def ham_candidates(data):
    if hashlib.sha256(data).hexdigest() != HAM_SHA:
        raise ValueError('Normal-mail archive differs from the pinned version')
    values = []
    excluded = 0
    # Read members in memory; never extract archive paths or links to disk.
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:bz2') as archive:
        for member in archive:
            if not member.isfile() or not member.name.rsplit('/', 1)[-1][:1].isdigit():
                continue
            if not 0 < member.size <= MAX_MAIL:
                excluded += 1
                continue
            with archive.extractfile(member) as stream:
                raw = stream.read(MAX_MAIL + 1)
            if len(raw) != member.size:
                raise ValueError('Archive member size mismatch')
            values.append((member.name, raw))
    return sorted(values), excluded


def prepare(output, count, seed):
    if not 1 <= count <= 500:
        raise ValueError('Use 1–500 messages per source')
    if output.exists():
        raise ValueError('Output already exists; use a new directory to preserve prior data')
    archive = download(HAM_URL, 10_000_000)
    ham, ham_excluded = ham_candidates(archive)
    tree = json.loads(download(f'https://api.github.com/repos/{POT_REPO}/git/trees/{POT_REV}?recursive=1', 4_000_000))
    if tree.get('truncated'):
        raise ValueError('Phishing inventory is incomplete')
    all_pot = [item for item in tree['tree'] if item['type'] == 'blob' and
               item['path'].startswith('email/') and item['path'].endswith('.eml')]
    pot = sorted((item for item in all_pot if 0 < item.get('size', 0) <= MAX_MAIL), key=lambda x: x['path'])
    if min(len(ham), len(pot)) < count:
        raise ValueError('Not enough eligible messages')
    rng = random.Random(seed)
    chosen_ham = rng.sample(ham, count)
    chosen_pot = rng.sample(pot, count)

    def fetch(item):
        raw = download(f'https://raw.githubusercontent.com/{POT_REPO}/{POT_REV}/' + item['path'], MAX_MAIL)
        # Git blob identity verifies bytes against the pinned tree, not HTTP alone.
        git_sha = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        if len(raw) != item['size'] or git_sha != item['sha']:
            raise ValueError('Phishing sample differs from pinned Git object')
        return raw
    with ThreadPoolExecutor(max_workers=4) as pool:
        phishing = list(pool.map(fetch, chosen_pot))
    output.mkdir(parents=True)
    (output / 'mail').mkdir()
    rows = []
    for source, label, samples in [('spamassassin-easy-ham', 'legitimate', [raw for _, raw in chosen_ham]),
                                   ('phishing-pot', 'phishing', phishing)]:
        for number, raw in enumerate(samples, 1):
            identifier = f'{source}-{number:04}'
            path = f'mail/{identifier}.eml'
            (output / path).write_bytes(raw)
            rows.append({'id': identifier, 'source_id': source, 'label': label,
                         'eml_path': path, 'content_sha256': hashlib.sha256(raw).hexdigest()})
    (output / 'records.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
    manifest = {'schema_version': 1, 'records': 'records.jsonl', 'exploratory_only': True, 'sources': [
        {'id': 'phishing-pot', 'url': f'https://github.com/{POT_REPO}', 'revision': POT_REV,
         'license': 'CC-BY-NC-4.0', 'label_basis': 'Repository collection label; not individually reviewed; may include spam/scam.'},
        {'id': 'spamassassin-easy-ham', 'url': HAM_URL, 'revision': 'sha256:' + HAM_SHA,
         'license': 'Public research corpus; message copyright retained by original senders',
         'label_basis': 'Upstream easy_ham label; historical normal mail, not contemporary business mail.'}],
        'study_notes': {'purpose': 'personal noncommercial exploratory evaluation', 'labels_human_reviewed': False,
                        'seed': seed, 'sample_count_per_source': count, 'max_mail_bytes': MAX_MAIL,
                        'sampling': 'seeded uniform sample within each size-eligible source; not representative of production prevalence',
                        'excluded_size': {'phishing-pot': len(all_pot) - len(pot), 'spamassassin-easy-ham': ham_excluded},
                        'training_independence': 'not_verified', 'provider_and_received_date': 'unknown; not inferred from sender or untrusted Date header'}}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return {'records': len(rows), 'count_per_source': count, 'labels': 'upstream assertions; unreviewed',
            'excluded_size': manifest['study_notes']['excluded_size']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--count', type=int, default=100)
    parser.add_argument('--seed', type=int, default=42)
    args = parser.parse_args()
    print(json.dumps(prepare(args.output, args.count, args.seed), indent=2))


if __name__ == '__main__':
    main()
