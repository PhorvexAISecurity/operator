"""Archived records (ARCHIVE.yaml): evidence removed at import is tolerated, structure is not."""
from __future__ import annotations

import argparse
import hashlib
import io
import re
import unittest
from contextlib import contextmanager, redirect_stdout
from pathlib import Path

from test_operations import prepare_fix_evidence, run, sandbox, workflow as w

FIX = 'T1-M001'
CAMPAIGN = '2026-09-07-archived-study'
ROLES = {'human_owner': 'owner', 'proposer': 'author', 'implementer': 'author',
         'skeptic': 'reviewer', 'live_verifier': 'reviewer', 'coordinator': 'coordinator'}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def declare(root: Path, *, fixes=(), absent_fixes=(), campaigns=None, assessments=()) -> None:
    """Write the import-time declaration, freezing each listed STATUS.yaml as it is now."""
    def frozen(path: Path):
        return digest(path) if path.is_file() else None
    w.write_yaml(root / 'ARCHIVE.yaml', {
        'schema_version': 1,
        'source': {'repository': 'Example/source', 'url': 'https://example.invalid/source.git',
                   'revision': 'a' * 40, 'imported_revision': 'b' * 40,
                   'import_date': '2026-10-16', 'commit_map': 'docs/provenance/map.tsv'},
        'records': {
            'fixes': {**{fix_id: {'status_sha256': frozen(root / 'fixes' / fix_id / 'STATUS.yaml')}
                         for fix_id in fixes},
                      **{fix_id: {'status_sha256': None} for fix_id in absent_fixes}},
            'campaigns': {campaign_id: {'status_sha256': frozen(root / 'campaigns' / campaign_id / 'STATUS.yaml'),
                                        'rounds': list(rounds)}
                          for campaign_id, rounds in (campaigns or {}).items()},
            'assessments': list(assessments),
        },
    })


def doctor() -> list[str]:
    output = io.StringIO()
    with redirect_stdout(output):
        args = w.build_parser().parse_args(['doctor'])
        args.func(args)
    return output.getvalue().splitlines()


def failures(lines: list[str], needle: str) -> list[str]:
    return [line for line in lines if line.startswith('FAIL: ') and needle in line]


def strip(record: Path, keep=()) -> None:
    """Mimic the import: drop evidence files and rewrite every pinned commit SHA."""
    for path in sorted(record.rglob('*'), reverse=True):
        relative = path.relative_to(record).as_posix()
        if path.is_file() and relative not in {'STATUS.yaml', *keep}:
            path.unlink()
        elif path.is_dir() and not any(path.iterdir()):
            path.rmdir()
    status = record / 'STATUS.yaml'
    text = status.read_text()
    for sha in set(re.findall(r'\b[0-9a-f]{40}\b', text)):
        text = text.replace(sha, hashlib.sha1(b'pre-import:' + sha.encode()).hexdigest())
    status.write_text(text)


@contextmanager
def attested_fix():
    """A deployed fix whose every gate passes before the import strips it."""
    with sandbox() as (repo, root, baseline):
        (repo / 'widget.txt').write_text('fixed\n')
        run(['git', 'add', 'widget.txt'], repo)
        run(['git', 'commit', '-m', 'widget correction'], repo)
        head = run(['git', 'rev-parse', 'HEAD'], repo)
        fix = w.create_fix_record(FIX, ['M-1'])
        status = w.load_yaml(fix / 'STATUS.yaml')
        status['roles'] = dict(ROLES)
        status['state'] = 'DEPLOYED'
        status['implementation'].update(branch='fix/widget', base_sha=baseline, head_sha=head)
        status['pull_request'].update(url='https://example.invalid/pr/1', reviewed_head=head,
                                      merge_sha=head, checks='PASS')
        status['deployment'].update(image='widget:test', digest='sha256:fixture', git_sha=head,
                                    rolled_out_at=w.utcnow())
        status['verification']['required'] = ['L0', 'L1', 'L2', 'L3']
        w.write_yaml(fix / 'STATUS.yaml', status)
        prepare_fix_evidence(FIX, repo)
        yield root, fix


class ArchivedFixTests(unittest.TestCase):
    def test_archived_record_tolerates_removed_evidence_and_commits(self):
        with attested_fix() as (root, fix):
            self.assertEqual(failures(doctor(), FIX), [], 'fixture must pass every gate before the import')
            strip(fix)
            declare(root, fixes=[FIX])
            lines = doctor()
            self.assertEqual(failures(lines, FIX), [])
            self.assertEqual(failures(lines, 'ARCHIVE.yaml'), [])

    def test_unarchived_record_with_removed_evidence_fails(self):
        with attested_fix() as (root, fix):
            strip(fix)
            declare(root, fixes=[])
            lines = doctor()
            self.assertIn(f'FAIL: {FIX}: missing evidence/manifest.yaml', lines)
            self.assertIn(f'FAIL: {FIX}: decision: missing or unchanged template artifact', lines)
            self.assertIn(f'FAIL: {FIX}: deployed source does not contain recorded merge', lines)
            # Without any declaration the same record is checked identically.
            (root / 'ARCHIVE.yaml').unlink()
            self.assertIn(f'FAIL: {FIX}: missing evidence/manifest.yaml', doctor())

    def test_archived_record_keeps_structural_checks(self):
        with attested_fix() as (root, fix):
            strip(fix)
            status = w.load_yaml(fix / 'STATUS.yaml')
            status['roles']['skeptic'] = status['roles']['implementer']
            status['checks']['l1']['by'] = 'someone-else'
            status['next_action'] = {}
            w.write_yaml(fix / 'STATUS.yaml', status)
            declare(root, fixes=[FIX])
            lines = doctor()
            self.assertIn(f'FAIL: {FIX}: skeptic must differ from proposer and implementer', lines)
            self.assertIn(f'FAIL: {FIX}: l1: signer must be assigned implementer', lines)
            self.assertIn(f'FAIL: {FIX}: no next action', lines)

    def test_retained_evidence_of_archived_record_is_still_verified(self):
        with attested_fix() as (root, fix):
            strip(fix, keep={'03-decision.md', 'evidence/manifest.yaml'})
            (fix / '03-decision.md').write_text('Rewritten after review.\n')
            declare(root, fixes=[FIX])
            lines = doctor()
            self.assertIn(f'FAIL: {FIX}: decision: artifact changed after attestation', lines)
            self.assertIn(f'FAIL: {FIX}: evidence hash mismatch 03-decision.md', lines)
            self.assertEqual([line for line in failures(lines, FIX) if 'missing' in line], [])

    def test_archived_status_is_immutable(self):
        with attested_fix() as (root, fix):
            strip(fix)
            declare(root, fixes=[FIX])
            status = w.load_yaml(fix / 'STATUS.yaml')
            status['state'] = 'LIVE_VERIFIED'
            w.write_yaml(fix / 'STATUS.yaml', status)
            self.assertTrue(failures(doctor(), f'fixes/{FIX}/STATUS.yaml: archived record changed since import'))

    def test_archived_ids_cannot_be_reused_or_removed(self):
        with sandbox() as (_, root, _):
            w.create_fix_record(FIX, ['M-1'])
            declare(root, absent_fixes=[FIX], campaigns={CAMPAIGN: []})
            (root / 'campaigns' / CAMPAIGN).mkdir()
            w.write_yaml(root / 'campaigns' / CAMPAIGN / 'STATUS.yaml', {'campaign_id': CAMPAIGN})
            lines = doctor()
            self.assertTrue(failures(lines, f'fixes/{FIX}/STATUS.yaml: archived id had no STATUS.yaml at import'))
            self.assertTrue(failures(lines, f'campaigns/{CAMPAIGN}/STATUS.yaml: archived id had no STATUS.yaml'))
        with sandbox() as (_, root, _):
            fix = w.create_fix_record(FIX, ['M-1'])
            declare(root, fixes=[FIX])
            for path in sorted(fix.rglob('*'), reverse=True):
                path.unlink() if path.is_file() else path.rmdir()
            fix.rmdir()
            self.assertTrue(failures(doctor(), f'fixes/{FIX}/STATUS.yaml: archived record was removed'))

    def test_summary_warning_counts_archived_records_once(self):
        with attested_fix() as (root, fix):
            strip(fix)
            self.assertFalse([line for line in doctor() if 'archived records' in line])
            declare(root, fixes=[FIX], absent_fixes=['T9-GONE'], campaigns={'2026-09-01-gone': []},
                    assessments=['20260901-first', '20260902-second'])
            summary = [line for line in doctor() if 'archived records' in line]
            self.assertEqual(len(summary), 1)
            self.assertTrue(summary[0].startswith(
                'WARN: 5 archived records (fixes 2, campaigns 1 with 0 rounds, assessments 2) '
                'are verified only against Example/source@aaaaaaaa'), summary[0])

    def test_invalid_declaration_fails_closed(self):
        with sandbox() as (_, root, _):
            declare(root)
            document = w.load_yaml(root / 'ARCHIVE.yaml')
            document['source']['revision'] = 'main'
            w.write_yaml(root / 'ARCHIVE.yaml', document)
            self.assertTrue(failures(doctor(), 'ARCHIVE.yaml: schema source.revision'))


class ArchivedCampaignTests(unittest.TestCase):
    def new_campaign(self) -> Path:
        args = w.build_parser().parse_args([
            'new-campaign', 'Archived study', '--id', CAMPAIGN, '--approval-ref', 'fixture:scope',
            '--environment', 'fixture', '--permission', 'read-only', '--duration-ceiling', '1m',
            '--cost-ceiling', 'zero', '--campaign-lead', 'verifier', '--coordinator', 'coordinator'])
        with redirect_stdout(io.StringIO()):
            self.assertEqual(args.func(args), 0)
            self.assertEqual(w.cmd_new_campaign_round(
                argparse.Namespace(campaign_id=CAMPAIGN, round_id='round-2')), 0)
        return w.CAMPAIGNS / CAMPAIGN

    def test_rounds_outside_the_archive_keep_full_checks(self):
        with sandbox() as (_, root, _):
            campaign = self.new_campaign()
            for name in ('CAMPAIGN.md', 'hypotheses.yaml', 'verdict.md',
                         'rounds/round-1/evidence/manifest.yaml', 'rounds/round-2/evidence/manifest.yaml'):
                (campaign / name).unlink()
            declare(root, campaigns={CAMPAIGN: ['round-1']})
            lines = doctor()
            self.assertEqual(failures(lines, f'campaigns/{CAMPAIGN}/rounds/round-1/'), [])
            self.assertEqual(failures(lines, f'{CAMPAIGN}: missing'), [])
            self.assertTrue(failures(lines, f'campaigns/{CAMPAIGN}/rounds/round-2/evidence/manifest.yaml: '
                                            'missing evidence manifest'))
            (root / 'ARCHIVE.yaml').unlink()
            lines = doctor()
            self.assertTrue(failures(lines, f'campaigns/{CAMPAIGN}/rounds/round-1/evidence/manifest.yaml: '
                                            'missing evidence manifest'))
            self.assertIn(f'FAIL: {CAMPAIGN}: missing CAMPAIGN.md', lines)


if __name__ == '__main__':
    unittest.main()
