"""Reviewed patch artifacts stay byte-exact across clones that abbreviate object ids differently."""
from __future__ import annotations

import re
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_operations import run
import patches
import jsonschema


def git_bytes(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(['git', *args], cwd=repo)


def init_repo(path: Path, *, object_format: str | None = None) -> None:
    extra = [f'--object-format={object_format}'] if object_format else []
    run(['git', 'init', '-q', '-b', 'main', *extra], path)
    run(['git', 'config', '--local', 'maintenance.auto', 'false'], path)
    run(['git', 'config', '--local', 'gc.auto', '0'], path)
    run(['git', 'config', 'user.name', 'Workflow Test'], path)
    run(['git', 'config', 'user.email', 'workflow@example.invalid'], path)


def fixture(path: Path, *, object_format: str | None = None) -> tuple[str, str]:
    """Text edits, added/deleted files, a mode change, a rename and binary content in two commits."""
    init_repo(path, object_format=object_format)
    (path/'text.txt').write_text('alpha\nbeta\ngamma\ndelta\n')
    (path/'gone.txt').write_text('to be deleted\n')
    (path/'script.sh').write_text('#!/bin/sh\necho hi\n')
    (path/'old-name.txt').write_text('line one\nline two\nline three\nline four\n')
    (path/'image.bin').write_bytes(bytes(range(256)) * 4)
    run(['git', 'add', '-A'], path); run(['git', 'commit', '-q', '-m', 'baseline'], path)
    base = run(['git', 'rev-parse', 'HEAD'], path)
    (path/'text.txt').write_text('alpha\nindex deadbeef..cafebabe 100644\nbeta\ngamma\ndelta\n')
    (path/'added.txt').write_text('new file\n')
    (path/'gone.txt').unlink()
    (path/'script.sh').chmod(0o755)
    (path/'old-name.txt').rename(path/'new-name.txt')
    (path/'new-name.txt').write_text('line one\nline two\nline three\nline four\nline five\n')
    (path/'image.bin').write_bytes(bytes(range(255, -1, -1)) * 4)
    (path/'blob.bin').write_bytes(b'\x00\x01\x02\xff' * 64)
    run(['git', 'add', '-A'], path); run(['git', 'commit', '-q', '-m', 'change'], path)
    return base, run(['git', 'rev-parse', 'HEAD'], path)


def abbreviated(repo: Path, base: str, head: str, abbrev: int | str) -> bytes:
    """What a worker's plain `git diff --binary` renders in a clone with this abbreviation."""
    return git_bytes(repo, '-c', f'core.abbrev={abbrev}', 'diff', '--binary', base, head)


def index_lines(patch: bytes) -> list[bytes]:
    return [line for line in patch.split(b'\n') if line.startswith(b'index ')]


class PatchPortabilityTests(unittest.TestCase):
    def setUp(self):
        self.raw = tempfile.TemporaryDirectory(prefix='workflow-patch-test-')
        self.repo = Path(self.raw.name)/'repo'; self.repo.mkdir()
        self.base, self.head = fixture(self.repo)
        self.canonical = patches.render(self.repo, self.base, self.head)
        self.hexsz = patches.hex_size(self.repo)

    def tearDown(self):
        self.raw.cleanup()

    def assertRejected(self, recorded: bytes, fragment: str):
        reason = patches.mismatch(recorded, self.canonical, self.hexsz)
        self.assertIsNotNone(reason, 'tampered patch was accepted')
        self.assertIn(fragment, reason)

    def test_fixture_exercises_every_header_shape(self):
        text = self.canonical.decode('latin-1')
        for marker in ('new file mode 100644', 'deleted file mode 100644', 'old mode 100644', 'new mode 100755',
                       'rename from old-name.txt', 'rename to new-name.txt', 'similarity index',
                       'GIT binary patch', '+index deadbeef..cafebabe 100644'):
            self.assertIn(marker, text)
        self.assertEqual(self.canonical.count(b'\ndiff --git '), 6)
        self.assertEqual(self.hexsz, 40)
        ids = [re.fullmatch(rb'index ([0-9a-f]+)\.\.([0-9a-f]+)( [0-7]{6})?', line) for line in index_lines(self.canonical)]
        self.assertTrue(ids and all(m and len(m[1]) == 40 and len(m[2]) == 40 for m in ids))
        short = abbreviated(self.repo, self.base, self.head, 8)
        self.assertTrue(any(len(re.match(rb'index ([0-9a-f]+)', line)[1]) == 8 for line in index_lines(short)))
        # Binary payloads already carry full ids under --binary; only text headers abbreviate.
        self.assertTrue(any(len(re.match(rb'index ([0-9a-f]+)', line)[1]) == 40 for line in index_lines(short)))

    def test_old_gate_rejects_and_new_gate_accepts_abbreviation_changes(self):
        default = git_bytes(self.repo, 'diff', '--binary', self.base, self.head)
        for abbrev in (7, 8, 12, 40, 'no'):
            recorded = abbreviated(self.repo, self.base, self.head, abbrev)
            self.assertIsNone(patches.mismatch(recorded, self.canonical, self.hexsz), abbrev)
            self.assertIsNone(patches.verify(self.repo, self._write(recorded), self.base, self.head), abbrev)
            self.assertEqual(recorded.split(b'\n')[0], self.canonical.split(b'\n')[0])
        eight = abbreviated(self.repo, self.base, self.head, 8)
        self.assertNotEqual(eight, default, 'fixture must change the rendered abbreviation')
        # The superseded contract was plain byte equality with this clone's `git diff --binary`.
        self.assertFalse(eight == default)
        self.assertEqual(abbreviated(self.repo, self.base, self.head, 'no'), self.canonical)
        self.assertIsNone(patches.mismatch(self.canonical, self.canonical, self.hexsz))

    def test_patch_copied_from_a_separate_clone_is_accepted(self):
        clone = Path(self.raw.name)/'clone'
        run(['git', 'clone', '-q', '--no-hardlinks', str(self.repo), str(clone)], Path(self.raw.name))
        run(['git', 'config', '--local', 'maintenance.auto', 'false'], clone)
        copied = abbreviated(clone, self.base, self.head, 8)
        self.assertNotEqual(copied, abbreviated(self.repo, self.base, self.head, 7))
        self.assertIsNone(patches.mismatch(copied, self.canonical, self.hexsz))
        self.assertEqual(patches.render(clone, self.base, self.head), self.canonical)
        self.assertIsNone(patches.verify(clone, self._write(abbreviated(self.repo, self.base, self.head, 7)), self.base, self.head))

    def test_material_tampering_still_fails(self):
        recorded = abbreviated(self.repo, self.base, self.head, 8)
        header = next(line for line in index_lines(recorded) if line.endswith(b' 100644') and not line.startswith(b'index 00000000'))
        old, new = re.match(rb'index ([0-9a-f]+)\.\.([0-9a-f]+)', header).groups()
        flipped = (b'0' if old[:1] != b'0' else b'1') + old[1:]
        cases = {
            'wrong old prefix': (header, b'index ' + flipped + b'..' + new + b' 100644', 'is not a prefix of pinned'),
            'wrong new prefix': (header, b'index ' + old + b'..' + new[:-1] + (b'0' if new[-1:] != b'0' else b'1') + b' 100644', 'is not a prefix of pinned'),
            'mode suffix': (header, header.replace(b' 100644', b' 100755'), 'mode differs'),
            'zero placeholder on a present side': (header, b'index ' + b'0' * 8 + b'..' + new + b' 100644', 'is not a prefix of pinned'),
            'too short': (header, b'index ' + old[:3] + b'..' + new + b' 100644', 'abbreviation length 3'),
            'too long': (header, b'index ' + old + b'f' * 33 + b'..' + new + b' 100644', 'abbreviation length 73'),
            'non hex': (header, b'index ' + old[:-1] + b'g..' + new + b' 100644', 'malformed'),
            'header without ids': (header, b'index', 'differs from the pinned source diff'),
            'header ids only': (header, b'index ' + old + b'..' + new + b' 100644 x', 'malformed'),
            'hunk range': (b'@@ -1,4 +1,5 @@', b'@@ -1,4 +1,6 @@', 'differs from the pinned source diff'),
            'added line': (b'+index deadbeef..cafebabe 100644', b'+index deadbeef0..cafebabe 100644', 'differs from the pinned source diff'),
            'context whitespace': (b'\n beta\n', b'\n beta \n', 'differs from the pinned source diff'),
            'renamed path': (b'rename to new-name.txt', b'rename to new-name2.txt', 'differs from the pinned source diff'),
            'diff header path': (b'diff --git a/added.txt b/added.txt', b'diff --git a/added.txt b/added2.txt', 'differs from the pinned source diff'),
            'new file mode': (b'new file mode 100644', b'new file mode 100755', 'differs from the pinned source diff'),
            'binary payload': (b'GIT binary patch\nliteral', b'GIT binary patch\ndelta', 'differs from the pinned source diff'),
        }
        for name, (before, after, fragment) in cases.items():
            self.assertIn(before, recorded, name)
            with self.subTest(name):
                self.assertRejected(recorded.replace(before, after, 1), fragment)
        literal = recorded.index(b'GIT binary patch')
        payload = recorded.index(b'\n', recorded.index(b'literal', literal)) + 1
        body = bytearray(recorded); body[payload + 1] = (body[payload + 1] + 1) % 256
        self.assertRejected(bytes(body), 'differs from the pinned source diff')
        headers = [line for line in index_lines(recorded) if line.endswith(b' 100644') and not line.startswith(b'index 00000000')]
        self.assertGreaterEqual(len(headers), 2)
        swapped = recorded.replace(headers[0], b'\x00', 1).replace(headers[1], headers[0], 1).replace(b'\x00', headers[1], 1)
        self.assertRejected(swapped, 'is not a prefix of pinned')
        self.assertRejected(recorded.replace(header, header + b'\n' + header, 1), 'line count differs')
        self.assertRejected(recorded.replace(b'\n beta\n', b'\n', 1), 'line count differs')
        self.assertRejected(recorded + b'\n', 'line count differs')
        self.assertRejected(recorded[:-1], 'line count differs')
        self.assertRejected(b'', 'recorded patch is empty')
        self.assertRejected(git_bytes(self.repo, 'diff', '--binary', '-U5', self.base, self.head), 'differs')
        self.assertRejected(git_bytes(self.repo, 'diff', '--binary', self.base, self.head, '--', 'text.txt'), 'line count differs')
        self.assertRejected(re.sub(rb'\nindex [0-9a-f]+\.\.[0-9a-f]+ 100644\n', b'\n', recorded, count=1), 'line count differs')

    def test_zero_placeholders_only_for_absent_sides(self):
        real = b'0' * 8 + b'a' * 32
        self.assertIsNone(patches.index_header_mismatch(b'index 00000000..' + real + b' 100644', b'index ' + b'0' * 40 + b'..' + real + b' 100644', 40))
        self.assertIn('zero placeholder', patches.index_header_mismatch(b'index 00000000..' + b'b' * 40 + b' 100644', b'index ' + real + b'..' + b'b' * 40 + b' 100644', 40))
        self.assertIn('not a full-index header', patches.index_header_mismatch(b'index 0000000..abcdef0', b'index 0000000..abcdef0', 40))
        self.assertIn('not a full-index header', patches.index_header_mismatch(b'index ' + b'0' * 40 + b'..' + real, b'index ' + b'0' * 40 + b'..' + real, 64))

    def test_empty_missing_or_invalid_pins_fail(self):
        self.assertEqual(patches.mismatch(b'', b'', 40), 'canonical diff is empty')
        self.assertIn('canonical diff is empty', patches.verify(self.repo, self._write(b''), self.head, self.head))
        self.assertIn('canonical diff is empty', patches.verify(self.repo, self._write(self.canonical), self.head, self.head))
        self.assertEqual(patches.verify(self.repo, None, self.base, self.head), patches.GATE_MESSAGE)
        self.assertIn(patches.GATE_MESSAGE, patches.verify(self.repo, self._write(self.canonical), self.base, 'f' * 40))
        self.assertIn('differs', patches.verify(self.repo, self._write(self.canonical), self.head, self.base))

    def test_sha256_repository_uses_its_own_id_width(self):
        repo = Path(self.raw.name)/'sha256'; repo.mkdir()
        base, head = fixture(repo, object_format='sha256')
        self.assertEqual(patches.hex_size(repo), 64)
        canonical = patches.render(repo, base, head)
        self.assertTrue(all(len(m) == 64 for line in index_lines(canonical) for m in re.match(rb'index ([0-9a-f]+)\.\.([0-9a-f]+)', line).groups()))
        for abbrev in (7, 8, 40, 64):
            self.assertIsNone(patches.mismatch(abbreviated(repo, base, head, abbrev), canonical, 64), abbrev)
        self.assertIsNone(patches.verify(repo, self._write(abbreviated(repo, base, head, 8)), base, head))
        self.assertIn('not a full-index header', patches.mismatch(abbreviated(repo, base, head, 8), canonical, 40))
        self.assertIn('not a full-index header', patches.mismatch(self.canonical, self.canonical.replace(b'\nindex ', b'\nindex 0', 1), 40))

    def test_digest_envelope_binds_every_canonical_diff_byte_and_pin(self):
        envelope = patches.render(self.repo, self.base, self.head, patches.DIGEST_FORMAT)
        expected = (f'format: {patches.DIGEST_FORMAT}\nbase_sha: {self.base}\nhead_sha: {self.head}\n'
                    f'diff_sha256: {hashlib.sha256(self.canonical).hexdigest()}\n').encode()
        self.assertEqual(envelope, expected)
        path = self._write(envelope)
        self.assertIsNone(patches.verify(self.repo, path, self.base, self.head, patches.DIGEST_FORMAT))

        cases = [
            envelope.replace(self.base.encode(), self.head.encode(), 1),
            envelope.replace(self.head.encode(), self.base.encode(), 1),
            envelope.replace(b'diff_sha256: ', b'diff_sha256: 0', 1),
            envelope + b'diff_sha256: ' + b'0' * 64 + b'\n',
            envelope.replace(b'format:', b'unknown:'),
            envelope.rstrip(b'\n'),
            self.canonical,
        ]
        for recorded in cases:
            with self.subTest(recorded=recorded[:30]):
                self.assertIsNotNone(patches.verify(self.repo, self._write(recorded), self.base, self.head,
                                                     patches.DIGEST_FORMAT))
        self.assertIsNotNone(patches.verify(self.repo, self._write(envelope), self.base, self.head, 'unknown'))
        self.assertIsNotNone(patches.verify(self.repo, self._write(envelope), self.head, self.head,
                                                 patches.DIGEST_FORMAT))

    def test_digest_omits_deleted_payload_and_is_portable_across_fresh_clones(self):
        secret = self.repo/'private-sentinel.txt'
        secret.write_text('harmless deleted sentinel\n')
        run(['git', 'add', 'private-sentinel.txt'], self.repo)
        run(['git', 'commit', '-q', '-m', 'sentinel baseline'], self.repo)
        base = run(['git', 'rev-parse', 'HEAD'], self.repo)
        secret.unlink(); run(['git', 'add', '-u'], self.repo)
        run(['git', 'commit', '-q', '-m', 'sentinel deletion'], self.repo)
        head = run(['git', 'rev-parse', 'HEAD'], self.repo)
        raw = patches.render(self.repo, base, head)
        envelope = patches.render(self.repo, base, head, patches.DIGEST_FORMAT)
        self.assertIn(b'harmless deleted sentinel', raw)
        self.assertNotIn(b'harmless deleted sentinel', envelope)
        for number in (1, 2):
            clone = Path(self.raw.name)/f'digest-clone-{number}'
            run(['git', 'clone', '-q', '--no-hardlinks', str(self.repo), str(clone)], Path(self.raw.name))
            self.assertEqual(patches.render(clone, base, head, patches.DIGEST_FORMAT), envelope)
            self.assertIsNone(patches.verify(clone, self._write(envelope), base, head,
                                             patches.DIGEST_FORMAT))

    def test_schema_accepts_known_formats_and_rejects_unknown_format(self):
        schema = json.loads((Path(__file__).parents[2]/'schemas/fix-status.schema.json').read_text())
        implementation_schema = schema['properties']['implementation']
        value = {'branch': 'fix/example', 'base_sha': self.base, 'head_sha': self.head,
                 'stacked_on': []}
        jsonschema.validate(value, implementation_schema)
        for selected in ('full-patch', patches.DIGEST_FORMAT):
            jsonschema.validate({**value, 'diff_format': selected}, implementation_schema)
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate({**value, 'diff_format': 'unknown'}, implementation_schema)

    def _write(self, data: bytes) -> Path:
        path = Path(self.raw.name)/'04-diff.patch'; path.write_bytes(data); return path


if __name__ == '__main__':
    unittest.main()
