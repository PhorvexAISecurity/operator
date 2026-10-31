import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import storage
import replay_build


class StorageTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='bot-storage-'))
        self.addCleanup(shutil.rmtree, self.root)
        self.cache = self.root/'go-build-cache'
        self.cache.mkdir()

    def entry(self, name, size, age):
        path = self.cache/name
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(b'x'*size)
        os.utime(path, (age, age))
        return path

    def test_oldest_cache_entries_trimmed_reports_and_other_caches_preserved(self):
        old = self.entry('aa/old', 20, 10)
        new = self.entry('bb/new', 20, 20)
        report = self.root/'report.html'; report.write_text('evidence')
        modules = self.root/'modules'; modules.mkdir(); (modules/'keep').write_text('module')
        result = storage.trim_cache(self.cache, max_bytes=20)
        self.assertFalse(old.exists()); self.assertTrue(new.exists())
        self.assertEqual(result['files_removed'], 1)
        self.assertEqual(result['cache_bytes_after'], 20)
        self.assertEqual(report.read_text(), 'evidence')
        self.assertTrue((modules/'keep').exists())

    def test_disk_pressure_can_reclaim_below_retention_target(self):
        old = self.entry('aa/old', 20, 10)
        new = self.entry('bb/new', 20, 20)
        def disk(_):
            return shutil._ntuple_diskusage(1000, 900, 100 if old.exists() else 120)
        with mock.patch.object(storage.shutil, 'disk_usage', side_effect=disk):
            result = storage.trim_cache(self.cache, max_bytes=100, min_free_bytes=110)
        self.assertFalse(old.exists()); self.assertTrue(new.exists())
        self.assertEqual(result['free_bytes_after'], 120)

    def test_symlinks_are_never_followed(self):
        outside = self.root/'outside'; outside.mkdir(); (outside/'keep').write_text('keep')
        (self.cache/'link-dir').symlink_to(outside, target_is_directory=True)
        (self.cache/'link-file').symlink_to(outside/'keep')
        self.entry('regular', 10, 1)
        storage.trim_cache(self.cache, max_bytes=0)
        self.assertEqual((outside/'keep').read_text(), 'keep')
        self.assertTrue((self.cache/'link-dir').is_symlink())
        link = self.root/'root-link'; link.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError): storage.trim_cache(link, max_bytes=0)

    def test_absent_cache_does_not_delete_or_create_anything(self):
        missing = self.root/'missing'
        result = storage.trim_cache(missing)
        self.assertEqual(result['files_removed'], 0)
        self.assertFalse(missing.exists())

    def test_build_environment_uses_owned_cache_without_global_mutation(self):
        src = self.root/'candidate-src'; src.mkdir()
        with mock.patch.dict(os.environ, {'GOCACHE': str(self.root/'global-cache'), 'OPENAI_API_KEY':'secret'}):
            env = replay_build.go_environment(src, cache_dir=self.cache)
            self.assertEqual(env['GOCACHE'], str(self.cache))
            self.assertEqual(os.environ['GOCACHE'], str(self.root/'global-cache'))
            self.assertNotIn('OPENAI_API_KEY', env)
        self.assertTrue(self.cache.is_dir())


if __name__ == '__main__':
    unittest.main()
