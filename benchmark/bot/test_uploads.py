"""Document parsing, upload authorization, batch execution and live activity cards."""
import io
import json
import sys
import threading
import unittest
import urllib.error
import zipfile
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import file_requests as files
import service
import test_bot as kit
import testkit
from progress import Progress
from telegram import Telegram, TelegramError, urllib_download


class ParserTest(unittest.TestCase):
    def parse(self, text):
        return files.parse(text, ticks=64)

    def test_all_completed_examples_parse_including_word(self):
        examples = list((HERE / 'templates').iterdir())
        self.assertGreaterEqual(len(examples), 7)
        for path in examples:
            with self.subTest(path=path.name):
                tasks = self.parse(files.document_text(path.name, path.read_bytes()))
                self.assertTrue(tasks)
                self.assertTrue(all(task['kind'] in ('bench', 'param', 'study') for task in tasks))
        word = next(path for path in examples if path.suffix == '.docx')
        self.assertEqual([t['kind'] for t in self.parse(files.document_text(word.name, word.read_bytes()))], ['bench', 'param'])

    def test_optional_sections_and_multiline_change(self):
        self.assertEqual(self.parse('[params]\nP-FEA-006: [1.0, 1.2]')[0]['kind'], 'param')
        task = self.parse('## Bench\nticks: 16\nsync: false\nchange: |\nIn a Go function,\nchange one threshold.')[0]
        self.assertEqual(task['kind'], 'bench')
        self.assertIn('ticks=16 nosync In a Go function, change one threshold.', task['text'])
        tasks = self.parse('params:\nP-FEA-006: 1.2\nP-FEA-005: 300, 900')
        self.assertEqual(len(tasks), 2)

    def test_command_list_and_strict_options(self):
        tasks = self.parse('# Commands\n```text\n/param P-FEA-006 1.2 ticks=16 nosync\n'
                           '/bench ticks=16 nosync explain one function with a comment\n```')
        self.assertEqual([task['kind'] for task in tasks], ['param', 'bench'])
        for command in ('/bench change one function ticks=16', '/param P-FEA-006 1.2 typo=3',
                        '/param P-FEA-006 1.2 ticks=3 ticks=4', '/status',
                        '/param P-FEA-006 1.2\nSome unrecognized prose'):
            with self.subTest(command=command), self.assertRaises(files.RequestError):
                self.parse(command)

    def test_invalid_fields_empty_sections_and_limits_are_rejected(self):
        invalid = ('', '[bench]\n', '[params]\n', '[params]\nP-FEA-006: 1.2\n[bench]',
                   '[bench]\ntikcs: 3\nchange: change the threshold please',
                   '[bench]\nchange: change the threshold please\nticks: 3',
                   '[params]\npolicy: bad\nP-FEA-006: 1.2',
                   '[params]\nticks: 5001\nP-FEA-006: 1.2',
                   '[params]\nsync: maybe\nP-FEA-006: 1.2',
                   '[params]\nP-FEA-006: 1.2\n## Paramz\nP-FEA-005: 900',
                   '[params]\nP-FEA-006: 1.2\nP-FEA-006: 1.5',
                   '\n'.join('/param P-FEA-006 1.2' for _ in range(6)))
        for text in invalid:
            with self.subTest(text=text), self.assertRaises(files.RequestError):
                self.parse(text)

    def test_registry_domains_and_duplicate_numeric_values(self):
        for parameter, values in (('P-FEA-006', '0'), ('P-FEA-006', '1001'), ('P-FEA-006', 'unset'),
                                  ('P-FEA-006', '1 1.0'), ('P-FEA-006', 'NaN'), ('P-FEA-006', 'Infinity'),
                                  ('P-FEA-006', '1e9999'), ('P-FEA-005', '1.5'), ('P-FEA-005', '604801'),
                                  ('P-OBJ-003', '-1'), ('P-OBJ-003', '11'), ('P-XXX-123', '1'),
                                  ('P-FEA-006', '۱٫۲')):
            with self.subTest(parameter=parameter, values=values), self.assertRaises(files.RequestError):
                self.parse('[params]\n%s: %s' % (parameter, values))
        self.assertTrue(self.parse('[params]\nP-OBJ-003: unset 0 1.2 10'))

    def test_file_formats_encodings_and_word_limits(self):
        text = '[params]\nP-FEA-006: 1.2'
        self.assertEqual(files.document_text('test.txt', text.encode('utf-16')), text)
        self.assertEqual(files.document_text('test.md', b'\xef\xbb\xbf' + text.encode()), text)
        for name, data in (('test.doc', b'old word'), ('test.docx', b'not a ZIP'),
                           ('test.txt', b'\xff'), ('test.txt', b'\x00hello'),
                           ('test.txt', b'x' * (files.MAX_TEXT_BYTES + 1))):
            with self.subTest(name=name), self.assertRaises(files.RequestError):
                files.document_text(name, data)
        for xml in (b'<!DOCTYPE x [<!ENTITY a "abc">]><x>&a;</x>', b'x' * (4 * 1024 * 1024 + 1)):
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as archive:
                archive.writestr('word/document.xml', xml)
            with self.assertRaises(files.RequestError):
                files.document_text('test.docx', buf.getvalue())


class UploadTest(unittest.TestCase):
    setUp = kit.BotTest.setUp
    bot = kit.BotTest.bot
    history = kit.BotTest.history
    bench_setup = kit.BotTest.bench_setup
    openai_returning = kit.BotTest.openai_returning

    def upload(self, bot, text, filename='request.md', caption='', user=kit.OWNER):
        data = text if isinstance(text, bytes) else text.encode()
        file_id = 'upload%d' % len(self.fake.files)
        self.fake.files[file_id] = data
        bot.tg.download_transport = lambda url, limit, timeout: self.fake.files[url.rsplit('/', 1)[1]]
        update = kit.message(user, '')
        update['message']['document'] = {'file_id': file_id, 'file_name': filename, 'file_size': len(data)}
        update['message']['caption'] = caption
        worker = bot.handle(update)
        if worker:
            worker.join(timeout=5)
            self.assertFalse(worker.is_alive())
        return worker

    def test_validate_only_and_invalid_mixed_file_never_enqueue(self):
        bot = self.bot(kit.FakeDashboard())
        self.upload(bot, '[params]\nP-FEA-006: 1.2', caption='/validate')
        self.assertEqual(bot.queue, [])
        self.assertTrue(any('nothing was run' in t for t in self.fake.texts()))
        self.upload(bot, '[params]\nP-FEA-006: 1.2\n[bench]\nticks: wrong\nchange: explain one function')
        self.assertEqual(bot.queue, [])
        self.assertEqual(bot.dashboard.calls, [])
        self.assertIn('File rejected:', self.fake.texts()[-1])
        self.assertFalse(bot.upload_chats)
        self.assertFalse(bot.activities)

    def test_unrecognized_caption_never_downloads_or_enqueues(self):
        bot = self.bot()
        for caption in ('\\validate', 'validate', '/validte', 'please validate', '/bench'):
            with self.subTest(caption=caption):
                self.assertIsNone(self.upload(bot, '[params]\nP-FEA-006: 1.2', caption=caption))
                self.assertEqual(bot.queue, [])
                self.assertIn('nothing was downloaded or queued', self.fake.texts()[-1])
        self.assertFalse(any(method == 'getFile' for method, _ in self.fake.calls))
        self.assertFalse(list((self.tmp/'state').glob('uploads/*')))
        self.upload(bot, '[params]\nP-FEA-006: 1.2', caption='/validate@phorvexbot')
        self.assertEqual(bot.queue, [])
        self.assertIn('nothing was run', self.fake.texts()[-1])
        self.upload(bot, '[params]\nP-FEA-006: 1.2', caption='/upload')
        self.assertEqual(len(bot.queue), 1)
        bot.finish_activity(bot.queue[0].progress, 'CANCELLED', 'Test cleanup')

    def test_unauthorized_and_oversized_uploads_are_not_downloaded(self):
        bot = self.bot()
        self.assertIsNone(self.upload(bot, '[params]\nP-FEA-006: 1.2', user=kit.STRANGER))
        self.assertEqual(self.fake.calls, [])
        self.assertIsNone(self.upload(bot, b'x' * (files.MAX_FILE_BYTES + 1)))
        self.assertFalse(any(method == 'getFile' for method, _ in self.fake.calls))

    def test_metadata_write_failure_does_not_claim_an_accepted_batch_was_rejected(self):
        bot = self.bot()
        original, writes = Path.write_text, []
        def write(path, *args, **kwargs):
            if path.name == 'VALIDATION.json':
                writes.append(path)
                if len(writes) == 2:
                    raise OSError('simulated record failure')
            return original(path, *args, **kwargs)
        with mock.patch.object(Path, 'write_text', write):
            self.upload(bot, '[params]\nP-FEA-006: 1.2')
        self.assertEqual(len(bot.queue), 1)
        self.assertIn('The batch is queued', self.fake.texts()[-1])
        bot.finish_activity(bot.queue[0].progress, 'CANCELLED', 'Test cleanup')

    def test_word_upload_queues_only_its_present_sections(self):
        bot = self.bot(kit.FakeDashboard())
        self.upload(bot, (HERE / 'templates/both-sections.docx').read_bytes(), filename='request.docx')
        self.assertEqual(len(bot.queue), 1)
        self.assertEqual([task['kind'] for task in bot.queue[0].specs], ['bench', 'param'])
        bot.finish_activity(bot.queue[0].progress, 'CANCELLED', 'Test cleanup')

    def test_param_only_upload_executes_and_keeps_batch_evidence(self):
        bot = self.bot(kit.FakeDashboard())
        self.upload(bot, '[params]\nticks: 16\nsync: false\nP-FEA-006: 1.0 1.2')
        root = bot.queue[0]
        self.assertTrue(bot.run_next())
        self.assertEqual([row['kind'] for row in self.history()], ['param', 'batch'])
        self.assertEqual(self.history()[-1]['state'], 'DONE')
        result = json.loads((root.dir / 'BATCH.json').read_text())
        self.assertEqual(result['results'][0]['state'], 'DONE')
        self.assertEqual(result['results'][0]['kind'], 'param')
        self.assertTrue((self.tmp / 'state/uploads' / root.upload_id / 'VALIDATION.json').exists())
        self.assertTrue(any(m == 'editMessageText' and 'DONE' in p['text'] for m, p in self.fake.calls))
        self.assertFalse(bot.activities)

    def test_mixed_upload_runs_real_code_pipeline_and_parameter_pipeline(self):
        repo, base, data, go = self.bench_setup()
        dash = kit.FakeDashboard()
        bot = self.bot(dash, self.openai_returning(testkit.threshold_diff(3, 5)),
                       BOT_REPO=str(repo), MATHLAB_DATA_DIR=str(data), BOT_GO=str(go))
        self.upload(bot, '[bench]\nsync: false\nticks: 6\nchange: raise the rotate threshold from 3 to 5\n'
                         '[params]\nsync: false\nticks: 6\nP-FEA-006: 1.2')
        self.assertTrue(bot.run_next())
        self.assertEqual([row['kind'] for row in self.history()], ['bench', 'param', 'batch'])
        self.assertTrue(all(row['state'] == 'DONE' for row in self.history()))
        self.assertEqual(len(self.fake.documents()), 9)
        self.assertIsNone(bot.current)
        self.assertFalse(bot.activities)

    def test_runtime_failure_continues_independent_experiments_and_reports_partial(self):
        bot = self.bot(kit.FakeDashboard())
        self.upload(bot, '[params]\nsync: false\nP-FEA-006: 1.2\nP-FEA-005: 900')
        real_run = bot.run_param
        def run(child):
            if child.text.startswith('P-FEA-006'):
                raise service.JobError('Simulated runtime preflight failure')
            return real_run(child)
        bot.run_param = run
        bot.run_next()
        self.assertEqual([row['state'] for row in self.history()], ['FAILED', 'DONE', 'PARTIAL'])
        self.assertTrue(any('1/2 experiments succeeded' in text for text in self.fake.texts()))

    def test_cancel_stops_remaining_experiments(self):
        bot = self.bot()
        self.upload(bot, '[params]\nP-FEA-006: 1.2\nP-FEA-005: 900')
        root = bot.queue[0]
        def run(child):
            child.cancel.set()
            raise service.JobError('cancelled during test')
        bot.run_param = run
        bot.run_next()
        result = json.loads((root.dir / 'BATCH.json').read_text())
        self.assertEqual(result['state'], 'CANCELLED')
        self.assertEqual([row['state'] for row in result['results']], ['CANCELLED', 'CANCELLED'])
        self.assertIsNone(result['results'][1]['job'])


class DownloadAndProgressTest(unittest.TestCase):
    def test_bounded_download_and_token_redaction(self):
        fake = kit.FakeTelegram()
        fake.files['x'] = b'hello'
        tg = Telegram(kit.TOKEN, fake, download_transport=lambda *args: b'hello')
        self.assertEqual(tg.download_document('x', 5), b'hello')
        with self.assertRaises(TelegramError):
            tg.download_document('x', 4)
        tg.download_transport = lambda *args: b'too many bytes'
        with self.assertRaises(TelegramError):
            tg.download_document('x', 5)
        url = 'https://api.telegram.org/file/bot' + kit.TOKEN + '/documents/x'
        with mock.patch('urllib.request.urlopen', side_effect=urllib.error.URLError(url)):
            with self.assertRaises(TelegramError) as err:
                urllib_download(url, 20, 1)
        self.assertNotIn(kit.TOKEN, str(err.exception))

    def test_progress_edits_one_card_heartbeats_and_finishes(self):
        fake = kit.FakeTelegram()
        tg = Telegram(kit.TOKEN, fake)
        now = [100.0]
        progress = Progress(tg, kit.OWNER, 'Test job', interval=0.01, clock=lambda: now[0])
        progress.start('Running Go tests')
        edited = threading.Event()
        real_edit = tg.edit_message
        def edit(*args):
            result = real_edit(*args)
            edited.set()
            return result
        tg.edit_message = edit
        now[0] += 65
        try:
            self.assertTrue(edited.wait(timeout=2))
        finally:
            progress.finish('DONE', 'Reports delivered')
            progress.worker.join(timeout=1)
        sends = [params for method, params in fake.calls if method == 'sendMessage']
        edits = [params for method, params in fake.calls if method == 'editMessageText']
        self.assertEqual(len(sends), 1)
        self.assertEqual(len({row['message_id'] for row in edits}), 1)
        self.assertTrue(any('1m 05s' in row['text'] for row in edits))
        self.assertIn('DONE', edits[-1]['text'])
        self.assertIn('Reports delivered', edits[-1]['text'])
        self.assertFalse(progress.worker.is_alive())

    def test_progress_api_failure_does_not_fail_the_operation(self):
        fake = kit.FakeTelegram()
        tg = Telegram(kit.TOKEN, fake)
        progress = Progress(tg, kit.OWNER, 'Test')
        with mock.patch.object(tg, 'edit_message', side_effect=TelegramError('message not found')):
            progress.start('Waiting for a model')
            progress.finish('FAILED', 'Backend failed')
        self.assertTrue(progress.closed.is_set())


if __name__ == '__main__':
    unittest.main()
