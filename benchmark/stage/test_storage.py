"""Lossless new-journal encoding, bounded decode, durable accounting and legacy controls."""
import io
import itertools
import json
from pathlib import Path
import random
import sqlite3
import tempfile
import threading
import tracemalloc
from types import SimpleNamespace
import unittest
from unittest import mock
import zlib

from . import evidence, observe
from .evidence import EvidenceError, Journal, MAX_EVENT_BYTES, MIN_FREE_BYTES, canonical
from .normalize import normalize
from .test_evidence import scope, seed, rotate, seal, export


class JournalStorageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def journal(self, name="compressed.db", **kwargs):
        journal = Journal(self.root/name, scope(), encoding="zlib-v1", **kwargs)
        self.addCleanup(journal.close)
        return journal

    def totals(self, journal):
        return dict(journal.db.execute("SELECT key,value FROM meta WHERE key IN ('encoded_bytes','decoded_bytes','logical_bytes')"))

    def test_plain_legacy_opens_without_metadata_or_body_migration(self):
        original = Journal(self.root/"legacy.db", scope())
        seed(original); rotate(original); seal(original, 400)
        # The existing deployed format predates the optional encoding marker.
        original.db.execute("DELETE FROM meta WHERE key='encoding'"); original.db.commit()
        expected = list(original.records())
        meta = list(original.db.execute("SELECT * FROM meta ORDER BY key"))
        original.close()
        before = (self.root/"legacy.db").read_bytes()
        reopened = Journal(self.root/"legacy.db")
        self.assertEqual(reopened.encoding, "plain-v1")
        self.assertEqual(list(reopened.records()), expected)
        self.assertEqual(list(reopened.db.execute("SELECT * FROM meta ORDER BY key")), meta)
        reopened.close()
        self.assertEqual((self.root/"legacy.db").read_bytes(), before)
        with self.assertRaisesRegex(EvidenceError, "encoding is immutable"):
            Journal(self.root/"legacy.db", encoding="zlib-v1")

    def test_uncached_legacy_is_readable_without_implicit_counter_migration(self):
        old = Journal(self.root/"uncached.db", scope())
        seed(old)
        expected = list(old.records())
        old.db.execute("DELETE FROM meta WHERE key IN ('encoding','logical_bytes')"); old.db.commit(); old.close()
        journal = Journal(self.root/"uncached.db")
        self.addCleanup(journal.close)
        self.assertEqual(list(journal.records()), expected)
        self.assertIsNone(journal.db.execute("SELECT value FROM meta WHERE key='logical_bytes'").fetchone())
        with self.assertRaisesRegex(EvidenceError, "lacks a transactional counter"):
            journal.append("checkpoint", {}, at=20)
        self.assertEqual(journal.storage_status()["encoded_accounted_bytes"], journal.storage_status()["decoded_accounted_bytes"])

    def test_lossless_encoded_chain_normalization_and_frozen_snapshot_parity(self):
        plain = Journal(self.root/"plain.db", scope())
        self.addCleanup(plain.close)
        seed(plain); rotate(plain); seal(plain, 400)
        compressed = self.journal(max_bytes=4 << 30)
        for event in plain.records():
            compressed.append(event["kind"], event["data"], at=event["at"])
        self.assertEqual(list(plain.records()), list(compressed.records()))
        self.assertEqual(normalize(plain.scope, plain.records, [export()], .9, 300, 300, 0),
                         normalize(compressed.scope, compressed.records, [export()], .9, 300, 300, 0))
        writer = Journal(compressed.path)
        self.addCleanup(writer.close)
        with compressed.read_snapshot() as prefix:
            frozen = list(compressed.records(cutoff=prefix["seq"]))
            seal(writer, 600)
            self.assertEqual(frozen, list(compressed.records(cutoff=prefix["seq"])))
        self.assertGreater(len(list(compressed.records())), len(frozen))
        encoded = compressed.db.execute("SELECT sum(length(body)+128) FROM events").fetchone()[0]
        decoded = sum(len(canonical({k:e[k] for k in ('schema','kind','data')}).encode())+128 for e in compressed.records())
        self.assertEqual(self.totals(compressed), {"encoded_bytes":str(encoded),"decoded_bytes":str(decoded)})
        self.assertLess(encoded,decoded)

    def test_format_capacity_and_scope_are_immutable(self):
        journal = self.journal(max_bytes=4 << 30)
        seed(journal)
        for options in ({"encoding":"plain-v1"},{"max_bytes":2 << 30},{"scope":{**scope(),"policy_uid":"changed"}}):
            with self.subTest(options=options), self.assertRaises(EvidenceError):
                Journal(journal.path,**options)
        for encoding,capacity in (("plain-v1",4 << 30),("zlib-v1",(4 << 30)+1),("future-v2",1 << 20)):
            with self.subTest(encoding=encoding), self.assertRaises(EvidenceError):
                Journal(self.root/(encoding+".db"),scope(),encoding=encoding,max_bytes=capacity)
        journal.db.execute("UPDATE meta SET value='unknown-v99' WHERE key='encoding'");journal.db.commit()
        with self.assertRaisesRegex(EvidenceError,"unsupported"):
            Journal(journal.path)

    def test_two_compressed_writers_serialize_clocks_and_both_counters(self):
        first=self.journal()
        second=Journal(first.path);self.addCleanup(second.close)
        errors=[]
        def write(journal):
            try:
                for index in range(10):
                    journal.append("checkpoint",{"writer":threading.current_thread().name,"index":index})
            except BaseException as exc:
                errors.append(exc)
        times=itertools.count(1)
        with mock.patch.object(evidence.time,"time",side_effect=lambda:next(times)):
            threads=[threading.Thread(target=write,args=(j,),name="writer%d"%i) for i,j in enumerate((first,second))]
            for thread in threads:thread.start()
            for thread in threads:thread.join(5)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(errors,[])
        records=list(first.records())
        self.assertEqual([r["at"] for r in records],list(range(1,21)))
        verified=Journal(first.path);self.addCleanup(verified.close)
        self.assertEqual(list(verified.records()),records)
        self.assertEqual(self.totals(verified),self.totals(first))

    def test_decoded_boundary_can_exceed_encoded_quota_without_truncation(self):
        journal = self.journal(max_bytes=1 << 20)
        overhead=len(canonical({"schema":evidence.SCHEMA,"kind":"checkpoint","data":{"padding":""}}).encode())
        padding="x"*(MAX_EVENT_BYTES-overhead)
        journal.append("checkpoint",{"padding":padding},at=1)
        self.assertEqual(list(journal.records())[0]["data"]["padding"],padding)
        self.assertGreater(int(self.totals(journal)["decoded_bytes"]),journal.max_bytes)
        self.assertLess(int(self.totals(journal)["encoded_bytes"]),journal.max_bytes)
        before=self.totals(journal)
        with self.assertRaisesRegex(EvidenceError,"bounded journal input"):
            journal.append("checkpoint",{"padding":padding+"x"},at=2)
        self.assertEqual(self.totals(journal),before)

    def test_encoded_quota_failure_and_failed_counter_update_roll_back_atomically(self):
        journal=self.journal(max_bytes=1 << 20)
        padding=random.Random(42).randbytes(600000).hex()
        journal.append("checkpoint",{"padding":padding},at=1)
        before=self.totals(journal),list(journal.records())
        with self.assertRaisesRegex(EvidenceError,"capacity exhausted"):
            journal.append("checkpoint",{"padding":padding},at=2)
        self.assertEqual((self.totals(journal),list(journal.records())),before)
        journal.db.execute("CREATE TRIGGER reject_decoded BEFORE UPDATE OF value ON meta WHEN OLD.key='decoded_bytes' BEGIN SELECT RAISE(ABORT,'counter-write-failed'); END")
        journal.db.commit()
        with self.assertRaisesRegex(sqlite3.IntegrityError,"counter-write-failed"):
            journal.append("checkpoint",{},at=2)
        self.assertEqual((self.totals(journal),list(journal.records())),before)

    def test_compressed_counters_and_chain_are_verified_on_open(self):
        for key in ("encoded_bytes","decoded_bytes"):
            with self.subTest(key=key):
                journal=self.journal(key+".db");seed(journal)
                journal.db.execute("UPDATE meta SET value='0' WHERE key=?",(key,));journal.db.commit()
                with self.assertRaisesRegex(EvidenceError,"size cache"):
                    Journal(journal.path)
        journal=self.journal("chain.db");seed(journal)
        journal.db.execute("UPDATE events SET hash=? WHERE seq=2",("f"*64,));journal.db.commit()
        with self.assertRaisesRegex(EvidenceError,"hash chain"):
            Journal(journal.path)

    def test_decoder_rejects_truncation_trailing_multiple_streams_and_malformed_json(self):
        journal=self.journal()
        raw=canonical({"schema":evidence.SCHEMA,"kind":"checkpoint","data":{}}).encode()
        compressed=zlib.compress(raw,1)
        bad=[compressed[:-1],compressed+b"extra",compressed+compressed,b"not-zlib",zlib.compress(b"\xff"),
             zlib.compress(b'{"schema":"phorvex-stage.observation.v1","kind":"checkpoint","data":{},"data":{}}'),
             zlib.compress(raw+b" "),zlib.compress(b'{"schema":"phorvex-stage.observation.v1","kind":"checkpoint","data":NaN}')]
        for value in bad:
            with self.subTest(value=value[:12]),self.assertRaises(EvidenceError):
                journal._decode(value)
        self.assertEqual(journal._decode(compressed)[0]["data"],{})
        journal.append("checkpoint",{},at=1)
        journal.db.execute("UPDATE events SET body=? WHERE seq=1",(compressed+b"extra",));journal.db.commit()
        with self.assertRaisesRegex(EvidenceError,"trailing/multiple"):
            Journal(journal.path)

    def test_compression_bomb_is_hard_bounded_and_never_flushed(self):
        journal=self.journal()
        bomb=zlib.compress(b"x"*(MAX_EVENT_BYTES*8),1)
        tracemalloc.start()
        try:
            with self.assertRaisesRegex(EvidenceError,"decoded bound"):
                journal._decode(bomb)
            _,peak=tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertLess(peak,16 << 20)

    def test_corrupt_oversized_encoded_blob_is_rejected_before_decode(self):
        journal=self.journal();journal.append("checkpoint",{},at=1)
        journal.db.execute("UPDATE events SET body=zeroblob(?) WHERE seq=1",(evidence.MAX_ENCODED_EVENT_BYTES+1,));journal.db.commit()
        with mock.patch.object(journal,"_decode",side_effect=AssertionError("must reject before decode")):
            with self.assertRaisesRegex(EvidenceError,"encoded bound"):
                list(journal.records())

    def test_free_disk_guard_stops_append_but_does_not_block_reading(self):
        journal=self.journal();seed(journal)
        before=self.totals(journal),list(journal.records())
        with mock.patch.object(evidence.shutil,"disk_usage",return_value=SimpleNamespace(free=MIN_FREE_BYTES)):
            with self.assertRaisesRegex(EvidenceError,"free-space reserve"):
                journal.append("checkpoint",{},at=20)
            self.assertEqual((self.totals(journal),list(journal.records())),before)
            reopened=Journal(journal.path);reopened.close()
            with self.assertRaisesRegex(EvidenceError,"free-space reserve"):
                Journal(self.root/"full.db",scope(),encoding="zlib-v1")
            self.assertFalse((self.root/"full.db").exists())

    def test_full_scan_timeout_produces_no_completeness_claim(self):
        journal=self.journal();seed(journal)
        journal.scan_timeout=1
        with mock.patch.object(evidence.time,"monotonic",side_effect=[0,2]):
            with self.assertRaisesRegex(EvidenceError,"full-scan runtime limit"):
                list(journal.records())
        with mock.patch.dict(evidence.os.environ,{"STAGE_JOURNAL_SCAN_TIMEOUT_SECONDS":"0"}):
            with self.assertRaisesRegex(EvidenceError,"timeout"):
                Journal(journal.path)

    def test_status_exposes_both_counters_physical_usage_and_estimate_limits(self):
        journal=self.journal();seed(journal);seal(journal,400)
        status=journal.storage_status()
        self.assertEqual(status["encoding"],"zlib-v1")
        self.assertLess(status["encoded_accounted_bytes"],status["decoded_accounted_bytes"])
        self.assertGreater(status["database_bytes"],0)
        self.assertGreater(status["free_disk_bytes"],0)
        self.assertEqual(status["protected_free_bytes"],4 << 30)
        self.assertIn("not a retention or continuity guarantee",status["estimates"]["classification"])
        self.assertEqual(status["estimates"]["event_clock_span_seconds"],390)
        output=io.StringIO()
        with mock.patch("sys.argv",["observe","status","--journal",str(journal.path)]),mock.patch("sys.stdout",output):
            observe.main()
        result=json.loads(output.getvalue())
        self.assertEqual(result["storage"]["decoded_accounted_bytes"],status["decoded_accounted_bytes"])
        self.assertEqual(result["complete_from"],10)


if __name__=="__main__":
    unittest.main()
