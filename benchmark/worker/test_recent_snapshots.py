"""Real PXMS/index producers expose oldest-page bootstrap and verify newest tail."""
from datetime import datetime, timedelta, timezone
import io
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE)); sys.path.insert(0,str(HERE.parents[1]))
from benchmark.bot import testkit
from mathlab import snapshots,stage_scope,recent_snapshots
from stage_reconcile import selected_entries,ReconcileBlocked


class RecentInventoryTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup); self.root=Path(temp.name)
        self.policy='phorvex-staging-demo/demo-api-defense'; self.now=datetime.now(timezone.utc)
        self.pin=testkit.write_stage_pin(self.root/'seed','a'*40)
        self.expected=stage_scope.snapshot_header(self.pin,self.policy)
        self.remote=self.root/'remote'; self.rows=[]; self.opens=0; self.queries=[]
        for index in range(650):
            at=(self.now-timedelta(seconds=(650-index)*5)).isoformat().replace('+00:00','Z')
            digest=testkit.make_snapshot(self.remote,'a'*40,index,index>3,at)
            self.rows.append({'digest':digest,'header':snapshots.read_header(self.remote/(digest+'.pxms'))})
        outer=self
        class Console:
            def request(self,url):
                query=parse_qs(urlsplit(url).query);outer.queries.append(query)
                lo=snapshots._clock(query.get('since',[None])[0]); hi=snapshots._clock(query.get('until',[None])[0])
                rows=[row for row in outer.rows if (lo is None or snapshots._clock(row['header']['capturedAt'])>=lo)
                      and (hi is None or snapshots._clock(row['header']['capturedAt'])<hi)]
                return {'entries':rows[:int(query['limit'][0])]}
            def open(self,url,**kwargs):
                outer.opens+=1; digest=parse_qs(urlsplit(url).query)['digest'][0]
                return io.BytesIO((outer.remote/(digest+'.pxms')).read_bytes())
        self.console=Console()

    def run_recent(self,data,**kwargs):
        return recent_snapshots.sync(data,*self.policy.split('/'),self.console,expected_header=self.expected,
            scope=self.pin['policies'][self.policy],progress_root=self.root/'progress',limit=256,
            recent_seconds=3600,max_bytes=1<<20,**kwargs)

    def test_oldest256_are_stale_but_complete_tail_yields_actual_newest64(self):
        ordinary=self.root/'ordinary'
        record=snapshots.sync(ordinary,*self.policy.split('/'),self.console,
            since=(self.now-timedelta(seconds=3600)).isoformat(),limit=256,expected_header=self.expected)
        self.assertEqual(record['downloaded'],256)
        with self.assertRaisesRegex(ReconcileBlocked,'more than600|more than 600'):
            selected_entries(ordinary,self.pin,self.policy,64)
        self.opens=0
        recent=self.root/'recent'; result=self.run_recent(recent)
        self.assertTrue(result['latest_scan_complete']);self.assertEqual(result['downloaded'],256)
        actual=selected_entries(recent,self.pin,self.policy,64)
        self.assertEqual([entry['digest'] for entry in actual],[row['digest'] for row in self.rows[-64:]])
        self.assertEqual(self.opens,256)
        self.assertEqual(result['recent_inventory']['recent_seconds'],3600)
        self.assertTrue(all('until' in query for query in self.queries))

    def test_cold_retry_retains_only_scoped_metadata_until_scan_is_complete(self):
        result=None
        with mock.patch.object(snapshots,'MAX_INDEX_PAGES',1):
            for attempt in range(4):
                cold=self.root/('cold-'+str(attempt)); result=self.run_recent(cold)
                if result['latest_scan_complete']:
                    actual=selected_entries(cold,self.pin,self.policy,64)
                    self.assertEqual([e['digest'] for e in actual],[r['digest'] for r in self.rows[-64:]])
                    break
                self.assertEqual(self.opens,0,'incomplete metadata must not download stale first pages')
                self.assertEqual(result['downloaded_digests'],[])
                shutil.rmtree(cold,ignore_errors=True)
        self.assertTrue(result['latest_scan_complete'])
        self.assertEqual(len({query['until'][0] for query in self.queries}),1,'retry must preserve its frozen upper bound')
        self.assertEqual(len(list((self.root/'progress').glob('*.json'))),1)

    def test_sparse_inventory_is_not_a_successful64_tick_cohort(self):
        self.rows=self.rows[-20:]
        data=self.root/'sparse'; result=self.run_recent(data)
        self.assertTrue(result['latest_scan_complete'])
        with self.assertRaisesRegex(ReconcileBlocked,'20/64'):
            selected_entries(data,self.pin,self.policy,64)


if __name__=='__main__':unittest.main()
