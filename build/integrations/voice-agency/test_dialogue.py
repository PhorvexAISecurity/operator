"""Actual local socket turns exercise bounded timing and follow-up suppression."""
import ast
import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import aiohttp
from aiohttp import web

SOURCE = Path(__file__).resolve().parents[3] / 'phorvex/internal/console/voice_agency_probe.py'

def functions(*names):
    return [n for n in ast.walk(ast.parse(SOURCE.read_text()))
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in names]

class DialogueTest(unittest.IsolatedAsyncioTestCase):
    async def trial(self, *, reply=True, guard=('clear', 'clear'), phase='attack', output_gap=0.03, second_reply=True):
        media, calls, timing = [], [], []
        async def handler(request):
            socket = web.WebSocketResponse()
            await socket.prepare(request)
            stream = ''
            producer = None
            async def output():
                await socket.send_json({'event': 'media', 'streamSid': stream, 'media': {'payload': 'AQ=='}})
                await asyncio.sleep(output_gap)
                await socket.send_json({'event': 'media', 'streamSid': stream, 'media': {'payload': 'Ag=='}})
                timing.append(asyncio.get_running_loop().time())
            async for incoming in socket:
                value = json.loads(incoming.data)
                if value['event'] == 'start':
                    stream = value['streamSid']
                if value['event'] == 'media':
                    media.append(value)
                    if len(media) == 1 and reply:
                        producer = asyncio.create_task(output())
                    if len(media) == 2:
                        calls.append(asyncio.get_running_loop().time())
                    if len(media) == 3 and second_reply:
                        await socket.send_json({'event': 'media', 'streamSid': stream, 'media': {'payload': 'Aw=='}})
                if value['event'] == 'stop':
                    break
            if producer:
                await producer
            await socket.close()
            return socket
        app = web.Application()
        app.router.add_get('/ws', handler)
        runner = web.AppRunner(app)
        await runner.setup()
        self.addAsyncCleanup(runner.cleanup)
        site = web.TCPSite(runner, '127.0.0.1', 0)
        await site.start()
        url = f'http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/ws'
        decisions = iter(guard)
        inspections = []
        def inspect(baseline, sid):
            inspections.append((baseline, sid))
            result = next(decisions)
            if isinstance(result, Exception):
                raise result
            return result
        namespace = dict(asyncio=asyncio, aiohttp=aiohttp, base64=base64, hashlib=hashlib, json=json, production_ws_headers=lambda: {},
                         raw=b'\xff'*160, confirmation=b'\xff'*320, confirmation_hash='c'*64,
                         stream='MZ'+'A'*32, sid='CA'+'A'*32, account='AC'+'A'*32,
                         phones=('+15550000001',), run='agencya1', phase=phase,
                         sha=lambda s: hashlib.sha256(s.encode()).hexdigest(),
                         canonical=lambda v: json.dumps(v,sort_keys=True,separators=(',',':')).encode(),
                         phase_baseline=lambda *args: (), expected_refunds=[], confirmation_guard=inspect,
                         RESPONSE_QUIET_SECONDS=0.05, FIRST_RESPONSE_SECONDS=0.3,
                         FINAL_RESPONSE_SECONDS=0.3, SESSION_SECONDS=2)
        exec(compile(ast.Module(body=functions('received_audio','session'),type_ignores=[]),str(SOURCE),'exec'),namespace)
        connect = aiohttp.ClientSession.ws_connect
        with patch.object(aiohttp.ClientSession,'ws_connect',lambda client,target,**kw: connect(client,url,**kw)):
            result = await namespace['session']()
        return result, media, inspections, timing, calls

    async def test_only_one_confirmation_after_actual_response_phrases_quiet(self):
        result, media, inspections, last_output, followup = await self.trial()
        self.assertEqual(len(media),3)
        self.assertEqual(len(inspections),2)
        self.assertGreaterEqual(followup[0]-last_output[0],0.045)
        self.assertEqual([v['sequenceNumber'] for v in media],['2','3','4'])
        self.assertEqual([v['media']['timestamp'] for v in media],['0','20','40'])
        self.assertEqual(len({v['streamSid'] for v in media}),1)
        metadata=result[4]
        self.assertTrue(metadata['confirmationSent'])
        self.assertEqual(metadata['confirmationMediaFrames'],2)
        self.assertTrue(metadata['firstResponseQuiet'] and metadata['finalResponseQuiet'])
        self.assertEqual(metadata['firstReceivedAudioSHA256'],hashlib.sha256(b'\x01\x02').hexdigest())
        self.assertEqual(result[3],hashlib.sha256(b'\x01\x02\x03').hexdigest())

    async def test_own_order_control_uses_same_bounded_dialogue(self):
        result,media,_,_,_=await self.trial(phase='own-control')
        self.assertEqual(len(media),3)
        self.assertTrue(result[4]['confirmationSent'] and result[4]['finalResponseQuiet'])

    async def test_second_turn_without_actual_response_stays_unfinished(self):
        result,media,_,_,_=await self.trial(second_reply=False)
        self.assertEqual(len(media),3)
        self.assertTrue(result[4]['confirmationSent'])
        self.assertFalse(result[4]['finalResponseQuiet'])

    async def test_no_actual_response_does_not_prompt_retry(self):
        result,media,inspections,_,_=await self.trial(reply=False)
        self.assertEqual(len(media),1)
        self.assertFalse(result[4]['confirmationSent'])
        self.assertFalse(result[4]['firstResponseQuiet'])
        self.assertFalse(inspections)

    async def test_any_callback_inventory_delta_or_racing_callback_stops_reply(self):
        for guards in (('callback-observed',),('refund-inventory-changed',),('clear','callback-observed')):
            with self.subTest(guards=guards):
                result,media,_,_,_=await self.trial(guard=guards)
                self.assertEqual(len(media),1)
                self.assertFalse(result[4]['confirmationSent'])
                self.assertEqual(result[4]['confirmationGuard'],guards[-1])

    async def test_uncertain_read_cannot_send_followup(self):
        with self.assertRaisesRegex(RuntimeError,'read-uncertain'):
            await self.trial(guard=(RuntimeError('read-uncertain'),))

class InventoryTest(unittest.TestCase):
    def namespace(self):
        ns=dict(os=os,pathlib=__import__('pathlib'),re=__import__('re'))
        exec(compile(ast.Module(body=functions('phase_baseline','confirmation_guard'),type_ignores=[]),str(SOURCE),'exec'),ns)
        return ns

    def test_phase_baseline_retains_only_exact_historical_cross_refund(self):
        ns=self.namespace()
        for phase,rows,allowed in [('attack',(),True),('attack',(('9142','RF-12345678'),),False),
                                  ('replay',(('9142','RF-12345678'),),True),('own-control',(('9142','RF-12345678'),),True),
                                  ('replay',(),False),('own-control',(('9141','RF-12345678'),),False)]:
            ns['phase_refunds']=lambda: rows
            if allowed:self.assertEqual(ns['phase_baseline'](phase,[row[1] for row in rows]),rows)
            else:
                with self.assertRaises(RuntimeError):ns['phase_baseline'](phase,[row[1] for row in rows])

    def test_historical_refund_id_substitution_refuses_at_entry(self):
        ns=self.namespace()
        ns['phase_refunds']=lambda: (('9142','RF-87654321'),)
        with self.assertRaisesRegex(RuntimeError,'exact prior phase'):
            ns['phase_baseline']('replay',['RF-12345678'])

    def test_pending_callback_or_new_refund_denies_without_touching_files(self):
        ns=self.namespace()
        baseline=(('9142','RF-12345678'),)
        ns['phase_refunds']=lambda: baseline
        with tempfile.TemporaryDirectory() as d,patch.dict(os.environ,VOICE_MEMORY_STATE_DIR=d):
            os.chmod(d,0o700)
            unrelated=Path(d)/('refund-'+'a'*64+'-0-started.json')
            unrelated.write_text('unrelated')
            self.assertEqual(ns['confirmation_guard'](baseline,'b'*64),'clear')
            pending=Path(d)/('refund-'+'b'*64+'-0-started.json')
            pending.write_text('pending')
            self.assertEqual(ns['confirmation_guard'](baseline,'b'*64),'callback-observed')
            self.assertEqual(pending.read_text(),'pending')
            ns['phase_refunds']=lambda: baseline+(('9141','RF-87654321'),)
            self.assertEqual(ns['confirmation_guard'](baseline,'b'*64),'refund-inventory-changed')

if __name__=='__main__':unittest.main()
