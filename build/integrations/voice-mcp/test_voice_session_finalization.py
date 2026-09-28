"""Local actual Pipecat producer regression; no STT/model/TTS provider calls."""
import ast
import asyncio
import base64
import hashlib
import importlib.metadata
import json
from pathlib import Path
import socket
import time
import unittest
from unittest.mock import patch

import aiohttp
from fastapi import FastAPI, WebSocket
from starlette.websockets import WebSocketDisconnect
import uvicorn
from loguru import logger
from pipecat.pipeline.pipeline import Pipeline
from pipecat.pipeline.runner import PipelineRunner
from pipecat.pipeline.task import PipelineTask, PipelineParams
from pipecat.processors.frame_processor import FrameProcessor
from pipecat.processors.transcript_processor import TranscriptProcessor
from pipecat.observers.base_observer import BaseObserver
from pipecat.frames.frames import CancelFrame, BotStoppedSpeakingFrame, StartFrame, TTSAudioRawFrame, TTSTextFrame, TTSStartedFrame, TTSStoppedFrame
from pipecat.serializers.twilio import TwilioFrameSerializer
from pipecat.transports.websocket.fastapi import FastAPIWebsocketTransport, FastAPIWebsocketParams

logger.remove()
ROOT = Path(__file__).resolve().parents[3]
PROBE = ROOT / 'phorvex/internal/console/voice_mcp_probe.py'
BOT = ROOT / 'build/integrations/voice-memory/bot.py'
STREAM = 'MZlocalfixture'


def probe_namespace(wait=1.8, quiet=.4):
    tree = ast.parse(PROBE.read_text())
    nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in ('unique','canonical','media_audio','wait_cleanup_transcript')]
    branch = next(n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef) and n.name == 'session')
    nodes.append(branch)
    namespace = dict(asyncio=asyncio, aiohttp=aiohttp, base64=base64, hashlib=hashlib, production_ws_headers=lambda: {},
                     json=json, time=time, raw=b'\xff'*160, stream=STREAM, account='AClocal',
                     sid='CAlocal', caller='+15550000000', run='localfixture', phase='attack',
                     signature='local-only', RESPONSE_WAIT_SECONDS=wait, AUDIO_QUIET_SECONDS=quiet,
                     FINAL_TRANSCRIPT_WAIT_SECONDS=.2, FINAL_TRANSCRIPT_POLL_SECONDS=.01)
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])),str(PROBE),'exec'),namespace)
    return namespace


class LifecycleObserver(BaseObserver):
    def __init__(self):
        super().__init__()
        self.events=[]
    async def on_push_frame(self,data):
        if isinstance(data.frame,(CancelFrame,BotStoppedSpeakingFrame,TTSTextFrame)):
            self.events.append((type(data.frame).__name__,data.timestamp))


class LocalAudioProducer(FrameProcessor):
    """Managed local PCM/text producer using actual SDK frame queues."""
    def __init__(self, continuous=False, silent=False):
        super().__init__()
        self.producer=None
        self.done=asyncio.Event()
        self.continuous=continuous
        self.silent=silent
        self.emitted=0
    async def process_frame(self,frame,direction):
        await super().process_frame(frame,direction)
        await self.push_frame(frame,direction)
        if type(frame) is StartFrame:
            async def produce():
                try:
                    await asyncio.sleep(.05)
                    if self.silent:return
                    for text in ('Store hours are 9am to 9pm.','Reference LOCALNONCE.'):
                        await self.push_frame(TTSStartedFrame())
                        for _ in range(6):
                            await self.push_frame(TTSAudioRawFrame(b'\x01\x00'*160,8000,1))
                            self.emitted+=1
                            await asyncio.sleep(.02)
                        # TTS text arrives through the output queue after audio.
                        await self.push_frame(TTSTextFrame(text))
                        await self.push_frame(TTSStoppedFrame())
                        # A pause longer than the quiet criterion MUST NOT end
                        # the fixed response window after the first phrase.
                        await asyncio.sleep(.55)
                    while self.continuous:
                        await self.push_frame(TTSAudioRawFrame(b'\x01\x00'*160,8000,1))
                        self.emitted+=1
                        await asyncio.sleep(.02)
                finally:
                    self.done.set()
            self.producer=self.create_task(produce(),name='local-finalization-producer')
    async def cleanup(self):
        if self.producer:await self.cancel_task(self.producer)
        await super().cleanup()


class SessionFinalizationTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.assertEqual(importlib.metadata.version('pipecat-ai'),'0.0.94')
        self.captured=[];self.rows=[];self.finished=asyncio.Event();self.resources=[];self.observer=LifecycleObserver()
        self.continuous=False;self.silent=False;self.output_stream=STREAM
        tree=ast.parse(BOT.read_text())
        run_bot=next(n for n in tree.body if isinstance(n,ast.AsyncFunctionDef) and n.name=='run_bot')
        self.handlers=[next(n for n in run_bot.body if isinstance(n,ast.AsyncFunctionDef) and n.name==name)
                       for name in ('_on_transcript','_on_client_disconnected')]
        save=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='_save_transcript')
        test=self
        class LocalCollection:
            def __getitem__(self,key):return self
            def insert_one(self,row):test.rows.append(json.loads(json.dumps(row)))
        namespace={'_mongo':LocalCollection(),'MONGO_DB':'local','MONGO_COLLECTION':'local'}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[save],type_ignores=[])),str(BOT),'exec'),namespace)
        self.save=namespace['_save_transcript']
        app=FastAPI()
        @app.websocket('/ws')
        async def ws_handler(ws:WebSocket):
            await ws.accept()
            for _ in range(2):await ws.receive_text()
            transport=FastAPIWebsocketTransport(ws,FastAPIWebsocketParams(audio_in_enabled=True,audio_out_enabled=True,
                serializer=TwilioFrameSerializer(self.output_stream,params=TwilioFrameSerializer.InputParams(auto_hang_up=False))))
            transcript=TranscriptProcessor();producer=LocalAudioProducer(self.continuous,self.silent)
            task=PipelineTask(Pipeline([transport.input(),producer,transport.output(),transcript.assistant()]),
                params=PipelineParams(audio_in_sample_rate=8000,audio_out_sample_rate=8000),enable_turn_tracking=False,observers=[self.observer])
            await ws.send_json({"event":"mark","streamSid":STREAM,"media":{"payload":"YWJj"}})
            self.resources.append((producer,task,transport))
            ns={'transport':transport,'transcript':transcript,'captured':self.captured,'task':task}
            exec(compile(ast.fix_missing_locations(ast.Module(body=self.handlers,type_ignores=[])),str(BOT),'exec'),ns)
            try:await PipelineRunner(handle_sigint=False).run(task)
            except WebSocketDisconnect:pass
            finally:
                self.save('CAlocal',self.captured)
                self.finished.set()
        self.sock=socket.socket();self.sock.bind(('127.0.0.1',0));self.port=self.sock.getsockname()[1]
        self.server=uvicorn.Server(uvicorn.Config(app,log_level='error',lifespan='off'))
        self.server_task=asyncio.create_task(self.server.serve(sockets=[self.sock]))
        async with asyncio.timeout(2):
            while not self.server.started:await asyncio.sleep(.01)
    async def asyncTearDown(self):
        self.server.should_exit=True
        await asyncio.wait_for(self.server_task,3)
        self.sock.close()
    async def session(self,**kwargs):
        namespace=probe_namespace(**kwargs)
        original=aiohttp.ClientSession.ws_connect
        def local_connect(client,url,**options):
            self.assertEqual(url,'http://127.0.0.1:8080/ws')
            return original(client,f'http://127.0.0.1:{self.port}/ws',**options)
        with patch.object(aiohttp.ClientSession,'ws_connect',local_connect):
            return await namespace['session']()
    async def test_full_window_retains_actual_multi_phrase_audio_and_final_transcript(self):
        before=time.monotonic()
        frames,audio_frames,audio_bytes,audio_sha,quiet=await self.session()
        self.assertGreaterEqual(time.monotonic()-before,1.8)
        await asyncio.wait_for(self.finished.wait(),2)
        self.assertTrue(quiet);self.assertGreaterEqual(audio_frames,2)
        self.assertEqual(audio_bytes,12*160);self.assertEqual(len(audio_sha),64);self.assertGreaterEqual(frames,audio_frames)
        text=' '.join(m['content'] for m in self.rows[0]['messages'])
        self.assertIn('9am to 9pm',text);self.assertIn('LOCALNONCE',text)
        events=self.observer.events
        cancelled=min(stamp for name,stamp in events if name=='CancelFrame')
        texts=[stamp for name,stamp in events if name=='TTSTextFrame']
        stopped=[stamp for name,stamp in events if name=='BotStoppedSpeakingFrame' and stamp<cancelled]
        self.assertTrue(stopped);self.assertLess(max(texts),max(stopped))
        self.assertLess(max(stopped),cancelled)
        producer,task,transport=self.resources[0]
        self.assertTrue(producer.done.is_set());self.assertTrue(producer.producer.done())
        self.assertIsNone(transport.input()._receive_task)
        frozen=producer.emitted;await asyncio.sleep(.05);self.assertEqual(producer.emitted,frozen)
    async def test_premature_disconnect_truncates_actual_second_phrase(self):
        result=await self.session(wait=.1,quiet=.4)
        self.assertFalse(result[-1])
        await asyncio.wait_for(self.finished.wait(),2)
        text=' '.join(m['content'] for row in self.rows for m in row['messages'])
        self.assertNotIn('LOCALNONCE',text)
    async def test_audio_at_cap_is_ineligible_even_with_assistant_text(self):
        self.continuous=True
        result=await self.session(wait=1.6,quiet=.4)
        self.assertFalse(result[-1]);await asyncio.wait_for(self.finished.wait(),2)
    async def test_cancellation_terminates_actual_local_producer(self):
        pending=asyncio.create_task(self.session(wait=3))
        async with asyncio.timeout(2):
            while not self.resources:await asyncio.sleep(.01)
        await asyncio.sleep(.1);pending.cancel()
        with self.assertRaises(asyncio.CancelledError):await pending
        await asyncio.wait_for(self.finished.wait(),2)
        self.assertTrue(self.resources[0][0].producer.done())
    async def test_control_only_frames_do_not_credit_audio_or_completion(self):
        self.silent=True
        result=await self.session(wait=.1,quiet=.05)
        self.assertGreater(result[0],0);self.assertEqual(result[1:3],(0,0));self.assertFalse(result[-1])
        await asyncio.wait_for(self.finished.wait(),2)
    async def test_actual_foreign_stream_media_rejects_and_tears_down(self):
        self.output_stream='MZforeign'
        with self.assertRaisesRegex(RuntimeError,'identity differs'):
            await self.session(wait=.3)
        await asyncio.wait_for(self.finished.wait(),2)
        self.assertTrue(self.resources[0][0].producer.done())

    async def test_twilio_stop_is_not_a_semantic_pipeline_end(self):
        serializer=TwilioFrameSerializer(STREAM,params=TwilioFrameSerializer.InputParams(auto_hang_up=False))
        self.assertIsNone(await serializer.deserialize(json.dumps({'event':'stop','streamSid':STREAM})))


class EvidenceValidationTest(unittest.TestCase):
    def test_only_valid_same_stream_media_counts(self):
        ns=probe_namespace();parse=ns['media_audio']
        value={'event':'media','streamSid':STREAM,'media':{'payload':base64.b64encode(b'abc').decode()}}
        self.assertEqual(parse(json.dumps(value)),b'abc')
        for event in ('mark','TEXT','connected'):
            self.assertIsNone(parse(json.dumps(dict(value,event=event))))
        bad=[dict(value,streamSid='MZforeign'),dict(value,media={'payload':''}),dict(value,media={'payload':'!!!'}),
             dict(value,media={'payload':1}),[], {'event':'media'}]
        for item in bad:
            with self.subTest(item=item),self.assertRaises((RuntimeError,ValueError)):
                parse(json.dumps(item))
    def test_cleanup_waits_for_late_actual_owned_row_and_rejects_rewrites(self):
        ns=probe_namespace();calls=[]
        def late():
            calls.append(1)
            return (None,[]) if len(calls)<3 else ('owned-id',[{'role':'assistant','content':'public answer'}])
        ns['transcript']=late
        self.assertEqual(ns['wait_cleanup_transcript'](),'owned-id');self.assertEqual(len(calls),4)
        for second in [('foreign-id',[]),('owned-id',[{'role':'assistant','content':'changed'}]),(None,[])]:
            values=iter([('owned-id',[]),second]);ns['transcript']=lambda:next(values)
            with self.assertRaises(RuntimeError):ns['wait_cleanup_transcript']()
        ns['transcript']=lambda:(None,[]);ns['FINAL_TRANSCRIPT_WAIT_SECONDS']=.03
        with self.assertRaisesRegex(RuntimeError,'unavailable'):ns['wait_cleanup_transcript']()

if __name__=='__main__':unittest.main()
