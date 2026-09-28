"""Real pinned Pipecat transport/task cleanup, with no remote providers or APIs."""

import ast
import asyncio
from importlib import metadata
from pathlib import Path
import unittest

from fastapi import FastAPI, WebSocket
from pipecat.frames.frames import Frame, StartFrame, OutputAudioRawFrame
from pipecat.pipeline.pipeline import Pipeline
from pipecat.pipeline.task import PipelineParams, PipelineTask
from pipecat.pipeline.runner import PipelineRunner
from pipecat.processors.frame_processor import FrameProcessor, FrameDirection
from pipecat.serializers.twilio import TwilioFrameSerializer
from pipecat.transports.websocket.fastapi import FastAPIWebsocketParams, FastAPIWebsocketTransport

from test_runtime import RuntimeFixture


class Producer(FrameProcessor):
    """An actual managed local producer, rather than a final cleanup flag stub."""
    def __init__(self):
        super().__init__()
        self.producing = None
        self.ticks = 0
        self.finished = asyncio.Event()

    async def process_frame(self, frame: Frame, direction: FrameDirection):
        await super().process_frame(frame, direction)
        await self.push_frame(frame, direction)
        if isinstance(frame, StartFrame) and self.producing is None:
            async def produce():
                try:
                    while True:
                        self.ticks += 1
                        await self.push_frame(OutputAudioRawFrame(b"\0" * 320, 8000, 1))
                        await asyncio.sleep(0.005)
                finally:
                    self.finished.set()
            self.producing = self.create_task(produce(), name="admission-local-producer")

    async def cleanup(self):
        if self.producing:
            await self.cancel_task(self.producing)
        await super().cleanup()


class InstalledPipecatTeardownTest(RuntimeFixture):
    # Reuse fixture utilities, but only run this actual Pipecat proof here.
    async def test_real_transport_disconnect_runs_exact_legacy_cancel_handler_and_cleanup(self):
        self.assertEqual(metadata.version("pipecat-ai"), "0.0.94")
        delegate = FastAPI()
        resources = []
        source = Path(__file__).parent.parent / "voice-memory" / "bot.py"
        tree = ast.parse(source.read_bytes())
        run_bot = next(node for node in tree.body if isinstance(node, ast.AsyncFunctionDef) and node.name == "run_bot")
        handler = next(node for node in run_bot.body if isinstance(node, ast.AsyncFunctionDef) and node.name == "_on_client_disconnected")
        self.assertEqual(ast.unparse(handler.body[0]), "await task.cancel(reason='websocket client disconnected')")

        @delegate.websocket("/ws")
        async def ws(websocket: WebSocket):
            await websocket.accept()
            for _ in range(2):
                await websocket.receive_text()
            serializer = TwilioFrameSerializer("MSlocal", params=TwilioFrameSerializer.InputParams(auto_hang_up=False))
            transport = FastAPIWebsocketTransport(websocket, FastAPIWebsocketParams(audio_in_enabled=True,
                audio_out_enabled=True, serializer=serializer))
            producer = Producer()
            task = PipelineTask(Pipeline([transport.input(), producer, transport.output()]),
                                params=PipelineParams(audio_in_sample_rate=8000, audio_out_sample_rate=8000),
                                enable_turn_tracking=False)
            # Compile the installed legacy handler unchanged, including its real
            # event registration. No substitute callback or outer-task cancellation.
            module = ast.fix_missing_locations(ast.Module(body=[handler], type_ignores=[]))
            exec(compile(module, str(source), "exec"), {"transport": transport, "task": task})
            resources.append((producer, transport, task))
            await PipelineRunner(handle_sigint=False).run(task)

        self.app.delegate = delegate
        unsigned = await self.socket()
        signed = await self.socket(signed=True)
        pending = await self.socket(run="pending123")
        await unsigned.start()
        await signed.start()
        await self.until(lambda: len(resources) == 2 and all(resource[0].ticks > 1 for resource in resources))
        self.enforce()
        await self.app.refresh()
        await asyncio.wait_for(unsigned.task, 3)
        await asyncio.wait_for(pending.task, 1)
        stopped, live = resources[0][0], resources[1][0]
        self.assertTrue(stopped.finished.is_set())
        self.assertTrue(stopped.producing.done())
        self.assertIsNone(resources[0][1].input()._receive_task)
        count, signed_count = stopped.ticks, live.ticks
        await asyncio.sleep(0.05)
        self.assertEqual(stopped.ticks, count)
        self.assertGreater(live.ticks, signed_count)
        self.assertFalse(signed.task.done())
        status, state = await self.state()
        self.assertEqual(status, 200)
        self.assertTrue(state["settled"])
        self.assertEqual(state["activeSigned"], 1)
        await signed.close()
        self.assertTrue(live.finished.is_set())


if __name__ == "__main__":
    unittest.main()
