#!/usr/bin/env python3
"""CPU controls for the patched vLLM 0.7.3 drain ordering primitive."""
from __future__ import annotations

import argparse
import ast
import asyncio
import hashlib
import importlib.metadata
import json
from dataclasses import dataclass, field
from pathlib import Path
import re
import types
import unittest
from typing import Dict, List, Optional, Union
import uuid

HERE = Path(__file__).resolve().parent


def find_class(path: Path, name: str) -> ast.ClassDef:
    tree = ast.parse(path.read_text(), filename=str(path))
    return next(node for node in tree.body
                if isinstance(node, ast.ClassDef) and node.name == name)


def load_dataclasses(path: Path):
    wanted = {
        "RPCError", "RPCProcessRequest", "RPCDrainCapabilityRequest",
        "RPCDrainBeginRequest", "RPCDrainObserveRequest",
        "RPCDrainReopenRequest", "RPCDrainResponse",
    }
    tree = ast.parse(path.read_text(), filename=str(path))
    nodes = [node for node in tree.body
             if isinstance(node, ast.ClassDef) and node.name in wanted]
    module = ast.Module(body=nodes, type_ignores=[])
    ast.fix_missing_locations(module)
    namespace = {
        "dataclass": dataclass, "field": field, "uuid": uuid,
        "Optional": Optional, "Union": Union, "Mapping": dict,
        "List": List, "Dict": Dict, "PromptType": object,
        "SamplingParams": object, "PoolingParams": object,
        "LoRARequest": object, "PromptAdapterRequest": object,
        "overload": lambda value: value,
        "deprecated": lambda *_args, **_kwargs: (lambda value: value),
        "deprecate_kwargs": lambda *_args, **_kwargs: (lambda value: value),
    }
    exec(compile(module, str(path), "exec"), namespace)
    return namespace


def load_method_class(path: Path, source_class: str, methods: set[str], globals_: dict):
    original = find_class(path, source_class)
    nodes = [node for node in original.body
             if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
             and node.name in methods]
    generated = ast.ClassDef(
        name="Loaded", bases=[], keywords=[], body=nodes or [ast.Pass()],
        decorator_list=[])
    module = ast.Module(body=[generated], type_ignores=[])
    ast.fix_missing_locations(module)
    namespace = dict(globals_)
    exec(compile(module, str(path), "exec"), namespace)
    return namespace["Loaded"]


def verify_patched_source(source_root: Path):
    manifest = json.loads((HERE / "manifest.json").read_text())
    for name, hashes in manifest["files"].items():
        actual = hashlib.sha256((source_root / name).read_bytes()).hexdigest()
        if actual != hashes["after"]:
            raise RuntimeError(f"patched source hash mismatch for {name}")


class Group:
    def __init__(self, request_id, finished=False):
        self.request_id = request_id
        self.finished = finished

    def is_finished(self):
        return self.finished


class FakeLLMEngine:
    def __init__(self, *, waiting=(), running=(), swapped=(), cached=()):
        self.scheduler = [types.SimpleNamespace(
            waiting=[Group(value) for value in waiting],
            running=[Group(value) for value in running],
            swapped=[Group(value) for value in swapped])]
        metadata = [Group(value) for value in cached] or None
        self.cached_scheduler_outputs = [types.SimpleNamespace(
            seq_group_metadata_list=metadata)]
        self.scheduler_contexts = [types.SimpleNamespace(output_queue=[])]
        self.abort_calls = []
        self.add_calls = []

    def abort_request(self, request_ids):
        ids = {request_ids} if isinstance(request_ids, str) else set(request_ids)
        self.abort_calls.append(ids)
        for scheduler in self.scheduler:
            for name in ("waiting", "running", "swapped"):
                setattr(scheduler, name, [group for group in getattr(scheduler, name)
                                         if group.request_id not in ids])

    def add_request(self, *, request_id, **_kwargs):
        self.add_calls.append(request_id)
        self.scheduler[0].waiting.append(Group(request_id))


class DrainProducerTest(unittest.IsolatedAsyncioTestCase):
    source_root: Path

    @classmethod
    def setUpClass(cls):
        definitions = load_dataclasses(
            cls.source_root / "vllm/engine/multiprocessing/__init__.py")
        for name, value in definitions.items():
            if name.startswith("RPC"):
                setattr(cls, name, value)
        engine_globals = dict(definitions)
        engine_globals.update({"ENGINE_DEAD_ERROR": RuntimeError, "re": re})
        cls.Engine = load_method_class(
            cls.source_root / "vllm/engine/multiprocessing/engine.py",
            "MQLLMEngine", {
                "_handle_process_request", "_phorvex_queue_snapshot",
                "_phorvex_ids", "_phorvex_response",
                "_handle_drain_capability_request",
                "_handle_drain_begin_request",
                "_handle_drain_observe_request",
                "_handle_drain_reopen_request",
            }, engine_globals)
        client_globals = dict(definitions)
        client_globals.update({
            "asyncio": asyncio, "BaseException": BaseException,
            "Union": Union, "VLLM_RPC_TIMEOUT": 100,
        })
        cls.Client = load_method_class(
            cls.source_root / "vllm/engine/multiprocessing/client.py",
            "MQLLMEngineClient", {
                "_add_output", "_phorvex_drain_rpc",
                "phorvex_drain_capability", "phorvex_drain_begin",
                "phorvex_drain_observe", "phorvex_drain_reopen",
            }, client_globals)

    def engine(self, llm=None, supported=True):
        instance = self.Engine()
        instance.engine = llm or FakeLLMEngine()
        instance.log_requests = False
        instance._errored_with = None
        instance._phorvex_drain_supported = supported
        instance._phorvex_engine_boot_id = "a" * 32
        instance._phorvex_admission_open = supported
        instance._phorvex_admission_generation = 0
        instance._phorvex_operation = None
        instance._phorvex_observation_sequence = 0
        instance.outputs = []
        instance._send_outputs = instance.outputs.append
        return instance

    def test_actual_engine_order_snapshot_abort_observe_and_reopen(self):
        llm = FakeLLMEngine(waiting=("wait",), running=("run",), swapped=("swap",))
        engine = self.engine(llm)
        pre = self.RPCProcessRequest(prompt="p", params=object(), request_id="pre")
        engine._handle_process_request(pre)
        self.assertEqual(llm.add_calls, ["pre"])

        begin = self.RPCDrainBeginRequest("1" * 32, "1")
        engine._handle_drain_begin_request(begin)
        response = engine.outputs[-1]
        self.assertEqual(response.admission, "CLOSED")
        self.assertEqual(response.snapshot[0]["waiting"], ["wait", "pre"])
        self.assertEqual(response.snapshot[0]["running"], ["run"])
        self.assertEqual(response.snapshot[0]["swapped"], ["swap"])
        self.assertEqual(response.queues[0]["waiting"], [])
        self.assertEqual(llm.abort_calls[-1], {"wait", "pre", "run", "swap"})
        self.assertEqual(response.terminal_dispositions,
                         {"wait": "aborted", "pre": "aborted",
                          "run": "aborted", "swap": "aborted"})

        post = self.RPCProcessRequest(prompt="p", params=object(), request_id="post")
        engine._handle_process_request(post)
        self.assertEqual(llm.add_calls, ["pre"])
        self.assertEqual(engine.outputs[-1].request_id, "post")
        self.assertIn("admission is closed", str(engine.outputs[-1].exception))

        for nonce in ("2" * 32, "3" * 32):
            engine._handle_drain_observe_request(
                self.RPCDrainObserveRequest("1" * 32, "1", nonce))
        observations = engine.outputs[-2:]
        self.assertEqual([item.observation_sequence for item in observations],
                         ["1", "2"])
        self.assertEqual([item.observation_nonce for item in observations],
                         ["2" * 32, "3" * 32])

        engine._handle_drain_reopen_request(
            self.RPCDrainReopenRequest("1" * 32, "1"))
        self.assertIsNone(engine.outputs[-1].error)
        self.assertEqual(engine.outputs[-1].admission, "OPEN")
        self.assertEqual(engine.outputs[-1].operation_id, "1" * 32)
        engine._handle_process_request(
            self.RPCProcessRequest(prompt="p", params=object(), request_id="after"))
        self.assertEqual(llm.add_calls, ["pre", "after"])

    def test_cached_work_blocks_quiescence_and_duplicate_begin_is_read_only(self):
        llm = FakeLLMEngine(cached=("gpu-output",))
        engine = self.engine(llm)
        begin = self.RPCDrainBeginRequest("4" * 32, "1")
        engine._handle_drain_begin_request(begin)
        self.assertEqual(engine.outputs[-1].terminal_dispositions,
                         {"gpu-output": "completed-before-abort"})
        abort_count = len(llm.abort_calls)
        engine._handle_drain_begin_request(begin)
        self.assertEqual(len(llm.abort_calls), abort_count)

        for nonce in ("5" * 32, "6" * 32):
            engine._handle_drain_observe_request(
                self.RPCDrainObserveRequest("4" * 32, "1", nonce))
        engine._handle_drain_reopen_request(
            self.RPCDrainReopenRequest("4" * 32, "1"))
        self.assertEqual(engine.outputs[-1].error, "not_quiescent")
        self.assertEqual(engine.outputs[-1].admission, "CLOSED")

        llm.cached_scheduler_outputs[0].seq_group_metadata_list = None
        for nonce in ("7" * 32, "8" * 32):
            engine._handle_drain_observe_request(
                self.RPCDrainObserveRequest("4" * 32, "1", nonce))
        engine._handle_drain_reopen_request(
            self.RPCDrainReopenRequest("4" * 32, "1"))
        self.assertIsNone(engine.outputs[-1].error)

        # The replay identity is the complete tuple: reusing a random ID in a
        # later generation is distinct, although callers must generate fresh IDs.
        engine._handle_drain_begin_request(
            self.RPCDrainBeginRequest("4" * 32, "2"))
        self.assertIsNone(engine.outputs[-1].error)
        self.assertEqual(engine.outputs[-1].operation_generation, "2")

    def test_running_work_with_queued_async_output_is_aborted(self):
        # vLLM's async output queue holds the last step of every generating
        # request, so an active stream appears in both running and cached.
        llm = FakeLLMEngine(running=("stream",), cached=("stream",))
        llm.scheduler_contexts[0].output_queue.append(types.SimpleNamespace(
            seq_group_metadata_list=[Group("stream")]))
        engine = self.engine(llm)
        engine._handle_drain_begin_request(self.RPCDrainBeginRequest("9" * 32, "1"))
        response = engine.outputs[-1]
        self.assertIsNone(response.error)
        self.assertEqual(response.snapshot[0]["running"], ["stream"])
        self.assertEqual(response.snapshot[0]["cached"], ["stream"])
        self.assertEqual(response.terminal_dispositions, {"stream": "aborted"})
        self.assertEqual(llm.abort_calls[-1], {"stream"})

    def test_already_finished_scheduler_work_completed_before_abort(self):
        llm = FakeLLMEngine(cached=("done", "queued-only"))
        llm.scheduler[0].running.append(Group("done", finished=True))
        llm.scheduler[0].running.append(Group("live"))
        engine = self.engine(llm)
        engine._handle_drain_begin_request(self.RPCDrainBeginRequest("a" * 32, "1"))
        self.assertEqual(engine.outputs[-1].terminal_dispositions,
                         {"done": "completed-before-abort",
                          "queued-only": "completed-before-abort",
                          "live": "aborted"})

    def test_unsupported_and_generation_conflicts_refuse_without_admission(self):
        unsupported = self.engine(supported=False)
        unsupported._handle_drain_capability_request(
            self.RPCDrainCapabilityRequest())
        self.assertFalse(unsupported.outputs[-1].supported)
        self.assertEqual(unsupported.outputs[-1].admission, "CLOSED")
        unsupported._handle_drain_begin_request(
            self.RPCDrainBeginRequest("9" * 32, "1"))
        self.assertEqual(unsupported.outputs[-1].error, "unsupported_engine_mode")

        engine = self.engine()
        for generation in ("0", "01", "18446744073709551616"):
            engine._handle_drain_begin_request(
                self.RPCDrainBeginRequest("a" * 32, generation))
            self.assertEqual(engine.outputs[-1].error, "generation_conflict")
            self.assertEqual(engine.outputs[-1].admission, "OPEN")

        # A new engine boot has no durable generation state. Its first control
        # adopts the proxy ledger's exact successor, then enforces +1 locally.
        restarted = self.engine()
        restarted._handle_drain_begin_request(
            self.RPCDrainBeginRequest("b" * 32, "42"))
        self.assertIsNone(restarted.outputs[-1].error)
        self.assertEqual(restarted.outputs[-1].admission_generation, "42")

    def client(self):
        client = self.Client()
        client.output_queues = {}
        client._phorvex_input_lock = asyncio.Lock()
        client._phorvex_admission_open = True
        client.input_socket = types.SimpleNamespace(closed=False)
        client.sent = []

        async def send(this, request, socket):
            del socket
            this.sent.append(request)
            response = self.RPCDrainResponse(
                request_id=request.request_id,
                action=("begin" if isinstance(request, self.RPCDrainBeginRequest)
                        else "observe" if isinstance(request, self.RPCDrainObserveRequest)
                        else "reopen" if isinstance(request, self.RPCDrainReopenRequest)
                        else "capability"),
                supported=True, engine_boot_id="b" * 32,
                admission=("OPEN" if isinstance(request, (self.RPCDrainCapabilityRequest,
                                                           self.RPCDrainReopenRequest))
                           else "CLOSED"),
                admission_generation="1", operation_id=getattr(request, "operation_id", None),
                operation_generation=getattr(request, "operation_generation", None),
                observation_nonce=getattr(request, "observation_nonce", None),
                observation_sequence="1", virtual_engine_ids=[0],
                snapshot={},
                queues={0: {"waiting": [], "running": [], "swapped": [], "cached": []}},
                terminal_dispositions={})
            this._add_output(response)

        client._send_one_way_rpc_request = types.MethodType(send, client)
        return client

    async def test_actual_frontend_control_methods_close_and_reopen_gate(self):
        client = self.client()
        capability = await client.phorvex_drain_capability()
        self.assertTrue(capability.supported)
        begin = await client.phorvex_drain_begin("c" * 32, "1")
        self.assertEqual(begin.admission, "CLOSED")
        self.assertFalse(client._phorvex_admission_open)
        observation = await client.phorvex_drain_observe(
            "c" * 32, "1", "d" * 32)
        self.assertEqual(observation.observation_nonce, "d" * 32)
        reopened = await client.phorvex_drain_reopen("c" * 32, "1")
        self.assertEqual(reopened.admission, "OPEN")
        self.assertTrue(client._phorvex_admission_open)
        self.assertEqual(len({request.request_id for request in client.sent}), 4)


def main():
    parser = argparse.ArgumentParser()
    roots = parser.add_mutually_exclusive_group(required=True)
    roots.add_argument("--source-root", type=Path)
    roots.add_argument("--installed", action="store_true")
    args, remaining = parser.parse_known_args()
    if args.installed:
        distribution = importlib.metadata.distribution("vllm")
        if distribution.version != "0.7.3":
            raise RuntimeError(f"vLLM version is {distribution.version!r}, expected '0.7.3'")
        DrainProducerTest.source_root = Path(distribution.locate_file(""))
    else:
        DrainProducerTest.source_root = args.source_root.resolve()
    verify_patched_source(DrainProducerTest.source_root)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(DrainProducerTest)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
