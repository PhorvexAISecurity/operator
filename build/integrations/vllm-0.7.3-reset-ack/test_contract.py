#!/usr/bin/env python3
"""Focused controls for the patched vLLM 0.7.3 reset contract.

The tests execute the reviewed method bodies directly from a patched source
tree. This avoids importing CUDA extensions while still exercising the exact
wrapper, correlation, cleanup, engine-handler, aggregation, and API code.
"""

from __future__ import annotations

import argparse
import ast
import asyncio
from dataclasses import dataclass, field
import hashlib
import importlib.metadata
import json
from pathlib import Path
import types
import unittest
from typing import Union
import uuid


HERE = Path(__file__).resolve().parent


def verify_patched_source(source_root: Path) -> None:
    manifest = json.loads((HERE / "manifest.json").read_text())
    for name, hashes in manifest["files"].items():
        actual = hashlib.sha256((source_root / name).read_bytes()).hexdigest()
        if actual != hashes["after"]:
            raise RuntimeError(f"patched source hash mismatch for {name}")


def find_node(path: Path, kind: type[ast.AST], name: str, parent: str | None = None) -> ast.AST:
    tree = ast.parse(path.read_text(), filename=str(path))
    bodies = [tree]
    if parent:
        bodies = [node for node in ast.walk(tree)
                  if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
                  and node.name == parent]
    for body in bodies:
        for node in ast.walk(body):
            if isinstance(node, kind) and getattr(node, "name", None) == name:
                return node
    raise AssertionError(f"{name} not found in {path}")


def load_function(path: Path, name: str, globals_: dict, parent: str | None = None):
    node = find_node(path, (ast.FunctionDef, ast.AsyncFunctionDef), name, parent)
    node.decorator_list = []
    future = ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0)
    module = ast.Module(body=[future, node], type_ignores=[])
    ast.fix_missing_locations(module)
    namespace = dict(globals_)
    exec(compile(module, str(path), "exec"), namespace)
    return namespace[name]


def load_dataclasses(path: Path):
    wanted = {"RPCError", "RPCResetPrefixCacheRequest", "RPCResetPrefixCacheResponse"}
    tree = ast.parse(path.read_text(), filename=str(path))
    nodes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name in wanted]
    module = ast.Module(body=nodes, type_ignores=[])
    ast.fix_missing_locations(module)
    namespace = {"dataclass": dataclass, "field": field, "uuid": uuid, "BaseException": BaseException,
                 "Optional": __import__("typing").Optional}
    exec(compile(module, str(path), "exec"), namespace)
    return namespace


class ContractTest(unittest.IsolatedAsyncioTestCase):
    source_root: Path

    @classmethod
    def setUpClass(cls):
        mp_init = cls.source_root / "vllm/engine/multiprocessing/__init__.py"
        definitions = load_dataclasses(mp_init)
        cls.ResetRequest = definitions["RPCResetPrefixCacheRequest"]
        cls.ResetResponse = definitions["RPCResetPrefixCacheResponse"]
        cls.RPCError = definitions["RPCError"]

        client_path = cls.source_root / "vllm/engine/multiprocessing/client.py"
        common = {
            "asyncio": asyncio,
            "Union": Union,
            "BaseException": BaseException,
            "RPCResetPrefixCacheRequest": cls.ResetRequest,
            "RPCResetPrefixCacheResponse": cls.ResetResponse,
            "RequestOutput": object,
            "RPCAdapterLoadedResponse": object,
            "VLLM_RPC_TIMEOUT": 100,
        }
        reset = load_function(client_path, "reset_prefix_cache", common, "MQLLMEngineClient")
        add_output = load_function(client_path, "_add_output", common, "MQLLMEngineClient")

        async def send(client, request, socket):
            if socket.closed:
                raise RuntimeError("closed")
            client.sent.append(request)
            client.sent_event.set()

        cls.Client = type("PatchedClient", (), {
            "reset_prefix_cache": reset,
            "_add_output": add_output,
            "_send_one_way_rpc_request": send,
        })

        engine_path = cls.source_root / "vllm/engine/multiprocessing/engine.py"
        handler = load_function(engine_path, "_handle_reset_prefix_cache_request", {
            "RPCResetPrefixCacheRequest": cls.ResetRequest,
            "RPCResetPrefixCacheResponse": cls.ResetResponse,
            "RPCError": cls.RPCError,
            "BaseException": BaseException,
        }, "MQLLMEngine")
        cls.Engine = type("PatchedEngine", (), {"_handle_reset_prefix_cache_request": handler})

    def client(self):
        client = self.Client()
        client.output_queues = {}
        client.sent = []
        client.sent_event = asyncio.Event()
        client.input_socket = types.SimpleNamespace(closed=False)
        return client

    async def wait_sent(self, client, count=1):
        while len(client.sent) < count:
            await asyncio.wait_for(client.sent_event.wait(), 1)
            client.sent_event.clear()

    async def test_correlated_true_false_and_generation_queue(self):
        client = self.client()
        generation_queue = asyncio.Queue()
        client.output_queues["generation"] = generation_queue
        tasks = [asyncio.create_task(client.reset_prefix_cache()) for _ in range(4)]
        await self.wait_sent(client, 4)
        self.assertEqual(len({request.request_id for request in client.sent}), 4)
        expected = {}
        for index, request in reversed(list(enumerate(client.sent))):
            success = index % 2 == 0
            expected[request.request_id] = success
            client._add_output(self.ResetResponse(request.request_id, success))
        generation = types.SimpleNamespace(request_id="generation", finished=False)
        client._add_output(generation)
        self.assertEqual(await asyncio.gather(*tasks), [True, False, True, False])
        self.assertIs(await generation_queue.get(), generation)
        self.assertEqual(client.output_queues, {"generation": generation_queue})

    async def test_exception_death_malformed_timeout_and_cancel_cleanup(self):
        for response in (RuntimeError("engine exception"), RuntimeError("engine died")):
            client = self.client()
            task = asyncio.create_task(client.reset_prefix_cache())
            await self.wait_sent(client)
            await client.output_queues[client.sent[0].request_id].put(response)
            with self.assertRaises(RuntimeError):
                await task
            self.assertFalse(client.output_queues)

        client = self.client()
        task = asyncio.create_task(client.reset_prefix_cache())
        await self.wait_sent(client)
        await client.output_queues[client.sent[0].request_id].put(
            types.SimpleNamespace(request_id=client.sent[0].request_id))
        with self.assertRaisesRegex(ValueError, "Unexpected prefix-cache"):
            await task
        self.assertFalse(client.output_queues)

        client = self.client()
        task = asyncio.create_task(client.reset_prefix_cache())
        await self.wait_sent(client)
        client._add_output(self.ResetResponse(client.sent[0].request_id, "true"))
        with self.assertRaisesRegex(ValueError, "must be bool"):
            await task
        self.assertFalse(client.output_queues)

        client = self.client()
        with self.assertRaisesRegex(TimeoutError, "didn't complete.*100ms"):
            await client.reset_prefix_cache()
        lost_request = client.sent[0]
        self.assertFalse(client.output_queues)
        client._add_output(self.ResetResponse(lost_request.request_id, True))
        self.assertFalse(client.output_queues)

        client = self.client()

        async def stalled_send(_client, request, socket):
            del socket
            client.sent.append(request)
            client.sent_event.set()
            await asyncio.Event().wait()

        client._send_one_way_rpc_request = types.MethodType(stalled_send, client)
        with self.assertRaisesRegex(TimeoutError, "didn't complete.*100ms"):
            await client.reset_prefix_cache()
        self.assertFalse(client.output_queues)

        client = self.client()
        task = asyncio.create_task(client.reset_prefix_cache())
        await self.wait_sent(client)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertFalse(client.output_queues)

    async def test_engine_handler_preserves_bool_and_scopes_exception(self):
        for result in (True, False):
            engine = self.Engine()
            engine.reset_prefix_cache = lambda value=result: value
            engine.outputs = []
            engine._send_outputs = engine.outputs.append
            request = self.ResetRequest()
            engine._handle_reset_prefix_cache_request(request)
            self.assertEqual(engine.outputs, [self.ResetResponse(request.request_id, result)])

        engine = self.Engine()
        engine.reset_prefix_cache = lambda: (_ for _ in ()).throw(RuntimeError("reset failed"))
        engine.outputs = []
        engine._send_outputs = engine.outputs.append
        request = self.ResetRequest()
        engine._handle_reset_prefix_cache_request(request)
        self.assertEqual(engine.outputs[0].request_id, request.request_id)
        self.assertFalse(engine.outputs[0].is_engine_errored)

        engine = self.Engine()
        engine.reset_prefix_cache = lambda: 1
        engine.outputs = []
        engine._send_outputs = engine.outputs.append
        request = self.ResetRequest()
        engine._handle_reset_prefix_cache_request(request)
        self.assertIsInstance(engine.outputs[0].exception, TypeError)

    async def test_inprocess_pipeline_and_api_preserve_false(self):
        async_path = self.source_root / "vllm/engine/async_llm_engine.py"
        wrapper = load_function(async_path, "reset_prefix_cache", {}, "AsyncLLMEngine")
        instance = types.SimpleNamespace(engine=types.SimpleNamespace(reset_prefix_cache=lambda: False))
        self.assertFalse(await wrapper(instance))
        instance.engine.reset_prefix_cache = lambda: 1
        with self.assertRaisesRegex(TypeError, "must be bool"):
            await wrapper(instance)

        pipeline = load_function(self.source_root / "vllm/engine/llm_engine.py",
                                 "reset_prefix_cache", {}, "LLMEngine")
        calls = []
        schedulers = [types.SimpleNamespace(reset_prefix_cache=lambda value=value: calls.append(value) or value)
                      for value in (True, False, True)]
        self.assertFalse(pipeline(types.SimpleNamespace(scheduler=schedulers)))
        self.assertEqual(calls, [True, False])

        class JSONResponse:
            def __init__(self, content, status_code):
                self.content = content
                self.status_code = status_code

        class Logger:
            def info(self, *_args):
                pass

        api_path = self.source_root / "vllm/entrypoints/openai/api_server.py"
        api_reset = load_function(api_path, "reset_prefix_cache", {
            "Request": object,
            "JSONResponse": JSONResponse,
            "logger": Logger(),
            "engine_client": lambda request: request.engine,
        })
        raw_request = types.SimpleNamespace(
            engine=types.SimpleNamespace(reset_prefix_cache=lambda: asyncio.sleep(0, result=False)))
        response = await api_reset(raw_request)
        self.assertEqual((response.status_code, response.content), (200, {"success": False}))
        raw_request.engine.reset_prefix_cache = lambda: asyncio.sleep(0, result=1)
        with self.assertRaisesRegex(TypeError, "must be bool"):
            await api_reset(raw_request)

    async def test_v1_startup_and_actual_reset_middleware_auth(self):
        api_path = self.source_root / "vllm/entrypoints/openai/api_server.py"
        envs = types.SimpleNamespace(VLLM_USE_V1=True)
        builder = load_function(api_path, "build_async_engine_client_from_engine_args", {
            "envs": envs,
        })
        with self.assertRaisesRegex(RuntimeError, "does not support.*VLLM_USE_V1"):
            await builder(types.SimpleNamespace()).__anext__()

        class JSONResponse:
            def __init__(self, content, status_code):
                self.content = content
                self.status_code = status_code

        app = types.SimpleNamespace(root_path="")
        token = "reset-secret"
        authentication = load_function(api_path, "authentication", {
            "Request": object,
            "JSONResponse": JSONResponse,
            "app": app,
            "token": token,
        }, "build_app")
        forwarded = []

        async def call_next(request):
            forwarded.append(request.url.path)
            return "forwarded"

        def request(path, authorization=None, method="POST"):
            headers = {} if authorization is None else {"Authorization": authorization}
            return types.SimpleNamespace(method=method, url=types.SimpleNamespace(path=path), headers=headers)

        for authorization in (None, "Bearer wrong"):
            response = await authentication(request("/reset_prefix_cache", authorization), call_next)
            self.assertEqual(response.status_code, 401)
        self.assertEqual(
            await authentication(request("/reset_prefix_cache", "Bearer reset-secret"), call_next),
            "forwarded")
        response = await authentication(request("/v1/models"), call_next)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(await authentication(request("/health"), call_next), "forwarded")
        self.assertEqual(forwarded, ["/reset_prefix_cache", "/health"])

        tree = ast.parse(api_path.read_text(), filename=str(api_path))
        build_app = next(node for node in tree.body
                         if isinstance(node, ast.FunctionDef) and node.name == "build_app")
        token_index = next(index for index, node in enumerate(build_app.body)
                           if isinstance(node, ast.Assign)
                           and any(isinstance(target, ast.Name) and target.id == "token"
                                   for target in node.targets))
        guard_nodes = build_app.body[token_index:token_index + 2]
        module = ast.Module(body=guard_nodes, type_ignores=[])
        ast.fix_missing_locations(module)
        guard = compile(module, str(api_path), "exec")
        with self.assertRaisesRegex(RuntimeError, "API_KEY.*required"):
            exec(guard, {
                "envs": types.SimpleNamespace(VLLM_API_KEY=None, VLLM_SERVER_DEV_MODE=True),
                "args": types.SimpleNamespace(api_key=None),
            })
        exec(guard, {
            "envs": types.SimpleNamespace(VLLM_API_KEY=None, VLLM_SERVER_DEV_MODE=False),
            "args": types.SimpleNamespace(api_key=None),
        })
        exec(guard, {
            "envs": types.SimpleNamespace(VLLM_API_KEY="reset-secret", VLLM_SERVER_DEV_MODE=True),
            "args": types.SimpleNamespace(api_key=None),
        })


def main() -> int:
    parser = argparse.ArgumentParser()
    roots = parser.add_mutually_exclusive_group(required=True)
    roots.add_argument("--source-root", type=Path)
    roots.add_argument("--installed", action="store_true")
    args, remaining = parser.parse_known_args()
    if args.installed:
        distribution = importlib.metadata.distribution("vllm")
        if distribution.version != "0.7.3":
            raise RuntimeError(f"vLLM version is {distribution.version!r}, expected '0.7.3'")
        ContractTest.source_root = Path(distribution.locate_file(""))
    else:
        ContractTest.source_root = args.source_root.resolve()
    verify_patched_source(ContractTest.source_root)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ContractTest)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
