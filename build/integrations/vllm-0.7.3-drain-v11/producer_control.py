#!/usr/bin/env python3
"""Unchanged control showing whether allocator false survives the HTTP producer."""

from __future__ import annotations

import argparse
import ast
import asyncio
import json
from pathlib import Path
import types


class Response:
    def __init__(self, status_code=200, content=None):
        self.status_code = status_code
        self.content = content


class JSONResponse(Response):
    def __init__(self, content, status_code=200):
        super().__init__(status_code=status_code, content=content)


class Logger:
    def info(self, *_args):
        pass


def load_handler(path: Path):
    tree = ast.parse(path.read_text(), filename=str(path))
    handler = next(node for node in ast.walk(tree)
                   if isinstance(node, ast.AsyncFunctionDef) and node.name == "reset_prefix_cache")
    handler.decorator_list = []
    module = ast.Module(body=[handler], type_ignores=[])
    ast.fix_missing_locations(module)
    namespace = {
        "Request": object,
        "Response": Response,
        "JSONResponse": JSONResponse,
        "logger": Logger(),
        "engine_client": lambda request: request.engine,
    }
    exec(compile(module, str(path), "exec"), namespace)
    return namespace["reset_prefix_cache"]


async def run(source_root: Path):
    handler = load_handler(source_root / "vllm/entrypoints/openai/api_server.py")
    request = types.SimpleNamespace(
        engine=types.SimpleNamespace(reset_prefix_cache=lambda: asyncio.sleep(0, result=False)))
    response = await handler(request)
    body = response.content
    print(json.dumps({
        "allocator_result": False,
        "http_status": response.status_code,
        "body": body,
        "strict_success_confirmed": response.status_code == 200 and body == {"success": True},
        "status_only_would_claim_success": response.status_code == 200,
    }, sort_keys=True))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(run(args.source_root.resolve()))


if __name__ == "__main__":
    main()
