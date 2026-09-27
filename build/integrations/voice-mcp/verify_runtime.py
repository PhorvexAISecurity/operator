"""Read-only dependency and source smoke check for the MCP runtime image."""

import asyncio
from importlib import metadata
import platform
import sys

from verify_wheelhouse import REQUIREMENT, lines


def verify(lock):
    if sys.version_info[:2] != (3, 11) or platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("MCP runtime requires linux/amd64 Python 3.11")
    pinned = {}
    for line in lines(lock):
        match = REQUIREMENT.fullmatch(line)
        if not match:
            raise ValueError("invalid requirement lock")
        name, version, _ = match.groups()
        pinned[name] = version
        if metadata.version(name) != version:
            raise ValueError("installed MCP dependency differs from lock: " + name)
    import fastmcp
    import mcp
    import httpx
    import server
    async def smoke():
        tools = await server.mcp.list_tools()
        if {tool.name for tool in tools} != {"store_directory", "check_promotions"}:
            raise ValueError("MCP tools unavailable")
    asyncio.run(smoke())
    return len(pinned)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_runtime.py LOCK")
    try:
        print("verified", verify(sys.argv[1]), "installed MCP dependencies and tools")
    except (OSError, ValueError, ImportError, metadata.PackageNotFoundError) as exc:
        raise SystemExit(f"MCP runtime verification failed: {exc}") from exc
