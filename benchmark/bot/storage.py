"""Reclaim only the bot's disposable Go build cache, between benchmark jobs."""
import os
import shutil
import stat
from pathlib import Path

DEFAULT_CACHE_BYTES = 2 * 1024 ** 3


def trim_cache(cache, max_bytes=DEFAULT_CACHE_BYTES, min_free_bytes=0):
    """Evict oldest regular cache files to meet retention/free-space targets.

    Never follow symlinks or touch modules, SDKs, job evidence or other caches.
    Call only before/after the single worker's Go process, not during a build.
    """
    cache = Path(cache)
    if cache.is_symlink():
        raise ValueError('managed Go cache must not be a symlink')
    free = lambda: shutil.disk_usage(cache.parent).free
    before_free = free()
    entries = []
    if cache.exists():
        if not cache.is_dir():
            raise ValueError('managed Go cache must be a directory')
        for root, dirs, files in os.walk(cache, followlinks=False):
            dirs[:] = [d for d in dirs if not (Path(root)/d).is_symlink()]
            for name in files:
                path = Path(root)/name
                info = path.lstat()
                if stat.S_ISREG(info.st_mode):
                    entries.append((info.st_mtime_ns, str(path), info.st_size))
    total = sum(row[2] for row in entries)
    record = {'cache_bytes_before': total, 'free_bytes_before': before_free,
              'files_removed': 0, 'bytes_removed': 0}
    for _, name, size in sorted(entries):
        if total <= max_bytes and free() >= min_free_bytes:
            break
        path = Path(name)
        # Do not follow a file replaced by a symlink during the scan.
        if not path.is_symlink():
            path.unlink(missing_ok=True)
            total -= size
            record['files_removed'] += 1
            record['bytes_removed'] += size
    record.update(cache_bytes_after=total, free_bytes_after=free())
    return record
