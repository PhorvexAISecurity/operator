#!/usr/bin/env python3
from pathlib import Path
import os
from drain_v11 import initialize_ledger

initialize_ledger(
    Path(os.environ.get("PHORVEX_DRAIN_LEDGER_DIR", "/var/lib/phorvex-drain")),
    os.environ["POD_UID"], os.urandom(16).hex())
