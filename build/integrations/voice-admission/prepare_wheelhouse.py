"""Download and verify exactly the official pure Python validator wheel."""
import hashlib
from pathlib import Path
import subprocess
import sys

EXPECTED = "03a137e2538ed2a6448c8b21c067f97ebabe273d76701744db4b6e5e47755df2"
FILENAME = "twilio-9.8.4-py2.py3-none-any.whl"
BASE = "753556437180.dkr.ecr.us-east-2.amazonaws.com/pipecat-voice@sha256:c9c598c406ed517eebf17f92a36863b39a15d9a7875cfcb2710f7b084dd539b8"


def verify(directory):
    if {p.name for p in directory.iterdir()} != {FILENAME} or hashlib.sha256((directory / FILENAME).read_bytes()).hexdigest() != EXPECTED:
        raise ValueError("wheelhouse is not the exact reviewed SDK")


if __name__ == "__main__":
    recipe = Path(__file__).parent
    assert (recipe / "Dockerfile").read_text().splitlines()[0] == "FROM --platform=linux/amd64 " + BASE
    assert (recipe / "requirements.lock").read_text() == "twilio==9.8.4 --hash=sha256:" + EXPECTED + "\n"
    directory = recipe / "wheelhouse"
    directory.mkdir(exist_ok=True)
    if not list(directory.iterdir()):
        subprocess.run([sys.executable, "-m", "pip", "download", "--no-deps", "--only-binary=:all:",
                        "twilio==9.8.4", "--dest", str(directory)], check=True)
    verify(directory)
