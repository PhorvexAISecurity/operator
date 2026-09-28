"""Exercise the pinned CLI/SDK without credentials, AWS access or an image build."""
import importlib.metadata
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading
import unittest

from verify_tag_absent import verify

TAG = "voice-admission-" + "a" * 40


class PublisherToolsTest(unittest.TestCase):
    def test_job_local_cli_and_exact_dependency_versions(self):
        executable = Path(sys.prefix) / "bin/aws"
        self.assertEqual(Path(shutil.which("aws")).resolve(), executable.resolve())
        self.assertNotEqual(sys.prefix, sys.base_prefix)
        lock = Path(__file__).with_name("publisher-requirements.lock").read_text()
        for line in lock.splitlines():
            if line.startswith("#"):
                continue
            match = re.fullmatch(r"([A-Za-z0-9_-]+)==([0-9A-Za-z.]+) --hash=sha256:([0-9a-f]{64})", line)
            self.assertIsNotNone(match)
            self.assertEqual(importlib.metadata.version(match[1]), match[2])
        result = subprocess.run([str(executable), "--version"], capture_output=True, text=True, check=True, timeout=10)
        self.assertRegex(result.stdout + result.stderr, r"aws-cli/1\.46\.1\b")
        self.assertRegex(result.stdout + result.stderr, r"botocore/1\.43\.62\b")

    def test_actual_ecr_sdk_requires_structured_absence_and_fails_on_service_error(self):
        requests = []
        class Handler(BaseHTTPRequestHandler):
            status = 200
            payload = {"images": [], "failures": [{"imageId": {"imageTag": TAG}, "failureCode": "ImageNotFound"}]}

            def do_POST(self):
                requests.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(self.status)
                self.send_header("Content-Type", "application/x-amz-json-1.1")
                self.end_headers()
                self.wfile.write(json.dumps(self.payload).encode())

            def log_message(self, *_):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        environment = dict(os.environ, AWS_ACCESS_KEY_ID="offline-test", AWS_SECRET_ACCESS_KEY="offline-test",
                           AWS_EC2_METADATA_DISABLED="true", AWS_MAX_ATTEMPTS="1", AWS_DEFAULT_REGION="us-east-2",
                           AWS_CONFIG_FILE=os.devnull, AWS_SHARED_CREDENTIALS_FILE=os.devnull)
        command = [str(Path(sys.prefix) / "bin/aws"), "ecr", "batch-get-image", "--repository-name", "phorvex",
                   "--image-ids", "imageTag=" + TAG, "--output", "json", "--endpoint-url",
                   "http://127.0.0.1:" + str(server.server_port)]
        result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        verify(json.loads(result.stdout), TAG)
        self.assertEqual(requests, [{"repositoryName": "phorvex", "imageIds": [{"imageTag": TAG}]}])
        Handler.status = 400
        Handler.payload = {"__type": "AccessDeniedException", "message": "offline denied"}
        result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
