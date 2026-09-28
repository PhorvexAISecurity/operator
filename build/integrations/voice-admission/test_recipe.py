import shutil
import copy
import tempfile
import unittest
from pathlib import Path

from prepare_wheelhouse import FILENAME, verify
from verify_tag_absent import verify as verify_absent


class TagAbsenceTest(unittest.TestCase):
    def test_only_exact_ecr_image_not_found_admits_publication(self):
        tag = "voice-admission-" + "a" * 40
        absent = {"images": [], "failures": [{"imageId": {"imageTag": tag}, "failureCode": "ImageNotFound",
                                               "failureReason": "Requested image not found"}]}
        verify_absent(absent, tag)
        for code in ("ServerException", "AccessDenied", "RepositoryNotFound", "not found"):
            changed = copy.deepcopy(absent)
            changed["failures"][0]["failureCode"] = code
            with self.assertRaises(ValueError):
                verify_absent(changed, tag)
        for changed in ({"images": [{}], "failures": []}, {"images": [], "failures": []},
                        {"error": "DNS not found"}, {"error": "docker: command not found"},
                        {"images": [], "failures": [{"imageId": {"imageTag": "foreign"}, "failureCode": "ImageNotFound"}]}):
            with self.assertRaises(ValueError):
                verify_absent(changed, tag)


class WheelClosureTest(unittest.TestCase):
    def test_exact_official_wheel_and_contamination_or_tampering(self):
        source = Path(__file__).parent / "wheelhouse" / FILENAME
        if not source.exists():
            self.skipTest("prepare_wheelhouse.py must download the pinned official wheel first")
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            wheel = directory / FILENAME
            shutil.copyfile(source, wheel)
            verify(directory)
            extra = directory / "other.whl"
            extra.write_bytes(b"unreviewed")
            with self.assertRaises(ValueError):
                verify(directory)
            extra.unlink()
            data = bytearray(wheel.read_bytes())
            data[-1] ^= 1
            wheel.write_bytes(data)
            with self.assertRaises(ValueError):
                verify(directory)
