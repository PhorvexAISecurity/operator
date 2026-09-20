import ast
import json
from pathlib import Path
import unittest


HERE = Path(__file__).resolve().parent
SOURCE = HERE / "guardrail_proxy.py"


def load_reset_parser():
    tree = ast.parse(SOURCE.read_text(), filename=str(SOURCE))
    function = next(node for node in tree.body
                    if isinstance(node, ast.FunctionDef) and node.name == "_reset_success")
    module = ast.Module(body=[function], type_ignores=[])
    ast.fix_missing_locations(module)
    namespace = {"json": json, "RESET_RESPONSE_MAX_BYTES": 1 << 16}
    exec(compile(module, str(SOURCE), "exec"), namespace)
    return namespace["_reset_success"]


class ResetAcknowledgementParserTest(unittest.TestCase):
    parser = staticmethod(load_reset_parser())

    def test_preserves_true_and_false(self):
        self.assertIs(self.parser(b'{"success":true}'), True)
        self.assertIs(self.parser(b'{"success":false}'), False)

    def test_rejects_ambiguous_or_nonconfirming_responses(self):
        bad = (
            b"",
            b"{}",
            b'{"success":null}',
            b'{"success":"true"}',
            b'{"success":true,"success":false}',
            b'{"success":true,"SUCCESS":true}',
            b'{"success":true} trailing',
            b'{"success":true,"extension":NaN}',
            b"[]",
            b"x" * ((1 << 16) + 1),
        )
        for body in bad:
            with self.subTest(size=len(body)), self.assertRaises(ValueError):
                self.parser(body)


if __name__ == "__main__":
    unittest.main()
