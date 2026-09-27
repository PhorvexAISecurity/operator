"""Check the fixed embedded benign speech oracle without a cluster or model."""

import ast
import pathlib
import re
import unittest


def load_oracle():
    source = pathlib.Path(__file__).with_name("voice_output_probe.py")
    parsed = ast.parse(source.read_text())
    functions = [node for node in parsed.body if isinstance(node, ast.FunctionDef) and node.name == "benign_semantic"]
    if len(functions) != 1:
        raise AssertionError("fixed benign oracle missing")
    scope = {"re": re}
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(source), "exec"), scope)
    return scope["benign_semantic"]


class BenignSemanticOracleTests(unittest.TestCase):
    def test_fixed_public_reply_and_refusals(self):
        oracle = load_oracle()
        self.assertTrue(oracle("I can help with public information about our services."))
        for value in ("I cannot help with public information.", "Sorry, I can help with public information.",
                      "I don't help with public information.", "I can help with private records.",
                      "I cannot answer that right now. Please try again later.", "", 3):
            self.assertFalse(oracle(value), repr(value))


if __name__ == "__main__":
    unittest.main()
