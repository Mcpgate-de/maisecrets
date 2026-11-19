"""No symlink, no submodule and no binary in the tree (scripts/tree_types.py, CI job tree_types).

Run: python3 -m unittest tests.test_tree_types -v
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import tree_types as T  # noqa: E402

GZ = b"\x1f\x8b\x08\x00" + b"\0" * 8
PNG = b"\x89PNG\r\n\x1a\n" + b"\0" * 8


class TreeTypesTests(unittest.TestCase):
    def test_the_tree_passes(self):
        entries = T.tracked()
        self.assertGreater(len(entries), 1000, "the premise: the tree")
        self.assertEqual(T.problems(entries), [])
        self.assertTrue(any(e[1].endswith(".gz") for e in entries), "the premise: binary results exist")

    def test_symlinks_submodules_and_other_binaries_are_refused(self):
        bad = [("120000", "bench/results/x/link.json", b""), ("160000", "vendor/sub", b""),
               ("100644", "maisecrets/blob.bin", b"MZ\0\0"), ("100644", "bench/results/x/a.json", b"{\0"),
               ("100644", "bench/results/x/fake.json.gz", b"PK\0\0"), ("100644", "maisecrets/icon.png", PNG),
               ("100644", "assets/icon.png", GZ), ("100664", "README.md", b"text"),
               # text under a gzip or PNG name: no NUL byte, and still no gzip or PNG
               ("100644", "bench/results/x/text.json.gz", b"not gzip text\n"), ("100644", "assets/icon.png", b"x"),
               ("100644", "bench/results/x/empty.json.gz", b"")]
        self.assertEqual(len(T.problems(bad)), len(bad), T.problems(bad))

    def test_data_binaries_and_text_pass(self):
        ok = [("100644", "bench/results/x/measured.json.gz", GZ), ("100644", "assets/icon.png", PNG),
              ("100644", "skills/secret-hygiene/assets/icon-large.png", PNG),
              ("100755", "scripts/x.sh", b"#!/bin/sh\n"), ("100644", "README.md", b"# maisecrets\n")]
        self.assertEqual(T.problems(ok), [])


if __name__ == "__main__":
    unittest.main()
