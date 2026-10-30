"""The vendored rules agree with their version files (scripts/check_vendored_rules.py)."""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import check_vendored_rules as cvr  # noqa: E402


class VendoredRulesTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="vendored-rules-"))
        shutil.copytree(ROOT / cvr.RULES, self.root / cvr.RULES)
        self.rules = self.root / cvr.RULES

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_the_committed_rules_agree_with_their_versions(self):
        self.assertEqual(cvr.problems(ROOT), [])

    def test_a_version_file_moved_alone_is_refused(self):
        # a version moved without its rules (a sync that did not run): it must not pass the pipeline
        for name, new in (("PRESIDIO_VERSION", "9.9.999"), ("DETECT_SECRETS_VERSION", "v9.9.9")):
            with self.subTest(name):
                saved = (self.rules / name).read_text(encoding="utf-8")
                (self.rules / name).write_text(new + "\n", encoding="utf-8")
                self.assertTrue(any(name in p for p in cvr.problems(self.root)), cvr.problems(self.root))
                (self.rules / name).write_text(saved, encoding="utf-8")
        self.assertEqual(cvr.problems(self.root), [])

    def test_a_symlink_or_broken_json_from_the_artifact_is_refused(self):
        target = self.rules / "presidio.json"
        target.unlink()
        try:
            os.symlink(ROOT / "scripts" / "check_vendored_rules.py", target)
        except OSError:                      # Windows without the symlink privilege
            symlinked = False
        else:
            symlinked = True
            self.assertIn("presidio.json: not a regular file", cvr.problems(self.root))
            target.unlink()
        target.write_text("{broken", encoding="utf-8")
        self.assertTrue(any(p.startswith("presidio.json: no JSON") for p in cvr.problems(self.root)))
        if not symlinked and os.name != "nt":
            self.fail("a symlink could not be made outside Windows")

    def test_a_betterleaks_json_without_rules_is_refused(self):
        (self.rules / "betterleaks.json").write_text(json.dumps({"title": "x"}), encoding="utf-8")
        self.assertIn("betterleaks.json: no rules", cvr.problems(self.root))


if __name__ == "__main__":
    unittest.main()


class PresidioPatternsCompileTests(unittest.TestCase):
    """Presidio runs the `regex` package and maisecrets runs `re`: a pattern `re` refuses raised in every scan, and a
    sync (2.2.365) turned the whole suite red without naming the rule."""

    def setUp(self):
        sys.path.insert(0, str(ROOT))
        from maisecrets.detection import core
        self.core = core
        data = json.loads((ROOT / cvr.RULES / "presidio.json").read_text(encoding="utf-8"))
        self.regions = tuple(sorted({core.presidio_region(r["id"]) for r in data["recognizers"]}))

    def test_every_presidio_pattern_of_every_region_compiles(self):
        import re
        rules = self.core._load_presidio(self.regions)
        self.assertGreater(len(rules), 100)
        for rule in rules:
            with self.subTest(rule.id):
                re.compile(rule.regex.pattern)

    def test_a_consumed_label_is_no_part_of_the_hit(self):
        consumed = self.core.PRESIDIO_LABEL_CONSUMED
        rules = [r for r in self.core._load_presidio(("us",)) if r.id.split("#")[0] in consumed]
        self.assertTrue(any(r.secret_group for r in rules))
        n = "".join(str((7 * i + 3) % 10) for i in range(8))
        for text, value in ((f"claim number: {n} was paid", n), (f"referral no. REF-{n[:7]}", f"REF-{n[:7]}"),
                            (f"prior auth #: PA-{n[:7]}", f"PA-{n[:7]}")):
            with self.subTest(text):
                self.assertEqual([m.value for m in self.core.scan(text, channel="tool", rule_list=rules)], [value])
