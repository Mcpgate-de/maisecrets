"""The rule registry (maisecrets/registry.py): every rule has a spec, a unique key and a unique rank, and the register
order is the order of detect.rules().

Run: python3 -m unittest tests.test_registry -v
"""
from __future__ import annotations

import collections
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect, registry  # noqa: E402


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.specs = detect.rule_specs()

    def test_the_register_order_is_the_order_of_the_rule_list(self):
        self.assertEqual([(s.id, s.type) for s, _ in self.specs], [(r.id, r.type) for r in detect.rules()])
        self.assertEqual([s.priority for s, _ in self.specs], sorted(s.priority for s, _ in self.specs))

    def test_each_rule_has_a_unique_key_and_a_unique_rank(self):
        keys = [s.key for s, _ in self.specs]
        self.assertEqual([k for k, n in collections.Counter(keys).items() if n > 1], [])
        self.assertEqual(len({s.priority for s, _ in self.specs}), len(self.specs))

    def test_three_ids_are_loaded_twice_and_keep_their_id(self):
        # the id is stored data (the vault index, the event log); the key tells the two rules apart
        twice = {i for i, n in collections.Counter(s.id for s, _ in self.specs).items() if n > 1}
        self.assertEqual(twice, {"mailchimp-api-key", "new-relic-insert-key", "flutterwave-secret-key"})
        for rid in twice:
            self.assertEqual(len({s.key for s, _ in self.specs if s.id == rid}), 2)

    def test_a_key_enables_one_of_two_rules_with_the_same_id_and_the_id_enables_both(self):
        import random
        r = random.Random(5)
        tok = "".join(r.choice("0123456789abcdef") for _ in range(32)) + "-us" + "7"
        text = f"key {tok} here"
        rules = [x for x in detect.rules() if x.id == "mailchimp-api-key"]
        self.assertEqual(sorted(x.key for x in rules),
                         ["betterleaks:mailchimp-api-key", "own-secret:mailchimp-api-key"])
        by_key = {k: detect.scan(text, enabled={k}) for k in (x.key for x in rules)}
        by_id = detect.scan(text, enabled={"mailchimp-api-key"})
        self.assertTrue(by_id and by_id[0].kind == "mailchimp-api-key")
        self.assertIn(by_id, list(by_key.values()))               # the id runs both; the first one takes the span
        self.assertEqual(detect.scan(text, enabled={"betterleaks:no-such-rule"}), [])
        for rule in detect.rules():
            self.assertTrue(rule.key, rule.id)                    # rules() gives every rule its key

    def test_a_rule_list_a_caller_built_runs_each_rule_as_the_registry_does(self):
        # scan(rule_list=...) and tests pass rules that rules() did not mark; the fallback must name the same matcher
        literal = {d["id"] for d in detect.LITERAL_RULES}
        for spec, rule in self.specs:
            with self.subTest(rule=spec.key):
                self.assertEqual(spec.matcher, registry.matcher_of(rule.id, "literal" if rule.id in literal else ""))
        self.assertEqual(collections.Counter(s.matcher for s, _ in self.specs)["lines"], 7)

    def test_each_named_filter_is_one_that_scan_runs(self):
        source = (ROOT / "maisecrets" / "detect.py").read_text(encoding="utf-8")
        names = {n for ns in registry.FILTERS.values() for n in ns} | {n for _, ns in registry.PREFIX_FILTERS
                                                                     for n in ns} | {"derived-label"}
        for name in sorted(names):
            with self.subTest(filter=name):
                self.assertIn(f'"{name}" in filters', source)
        for spec, rule in self.specs:
            self.assertEqual(rule.filters, registry.filters_of(rule.id))
            self.assertEqual(spec.filters, rule.filters)

    def test_each_correction_of_a_vendored_rule_names_the_upstream_rule_it_was_written_against(self):
        """After a sync that changes a corrected upstream rule this goes red: check the correction against the new
        rule, then update rules/patched_upstream.txt or drop the correction."""
        import json
        recorded = registry.patched_upstream(detect.RULES_DIR)
        upstream = {r["id"]: r for r in json.loads((detect.RULES_DIR / "betterleaks.json").read_text("utf-8"))["rules"]}
        self.assertEqual(set(recorded), {"betterleaks:" + i for i in detect.BETTERLEAKS_PATCHES})
        for key, digest in recorded.items():
            with self.subTest(rule=key):
                self.assertEqual(registry.canonical_sha256(upstream[key.split(":", 1)[1]]), digest)
        specs = {s.key: s for s, _ in self.specs}
        for rid in detect.BETTERLEAKS_PATCHES:
            spec = specs["betterleaks:" + rid]
            self.assertEqual(spec.origin, "patched")
            self.assertTrue(spec.patches and all(p.upstream_sha256 == spec.upstream.sha256 for p in spec.patches))

    def test_a_vendored_rule_names_its_upstream_and_a_corrected_one_its_patches(self):
        for spec, _ in self.specs:
            with self.subTest(rule=spec.key):
                vendored = spec.source in registry.VENDORED
                self.assertEqual(spec.upstream is not None, vendored)
                self.assertEqual(spec.origin == "patched", vendored and bool(spec.patches))
        specs = {s.key: s for s, _ in self.specs}
        self.assertIn(("validator", "set", "de_tax_id"), [(p.field, p.op, p.value)
                                                          for p in specs["presidio:de-tax-id"].patches])
        self.assertIn("context_rule", [p.field for p in specs["presidio:de-vat-id#0"].patches])

    def test_the_passes_outside_the_rule_list_have_their_phase_and_channel(self):
        passes = detect.pass_specs()
        keys = [s.key for s in passes] + [s.key for s, _ in self.specs]
        self.assertEqual(len(keys), len(set(keys)))
        export = [s for s in passes if s.source == "export"]
        self.assertEqual([(s.id, s.priority[0], s.channel) for s in export], [(detect.EXPORT_RULE, 0, "tool")])
        personal = [s for s in passes if s.source == "personal"]
        self.assertTrue(personal)
        for s in personal:
            self.assertEqual(s.priority[0], registry.PHASES["personal"])
            self.assertEqual(s.channel, "both" if s.id == "phone-one-digit-groups" else "tool")
        # the rules of your own run after the personal-data step: their phase is after it
        self.assertGreater(registry.PHASES["user"], registry.PHASES["personal"])
        self.assertTrue(all(r.phase == registry.PHASES["rules"] for r in detect.rules()))

    def test_every_source_has_its_band_and_the_bands_keep_the_measured_order(self):
        self.assertEqual({s.source for s, _ in self.specs}, set(registry.SOURCES) - {"user"})
        bands = [registry.BANDS[x] for x in registry.SOURCES]
        self.assertEqual(bands, sorted(bands))
        for s, _ in self.specs:
            self.assertEqual(s.priority[1], registry.BANDS[s.source])

    def test_the_form_is_the_one_of_the_old_id_prefixes(self):
        for s, _ in self.specs:
            with self.subTest(rule=s.key):
                self.assertEqual(s.form != "shape", s.id.startswith(detect.LABEL_RULES))
                self.assertEqual(s.form == "keyword", s.id.startswith(detect.KEYWORD_RULES))

    def test_a_presidio_or_regional_rule_names_its_region(self):
        active = detect.active_regions().regions
        for spec, rule in self.specs:
            self.assertEqual(spec.region, rule.region)          # the loader set it once; the spec reads the rule
            self.assertIn(rule.region, active)
            if spec.source == "presidio":
                self.assertEqual(rule.region, detect.presidio_region(rule.id.split("#", 1)[0]))
        regions = {s.region for s, _ in self.specs if s.source in ("regional", "presidio")}
        self.assertIn("de", regions)          # the test locale is de_DE: the German rules are on
        self.assertTrue(all(s.region == "generic" for s, _ in self.specs
                            if s.source not in ("regional", "presidio")))


if __name__ == "__main__":
    unittest.main()
