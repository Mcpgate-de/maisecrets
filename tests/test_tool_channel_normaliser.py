"""The tool channel also looks through terminal and encoding disguises: an ANSI colour code or a zero-width character
inside a token, HTML entities, fullwidth letters, and a base64 or hex run that encodes text with a value in it. A hit
redacts the original span, hidden characters included; a value inside a decoded run takes the whole run. A typed
prompt keeps its decisions.

Adapted from a public fork of maisecrets (Apache-2.0, see NOTICE).

Run: python3 -m unittest tests.test_tool_channel_normaliser -v
Every value is built at run time from parts, so no literal sits in the tree and the tree scan stays clean.
"""
from __future__ import annotations

import base64
import gzip
import os
import random
import string
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect, normalise  # noqa: E402

RNG = random.Random(4)
TOKEN = "gh" + "p_" + "".join(RNG.choice(string.ascii_letters + string.digits) for _ in range(36))
PASSWORD = "Qz8" + "".join(RNG.choice(string.ascii_letters + string.digits) for _ in range(13))
ZW = "​"
ESC = "\x1b"


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def spans(text: str, channel: str = "tool") -> list[tuple[str, str]]:
    return [(m.type, text[m.start:m.end]) for m in detect.scan(text, channel=channel)]


class DisguiseTests(unittest.TestCase):
    def test_each_disguise_hides_a_token_from_the_raw_scan_but_not_from_the_tool_channel(self):
        cases = {
            "zero-width": TOKEN[:10] + ZW + TOKEN[10:],
            "ansi": TOKEN[:10] + ESC + "[31m" + TOKEN[10:] + ESC + "[0m",
            "entity": "".join("&#%d;" % ord(c) if i < 4 else c for i, c in enumerate(TOKEN)),
            "fullwidth": "".join(chr(ord(c) + 0xFEE0) for c in TOKEN),
            "hex": TOKEN.encode().hex(),
            "zero-width as an entity": TOKEN[:12] + "&#8203;" + TOKEN[12:],
            "soft hyphen as an entity": TOKEN[:12] + "&shy;" + TOKEN[12:],
            "ansi as an entity": TOKEN[:12] + "&#27;[1m" + TOKEN[12:],
        }
        for name, disguised in cases.items():
            with self.subTest(name=name):
                text = f"token {disguised} end"
                self.assertEqual(spans(text, "prompt"), [], "a typed prompt keeps its decision")
                got = spans(text)
                self.assertEqual(len(got), 1, got)
                self.assertEqual(got[0][0], "SECRET")
                # the span is the original text: the hidden characters go with the value
                self.assertTrue(got[0][1].startswith(disguised[:4]), name)
                self.assertNotIn(got[0][1], ("token", "end"))
                self.assertIn(got[0][1].rstrip(ESC + "[0m"), disguised)

    def test_a_value_in_a_base64_run_takes_the_whole_run(self):
        for name, plain in (("url", f"postgres://app:{PASSWORD}@db.example.com/app"),
                            ("label", f"password={PASSWORD}\nuser=app\n")):
            with self.subTest(name=name):
                run = b64(plain)
                text = f"data:\n  config: {run}\n"
                self.assertEqual(spans(text, "prompt"), [])
                self.assertEqual(spans(text), [("SECRET", run)])

    def test_gzip_inside_base64_is_opened(self):
        run = base64.b64encode(gzip.compress(f"password={PASSWORD}\n".encode())).decode()
        self.assertEqual(spans(f"blob: {run}"), [("SECRET", run)])

    def test_a_disguised_value_far_down_a_long_output_is_found(self):
        lines = [f"10:00:{i % 60:02d} INFO request {i} ok" for i in range(2000)]
        lines[1500] = f"10:25:00 INFO token {TOKEN[:12]}{ZW}{TOKEN[12:]}"
        got = spans("\n".join(lines))
        self.assertEqual([t for t, _ in got], ["SECRET"])

    def test_a_context_word_lines_away_still_counts_for_a_disguised_value(self):
        # a card number needs a card word within 80 characters; the word stands two short lines above (Gate A)
        body = "4929" + "".join(RNG.choice(string.digits) for _ in range(11))
        total = 0
        for i, ch in enumerate(reversed(body)):
            d = int(ch)
            if i % 2 == 0:
                d = d * 2 - 9 if d * 2 > 9 else d * 2
            total += d
        card = body + str((10 - total % 10) % 10)
        grouped = " ".join(card[i:i + 4] for i in range(0, 16, 4))
        disguised = grouped[:6] + ESC + "[31m" + grouped[6:] + ESC + "[0m"
        text = "card\nx\n" + disguised + "\n"
        self.assertEqual(spans("card\nx\n" + grouped + "\n"), [("CARD", grouped)], "the raw text")
        self.assertEqual([t for t, _ in spans(text)], ["CARD"])
        # a line that held only ANSI codes pushed the word out of reach of the raw scan (Gate A, round 2)
        for gap in ("card\n" + (ESC + "[31m") * 20 + "\n", "card " + (ESC + "[31m") * 20 + "\n"):
            with self.subTest(gap=len(gap)):
                self.assertEqual([t for t, _ in spans(gap + grouped + "\n")], ["CARD"])

    def test_a_rule_that_reads_lines_back_still_sees_its_label(self):
        # an AWS secret may follow its key id four lines of up to 400 characters later (Gate A, round 3)
        key_id = "AK" + "IA" + "".join(RNG.choice(string.ascii_uppercase + "234567") for _ in range(16))
        secret = "".join(RNG.choice(string.ascii_letters + string.digits + "/+") for _ in range(40))
        gap = ("x" * 380 + "\n") * 3   # longer than the old 512 characters of context, within the rule's reach
        plain = key_id + "\n" + gap + secret + "\n"
        disguised = key_id + "\n" + gap + secret[:20] + ZW + secret[20:] + "\n"
        want = [k for k, _ in spans(plain)]
        self.assertEqual(len(want), 2, want)
        self.assertEqual([k for k, _ in spans(disguised)], want)

    def test_text_without_a_value_stays_text(self):
        cases = {
            "encoded prose": "note: " + b64("the retry timeout of the client is 200 ms, see the docs"),
            "html": "<p>Tom &amp; Jerry &quot;quoted&quot; caf&eacute; &#169; 2026</p>\n" * 20,
            "coloured test run": (ESC + "[32mPASSED" + ESC + "[0m tests/test_auth.py::test_token_refresh\n") * 30,
            "zero-width prose": f"Bitte{ZW} lies{ZW} die Doku zum Retry.",
            "hex of prose": "payload " + "a short note about the retry timeout".encode().hex(),
            "fullwidth word": "".join(chr(ord(c) + 0xFEE0) for c in "Note: test only"),
        }
        for name, text in cases.items():
            with self.subTest(name=name):
                self.assertEqual(spans(text), [])

    def test_the_raw_hits_keep_their_spans(self):
        text = f"a {TOKEN} b {TOKEN[:10]}{ZW}{TOKEN[10:]} c"
        got = detect.scan(text, channel="tool")
        self.assertEqual([(m.start, m.end) for m in got],
                         [(2, 2 + len(TOKEN)), (5 + len(TOKEN), 5 + 2 * len(TOKEN) + 1)])


class NormaliseTests(unittest.TestCase):
    def test_an_unchanged_text_is_the_same_object(self):
        text = "plain ascii text with no disguise"
        self.assertIs(normalise.normalise(text).text, text)

    def test_the_map_leads_back_to_the_original_range(self):
        text = "ab" + ESC + "[1mcd" + ZW + "ef &amp; g"
        n = normalise.normalise(text)
        self.assertEqual(n.text, "abcdef & g")
        a = n.text.index("cd")
        self.assertEqual(text[slice(*n.span(a, a + 4))], "cd" + ZW + "ef")
        amp = n.text.index("&")
        self.assertEqual(text[slice(*n.span(amp, amp + 1))], "&amp;")

    def test_the_decode_stage_is_bounded(self):
        big = "x " * (normalise.MAX_TEXT // 2 + 1) + b64(f"password={PASSWORD}")
        self.assertIs(normalise.normalise(big, ("decode",)).text, big)
        coloured = ESC + "[1m" + big   # every stage stops at MAX_TEXT: a second scan of 1 MB costs seconds
        self.assertIs(normalise.normalise(coloured).text, coloured)
        long_run = b64("a" * (normalise.MAX_RUN))
        self.assertIsNone(normalise.decode_run(long_run))
        self.assertIsNone(normalise.decode_run(b64("short")))
        mixed = "abcdefghij+/klmnopqrstuv-_wxyz0123"
        self.assertIsNone(normalise.decode_run(mixed), "two alphabets mixed is no encoding")

    def test_the_decode_budget_stops_at_its_candidates_and_bytes(self):
        runs = [b64(f"note number {i:03d} of the retry docs") for i in range(normalise.MAX_CANDIDATES + 5)]
        out = normalise.normalise("\n".join(runs), ("decode",)).text.split("\n")
        decoded = sum(1 for line in out if line.startswith("note number"))
        self.assertEqual(decoded, normalise.MAX_CANDIDATES)
        chunk = "w" * 3000
        big = [b64(chunk + str(i)) for i in range(normalise.MAX_DECODED // 3000 + 5)]
        out = normalise.normalise("\n".join(big), ("decode",)).text.split("\n")
        self.assertLessEqual(sum(len(line) for line in out if line.startswith("w")), normalise.MAX_DECODED)
        self.assertTrue(any(not line.startswith("w") for line in out), "the bytes budget ends the decoding")

    def test_an_unknown_stage_is_refused(self):
        with self.assertRaises(ValueError):
            normalise.normalise("x", ("unwrap",))


if __name__ == "__main__":
    unittest.main()
