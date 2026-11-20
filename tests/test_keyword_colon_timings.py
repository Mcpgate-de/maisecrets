"""ds-keyword-colon and a list of timings (#92).

A log line of hook timings such as `timings=a:1.0,secret_shape_scan:12.3,response_size_tier:1.4` put the label
`secret` (the start of the field name) before the value `12.3,response_size_tier:1.4`. The value of the rule ends
only at a quote or a line break, so it ran over the comma into the next field and read as a credential. A number and
then one or more `,name:number` fields are a list of fields, not a value. A labelled random value stays a hit, also
one with a comma and a colon in it.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect  # noqa: E402


def J(parts: list) -> str:
    """Joined at run time, so the scan of the tree does not take a test literal for a secret."""
    return "".join(parts)


def keyword_hits(text: str, channel: str) -> list:
    return [(m.kind, m.value) for m in detect.scan(text, channel=channel) if m.kind.startswith("ds-keyword")]


class TimingListTests(unittest.TestCase):
    NO_VALUE = [
        "timings=a:1.0," + J(["sec", "ret_shape_scan:12.3,response_size_tier:1.4"]),    # the four texts of #92
        "timings=" + J(["sec", "ret_scan:12.3,x:1.4"]),
        "timings=a:1.0," + J(["sec", "ret_shape_scan:12.3"]),
        "timings=a:1.0," + J(["sec", "ret_shape_scan:12.3, response_size_tier:1.4"]),
        J(["sec", "ret_scan:7,x:1,y:22.5,z.total:3"]),                                  # an integer, more fields
        "hook done " + J(["pass", "word_check:0.4,mask_ms:12,store-write:3.0"]),
    ]
    VALUE = [
        ("client_" + J(["sec", "ret:"]) + J(["Zq8", "Lr2Wv5Tn9Kc4Hx7Bm3Pd6Fs1Jy0Ag5Qe8Ru2Ow"]),
         J(["Zq8", "Lr2Wv5Tn9Kc4Hx7Bm3Pd6Fs1Jy0Ag5Qe8Ru2Ow"])),
        (J(["pass", "word:"]) + J(["Xq7v", ",Pz9k:44"]), J(["Xq7v", ",Pz9k:44"])),   # a comma and a colon in a value
        (J(["pass", "word:"]) + J(["hunter", "2,x:1"]), J(["hunter", "2,x:1"])),
        (J(["sec", "ret:"]) + J(["12.3", ",abc"]), J(["12.3", ",abc"])),                  # no field after the comma
    ]

    def test_a_list_of_timings_after_a_secret_field_name_is_no_value(self):
        for text in self.NO_VALUE:
            for channel in ("prompt", "tool"):
                with self.subTest(text=text, channel=channel):
                    self.assertEqual(keyword_hits(text, channel), [])

    def test_a_labelled_value_stays_a_hit(self):
        for text, value in self.VALUE:
            for channel in ("prompt", "tool"):
                with self.subTest(text=text, channel=channel):
                    self.assertIn(("ds-keyword-colon", value), keyword_hits(text, channel))


if __name__ == "__main__":
    unittest.main()
