"""A file sent as base64 is not scanned as text (0.6.15).

A Read of an image or a PDF returns the file as base64, and the client gives it to the model as an image or a
document block. The released code scanned the base64 as text: 1 MB took 10.9 s, a larger image ran into the
watchdog, and a chance hit inside the base64 would put a placeholder into the image. The payload shapes are the ones
Claude Code 2.1.296 sent (tests/client_payloads/claude-*-post.json, recorded by harness/probe_file_reads.py on the
research branch of the epic, commit a5c533d; each base64 body there keeps its first 40 characters).

Run: python3 -m unittest tests.test_binary_payloads -v
"""
from __future__ import annotations

import base64
import copy
import json
import os
import random
import string
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402  first: a temp vault home, never the real one
Path(_isolate.HOME).mkdir(parents=True, exist_ok=True)
Path(_isolate.HOME, "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

from maisecrets import hooks  # noqa: E402

PAYLOADS = Path(__file__).resolve().parent / "client_payloads"
_R = random.Random(1506)
PNG = b"\x89PNG\r\n\x1a\n"
PDF = b"%PDF-1.4\n"
JPEG = b"\xff\xd8\xff\xe0"


def recorded(name: str) -> dict:
    p = json.loads((PAYLOADS / f"claude-{name}-post.json").read_text(encoding="utf-8"))
    p["session_id"] = "s-binary-" + name
    p["tool_use_id"] = "t-" + name
    return p


def akid() -> str:
    return "AK" + "IA" + "".join(_R.choice(string.ascii_uppercase + "234567") for _ in range(16))


def glpat() -> str:
    return "gl" + "pat-" + "".join(_R.choice(string.ascii_letters + string.digits) for _ in range(20))


def body(magic: bytes, size: int = 3000, plant: str = "") -> str:
    """Base64 of a file that starts with `magic`; `plant` (base64 characters) replaces a slice in the middle, between
    two slashes, so a rule that wants a word boundary sees one."""
    b = base64.b64encode(magic + os.urandom(size)).decode()
    if plant:
        mid = (len(b) // 2) // 4 * 4
        cut = "/" + plant + "/"
        b = b[:mid] + cut + b[mid + len(cut):]
    return b


def withheld(answer: dict):
    return answer.get("hookSpecificOutput", {}).get("updatedToolOutput")


class ReadOfAFileAsBase64Tests(unittest.TestCase):
    def test_the_base64_of_an_image_is_left_as_it_is_also_with_a_key_shape_in_it(self):
        p = recorded("read-png")
        p["tool_response"]["file"]["base64"] = body(PNG, plant=akid())
        self.assertEqual(hooks.post_tool(p), {}, "no placeholder inside the image")

    def test_the_base64_of_a_pdf_is_left_as_it_is_and_its_other_fields_are_scanned(self):
        p = recorded("read-pdf")
        b64 = body(PDF, plant=akid())
        p["tool_response"]["file"]["base64"] = b64
        self.assertEqual(hooks.post_tool(copy.deepcopy(p)), {})
        token = glpat()
        p["tool_response"]["file"]["filePath"] = f"/tmp/{token}/hello.pdf"
        out = withheld(hooks.post_tool(p))
        self.assertIsNotNone(out, "the path is text and is scanned as before")
        self.assertNotIn(token, json.dumps(out))
        self.assertEqual(out["file"]["base64"], b64, "the file itself is unchanged")

    def test_the_pages_of_a_pdf_read_as_images_are_left_as_they_are(self):
        p = recorded("read-pdf-pages")
        p["tool_response"]["pages"][0]["base64"] = body(JPEG, plant=akid())
        self.assertEqual(hooks.post_tool(p), {})

    def test_a_value_this_session_resolved_is_still_matched_in_the_base64(self):
        # as before the change: the exact match of a stored value runs on the file too (only the shape scan is left
        # out), so a resolved value written raw into an uncompressed PDF is caught where its base64 form aligns
        from maisecrets import vault as vault_mod
        hooks._live_cache.clear()
        self.addCleanup(hooks._live_cache.clear)
        raw = "Zq7k-Pdf-" + "".join(_R.choice(string.ascii_letters) for _ in range(12))
        v = vault_mod.Vault()
        e = v.put(raw, "SECRET", "manual", session="s-binary-read-pdf")
        self.addCleanup(v.forget, e.key)
        self.assertEqual(v.record_resolve(e.key, "s-binary-read-pdf", "Bash", "{}"), "ok")
        p = recorded("read-pdf")
        pdf = b"%PDF-1.4\n%%(" + raw.encode() + b") Tj\n"            # 12 bytes before the value: aligned
        p["tool_response"]["file"]["base64"] = base64.b64encode(pdf).decode()
        out = withheld(hooks.post_tool(p))
        self.assertIsNotNone(out)
        self.assertNotIn(base64.b64encode(raw.encode()).decode().rstrip("="), json.dumps(out))
        self.assertIn(e.ref, out["file"]["base64"])

    def test_a_1_mb_image_is_checked_in_under_a_second(self):
        # released code: 1 MB took 10.9 s; from about 1.5 MB the watchdog withheld the image
        p = recorded("read-png")
        p["tool_response"]["file"]["base64"] = body(PNG, size=750 * 1024)
        started = time.perf_counter()
        hooks.post_tool(p)
        self.assertLess(time.perf_counter() - started, 1.0)

    def test_a_text_read_and_another_tool_with_the_same_shape_are_scanned(self):
        token = glpat()
        for tool, resp in (("Read", {"type": "text", "file": {"filePath": "/tmp/a.txt", "content": token}}),
                           ("mcp__files__get", {"type": "image", "file": {"base64": token}})):
            with self.subTest(tool):
                p = recorded("read-png")
                p["tool_name"], p["tool_response"] = tool, resp
                out = withheld(hooks.post_tool(p))
                self.assertIsNotNone(out)
                self.assertNotIn(token, json.dumps(out))


class BashImageOutputTests(unittest.TestCase):
    def run_bash(self, stdout: str, is_image: bool, stderr: str = ""):
        p = recorded("bash-datauri")
        p["tool_response"].update({"stdout": stdout, "stderr": stderr, "isImage": is_image})
        return withheld(hooks.post_tool(p))

    def test_an_image_the_client_sends_as_an_image_is_left_as_it_is(self):
        self.assertIsNone(self.run_bash("data:image/png;base64," + body(PNG, plant=akid()), True))

    def test_its_stderr_is_still_scanned(self):
        token = glpat()
        image = "data:image/png;base64," + body(PNG)
        out = self.run_bash(image, True, stderr=f"warning: {token}\n")
        self.assertIsNotNone(out)
        self.assertNotIn(token, json.dumps(out))
        self.assertEqual(out["stdout"], image)

    def test_a_data_uri_prefix_does_not_switch_off_the_redaction(self):
        # the client sets isImage from the text prefix, which an agent can print in front of anything
        kid = akid()
        for stdout, is_image in (("data:image/png;base64," + glpat(), False),
                                 ("data:image/png;base64," + glpat(), True),
                                 ("data:image/png;base64," + kid, True),                   # base64 letters, no PNG
                                 ("data:image/png;base64," + body(PNG) + "\n" + glpat(), True),
                                 ("data:image/jpeg;base64," + body(PNG, plant=kid), True),  # type and magic differ
                                 ("data:image/png;base64," + body(PNG, plant=kid), False)):
            with self.subTest(stdout[:30], is_image=is_image):
                out = self.run_bash(stdout, is_image)
                self.assertIsNotNone(out, "the output is scanned")
                self.assertIn("⟦", out["stdout"])


if __name__ == "__main__":
    unittest.main()
