"""PDFs and images the AI reads (maisecrets/file_reads.py, C26): the settings read_pdf and read_image, clean_dirs, and
the convert mode that sends a PDF as masked text.

The payloads are the goldens that harness/probe_file_reads.py recorded from Claude Code 2.1.296 (research commit
a5c533d). The measured rule that every test here leans on: only a text-shaped updatedToolOutput takes an image or a
PDF out of the request. A string, or a PDF-shaped object with an empty base64, fails open.
"""
from __future__ import annotations

import base64
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import file_reads, hooks, settings  # noqa: E402
from maisecrets.vault import HOME, load_config  # noqa: E402
import _hygiene  # noqa: E402

GOLDEN = ROOT / "harness" / "golden"
TEST_CONFIG = {"backend": "jsonfile", "allow_plaintext_store": True}
CONFIG = Path(HOME, "config.json")
HINTS = Path(HOME, "hints.json")
TOKEN = "glpat-" + "Rk4tW9xQ2mZ7vB3nL8pY"          # a token shape, built at run time (scan_tree)
REAL_PDFTOTEXT = shutil.which("pdftotext")


def tearDownModule():  # noqa: N802 - unittest hook
    _reset()
    _hygiene.assert_pristine()


def _reset(**user) -> None:
    CONFIG.write_text(json.dumps({**TEST_CONFIG, **user}))
    # the values a converted PDF stored, too: a later module must not find a live store (test_hooks_paths does this)
    for f in (HINTS, Path(HOME, "index.json"), Path(HOME, "vault.json"), Path(HOME, "audit.log"),
              Path(HOME, "hooks.log")):
        try:
            os.unlink(f)
        except FileNotFoundError:
            pass
    shutil.rmtree(Path(HOME, "sessions-seen"), ignore_errors=True)    # the session S1 starts anew
    hooks._live_cache.clear()


def pdf_bytes(*lines: str) -> bytes:
    """A one-page PDF with these lines in Helvetica, standard library only (the builder of harness/probe_file_reads.py,
    with more than one line)."""
    ops = b" ".join(b"BT /F1 12 Tf 72 %d Td (%s) Tj ET" % (720 - 20 * i, ln.encode("latin-1"))
                    for i, ln in enumerate(lines))
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
            b"/Resources << /Font << /F1 5 0 R >> >> >>",
            b"<< /Length %d >>\nstream\n" % len(ops) + ops + b"\nendstream",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    out = b"%PDF-1.4\n"
    offs = []
    for i, o in enumerate(objs, 1):
        offs.append(len(out))
        out += b"%d 0 obj\n" % i + o + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    out += b"".join(b"%010d 00000 n \n" % o for o in offs)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    return out


def golden(name: str, cwd: str, **swap) -> dict:
    """A recorded payload with its placeholders filled in; `file_path` moves the read to another file."""
    text = (GOLDEN / f"{name}.json").read_text()
    # JSON-escaped: a Windows path has backslashes
    text = text.replace("{cwd}", json.dumps(cwd)[1:-1]).replace("{session_id}", "S1").replace("{prompt_id}", "p1")
    p = json.loads(text)
    fp = swap.pop("file_path", None)
    if fp:
        p["tool_input"]["file_path"] = fp
        if isinstance(p.get("tool_response"), dict) and isinstance(p["tool_response"].get("file"), dict) \
                and "filePath" in p["tool_response"]["file"]:
            p["tool_response"]["file"]["filePath"] = fp
    p.update(swap)
    return p


def run_hook(event: str, payload: dict) -> dict:
    """The real entry point of the hooks, as dispatch.py calls it, with the JSON on stdin."""
    hooks._live_cache.clear()
    buf = io.StringIO()
    with mock.patch.object(sys, "stdin", io.StringIO(json.dumps(payload))), redirect_stdout(buf):
        rc = hooks.main(["hook", event])
    assert rc == 0, rc
    return json.loads(buf.getvalue()) if buf.getvalue() else {}


def output(answer: dict):
    return (answer.get("hookSpecificOutput") or {}).get("updatedToolOutput")


def said(answer: dict) -> str:
    """What the person reads after a typed setting: a block reason (Codex form) or the context of a slash command,
    which runs on and shows the card."""
    return answer.get("reason") or (answer.get("hookSpecificOutput") or {}).get("additionalContext") or ""


def decision(answer: dict) -> str | None:
    return (answer.get("hookSpecificOutput") or {}).get("permissionDecision")


class _Work(unittest.TestCase):
    """A work folder with a PDF and a PNG, and a bin folder for a stub pdftotext."""

    def setUp(self):
        _reset()
        self.dir = Path(tempfile.mkdtemp(prefix="file-reads-", dir=_isolate.TMP)).resolve()
        self.cwd = str(self.dir / "work")
        os.makedirs(self.cwd)
        self.pdf = os.path.join(self.cwd, "hello.pdf")
        Path(self.pdf).write_bytes(pdf_bytes("Invoice 2026", f"deploy token {TOKEN}"))
        self.png = os.path.join(self.cwd, "tiny.png")
        Path(self.png).write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 16)
        self.bin = self.dir / "bin"
        self.bin.mkdir()
        self.calls = self.dir / "calls.txt"
        # no pdftotext of this machine, unless a test puts the stub or the real one there
        p = mock.patch.dict(os.environ, {"PATH": str(self.bin)})
        p.start()
        self.addCleanup(p.stop)
        p2 = mock.patch.object(file_reads, "_EXTRA_DIRS", ())
        p2.start()
        self.addCleanup(p2.stop)
        self.addCleanup(shutil.rmtree, self.dir, True)

    def stub(self, body: str = None) -> None:
        """A pdftotext that notes its arguments and prints a text with a token in it."""
        if os.name == "nt":
            self.skipTest("the stub pdftotext is a shell script; the same code runs on macOS and Linux")
        body = body if body is not None else f"printf 'Invoice 2026\\ndeploy token {TOKEN}\\n\\f'"
        tool = self.bin / "pdftotext"
        tool.write_text(f"#!/bin/sh\necho \"$@\" >> '{self.calls}'\n{body}\n")
        tool.chmod(0o755)

    def post(self, name: str = "PostToolUse_Read_pdf", **swap) -> dict:
        return run_hook("post-tool", golden(name, self.cwd, **swap))

    def pre(self, name: str = "PreToolUse_Read_pdf_pages", **swap) -> dict:
        return run_hook("pre-tool", golden(name, self.cwd, **swap))


# ------------------------------------------------------------ the shape --
class TheMeasuredShape(unittest.TestCase):
    def test_the_text_result_is_the_shape_the_probe_measured(self):
        # the replace_text branch of the probe is the shape that removed the PDF and the image (model view golden)
        probe = (ROOT / "harness" / "probe_file_reads.py").read_text()
        branch = probe[probe.index('mode == "replace_text"'):probe.index('mode == "replace_pdf_obj"')]
        measured = re.findall(r'"(\w+)":', branch[branch.index('"file": {') + 9:])
        self.assertEqual(tuple(measured), file_reads.TEXT_KEYS)
        r = file_reads.text_result("/x/a.pdf", "one\ntwo")
        self.assertEqual(r["type"], "text")
        self.assertEqual(set(r), {"type", "file"})
        self.assertEqual(tuple(r["file"]), file_reads.TEXT_KEYS)
        self.assertEqual((r["file"]["numLines"], r["file"]["startLine"], r["file"]["totalLines"]), (2, 1, 2))
        view = json.loads((GOLDEN / "file_reads_model_view.json").read_text())
        self.assertEqual(view["pdf_replace_text"][0]["content"], "1\tPROBE-REPLACED-TEXT: withheld",
                         "the text shape reaches the model as text, without the document")
        self.assertEqual(view["pdf_replace_obj"][0]["content"][1]["type"], "document",
                         "a PDF-shaped answer with an empty base64 still sends the PDF: never answer with it")
        self.assertEqual(view["png_replace"][0]["content"][0]["type"], "image",
                         "a string answer fails open: never answer with it")


class OnlyTheTextShapeLeaves(_Work):
    """Every answer that stands in for a PDF or an image, in every mode, with or without pdftotext, is the text
    shape (Read) or a text Bash result. A string or a PDF shape would fail open."""

    def test_every_mode_and_every_payload(self):
        cases = (("PostToolUse_Read_pdf", {}), ("PostToolUse_Read_pdf_pages", {}),
                 ("PostToolUse_Read_png", {"file_path": self.png}),
                 ("PostToolUse_Read_pdf", {"file_path": os.path.join(self.cwd, "noext")}))
        seen = 0
        for tool_present in (True, False):
            if tool_present:
                self.stub()
            else:
                (self.bin / "pdftotext").unlink()
            for pdf_mode in file_reads.MODES["read_pdf"]:
                for img_mode in file_reads.MODES["read_image"]:
                    for name, swap in cases:
                        with self.subTest(tool=tool_present, pdf=pdf_mode, img=img_mode, payload=name, **swap):
                            _reset(read_pdf=pdf_mode, read_image=img_mode, tips=False)
                            out = output(self.post(name, **dict(swap)))
                            if out is None:
                                continue
                            seen += 1
                            self.assertIsInstance(out, dict, "a string fails open")
                            self.assertEqual(out["type"], "text")
                            self.assertEqual(tuple(out["file"]), file_reads.TEXT_KEYS)
                            self.assertNotIn("base64", json.dumps(out))
                            self.assertNotIn(TOKEN, json.dumps(out))
        self.assertGreater(seen, 20)

    def test_a_failure_in_the_redaction_withholds_with_the_text_shape(self):
        _reset(read_pdf="convert")
        self.stub()
        with mock.patch.object(hooks, "post_tool", side_effect=RuntimeError("boom")):
            out = output(self.post())
        self.assertEqual(out["type"], "text", "the fail-closed answer of a Read must not be a string")
        self.assertIn("withheld", out["file"]["content"])

    def test_the_watchdog_answer_of_a_read_is_the_text_shape(self):
        p = golden("PostToolUse_Read_pdf", self.cwd)
        out = output(hooks._fail_closed("post-tool", p, "took longer than 16s."))
        self.assertEqual(out["type"], "text")
        self.assertEqual(out["file"]["filePath"], self.pdf)
        self.assertIsInstance(output(hooks._fail_closed("post-tool", {"tool_name": "Bash"}, "x")), str,
                              "other tools keep their answer")


# ------------------------------------------------------------ the modes --
class Allow(_Work):
    def test_allow_passes_unscanned_and_gives_the_hint_once(self):
        with mock.patch.object(hooks.detect, "scan", side_effect=AssertionError("base64 is no text to scan")):
            first = self.post()
            second = self.post()
        self.assertIsNone(output(first), "the PDF passes as it is")
        ctx = first["hookSpecificOutput"]["additionalContext"]
        self.assertIn("/maisecrets:settings read_pdf MODE", ctx)
        self.assertIn("convert", ctx)
        self.assertNotIn("hello.pdf", ctx, "nothing of the file is in the hint")
        self.assertEqual(second, {}, "once")
        img = self.post("PostToolUse_Read_png", file_path=self.png)
        self.assertIn("read_image", img["hookSpecificOutput"]["additionalContext"], "the image has its own hint")

    def test_no_hint_when_decided_silenced_or_in_a_subagent(self):
        for user, extra in (({"read_pdf": "allow"}, {}), ({"tips": False}, {}), ({}, {"agent_id": "a1"})):
            with self.subTest(user=user, extra=extra):
                _reset(**user)
                self.assertEqual(self.post(**extra), {})

    def test_codex_hint_names_the_codex_form(self):
        p = golden("PostToolUse_Read_pdf", self.cwd)
        p.pop("prompt_id")
        p["turn_id"] = "t1"
        ctx = run_hook("post-tool", p)["hookSpecificOutput"]["additionalContext"]
        self.assertIn("maisecrets: set read_pdf MODE", ctx)

    def test_pre_tool_lets_it_run(self):
        self.assertEqual(self.pre(), {})


class AskAndBlock(_Work):
    def test_block_denies_before_the_read(self):
        _reset(read_pdf="block", read_image="block")
        for name, swap, key in (("PreToolUse_Read_pdf_pages", {}, "read_pdf"),
                                ("PreToolUse_Read_png", {"file_path": self.png}, "read_image")):
            with self.subTest(name):
                out = self.pre(name, **swap)
                self.assertEqual(decision(out), "deny")
                self.assertIn(f"{key} is block", out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_block_withholds_what_the_pre_tool_did_not_see(self):
        _reset(read_pdf="block")
        out = output(self.post(file_path=os.path.join(self.cwd, "report")))
        self.assertIn("read_pdf is block", out["file"]["content"])

    def test_ask_asks_in_claude_code_and_refuses_in_codex(self):
        _reset(read_pdf="ask")
        out = self.pre()
        self.assertEqual(decision(out), "ask")
        self.assertIn("cannot look inside it", out["hookSpecificOutput"]["permissionDecisionReason"])
        p = golden("PreToolUse_Read_pdf_pages", self.cwd)
        p.pop("prompt_id")
        p["turn_id"] = "t1"
        out = run_hook("pre-tool", p)
        self.assertEqual(decision(out), "deny")
        self.assertIn("maisecrets: set read_pdf allow", out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_after_a_yes_the_file_passes_and_without_an_ask_it_is_withheld(self):
        _reset(read_pdf="ask")
        self.assertEqual(self.post(), {}, "the person said yes to the ask")
        out = output(self.post(file_path=os.path.join(self.cwd, "report")))
        self.assertEqual(out["type"], "text", "no ask came for a name without .pdf")

    def test_an_unknown_mode_blocks(self):
        _reset(read_pdf="convrt")
        self.assertEqual(decision(self.pre()), "deny")


class Convert(_Work):
    def test_the_pdf_goes_as_masked_text(self):
        _reset(read_pdf="convert")
        self.stub()
        self.assertEqual(self.pre(), {})
        answer = self.post()
        out = output(answer)
        self.assertEqual(out["type"], "text")
        self.assertEqual(tuple(out["file"]), file_reads.TEXT_KEYS)
        self.assertEqual(out["file"]["filePath"], self.pdf)
        self.assertIn("Invoice 2026", out["file"]["content"])
        self.assertNotIn(TOKEN, json.dumps(answer), "the redaction ran on the text")
        self.assertRegex(out["file"]["content"], r"⟦SECRET_c\d+⟧")
        self.assertIn("as text only", answer["systemMessage"])

    def test_a_text_without_a_hit_still_replaces_the_pdf(self):
        _reset(read_pdf="convert")
        self.stub("printf 'just words\\n'")
        out = output(self.post())
        self.assertEqual(out["file"]["content"], "just words\n")

    def test_pages_go_to_pdftotext(self):
        _reset(read_pdf="convert")
        self.stub()
        p = golden("PostToolUse_Read_pdf_pages", self.cwd)
        p["tool_input"]["pages"] = "2-3"
        out = output(run_hook("post-tool", p))
        self.assertEqual(out["type"], "text")
        self.assertIn("-f 2 -l 3", self.calls.read_text())
        self.assertNotIn("base64", json.dumps(out))

    def test_a_page_range_that_is_no_range_is_refused(self):
        _reset(read_pdf="convert")
        self.stub()
        p = golden("PreToolUse_Read_pdf_pages", self.cwd)
        p["tool_input"]["pages"] = "1;rm"
        self.assertEqual(decision(run_hook("pre-tool", p)), "deny")
        p = golden("PostToolUse_Read_pdf_pages", self.cwd)
        p["tool_input"]["pages"] = "3-1"
        self.assertIn("not one page", output(run_hook("post-tool", p))["file"]["content"])

    def test_without_pdftotext_the_read_is_refused_and_the_message_says_how_to_install(self):
        _reset(read_pdf="convert")
        out = self.pre()
        self.assertEqual(decision(out), "deny")
        reason = out["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("pdftotext", reason)
        self.assertIn("brew install poppler", reason)
        self.assertIn("poppler-utils", reason)
        self.assertIn("pdftotext", output(self.post())["file"]["content"], "the post-tool refuses it too")

    def test_a_short_path_of_a_desktop_client_still_finds_pdftotext(self):
        self.stub()
        with mock.patch.dict(os.environ, {"PATH": "/nonexistent"}), \
                mock.patch.object(file_reads, "_EXTRA_DIRS", (str(self.bin),)):
            self.assertEqual(file_reads.pdftotext(), str(self.bin / "pdftotext"))
        with mock.patch.dict(os.environ, {"PATH": "/nonexistent"}):
            self.assertIsNone(file_reads.pdftotext())

    def test_a_failing_or_slow_pdftotext_withholds(self):
        _reset(read_pdf="convert")
        for body, why in (("exit 3", "exit 3"), ("/bin/sleep 5", "longer than")):
            with self.subTest(body):
                self.stub(body)
                with mock.patch.object(file_reads, "EXTRACT_SECONDS", 0.5):
                    started = time.monotonic()
                    out = output(self.post())
                self.assertLess(time.monotonic() - started, 4)
                self.assertEqual(out["type"], "text")
                self.assertIn(why, out["file"]["content"])

    def test_an_exception_during_the_extraction_kills_the_child_and_fails_closed(self):
        # any exception in the main thread while pdftotext runs. This tree's watchdog is a thread and cannot raise
        # here; the finally block must still end the child for a watchdog that could
        _reset(read_pdf="convert")
        self.stub("/bin/sleep 30")
        children = []
        real_stop = file_reads._stop

        def stop(child):
            children.append(child)
            real_stop(child)

        def interrupted(thread, seconds):
            raise RuntimeError("an exception in the main thread")
        with mock.patch.object(file_reads, "_wait", interrupted), mock.patch.object(file_reads, "_stop", stop):
            out = output(self.post())
        self.assertEqual(out["type"], "text")
        self.assertIn("withheld", out["file"]["content"])
        self.assertIsNotNone(children[0].poll(), "the child ended with the hook")

    def test_a_long_text_is_cut(self):
        _reset(read_pdf="convert")
        self.stub("/usr/bin/yes 'some words in a line' | /usr/bin/head -c 400000")
        content = output(self.post())["file"]["content"]
        self.assertLess(len(content), file_reads.MAX_TEXT_CHARS + 300)
        self.assertIn("the text stops here", content)

    def test_the_worst_text_at_the_cap_is_redacted_inside_the_budget(self):
        # review of block 4: 256K of AWS key shapes held the hook 97 s, past the client's 20 s, and it failed open.
        # The cap is the bound; the budget here leaves room for the extraction (6 s) under the 16 s watchdog
        import random
        rnd = random.Random(7)
        abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        text = " ".join("AKIA" + "".join(rnd.choice(abc) for _ in range(16))
                        for _ in range(file_reads.MAX_TEXT_CHARS // 21 + 1))[:file_reads.MAX_TEXT_CHARS]
        from maisecrets import detect
        t0 = time.monotonic()
        detect.scan(text)
        self.assertLess(time.monotonic() - t0, 8.0)

    def test_a_pdf_larger_than_the_cap_is_refused_before_pdftotext(self):
        _reset(read_pdf="convert")
        self.stub()
        with mock.patch.object(file_reads, "MAX_PDF_BYTES", 10):
            out = output(self.post())
        self.assertIn("larger than", out["file"]["content"])
        self.assertFalse(self.calls.exists(), "pdftotext did not run")

    def test_an_endless_output_is_read_up_to_the_cap_and_the_child_ends(self):
        _reset(read_pdf="convert")
        self.stub("/usr/bin/yes 'some words in a line'")
        t0 = time.monotonic()
        content = output(self.post())["file"]["content"]
        self.assertLess(time.monotonic() - t0, file_reads.EXTRACT_SECONDS, "it stops at the cap, not at the timeout")
        self.assertIn("the text stops here", content)

    def test_the_fixed_folders_come_before_the_path(self):
        fixed = self.dir / "fixed"
        fixed.mkdir()
        for folder in (fixed, self.bin):
            tool = folder / "pdftotext"
            tool.write_text("#!/bin/sh\n")
            tool.chmod(0o755)
        with mock.patch.object(file_reads, "_EXTRA_DIRS", (str(fixed),)):
            self.assertEqual(file_reads.pdftotext(), str(fixed / "pdftotext"),
                             "a folder on the PATH that the agent can write to does not win")

    def test_the_module_loads_without_subprocess(self):
        # it loads on every PostToolUse: subprocess and shutil cost about 30 ms and load only for a conversion
        code = ("import sys; sys.path.insert(0, sys.argv[1]); import maisecrets.file_reads; "
                "print(sorted(m for m in ('subprocess', 'shutil') if m in sys.modules))")
        r = subprocess.run([sys.executable, "-I", "-c", code, str(ROOT)], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.stdout.strip(), "[]", r.stderr)

    def test_a_pdf_without_text_says_so(self):
        _reset(read_pdf="convert")
        self.stub("printf '\\f'")
        self.assertIn("no OCR", output(self.post())["file"]["content"])

    def test_read_image_has_no_convert(self):
        _reset(read_image="convert")      # a hand-edited file: no mode, so it blocks
        self.assertEqual(decision(self.pre("PreToolUse_Read_png", file_path=self.png)), "deny")


class CleanDirs(_Work):
    def begin(self) -> None:
        """The session S1 starts now: every file that exists already is older than it."""
        time.sleep(0.02)
        file_reads.mark_session("S1")
        time.sleep(0.02)

    @unittest.skipIf(os.name == "nt", "a symbolic link needs a privilege on Windows")
    def test_a_read_inside_passes_and_a_way_out_does_not(self):
        clean = self.dir / "clean"
        clean.mkdir()
        inside = clean / "a.pdf"
        inside.write_bytes(b"%PDF-1.4\n")
        os.symlink(self.pdf, clean / "link.pdf")                 # a link in the clean folder to a file outside
        os.symlink(clean, self.dir / "clean-link")               # the clean folder through a link
        _reset(read_pdf="block", clean_dirs=[str(clean)])
        self.begin()
        cases = ((str(inside), "pass"), (str(self.dir / "clean-link" / "a.pdf"), "pass"),
                 (str(clean / "link.pdf"), "deny"), (str(clean / ".." / "work" / "hello.pdf"), "deny"),
                 (str(self.dir / "clean2" / "a.pdf"), "deny"))
        for path, want in cases:
            with self.subTest(path):
                pre = self.pre(file_path=path)
                post = self.post(file_path=path)
                if want == "pass":
                    self.assertEqual((pre, post), ({}, {}))
                else:
                    self.assertEqual(decision(pre), "deny")
                    self.assertEqual(output(post)["type"], "text")

    def test_a_relative_path_resolves_from_the_cwd(self):
        _reset(read_pdf="block", clean_dirs=[self.cwd])
        self.begin()
        self.assertEqual(self.pre(file_path="hello.pdf"), {})

    def test_a_file_the_agent_puts_there_in_the_session_is_not_clean(self):
        # review of block 4: cp, mv or ln of a file from outside into the clean folder undid the block
        clean = self.dir / "clean"
        clean.mkdir()
        old = clean / "old.pdf"
        old.write_bytes(b"%PDF-1.4\n")
        moved = self.dir / "moved.pdf"
        moved.write_bytes(b"%PDF-1.4\n")                         # older than the session, outside the folder
        _reset(read_pdf="block", clean_dirs=[str(clean)])
        self.begin()
        shutil.copy2(self.pdf, clean / "copied.pdf")              # cp -p keeps the mtime, not the change time
        os.rename(moved, clean / "moved.pdf")
        os.link(self.pdf, clean / "hard.pdf")
        self.assertEqual(self.pre(file_path=str(old)), {}, "a file that was there before the session passes")
        for name in ("copied.pdf", "moved.pdf", "hard.pdf"):
            with self.subTest(name):
                self.assertEqual(decision(self.pre(file_path=str(clean / name))), "deny")
                self.assertEqual(output(self.post(file_path=str(clean / name)))["type"], "text")

    def test_a_link_to_a_file_that_also_has_a_name_outside_is_not_clean(self):
        clean = self.dir / "clean"
        clean.mkdir()
        os.link(self.pdf, clean / "hard.pdf")                     # made before the session: still two names
        _reset(read_pdf="block", clean_dirs=[str(clean)])
        self.begin()
        self.assertEqual(decision(self.pre(file_path=str(clean / "hard.pdf"))), "deny")

    def test_without_a_note_of_the_session_nothing_is_clean(self):
        _reset(read_pdf="block", clean_dirs=[self.cwd])
        self.assertEqual(decision(self.pre(file_path=self.pdf)), "deny")

    def test_the_first_prompt_notes_the_session_and_a_later_one_keeps_the_time(self):
        p = golden("UserPromptSubmit_pasted_image", self.cwd, prompt="hello")
        run_hook("user-prompt", p)
        first = file_reads.session_start("S1")
        self.assertIsNotNone(first)
        time.sleep(0.02)
        run_hook("user-prompt", p)
        self.assertEqual(file_reads.session_start("S1"), first)
        self.assertIsNone(file_reads.session_start("../x"), "a session id is no path")

    def test_a_folder_that_holds_the_work_is_refused(self):
        def add(folder):
            p = golden("UserPromptSubmit_pasted_image", self.cwd,
                       prompt=f"/maisecrets:settings clean_dirs add {folder}")
            return said(run_hook("user-prompt", p))
        for folder, why in (("/", "home folder"), ("~", "home folder"), (str(self.dir), "works in"),
                            (self.cwd, "works in")):
            with self.subTest(folder):
                self.assertIn(why, add(folder))
                self.assertEqual(load_config()["clean_dirs"], [])
        add(str(self.dir / "scans"))
        self.assertEqual(load_config()["clean_dirs"], [str(self.dir / "scans")], "a folder beside the work")


class BashDataUri(_Work):
    def test_a_data_uri_image_counts_as_an_image_read(self):
        _reset(read_image="block")
        out = output(self.post("PostToolUse_Bash_datauri"))
        self.assertIs(out["isImage"], False)
        self.assertIn("read_image is block", out["stdout"])
        self.assertNotIn("base64,", out["stdout"])
        _reset(read_image="ask")
        self.assertIn("read_image is ask", output(self.post("PostToolUse_Bash_datauri"))["stdout"],
                      "no ask came before a Bash call")

    def test_allow_passes_it_and_gives_the_image_hint(self):
        out = self.post("PostToolUse_Bash_datauri")
        self.assertIsNone(output(out))
        self.assertIn("read_image", out["hookSpecificOutput"]["additionalContext"])

    def test_plain_base64_text_is_no_image(self):
        p = golden("PostToolUse_Bash_base64", self.cwd)
        self.assertIsNone(file_reads.post_read(p, {**load_config(), "read_image": "block"}, False))
        p["tool_response"]["stdout"] = "  data:image/png;base64,iVBOR"
        self.assertIsNone(file_reads.kind_of_response("Bash", p["tool_response"]),
                          "only the client's isImage makes an image, never the text")

    def test_a_data_uri_prefix_without_is_image_is_scanned(self):
        # review of block 4: a stdout that starts like a data URI let the whole Bash result pass unscanned
        p = golden("PostToolUse_Bash_datauri", self.cwd)
        p["tool_response"].update(isImage=False, stdout=f"data:image/png;base64,x\nDB_TOKEN={TOKEN}\n")
        answer = run_hook("post-tool", p)
        self.assertNotIn(TOKEN, json.dumps(answer))
        self.assertRegex(output(answer)["stdout"], r"DB_TOKEN=⟦SECRET_c\d+⟧")

    def test_an_image_passes_but_its_stderr_is_scanned(self):
        p = golden("PostToolUse_Bash_datauri", self.cwd)
        image = p["tool_response"]["stdout"]
        p["tool_response"]["stderr"] = f"curl: Authorization: Bearer {TOKEN}\n"
        answer = run_hook("post-tool", p)
        out = output(answer)
        self.assertNotIn(TOKEN, json.dumps(answer))
        self.assertRegex(out["stderr"], r"Bearer ⟦SECRET_c\d+⟧")
        self.assertEqual((out["stdout"], out["isImage"]), (image, True), "the image itself goes on unchanged")

    def test_the_fail_closed_answer_of_a_bash_image_is_its_text_shape(self):
        p = golden("PostToolUse_Bash_datauri", self.cwd)
        out = output(hooks._fail_closed("post-tool", p, "took longer than 16s."))
        self.assertIsInstance(out, dict, "a string fails open: the image is sent")
        self.assertIs(out["isImage"], False)
        self.assertEqual(out["stderr"], "")
        self.assertIn("withheld", out["stdout"])
        self.assertNotIn("base64,", json.dumps(out))


class Notebook(_Work):
    """A notebook Read with an image output (harness/golden/PostToolUse_Read_notebook.json): its text is scanned as
    always; ask and block send it as text, without the image."""

    def _post(self, **cell_text):
        p = golden("PostToolUse_Read_notebook", self.cwd)
        p["tool_response"]["file"]["cells"][0]["source"] = f"key = '{TOKEN}'"
        return run_hook("post-tool", p)

    def test_block_sends_the_text_without_the_image(self):
        _reset(read_image="block")
        answer = self._post()
        out = output(answer)
        self.assertEqual(out["type"], "text")
        self.assertEqual(tuple(out["file"]), file_reads.TEXT_KEYS)
        content = out["file"]["content"]
        self.assertIn("<Figure>", content)
        self.assertIn("image output was withheld (setting read_image block)", content)
        self.assertNotIn("iVBOR", json.dumps(answer))
        self.assertNotIn(TOKEN, json.dumps(answer), "the cells are scanned too")

    def test_ask_withholds_too(self):
        _reset(read_image="ask")
        self.assertNotIn("iVBOR", json.dumps(self._post()))

    def test_allow_keeps_the_image_and_still_scans_the_cells(self):
        answer = self._post()
        self.assertNotIn(TOKEN, json.dumps(answer))
        self.assertIn("iVBOR", json.dumps(output(answer)))

    def test_a_notebook_without_an_image_is_no_image_read(self):
        p = golden("PostToolUse_Read_notebook", self.cwd)
        del p["tool_response"]["file"]["cells"][0]["outputs"][0]["image"]
        self.assertIsNone(file_reads.kind_of_response("Read", p["tool_response"]))


# ------------------------------------------------------- typed settings --
class TypedSettings(_Work):
    def _prompt(self, text: str, **client) -> dict:
        p = golden("UserPromptSubmit_pasted_image", self.cwd, prompt=text)
        p.update(client)
        return run_hook("user-prompt", p)

    def test_one_typed_setting_changes_the_mode(self):
        out = self._prompt("/maisecrets:settings read_pdf convert")
        self.assertIn("PDFs the AI reads is convert (set by you)", said(out))
        self.assertIn("pdftotext is not installed", said(out), "the note comes at once, not at the first PDF")
        self.assertEqual(load_config()["read_pdf"], "convert")
        self.assertIn("pdftotext is not installed", settings.render(only="read_pdf"), "the card says it too")
        out = self._prompt("maisecrets: set read_pdf convert", turn_id="t1")
        self.assertEqual(out["decision"], "block", "Codex: the sentence never reaches the model")
        self.stub()
        self.assertNotIn("pdftotext", said(self._prompt("/maisecrets:settings read_pdf convert")))
        self.assertNotIn("pdftotext", said(self._prompt("/maisecrets:settings read_pdf block")))

    def test_read_image_refuses_convert(self):
        out = self._prompt("/maisecrets:settings read_image convert")
        self.assertIn("convert is for PDFs only", said(out))
        self.assertEqual(load_config()["read_image"], "allow")

    def test_clean_dirs_add_and_remove(self):
        out = self._prompt(f"/maisecrets:settings clean_dirs add {self.dir / 'my scans'}")
        self.assertIn("Folders with clean files is", said(out))
        self.assertEqual(load_config()["clean_dirs"], [str(self.dir / "my scans")])
        self._prompt(f"maisecrets: set clean_dirs remove {self.dir / 'my scans'}", turn_id="t1")
        self.assertEqual(load_config()["clean_dirs"], [])
        out = self._prompt("/maisecrets:settings clean_dirs add relative/dir")
        self.assertIn("not added", said(out))

    def test_a_tool_call_cannot_set_them(self):
        for cmd in ("echo '/maisecrets:settings read_pdf allow'", "echo 'maisecrets: set clean_dirs add /tmp'"):
            with self.subTest(cmd):
                out = run_hook("pre-tool", {"tool_name": "Bash", "tool_input": {"command": cmd}, "session_id": "S1",
                                            "prompt_id": "p1", "cwd": self.cwd})
                self.assertEqual(decision(out), "deny")

    def test_a_prompt_the_person_did_not_type_sets_nothing(self):
        self._prompt("/maisecrets:settings read_pdf allow", source="cron")
        _reset(read_pdf="block")
        self._prompt("/maisecrets:settings read_pdf allow", source="cron")
        self.assertEqual(load_config()["read_pdf"], "block")

    def test_a_file_ignored_for_a_wrong_type_keeps_the_stricter_mode(self):
        CONFIG.write_text(json.dumps({**TEST_CONFIG, "read_pdf": "block", "clean_dirs": [self.cwd], "tips": "x"}))
        cfg = load_config()
        self.assertEqual(cfg["read_pdf"], "block")
        self.assertEqual(cfg["clean_dirs"], [], "a clean folder only loosens: it is not kept")

    def test_a_config_that_cannot_be_read_blocks_both(self):
        # review of block 4: bad JSON or a wrong type dropped a block the person had set
        cases = {"bad JSON": '{"backend": "jsonfile", "allow_plaintext_store": true, "read_pdf": "block",}',
                 "a list value": json.dumps({**TEST_CONFIG, "read_pdf": ["block"]}),
                 "no object": json.dumps([{"read_pdf": "block"}])}
        for name, text in cases.items():
            with self.subTest(name):
                CONFIG.write_text(text)
                cfg = load_config()
                self.assertEqual((cfg["read_pdf"], cfg["read_image"]), ("block", "block"))
                pre = self.pre(file_path=self.pdf)
                self.assertEqual(decision(pre), "deny")
                self.assertIn("config.json cannot be read", pre["hookSpecificOutput"]["permissionDecisionReason"])
        CONFIG.write_text(json.dumps({**TEST_CONFIG, "read_pdf": "allow", "tips": "x"}))
        self.assertEqual(load_config()["read_pdf"], "allow", "a valid allow next to another bad key stays allow")

    def test_the_card_names_the_modes(self):
        text = settings.render()
        self.assertIn("PDFs the AI reads · allow · not decided", text)
        self.assertIn("convert     send only its text", text)
        self.assertIn("/maisecrets:settings read_pdf convert", text)


# ------------------------------------------------- end to end, real hooks --
def _launcher(event: str, payload: dict, home: Path, path: str) -> dict:
    """hooks/run.sh with the JSON on stdin, as Claude Code starts it: a temp HOME and a temp maisecrets home."""
    env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE", "CODEX_"))}
    env.update({"HOME": str(home), "MAISECRETS_" + "HOME": str(home / "store"), "PATH": path,
                "PYTHONDONTWRITEBYTECODE": "1"})
    r = subprocess.run(["bash", str(ROOT / "hooks" / "run.sh"), event], input=json.dumps(payload),
                       capture_output=True, text=True, env=env, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout) if r.stdout.strip() else {}


class EndToEnd(_Work):
    """The person types one setting, then drags a PDF into the session; the model sees only the masked text."""

    def _run(self, path: str) -> None:
        home = self.dir / "home"
        (home / "store").mkdir(parents=True)
        (home / "store" / "config.json").write_text(json.dumps(TEST_CONFIG))
        py_dir = os.path.dirname(sys.executable)
        path = f"{path}{os.pathsep}{py_dir}{os.pathsep}/usr/bin{os.pathsep}/bin"
        typed = golden("UserPromptSubmit_pasted_image", self.cwd, prompt="/maisecrets:settings read_pdf convert")
        out = _launcher("user-prompt", typed, home, path)
        self.assertIn("is convert (set by you)", said(out))
        pre = golden("PreToolUse_Read_pdf_pages", self.cwd)
        del pre["tool_input"]["pages"]
        self.assertEqual(_launcher("pre-tool", pre, home, path), {}, "the read runs")
        post = golden("PostToolUse_Read_pdf", self.cwd)
        post["tool_response"]["file"]["base64"] = base64.b64encode(Path(self.pdf).read_bytes()).decode()
        answer = _launcher("post-tool", post, home, path)
        out = output(answer)
        self.assertEqual(out["type"], "text")
        self.assertEqual(tuple(out["file"]), file_reads.TEXT_KEYS)
        self.assertIn("Invoice 2026", out["file"]["content"])
        self.assertRegex(out["file"]["content"], r"deploy token ⟦SECRET_c\d+⟧")
        self.assertNotIn(TOKEN, json.dumps(answer))
        self.assertNotIn(post["tool_response"]["file"]["base64"][:40], json.dumps(answer))

    def test_with_a_stub_pdftotext(self):
        self.stub()
        self._run(str(self.bin))

    @unittest.skipUnless(REAL_PDFTOTEXT, "pdftotext is not installed")
    def test_with_the_real_pdftotext(self):
        self._run(os.path.dirname(REAL_PDFTOTEXT))


@unittest.skipUnless(REAL_PDFTOTEXT, "pdftotext is not installed")
class RealPdftotext(unittest.TestCase):
    def test_pages_and_text_of_a_synthetic_pdf(self):
        d = Path(tempfile.mkdtemp(dir=_isolate.TMP))
        f = d / "a.pdf"
        f.write_bytes(pdf_bytes("first line", "second line"))
        text, why = file_reads.extract(str(f), "1")
        self.assertEqual(why, "")
        self.assertIn("first line", text)
        self.assertIn("second line", text)
        self.assertEqual(file_reads.extract(str(d / "missing.pdf"))[0], None)
        (d / "bad.pdf").write_bytes(b"not a pdf")
        text, why = file_reads.extract(str(d / "bad.pdf"))
        self.assertIsNone(text)
        self.assertIn("failed", why)
        shutil.rmtree(d, True)


if __name__ == "__main__":
    unittest.main()
