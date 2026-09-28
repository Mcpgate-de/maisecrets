"""Invariant I4: every value the detector finds can be scrubbed from a transcript.

THREAT-MODEL C3 masks a value in the client's transcript. This module holds the goal over the
population the detector defines: every value that `detect.scan` returns for the generated matrix
(tests/detection_matrix.py), the provider token corpus and one PII value of each type. Each value
goes into every record shape Claude Code and Codex write, in each JSON writer they use (JS and
serde write UTF-8, a Python writer escapes to ASCII), and the scrub must leave no form of it,
keep every line valid JSON, keep the rest of each record, and keep the file's size and inode.

The oracle is this file's own: `json_forms` builds the escaped forms without `_scrub_forms`.
"""
from __future__ import annotations

import json
import os
import random
import secrets
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
Path(os.environ["MAISECRETS_HOME"]).mkdir(parents=True, exist_ok=True)
Path(os.environ["MAISECRETS_HOME"], "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

from maisecrets import detect, hooks  # noqa: E402
from maisecrets.vault import HOME  # noqa: E402
import detection_matrix  # noqa: E402
from test_detect_rules import _provider_tokens, iban_complete, luhn_complete, tax_id_check  # noqa: E402
from _hygiene import CLAUDE, CODEX  # noqa: E402


def _pii_texts() -> list[str]:
    r = random.Random(28)
    digits = list("0123456789")
    r.shuffle(digits)
    if digits[0] == "0":
        digits[0], digits[1] = digits[1], digits[0]
    tid = "".join(digits)
    return [
        "Kontakt: anna.berg@firma-xyz.de", "Kontakt: jürgen.müller@firma-xyz.de",
        "ruf an: +49 170 " + str(r.randint(1000000, 9999999)),
        "card " + luhn_complete("4" + "".join(str(r.randint(0, 9)) for _ in range(14))),
        "IBAN " + iban_complete("DE", "37040044" + "".join(str(r.randint(0, 9)) for _ in range(10))),
        f"from 93.184.{r.randint(1, 250)}.{r.randint(1, 250)} ok",
        "Steuer-ID: " + tid + tax_id_check(tid),
        "passwort" + ": Grün€Wald" + str(r.randint(2020, 2030)) + "!",   # assembled: the repo scan flags it
        # a value that ends in a backslash: a plain mask before the escaped one breaks the record
        "password=" + "".join(r.choice("abcdefGHJK23456789") for _ in range(11)) + "\\",
        "password: " + "".join(r.choice("abcdefGHJK23456789") for _ in range(5)) + "\\" + "Qz7" + "wX",
    ]


def population() -> list[tuple[str, str, str]]:
    """(type, value, source text) for every distinct value the detector returns on the inputs above."""
    texts = [c.text for c in detection_matrix.cases()]
    texts += [f"here: {t} done" for t in _provider_tokens().values()]
    texts += _pii_texts()
    seen: dict[str, tuple[str, str]] = {}
    for t in texts:
        for m in detect.scan(t):
            seen.setdefault(m.value, (m.type, t))
    return [(typ, v, src) for v, (typ, src) in seen.items()]


POPULATION = population()


def json_forms(value: str) -> list[bytes]:
    """The bytes of a value inside a JSON string, escaped once and twice, UTF-8 and ASCII."""
    once = [json.dumps(value)[1:-1], json.dumps(value, ensure_ascii=False)[1:-1]]
    twice = [json.dumps(o)[1:-1] for o in once] + [json.dumps(o, ensure_ascii=False)[1:-1] for o in once]
    return [f.encode("utf-8") for f in dict.fromkeys([value, *once, *twice]) if len(f) >= 4]


WRITERS = {
    "js": lambda o: json.dumps(o, ensure_ascii=False, separators=(",", ":")),
    "ascii": lambda o: json.dumps(o),
}


def records(value: str, keep: str) -> list[dict]:
    """The records of a Claude Code transcript and a Codex rollout that carry a value."""
    text = f"see {value} here"
    return [
        {"type": "user", "message": {"role": "user", "content": text}, "k": keep},
        {"type": "user", "message": {"content": [{"type": "text", "text": text}]}, "k": keep},
        {"type": "assistant", "message": {"content": [{"type": "tool_use", "name": "Bash",
                                                       "input": {"command": f"echo {value}"}}]}, "k": keep},
        {"type": "user", "message": {"content": [{"type": "tool_result", "content": text}]}, "k": keep},
        # the hook's own stdout, recorded as a string: the value is escaped twice
        {"type": "attachment", "attachment": {"type": "hook_success", "stdout": json.dumps(
            {"hookSpecificOutput": {"updatedInput": {"token": value}}})}, "k": keep},
        {"type": "queue-operation", "operation": "enqueue", "content": text, "k": keep},
        {"type": "event_msg", "payload": {"type": "exec_command_end", "stdout": text + "\n"}, "k": keep},
        # Codex writes the command and its raw output here before the PostToolUse hook runs
        {"type": "event_msg", "payload": {"type": "item_completed", "item": {
            "type": "CommandExecution", "command": f"echo {value}", "aggregated_output": text}}, "k": keep},
        {"type": "response_item",
         "payload": {"type": "function_call", "arguments": json.dumps({"cmd": f"echo {value}"})}, "k": keep},
        {"type": "response_item",
         "payload": {"type": "custom_tool_call",
                     "input": f"await tools.exec_command({{cmd: {json.dumps('echo ' + value)}}})"}, "k": keep},
    ]


class _Transcript:
    def __init__(self, lines: list[str]) -> None:
        fd, self.path = tempfile.mkstemp(suffix=".jsonl")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        st = os.stat(self.path)
        self.size, self.ino = st.st_size, st.st_ino

    def check(self, value: str, keep: str) -> list[str]:
        problems = []
        data = Path(self.path).read_bytes()
        left = [i for i, f in enumerate(json_forms(value)) if value and f in data]
        if left:
            problems.append(f"form(s) {left} of the value are still in the file")
        st = os.stat(self.path)
        if (st.st_size, st.st_ino) != (self.size, self.ino):
            problems.append("the file changed its size or inode (not masked in place)")
        for n, line in enumerate(data.decode("utf-8").splitlines()):
            try:
                rec = json.loads(line)
            except ValueError:
                problems.append(f"line {n} is no longer valid JSON")
                continue
            if rec.get("k") != keep:
                problems.append(f"line {n} lost the rest of its record")
        return problems

    def remove(self) -> None:
        os.unlink(self.path)


class ScrubTests(unittest.TestCase):
    def test_the_population_covers_every_placeholder_type_and_the_hard_shapes(self):
        types = {t for t, _v, _s in POPULATION}
        for typ in ("SECRET", "EMAIL", "PHONE", "CARD", "IBAN", "IP", "DE_TAX_ID"):
            self.assertIn(typ, types, f"no {typ} value in the population")
        values = [v for _t, v, _s in POPULATION]
        self.assertGreater(len(values), 1000)
        self.assertTrue(any(v.isdigit() for v in values), "no value of digits only")
        self.assertTrue(any(v.endswith("\\") for v in values), "no value that ends in a backslash")
        self.assertTrue(any(any(ord(c) > 127 for c in v) for v in values), "no value outside ASCII")
        self.assertTrue(any("\n" in v for v in values), "no value over several lines")

    def test_every_detected_value_is_scrubbed_from_every_record_and_writer(self):
        # 50 values per transcript, scrubbed in one call, as a hook scrubs the values of one prompt.
        # The scrub reads the file once per form, so one file per value took a minute and one file
        # for all values six seconds
        bad = []
        keep = "KEEP-" + secrets.token_hex(4)
        for start in range(0, len(POPULATION), 50):
            batch = POPULATION[start:start + 50]
            values = [v for _t, v, _s in batch]
            for writer, dump in WRITERS.items():
                t = _Transcript([dump(r) for v in values for r in records(v, keep)])
                try:
                    hooks._scrub_transcript(t.path, values, ["ref"])
                    data = Path(t.path).read_bytes()
                    for i, (typ, value, _s) in enumerate(batch, start):
                        left = [n for n, f in enumerate(json_forms(value)) if f in data]
                        if left:
                            bad.append(f"#{i} {typ} len {len(value)} / {writer}: form(s) {left} are still in the file")
                    bad += [f"batch {start} / {writer}: {p}" for p in t.check("", keep)]
                finally:
                    t.remove()
        self.assertEqual(bad, [], f"{len(bad)} problems:\n" + "\n".join(bad[:20]))

    def test_a_value_across_the_read_window_is_scrubbed(self):
        # The scrub reads windows of 8 MiB plus an overlap of the longest form and ends each window
        # at its last newline. A value is placed exactly across the mark 8 MiB + overlap, where a
        # window that did not end at a newline would cut it in two.
        # The value is fixed and plain, so the overlap is its length; a value taken from the
        # population moved when the population changed, and the test stopped reaching the edge.
        value = "Wz" + "k4R9" * 6 + "Qe"
        overlap = max(len(f) for f in json_forms(value))
        keep = "KEEP-edge"
        dump = WRITERS["js"]
        head = dump({"type": "user", "message": {"content": "a " + value + " b"}, "k": keep})
        at = head.index(value)                      # the value's offset inside its record
        lines: list[str] = []
        size = 0

        def pad_to(offset: int) -> None:
            """Pad records until the next record starts where its value begins at ``offset``."""
            nonlocal size
            target = offset - at
            empty = len(dump({"type": "pad", "k": keep, "p": ""})) + 1
            while target - size > 4000 + empty:
                line = dump({"type": "pad", "k": keep, "p": "x" * 4000})
                lines.append(line)
                size += len(line) + 1
            rest = target - size - empty
            assert rest >= 0, "the edges are too close for the pad"
            line = dump({"type": "pad", "k": keep, "p": "x" * rest})
            lines.append(line)
            size += len(line) + 1
            assert size == target
        chunk = 8 * 1024 * 1024
        # a record whose value runs across the end of a window that did not end at a newline
        pad_to(chunk + overlap - len(value) // 2)
        lines.append(head)
        size += len(head) + 1
        lines.append(dump({"type": "pad", "k": keep, "p": "end"}))
        t = _Transcript(lines)
        try:
            hooks._scrub_transcript(t.path, [value], ["ref"])
            self.assertEqual(t.check(value, keep), [])
        finally:
            t.remove()


class ThroughTheHooksTests(unittest.TestCase):
    """The same records, scrubbed by the hooks that own the scrub: a blocked prompt (both clients)
    and a Codex tool result. The delayed child is the subject of test_promises.py; here the scrub
    before the answer runs, on the records that exist already."""

    def test_the_hooks_scrub_one_value_of_each_type_in_every_record(self):
        one_each: dict[str, tuple[str, str]] = {}
        for typ, v, src in POPULATION:
            one_each.setdefault(typ, (v, src))
        bad = []
        for typ, (value, source) in one_each.items():
            for event, client in (("user-prompt", CLAUDE), ("user-prompt", CODEX), ("post-tool", CODEX)):
                keep = "KEEP-" + secrets.token_hex(4)
                t = _Transcript([WRITERS["js"](r) for r in records(value, keep)])
                payload = {"session_id": "S1", "transcript_path": t.path, "prompt": source,
                           "tool_name": "Bash", "tool_input": {"command": "cat notes"},
                           "tool_response": {"stdout": source}, **client}
                try:
                    with mock.patch.object(hooks, "_scrub_transcript_later"), \
                            mock.patch.object(hooks, "_clipboard", return_value=False):
                        hooks._live_cache.clear()
                        (hooks.user_prompt if event == "user-prompt" else hooks.post_tool)(payload)
                    bad += [f"{typ} / {event} / {client}: {p}" for p in t.check(value, keep)]
                finally:
                    t.remove()
                    for f in (HOME / "pending").glob("*.txt") if (HOME / "pending").is_dir() else []:
                        f.unlink()
        self.assertEqual(bad, [], "\n".join(bad))


if __name__ == "__main__":
    unittest.main()
