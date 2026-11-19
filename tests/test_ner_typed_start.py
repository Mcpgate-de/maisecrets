"""`ner local`, typed by the person, starts the name service at once (no question first, 0.9.19); a setting of a policy
or of an earlier session never starts a download; `ner off` stops a start that runs.

The lifecycle (ner_setup.start_typed, run_start, stop_local): the start owns a nonce. Its container carries the label
`maisecrets.start=<nonce>`, and `ner off` removes only a container with that label. `ner off` signals no process: it
writes a stop request, and the start ends its own docker child, removes its own labelled container and its record. A
record whose start ended without its cleanup goes, and no process is touched.

Docker is a fake shell script on PATH (POSIX only: on Windows the fake would need a .cmd of its own), and the probe of
127.0.0.1:8765 is a fake too, so a real container of the person on that port changes nothing."""
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
from _hygiene import CLAUDE  # noqa: E402

from maisecrets import hooks, ner_setup  # noqa: E402
from maisecrets.vault import HOME  # noqa: E402

CONFIG = {"backend": "jsonfile", "allow_plaintext_store": True}
CID = "feed" * 16
# the fake docker: every call goes into the log. `run` makes the container (the file `made`, and `label` with the value
# of its --label) and waits (the download): FAKE_RUN=late waits first and makes it after. `ps --filter label=…` lists it
# only when its label is that value. A wait ends when the test writes the file `die` (no fake outlives the test)
FAKE = r"""#!/bin/sh
echo "$*" >> "$FAKE_DOCKER_LOG"
D="$FAKE_DOCKER_DIR"
pause() { i=0; while [ $i -lt 600 ]; do [ -f "$D/die" ] && exit 0; sleep 0.1; i=$((i+1)); done; }
case "$1" in
  info) exit 1 ;;
  container)
    [ -f "$D/made" ] || { echo "no such container" >&2; exit 1; }
    case "$*" in
      *State.Running*) echo "%(cid)s true sha256:abc mcpgate/ner:v2.0.3916" ;;
      *) echo "%(cid)s mcpgate/ner:v2.0.3916" ;;
    esac ;;
  ps)
    [ -f "$D/made" ] || exit 0
    case "$*" in
      *label=maisecrets.start=*)
        all="$*"; want="${all##*label=maisecrets.start=}"
        [ -f "$D/label" ] && [ "$(cat "$D/label")" = "$want" ] && echo "%(cid)s" ;;
      *) echo "%(cid)s" ;;
    esac ;;
  run)
    label=""; prev=""
    for a in "$@"; do [ "$prev" = "--label" ] && label="${a#maisecrets.start=}"; prev="$a"; done
    [ "$FAKE_RUN" = "late" ] && pause
    touch "$D/made"; [ -n "$label" ] && printf %%s "$label" > "$D/label"
    pause
    echo "%(cid)s" ;;
  start) [ -n "$FAKE_SLOW_START" ] && pause ;;
  rm) rm -f "$D/made" "$D/label" ;;
esac
exit 0
""" % {"cid": CID}


def _prompt(text: str) -> dict:
    return hooks.user_prompt({"prompt": text, "session_id": "S1", **CLAUDE})


def _record() -> dict:
    try:
        return json.loads(Path(HOME, ner_setup.START_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


@unittest.skipIf(os.name == "nt", "the fake docker is a shell script")
class TypedStartTests(unittest.TestCase):
    def setUp(self):
        Path(HOME, "config.json").write_text(json.dumps(CONFIG), encoding="utf-8")
        self.dir = tempfile.mkdtemp(prefix="fake-docker-")
        self.log = Path(self.dir, "calls.log")
        self.log.write_text("", encoding="utf-8")
        tool = Path(self.dir, "docker")
        tool.write_text(FAKE, encoding="utf-8")
        tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
        env = {"PATH": self.dir + os.pathsep + os.environ.get("PATH", ""), "FAKE_DOCKER_LOG": str(self.log),
               "FAKE_DOCKER_DIR": self.dir}
        for p in (mock.patch.dict(os.environ, env), mock.patch.object(ner_setup, "probe", return_value=(False, ""))):
            p.start()
            self.addCleanup(p.stop)
        os.environ.pop(ner_setup.NO_START_ENV, None)
        self.addCleanup(self._clean)

    def _clean(self):
        # a start that still runs gets the stop request; every fake wait ends
        d = _record()
        if d.get("nonce"):
            Path(HOME, ner_setup.STOP_FILE).write_text(json.dumps({"nonce": d["nonce"]}), encoding="utf-8")
            self.wait_for(lambda: not Path(HOME, ner_setup.START_FILE).exists(), 5)
        Path(self.dir, "die").write_text("", encoding="utf-8")
        for name in (ner_setup.START_FILE, ner_setup.STOP_FILE, ner_setup.START_LOG):
            Path(HOME, name).unlink(missing_ok=True)
        Path(HOME, "config.json").write_text(json.dumps(CONFIG), encoding="utf-8")

    def calls(self) -> list:
        return self.log.read_text(encoding="utf-8").splitlines()

    def wait_for(self, cond, seconds=20.0):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if cond():
                return True
            time.sleep(0.05)
        return False

    def started(self) -> str:
        """The nonce of the start, once its docker run began."""
        self.assertTrue(self.wait_for(lambda: any(c.startswith("run ") for c in self.calls())), self.calls())
        return _record().get("nonce", "")

    def test_typed_local_starts_without_a_question_and_off_ends_it_with_its_own_container(self):
        out = _prompt("/maisecrets:ner local")
        # a success: the slash command runs on (the hook path of Codex and claude -p), with the note of the start
        self.assertIn(ner_setup.START_NOTE, out["hookSpecificOutput"]["additionalContext"])
        self.assertTrue(ner_setup.start_running())
        nonce = self.started()
        run = [c for c in self.calls() if c.startswith("run ")][0]
        self.assertIn(f"--label maisecrets.start={nonce}", run)
        self.assertIn("mcpgate/ner", run)
        self.assertTrue(self.wait_for(lambda: Path(self.dir, "label").exists()))
        # a second typed choice while it runs starts no second one
        _prompt("/maisecrets:ner local")
        self.assertEqual(_record().get("nonce"), nonce)
        # off: a stop request; the start ends its own docker child and removes its own labelled container
        out = _prompt("/maisecrets:ner off")
        self.assertIn("download and start of the name service stopped", json.dumps(out).lower())
        self.assertFalse(Path(HOME, ner_setup.START_FILE).exists())
        self.assertFalse(ner_setup.start_running())
        self.assertIn(f"rm -f {CID}", self.calls())
        self.assertFalse(Path(self.dir, "made").exists())
        self.assertTrue(self.wait_for(lambda: "stopped:" in Path(HOME, ner_setup.START_LOG).read_text()))

    def test_a_container_made_by_hand_after_the_start_survives_off(self):
        with mock.patch.dict(os.environ, {"FAKE_RUN": "late"}):
            _prompt("/maisecrets:ner local")
            self.started()
            # while the start downloads, the person makes a container ner of the image by hand: it has no label
            Path(self.dir, "made").write_text("", encoding="utf-8")
            out = _prompt("/maisecrets:ner off")
        self.assertIn("stopped", json.dumps(out))
        self.assertFalse([c for c in self.calls() if c.startswith("rm ")], self.calls())
        self.assertTrue(Path(self.dir, "made").exists())

    def test_a_container_made_by_hand_before_the_start_survives_off(self):
        Path(self.dir, "made").write_text("", encoding="utf-8")
        with mock.patch.dict(os.environ, {"FAKE_SLOW_START": "1"}):
            _prompt("/maisecrets:ner local")
            self.assertTrue(self.wait_for(lambda: "start ner" in self.calls()), self.calls())
            out = _prompt("/maisecrets:ner off")
        self.assertIn("stopped", json.dumps(out))
        self.assertFalse([c for c in self.calls() if c.startswith("rm ")], self.calls())
        self.assertTrue(Path(self.dir, "made").exists())

    def test_a_record_that_a_crashed_start_left_is_cleared_with_no_process_touched(self):
        old = "c" * 32
        # the start crashed after its docker run: its labelled container is there, its beat is old
        Path(self.dir, "made").write_text("", encoding="utf-8")
        Path(self.dir, "label").write_text(old, encoding="utf-8")
        stale = {"nonce": old, "t": time.time() - 600, "beat": time.time() - 600}
        Path(HOME, ner_setup.START_FILE).write_text(json.dumps(stale), encoding="utf-8")
        self.assertFalse(ner_setup.start_running())
        lines = ner_setup.stop_local()
        # no process is asked or signalled: the code of ner off has no signal, and a stale record gets no stop request
        self.assertFalse(Path(HOME, ner_setup.STOP_FILE).exists())
        self.assertFalse(Path(HOME, ner_setup.START_FILE).exists())
        self.assertIn(f"rm -f {CID}", self.calls())
        self.assertIn("the container that the start made was removed", lines)
        # the next typed start clears such a record too, and removes only that start's labelled container
        Path(self.dir, "made").write_text("", encoding="utf-8")
        Path(self.dir, "label").write_text(old, encoding="utf-8")
        Path(HOME, ner_setup.START_FILE).write_text(json.dumps(stale), encoding="utf-8")
        import subprocess
        real, spawned = subprocess.Popen, []

        def popen(argv, *a, **k):
            if "maisecrets.cli" in argv:
                spawned.append(argv)
                return mock.Mock(pid=1)
            return real(argv, *a, **k)
        with mock.patch.object(ner_setup.subprocess, "Popen", popen):
            self.assertTrue(ner_setup.start_typed("slash command"))
        self.assertEqual(len(spawned), 1)
        self.assertNotEqual(_record().get("nonce"), old)
        self.assertEqual(self.calls().count(f"rm -f {CID}"), 2)

    def test_a_spawn_that_fails_leaves_no_record(self):
        with mock.patch.object(ner_setup.subprocess, "Popen", side_effect=OSError("no python")):
            self.assertFalse(ner_setup.start_typed("slash command"))
        self.assertFalse(Path(HOME, ner_setup.START_FILE).exists())

    def test_two_sessions_at_once_start_one_download(self):
        import subprocess
        gate = Path(self.dir, "go")
        driver = Path(self.dir, "driver.py")
        driver.write_text(
            "import os, sys, time\n"
            f"sys.path.insert(0, {str(Path(__file__).resolve().parent.parent)!r})\n"
            "from maisecrets import ner_setup\n"
            "ner_setup.probe = lambda *a, **k: (False, '')\n"
            # a slow process start: the time between the check and the record is wide, as on a loaded machine
            "real = ner_setup.subprocess.Popen\n"
            "def slow(*a, **k):\n"
            "    if 'maisecrets.cli' not in a[0]:\n"
            "        return real(*a, **k)\n"
            "    time.sleep(0.5)\n"
            "    p = real(*a, **k)\n"
            "    print('spawned', p.pid, flush=True)\n"
            "    return p\n"
            "ner_setup.subprocess.Popen = slow\n"
            f"while not os.path.exists({str(gate)!r}):\n"
            "    time.sleep(0.001)\n"
            "print(ner_setup.start_typed('slash command'))\n", encoding="utf-8")
        env = {k: v for k, v in os.environ.items() if k != ner_setup.NO_START_ENV}
        runs = [subprocess.Popen([sys.executable, str(driver)], env=env, stdout=subprocess.PIPE, text=True)
                for _ in range(2)]
        time.sleep(0.5)
        gate.write_text("", encoding="utf-8")
        outs = [r.communicate(timeout=60)[0].split("\n") for r in runs]
        spawned = [line for out in outs for line in out if line.startswith("spawned ")]
        self.assertEqual([out[-2] for out in outs], ["True", "True"])
        self.assertEqual(len(spawned), 1, "two sessions started two downloads")

    def test_a_setting_alone_never_starts_a_download(self):
        # the setting is local (a policy or an earlier session), and no container exists
        Path(HOME, "config.json").write_text(json.dumps({**CONFIG, "remote_detector": {"url": ner_setup.LOCAL_URL}}),
                                             encoding="utf-8")
        tool = ner_setup.container_tool()
        self.assertEqual(ner_setup.follow_pin(tool), "none")       # what the session start runs in the background
        with mock.patch.object(ner_setup.subprocess, "Popen") as popen:
            # the session start says that nothing starts: the start line names /maisecrets:ner local
            self.assertFalse(ner_setup.restart_local({"url": ner_setup.LOCAL_URL}))
        popen.assert_called_once()
        # only a typed route starts it
        for route in ("session start", "policy", "cli", ""):
            self.assertFalse(ner_setup.start_typed(route), route)
        self.assertFalse(ner_setup.start_running())
        self.assertFalse([c for c in self.calls() if c.startswith(("run ", "pull "))], self.calls())

    def test_the_start_line_names_the_command_that_starts_it(self):
        from maisecrets import ner_health
        fact, step = ner_health.fact_and_step("local_down", {"url": ner_setup.LOCAL_URL})
        self.assertIn("not running", fact)
        self.assertIn("/maisecrets:ner local", step)


if __name__ == "__main__":
    unittest.main()
