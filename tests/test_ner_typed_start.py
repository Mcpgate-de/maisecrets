"""`ner local`, typed by the person, starts the name service at once (no question first, 0.9.19); a setting of a policy
or of an earlier session never starts a download; `ner off` stops a start that runs. Docker is a fake shell script on
PATH (POSIX only: on Windows the fake would need a .cmd of its own), and the probe of 127.0.0.1:8765 is a fake too, so
a real container of the person on that port changes nothing."""
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
# the fake docker: every call goes into the log; `run` marks a container made halfway, then waits (the download)
FAKE = """#!/bin/sh
echo "$*" >> "$FAKE_DOCKER_LOG"
case "$1" in
  info) exit 1 ;;
  container)
    [ -f "$FAKE_DOCKER_DIR/made" ] || { echo "no such container" >&2; exit 1; }
    case "$*" in
      *State.Running*) echo "%(cid)s true sha256:abc mcpgate/ner:v2.0.3916" ;;
      *) echo "%(cid)s mcpgate/ner:v2.0.3916" ;;
    esac ;;
  run) touch "$FAKE_DOCKER_DIR/made"; sleep 60; echo "%(cid)s" ;;
  start) [ -n "$FAKE_SLOW_START" ] && sleep 60 ;;
  rm) rm -f "$FAKE_DOCKER_DIR/made" ;;
esac
exit 0
""" % {"cid": CID}


def _gone(pid: int) -> bool:
    """The start ended: reaped here when this test process is its parent (a zombie still answers kill 0)."""
    try:
        os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        pass
    return not ner_setup._alive(pid)


def _kill_group(pid: int) -> None:
    import signal
    try:
        os.killpg(pid, signal.SIGKILL)
    except OSError:
        pass


def _prompt(text: str) -> dict:
    return hooks.user_prompt({"prompt": text, "session_id": "S1", **CLAUDE})


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
        self.addCleanup(self._stop)

    def _stop(self):
        pid = ner_setup.start_pid()
        if pid:
            import signal
            try:
                os.killpg(pid, signal.SIGKILL)
            except OSError:
                pass
        for name in (ner_setup.START_PID, ner_setup.START_LOG):
            try:
                os.unlink(Path(HOME, name))
            except FileNotFoundError:
                pass
        Path(HOME, "config.json").write_text(json.dumps(CONFIG), encoding="utf-8")

    def calls(self) -> list:
        return self.log.read_text(encoding="utf-8").splitlines()

    def wait_for(self, cond, seconds=20.0):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if cond():
                return True
            time.sleep(0.1)
        return False

    def test_typed_local_starts_without_a_question_and_off_stops_it(self):
        out = _prompt("/maisecrets:ner local")
        # a success: the slash command runs on (the hook path of Codex and claude -p), with the note of the start
        context = out["hookSpecificOutput"]["additionalContext"]
        self.assertIn(ner_setup.START_NOTE, context)
        pid = ner_setup.start_pid()
        self.assertTrue(pid)
        self.assertTrue(self.wait_for(lambda: any(c.startswith("run ") for c in self.calls())), self.calls())
        self.assertIn("mcpgate/ner", [c for c in self.calls() if c.startswith("run ")][0])
        # a second typed choice while it runs starts no second one
        _prompt("/maisecrets:ner local")
        self.assertEqual(ner_setup.start_pid(), pid)
        # off stops the start (the docker client of the pull goes with its process group) and the half-made container
        out = _prompt("/maisecrets:ner off")
        self.assertIn("stopped", json.dumps(out))
        self.assertTrue(self.wait_for(lambda: _gone(pid), 10), "the start still runs")
        self.assertEqual(ner_setup.start_pid(), 0)
        self.assertIn(f"rm -f {CID}", self.calls())
        self.assertFalse(Path(self.dir, "made").exists())

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
        self.assertEqual(ner_setup.start_pid(), 0)
        self.assertFalse([c for c in self.calls() if c.startswith(("run ", "pull "))], self.calls())

    def test_off_never_removes_a_container_the_person_made_by_hand(self):
        # a container ner of the image, made by hand before the start (no secret of maisecrets); the start starts it
        Path(self.dir, "made").write_text("", encoding="utf-8")
        with mock.patch.dict(os.environ, {"FAKE_SLOW_START": "1"}):
            _prompt("/maisecrets:ner local")
            pid = ner_setup.start_pid()
            self.assertTrue(pid)
            self.assertTrue(self.wait_for(lambda: "start ner" in self.calls()), self.calls())
            self.assertEqual(json.loads(Path(HOME, ner_setup.START_PID).read_text())["pre"], CID)
            out = _prompt("/maisecrets:ner off")
        self.assertIn("stopped", json.dumps(out))
        self.assertTrue(self.wait_for(lambda: _gone(pid), 10), "the start still runs")
        self.assertFalse([c for c in self.calls() if c.startswith("rm ")], self.calls())
        self.assertTrue(Path(self.dir, "made").exists())

    def test_a_pid_the_os_gave_to_another_process_gets_no_signal(self):
        import subprocess
        other = subprocess.Popen(["sleep", "60"], start_new_session=True)
        self.addCleanup(other.wait)
        self.addCleanup(other.kill)
        # the record of an old start whose pid now belongs to another live process: another OS start time
        Path(HOME, ner_setup.START_PID).write_text(json.dumps(
            {"pid": other.pid, "t": time.time(), "start": "ps:Mon Jan  1 00:00:00 2001", "nonce": "a" * 32}))
        self.assertEqual(ner_setup.start_pid(), 0)
        lines = ner_setup.stop_local()
        time.sleep(0.3)
        self.assertIsNone(other.poll(), "the other process got a signal")
        self.assertFalse(Path(HOME, ner_setup.START_PID).exists(), "the stale record stays")
        self.assertNotIn("stopped", " ".join(lines))
        # with its real start time the same record is the start, and off stops it
        Path(HOME, ner_setup.START_PID).write_text(json.dumps(
            {"pid": other.pid, "t": time.time(), "start": ner_setup._proc_start(other.pid), "nonce": "a" * 32}))
        self.assertEqual(ner_setup.start_pid(), other.pid)
        ner_setup.stop_local()
        self.assertTrue(self.wait_for(lambda: other.poll() is not None, 5))

    def test_a_record_that_cannot_be_written_ends_the_start_it_spawned(self):
        with mock.patch.object(ner_setup, "_write_start", side_effect=OSError("disk full")), \
                mock.patch.object(ner_setup.subprocess, "Popen") as popen, \
                mock.patch.object(ner_setup.os, "killpg") as killpg:
            popen.return_value.pid = 4242
            self.assertFalse(ner_setup.start_typed("slash command"))
        killpg.assert_called_once()
        self.assertEqual(killpg.call_args.args[0], 4242)
        popen.return_value.wait.assert_called_once()

    def test_a_kill_that_fails_keeps_the_record_and_says_so(self):
        Path(HOME, ner_setup.START_PID).write_text(json.dumps({"pid": 4242, "t": time.time(), "start": "ps:x",
                                                               "nonce": "b" * 32}))
        with mock.patch.object(ner_setup, "_verified", return_value=4242), \
                mock.patch.object(ner_setup.os, "killpg", side_effect=PermissionError("not permitted")):
            lines = ner_setup.stop_local()
        self.assertIn("could not be stopped", " ".join(lines))
        self.assertTrue(Path(HOME, ner_setup.START_PID).exists())

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
        spawned = [int(line.split()[1]) for out in outs for line in out if line.startswith("spawned ")]
        for pid in spawned:
            self.addCleanup(_kill_group, pid)
        self.assertEqual([out[-2] for out in outs], ["True", "True"])
        self.assertEqual(len(spawned), 1, "two sessions started two downloads")

    def test_the_start_line_names_the_command_that_starts_it(self):
        from maisecrets import ner_health
        fact, step = ner_health.fact_and_step("local_down", {"url": ner_setup.LOCAL_URL})
        self.assertIn("not running", fact)
        self.assertIn("/maisecrets:ner local", step)


if __name__ == "__main__":
    unittest.main()
