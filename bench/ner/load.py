"""The load test of #105 ("Order", step 4): N sessions at once send long tool results through the real plugin path,
and the run says how many results kept a rest the name service did not check. Counts and times only, never a value.

    python3 bench/ner/load.py --url http://127.0.0.1:8766 --out DIR            # a NER container on this computer
    python3 bench/ner/load.py --home TEMP_HOME --out DIR                       # the gateway of a login in TEMP_HOME
    python3 bench/ner/load.py --dry-run --duration 5 --out DIR                 # the fake service of the harness

Each session is a process of its own, as each hook call is. A session makes tool results of 20,000 to 100,000
characters (seeded; the synthetic tool responses of bench/gatewaygen.py, with synthetic names) in the shapes of a
Bash output and an MCP result. For each result it opens the hook's window (vault.hook_deadline with the PostToolUse
watchdog, 16 s) and calls remote_layer.for_tool_result with the tool scan of hooks.post_tool, so the result waits as
long as a PostToolUse hook would let it (remote_layer.tool_deadline) and goes in pieces where the source takes them.

Each result is a row: its length, the pieces planned, the requests sent, the checked share, the state (ok, partial,
unavailable, too_long), the reason, the refusals of its requests (busy, rate_limited) and the wall time. The run adds
the share of results with a rest (any state but ok), the median and the 95th percentile of the wall time, the
refusals by reason, and the verdict against "Done when" of #105: at most 1 % of the results with a rest.

The home is never the person's own: --url and --dry-run make a temp home with the file store; --home names a temp
home the operator prepared with a login (docs/TESTING.md, "The load test of the name check"). The script refuses
~/.maisecrets and never reads it."""
from __future__ import annotations

import argparse
import collections
import json
import os
import platform
import random
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
LIMIT_PCT = 1.0                 # "Done when" of #105: at most 1 % of the tool results with a rest
MIN_CHARS, MAX_CHARS = 20_000, 100_000
WATCHDOG_S = 16.0               # hooks.WATCHDOG_SECONDS["post-tool"]; the worker reads the real value
SEED = 20261125
STORE = {"backend": "jsonfile", "allow_plaintext_store": True}
# the environment of a client that would change what the plugin code does (tests/_isolate.py)
CLIENT_PREFIXES = ("CODEX_", "CLAUDE_CODE_", "CLAUDE_PLUGIN_OPTION_")
CLIENT_NAMES = ("CLAUDECODE", "XDG_RUNTIME_DIR", "MAISECRETS_KEY_FILE", "MAISECRETS_DEBUG_LOG", "MAISECRETS_MOD_NET")


def own_home() -> str:
    """The person's own store home, as a path only: it is compared, never opened."""
    return os.path.realpath(os.path.join(os.path.expanduser("~"), ".maisecrets"))


def pct(xs: list, q: float) -> float:
    xs = sorted(xs)
    return round(xs[min(len(xs) - 1, int(q * (len(xs) - 1)))], 1) if xs else 0.0


# ------------------------------------------------------------------------------------------------ the tool results --
def results(session: int, seed: int):
    """Endless (shape, response, chars) for one session: Bash and MCP in turn, the length uniform in 20k..100k."""
    sys.path.insert(0, str(ROOT))
    from bench import gatewaygen
    r = random.Random(f"{seed}/session/{session}")
    cases = gatewaygen.objects(10 ** 9, seed + session)
    n = 0
    while True:
        want = r.randint(MIN_CHARS, MAX_CHARS)
        parts, size = [], 0
        while size < want:
            text = next(cases)[0]["text"]
            parts.append(text)
            size += len(text) + 1
        text = "\n".join(parts)[:want]
        if n % 2 == 0:
            yield "bash", {"stdout": text, "stderr": "", "interrupted": False, "isImage": False}, len(text)
        else:
            # an MCP result: its text in blocks, as a server returns a list of records
            cut = len(text) // 2
            yield "mcp", [{"type": "text", "text": text[:cut]}, {"type": "text", "text": text[cut:]}], len(text)
        n += 1


# ---------------------------------------------------------------------------------------------------- the session --
def worker(args) -> int:
    """One session: rows as JSON lines on stdout. MAISECRETS_HOME is set by the driver before maisecrets loads."""
    home = os.environ.get("MAISECRETS_HOME", "")
    if not home or os.path.realpath(home) == own_home():
        print(json.dumps({"error": "no temp home"}), flush=True)
        return 2
    sys.path.insert(0, str(ROOT))
    from maisecrets import detect, home as mhome, hooks, remote_layer, vault
    from maisecrets.detection import remote

    cfg = mhome.load_config()
    conf = dict(cfg.get("remote_detector") or {})
    if args.url:
        conf = {**{k: v for k, v in conf.items() if k not in ("gateway", "gateway_url")}, "url": args.url}
    if not conf.get("url"):
        print(json.dumps({"error": "the home sets no remote_detector (/maisecrets ner gateway URL)"}), flush=True)
        return 2
    cfg = {**cfg, "remote_detector": conf}
    watchdog = float(hooks.WATCHDOG_SECONDS.get("post-tool", WATCHDOG_S))

    count = {"requests": 0, "refused": collections.Counter()}
    plan = {"pieces": 1}
    real_request, real_ask = remote.RemoteDetector._request, remote.RemoteDetector.ask

    def request(self, body, deadline, gate=None):
        count["requests"] += 1
        try:
            return real_request(self, body, deadline, gate)
        except remote._HttpStatus as exc:
            count["refused"][remote._why(exc)] += 1
            raise

    def ask(self, text, occupied, deadline=None, kind=None):
        plain = remote.unescape_json(text)[0]
        plan["pieces"] = len(remote.plan_pieces(plain, self.max_chars)) if self.pieces else 1
        plan["max_chars"], plan["takes_pieces"] = self.max_chars, bool(self.pieces)
        plan["deadline_ms"] = getattr(self, "gateway_deadline_ms", None)
        return real_ask(self, text, occupied, deadline, kind)

    remote.RemoteDetector._request, remote.RemoteDetector.ask = request, ask

    def scan(s: str) -> list:
        return detect.scan(s, channel="tool", path="")

    end = time.monotonic() + args.duration
    t0 = time.monotonic()
    done = 0
    for shape, response, chars in results(args.session, args.seed):
        if (args.count and done >= args.count) or (not args.count and time.monotonic() >= end):
            break
        before, refused_before = count["requests"], collections.Counter(count["refused"])
        began = time.monotonic()
        vault.hook_deadline(watchdog)          # the window of a PostToolUse hook opens here
        try:
            layer = remote_layer.for_tool_result(cfg, response, set(), None, scan, lambda: None)
        finally:
            vault.hook_deadline(None)
        wall = (time.monotonic() - began) * 1000
        if layer is None:
            print(json.dumps({"error": "no remote detector"}), flush=True)
            return 2
        st = layer.status
        total = st.total or chars
        checked = 100.0 if st.state == "ok" else (round(100 * st.checked_to / total, 1) if total else 0.0)
        print(json.dumps({
            "session": args.session, "t_s": round(began - t0, 2), "shape": shape, "chars": chars, "total": total,
            "pieces": plan["pieces"], "requests": count["requests"] - before, "checked_pct": checked,
            "state": st.state, "reason": st.reason, "rest": st.state != "ok",
            "refused": dict(count["refused"] - refused_before), "ner_ms": round(st.ms, 1), "wall_ms": round(wall, 1),
            "max_chars": plan.get("max_chars"), "takes_pieces": plan.get("takes_pieces"),
            "deadline_ms": plan.get("deadline_ms")}), flush=True)
        done += 1
        if args.pause > 0:
            time.sleep(args.pause)
    return 0


# ----------------------------------------------------------------------------------------------------- the driver --
def summarize(rows: list, meta: dict) -> dict:
    n = len(rows)
    rest = sum(1 for r in rows if r["rest"])
    walls = [r["wall_ms"] for r in rows]
    refused = collections.Counter()
    for r in rows:
        refused.update(r["refused"])
    share = round(100 * rest / n, 2) if n else 100.0
    return {
        "results": n, "with_rest": rest, "rest_pct": share, "limit_pct": LIMIT_PCT,
        "verdict": "PASS" if n and share <= LIMIT_PCT else "FAIL",
        "wall_p50_ms": pct(walls, 0.5), "wall_p95_ms": pct(walls, 0.95), "wall_max_ms": max(walls) if walls else 0.0,
        "states": dict(collections.Counter(r["state"] for r in rows)),
        "reasons": dict(collections.Counter(r["reason"] for r in rows if r["rest"])),
        "refusals": dict(refused), "requests": sum(r["requests"] for r in rows),
        "pieces": sum(r["pieces"] for r in rows), "chars": sum(r["chars"] for r in rows),
        "checked_pct_of_rests": pct([r["checked_pct"] for r in rows if r["rest"]], 0.5),
        "by_session": {str(s): sum(1 for r in rows if r["session"] == s) for s in range(meta["sessions"])},
    }


def markdown(meta: dict, s: dict) -> str:
    lines = [
        f"# The load test of the name check (#105): {meta['target']}",
        "",
        f"- Started {meta['started']} on {meta['host']}; {meta['sessions']} sessions, "
        + (f"{meta['count']} results each" if meta["count"] else f"{meta['duration_s']} s")
        + f", a pause of {meta['pause_s']} s after each result, seed {meta['seed']}.",
        f"- Results of {MIN_CHARS:,} to {MAX_CHARS:,} characters (synthetic, bench/gatewaygen.py), Bash and MCP in "
        f"turn, through remote_layer.for_tool_result in the window of a PostToolUse hook.",
        f"- The source: max_chars {meta.get('max_chars')}, pieces {meta.get('takes_pieces')}, the gateway's "
        f"deadline {meta.get('deadline_ms')} ms. Load average before {meta['load_before']}, at most "
        f"{meta['load_max']} during the run.",
        "",
        "| Results | With a rest | Share | Limit | Verdict | Wall p50 | Wall p95 | Wall max |",
        "|---:|---:|---:|---:|---|---:|---:|---:|",
        f"| {s['results']} | {s['with_rest']} | {s['rest_pct']} % | {s['limit_pct']} % | {s['verdict']} | "
        f"{s['wall_p50_ms']} ms | {s['wall_p95_ms']} ms | {s['wall_max_ms']} ms |",
        "",
        f"- States: {json.dumps(s['states'], sort_keys=True)}; reasons of a rest: "
        f"{json.dumps(s['reasons'], sort_keys=True)}.",
        f"- Refused requests: {json.dumps(s['refusals'], sort_keys=True)}; {s['requests']} requests for "
        f"{s['pieces']} pieces planned, {s['chars']:,} characters.",
        "- `load.json` holds the run, the summary and one row per result (no text).",
        "",
    ]
    return "\n".join(lines)


def child_env(home: str) -> dict:
    env = {k: v for k, v in os.environ.items() if not (k.startswith(CLIENT_PREFIXES) or k in CLIENT_NAMES)}
    env.update(MAISECRETS_HOME=home, MAISECRETS_NO_CONTAINER_START="1", MAISECRETS_GUARD_CLIPBOARD="off",
               PYTHONDONTWRITEBYTECODE="1")
    return env


def watch_load(stop: threading.Event, seen: list) -> None:
    while not stop.wait(5.0):
        try:
            seen.append(os.getloadavg()[0])
        except OSError:
            return


def quiet_host() -> bool:
    """No CI build container (a name starting with runner-) and a 1-minute load average below 0.5."""
    try:
        names = subprocess.run(["docker", "ps", "--format", "{{.Names}}"], capture_output=True, text=True,
                               timeout=20).stdout.split()
    except (OSError, subprocess.SubprocessError):
        names = []
    return not any(n.startswith("runner-") for n in names) and os.getloadavg()[0] < 0.5


def driver(args) -> int:
    if args.home and os.path.realpath(args.home) == own_home():
        print("refused: --home is the person's own maisecrets home; prepare a temp home (docs/TESTING.md)",
              file=sys.stderr)
        return 2
    fake = None
    made = ""
    if args.dry_run:
        sys.path.insert(0, str(ROOT))
        from harness.fake_ner import FakeNer
        fake = FakeNer()
        args.url = fake.url
    if args.home:
        home = args.home
    else:
        if not args.url:
            print("give --url, --home or --dry-run", file=sys.stderr)
            return 2
        home = made = tempfile.mkdtemp(prefix="maisecrets-load-home-")
        with open(os.path.join(home, "config.json"), "w", encoding="utf-8") as f:
            json.dump({**STORE, "remote_detector": {"url": args.url}}, f)
    if args.wait_quiet:
        ok = 0
        print("waiting for a quiet host", file=sys.stderr)
        while ok < 3:
            ok = ok + 1 if quiet_host() else 0
            time.sleep(20)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    meta = {"target": "dry run (harness/fake_ner.py)" if args.dry_run else (args.url or "gateway of the temp home"),
            "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "host": f"{platform.system()} {platform.machine()}, {os.cpu_count()} CPUs",
            "sessions": args.sessions, "duration_s": args.duration, "count": args.count, "pause_s": args.pause,
            "seed": args.seed, "load_before": round(os.getloadavg()[0], 2)}
    seen: list = []
    stop = threading.Event()
    threading.Thread(target=watch_load, args=(stop, seen), daemon=True).start()
    cmd = [sys.executable, str(Path(__file__).resolve()), "--worker", "--duration", str(args.duration),
           "--count", str(args.count), "--pause", str(args.pause), "--seed", str(args.seed)]
    if args.url and not args.home:
        cmd += ["--url", args.url]
    procs = [subprocess.Popen(cmd + ["--session", str(i)], env=child_env(home), stdout=subprocess.PIPE,
                              text=True, cwd=str(ROOT)) for i in range(args.sessions)]
    rows, errors = [], []
    try:
        for p in procs:
            stdout, _ = p.communicate()
            for line in stdout.splitlines():
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                (errors if "error" in row else rows).append(row)
    finally:
        stop.set()
        if fake is not None:
            fake.close()
        if made:
            shutil.rmtree(made, ignore_errors=True)
    if errors:
        print(f"a session stopped: {errors[0]['error']}", file=sys.stderr)
        return 2
    rows.sort(key=lambda r: (r["t_s"], r["session"]))
    first = rows[0] if rows else {}
    meta.update(load_max=round(max(seen + [meta["load_before"]]), 2), max_chars=first.get("max_chars"),
                takes_pieces=first.get("takes_pieces"), deadline_ms=first.get("deadline_ms"))
    summary = summarize(rows, meta)
    (out / "load.json").write_text(json.dumps({"meta": meta, "summary": summary, "rows": rows}, indent=1) + "\n",
                                   encoding="utf-8")
    (out / "README.md").write_text(markdown(meta, summary), encoding="utf-8")
    print(json.dumps({k: summary[k] for k in ("results", "with_rest", "rest_pct", "wall_p50_ms", "wall_p95_ms",
                                              "states", "reasons", "refusals")}))
    print(f"{summary['verdict']}: {summary['rest_pct']} % of {summary['results']} results with a rest "
          f"(limit {LIMIT_PCT} %)")
    return 0 if summary["verdict"] == "PASS" else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--url", default="", help="a name service (hf) on this computer, e.g. http://127.0.0.1:8766")
    ap.add_argument("--home", default="", help="a temp maisecrets home with a gateway login and its ner setting")
    ap.add_argument("--dry-run", action="store_true", help="against harness/fake_ner.py on this computer")
    ap.add_argument("--sessions", type=int, default=2)
    ap.add_argument("--duration", type=float, default=600.0, help="seconds per session (without --count)")
    ap.add_argument("--count", type=int, default=0, help="results per session (0: run for --duration)")
    ap.add_argument("--pause", type=float, default=0.0, help="seconds a session waits after each result")
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--wait-quiet", action="store_true",
                    help="first wait for a quiet host: no runner- container, load below 0.5 three times 20 s apart")
    ap.add_argument("--out", default="", help="the directory for load.json and README.md")
    ap.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--session", type=int, default=0, help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    if args.worker:
        return worker(args)
    if not args.out:
        ap.error("--out is required")
    if sum(map(bool, (args.url, args.home, args.dry_run))) != 1:
        ap.error("give exactly one of --url, --home and --dry-run")
    return driver(args)


if __name__ == "__main__":
    sys.exit(main())
