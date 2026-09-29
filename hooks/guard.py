#!/usr/bin/env python3
"""The maisecrets guard: a hook that lives outside the plugin folder.

A Claude Code update of a synced plugin rewrites its folder, and a session whose plugin was loaded
from it then runs none of its hooks, silently (anthropics/claude-code#97847; measured 2026-09-29:
the session that started the sync ran no maisecrets hook either, while /plugin showed the new
version). Nothing inside the plugin can see that. A synced maisecrets places this script at
~/.claude/maisecrets-guard.py and registers it with the plugin's matchers.

For each prompt and tool call it waits a moment for the heartbeat that every maisecrets hook writes
when it starts (~/.maisecrets/alive/<hash of session, event and id>). No heartbeat means maisecrets
did not run for this call: the prompt is blocked, the tool call denied, a tool result withheld. It
stays silent where maisecrets is not meant to run: another account, a plugin switched off in the
user, project, local or managed settings, Codex. The heartbeat stays where it is (a second guard
registration may wait for the same one); maisecrets sweeps old ones. Standard library only, and no
import from the plugin: the plugin folder is exactly what may be missing.

    python3 ~/.claude/maisecrets-guard.py --off    switch the guard off from a terminal
"""
import hashlib
import json
import os
import re
import sys
import time

EVENTS = {"UserPromptSubmit": "user-prompt", "PreToolUse": "pre-tool", "PostToolUse": "post-tool"}
MESSAGE = ("maisecrets did not run for this call: a plugin update replaced its folder, or it started too slowly. "
           "Run /reload-plugins, then try again. If maisecrets is off on purpose, switch the guard off in a terminal: "
           "python3 {script} --off")
MANAGED = {"darwin": "/Library/Application Support/ClaudeCode/managed-settings.json",
           "linux": "/etc/claude-code/managed-settings.json"}


def _home() -> str:
    return os.environ.get("MAISECRETS_HOME") or os.path.join(os.path.expanduser("~"), ".maisecrets")


def _claude_dir() -> str:
    return os.environ.get("CLAUDE_CONFIG_DIR") or os.path.join(os.path.expanduser("~"), ".claude")


def _load(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _switched_off(cwd: str) -> bool:
    """maisecrets disabled in any settings Claude Code reads: user, managed, or a project's own."""
    files = [os.path.join(_claude_dir(), "settings.json"), MANAGED.get(sys.platform, "")]
    # the project's own settings: from cwd up to the project root (a .git) or the home directory
    d = os.path.abspath(cwd) if cwd else ""
    stop = os.path.expanduser("~")
    while d:
        files += [os.path.join(d, ".claude", "settings.json"), os.path.join(d, ".claude", "settings.local.json")]
        parent = os.path.dirname(d)
        # a submodule has a .git file, not a folder: its superproject's settings count too
        if parent == d or d == stop or os.path.isdir(os.path.join(d, ".git")):
            break
        d = parent
    for f in files:
        plugins = _load(f).get("enabledPlugins") if f else None
        if isinstance(plugins, dict) and any("maisecrets" in k and v is False for k, v in plugins.items()):
            return True
    return False


def _account() -> str:
    """<organizationUuid>_<accountUuid> of the account Claude Code runs as, the name of its synced folder."""
    account_file = (os.path.join(_claude_dir(), ".claude.json") if os.environ.get("CLAUDE_CONFIG_DIR")
                    else os.path.join(os.path.expanduser("~"), ".claude.json"))
    acc = _load(account_file).get("oauthAccount") or {}
    org, user = acc.get("organizationUuid"), acc.get("accountUuid")
    return f"{org}_{user}" if org and user else ""


TRASH_WINDOW = 15 * 60
# the folder names of a synced copy: an update writes the next generation beside the last one
# (maisecrets, then maisecrets~g2, ...; measured 2026-09-29) and moves the old one to the trash
_SYNCED_NAME = re.compile(r"maisecrets(~g\d+)?")


def _synced_copies(claude: str, account: str) -> list:
    """Every maisecrets copy the sync holds for this account, whichever generation it is."""
    base = os.path.join(claude, "plugins", "synced", account)
    try:
        names = os.listdir(base)
    except OSError:
        return []
    return [os.path.join(base, n) for n in names if _SYNCED_NAME.fullmatch(n)
            and os.path.isfile(os.path.join(base, n, ".claude-plugin", "plugin.json"))]
# after the start, how long an answer may take: maisecrets answers within its own watchdog (7 s for a
# prompt and a tool call, 16 s for a tool result; maisecrets/hooks.py WATCHDOG_SECONDS) plus a margin. The
# guard's hook timeout (GUARD_TIMEOUTS in maisecrets/cli.py) covers the start wait and this
ANSWER_WAIT = {"UserPromptSubmit": 8.0, "PreToolUse": 8.0, "PostToolUse": 17.0}


def _recently_trashed(claude: str) -> bool:
    """A maisecrets folder that Claude Code moved to plugins/.trash in the last minutes (an update)."""
    trash = os.path.join(claude, "plugins", ".trash")
    now = time.time()
    try:
        entries = os.listdir(trash)
    except OSError:
        return False
    for entry in entries:
        d = os.path.join(trash, entry)
        try:
            names = os.listdir(d)
            # a move keeps a folder's mtime on APFS; the change time, and the new trash entry, say when
            st = os.stat(d)
            moved = max(st.st_mtime, st.st_ctime)
        except OSError:
            continue            # a plain file or a folder we cannot read: the next entry
        if any(n.startswith("maisecrets") for n in names) and now - moved < TRASH_WINDOW:
            return True
    return False


def expected(cwd: str = "") -> bool:
    """Whether maisecrets is meant to run here, by the same rule under which it writes its heartbeat
    (guard.json present, or a synced copy)."""
    cfg = _load(os.path.join(_home(), "guard.json"))
    mode = cfg.get("expect")
    if mode == "off":
        return False
    if _switched_off(cwd):
        return False
    if mode == "always":
        return True
    claude = _claude_dir()
    account = _account()
    # the synced copy that registered the guard wrote the account it ran as. For that account maisecrets is
    # meant to run while its synced folder is there, and in the minutes after an update moved it to the
    # trash (a folder that is gone is the case the guard is for). A folder gone for longer means the
    # organisation took maisecrets out of the sync: the guard stops expecting it, or it would block every
    # session for good (reviews, 2026-09-29). Another account falls through to its own synced folder.
    registered = cfg.get("accounts") if isinstance(cfg.get("accounts"), list) else [cfg.get("account")]
    if account and account in registered:
        roots = cfg.get("roots") if isinstance(cfg.get("roots"), dict) else {}
        folders = [roots[account]] if isinstance(roots.get(account), str) else []
        # the folder this account's copy ran from (measured), then every copy the sync holds for it now
        folders += _synced_copies(claude, account)
        return (any(os.path.isfile(os.path.join(f, ".claude-plugin", "plugin.json")) for f in folders)
                or _recently_trashed(claude))
    if account and _synced_copies(claude, account):
        return True
    if mode is None:
        return False            # no guard.json and no synced copy: maisecrets writes no heartbeat here
    installed = _load(os.path.join(claude, "plugins", "installed_plugins.json")).get("plugins") or {}
    return any(k.startswith("maisecrets@") for k in installed)


def heartbeat_name(session: str, event: str, ident: str) -> str:
    """The same name maisecrets.hooks._heartbeat writes; the tests hold both to it."""
    return hashlib.sha256(f"{session}\0{event}\0{ident}".encode()).hexdigest()[:32]


def _refusal(hook_event: str) -> dict:
    message = MESSAGE.format(script=os.path.join(_claude_dir(), "maisecrets-guard.py"))
    if hook_event == "UserPromptSubmit":
        return {"decision": "block", "reason": message}
    if hook_event == "PreToolUse":
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                       "permissionDecisionReason": message}}
    return {"hookSpecificOutput": {"hookEventName": "PostToolUse",
                                   "updatedToolOutput": f"[{message} The tool ran; its output is withheld.]"}}


def decide(payload: dict, wait: float) -> dict:
    hook_event = payload.get("hook_event_name", "")
    event = EVENTS.get(hook_event)
    if event is None or "turn_id" in payload or "prompt_id" not in payload:
        return {}               # not an event maisecrets guards, or not Claude Code (Codex sends turn_id)
    ident = payload.get("prompt_id") if event == "user-prompt" else payload.get("tool_use_id")
    session = payload.get("session_id")
    if not ident or not session or not expected(str(payload.get("cwd") or "")):
        return {}
    done = os.path.join(_home(), "alive", heartbeat_name(session, event, ident))
    started = done + ".s"
    begin = time.monotonic()
    while True:
        if os.path.exists(done):
            return {}           # maisecrets answered this call
        now = time.monotonic()
        # no start within `wait`: maisecrets does not run; started but no answer by its own watchdog: it died
        if (now - begin >= wait and not os.path.exists(started)) or now - begin >= wait + ANSWER_WAIT[hook_event]:
            return _refusal(hook_event)
        time.sleep(0.05)


def switch_off() -> str:
    home = _home()
    os.makedirs(home, mode=0o700, exist_ok=True)
    cfg = _load(os.path.join(home, "guard.json"))
    with open(os.path.join(home, "guard.json"), "w", encoding="utf-8") as f:
        # the person's own off: without "by", so a policy that allows the guard again does not undo it
        json.dump({**{k: v for k, v in cfg.items() if k != "by"}, "expect": "off"}, f)
    return f"the maisecrets guard is off ({os.path.join(home, 'guard.json')}); /maisecrets:guard install turns it on"


def main() -> int:
    if sys.argv[1:] == ["--off"]:
        print(switch_off())
        return 0
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        payload = {}
    try:
        wait = float(os.environ.get("MAISECRETS_GUARD_WAIT", "5"))
    except ValueError:
        wait = 5.0
    out = decide(payload if isinstance(payload, dict) else {}, wait)
    sys.stdout.write(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
