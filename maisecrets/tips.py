"""One short tip per day at session start, rotating. Off with {"tips": false} in config.json."""
from __future__ import annotations

import time

from .vault import HOME, load_config

TIPS = [
    "maisecrets: write `password: <value>` (or passwort:, api_key=) and the value goes to your vault; "
    "Claude gets a placeholder and can still use it in commands.",
    "maisecrets: copy a value, then /maisecrets:put stores it and hands back the placeholder in your clipboard.",
    "maisecrets: a placeholder resolves only in a session where you typed it. Paste it into a prompt to allow it here.",
    "maisecrets: /maisecrets:report prepares a GitHub issue from the last detection, without the value. "
    "Also: report bug <text>, report feature <text>.",
    "maisecrets: `python3 -m maisecrets.cli audit` lists every resolve: when, which key, which command.",
    "maisecrets: a bare password in prose is not detected. Label it, or use /maisecrets:put.",
]


def tip_of_the_day() -> str | None:
    if load_config().get("tips", True) is False:
        return None
    state = HOME / ".tip"
    today = time.strftime("%Y-%m-%d")
    try:
        last_day, idx = state.read_text(encoding="utf-8").split()
        idx = int(idx)
    except (OSError, ValueError):
        last_day, idx = "", -1
    if last_day == today:
        return None
    idx = (idx + 1) % len(TIPS)
    try:
        HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
        state.write_text(f"{today} {idx}\n", encoding="utf-8")
    except OSError:
        pass
    return TIPS[idx]
