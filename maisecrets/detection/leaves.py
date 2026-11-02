"""The findings of a JSON-shaped object, one scan for the whole object, each finding placed in its string leaf.

A caller that holds a parsed response (a dict from an API) and wants the findings of each string in it can scan each
string apart, or write the object as JSON once and scan that. The second finds what the first finds with a field name
before each string (the core reads JSON keys as labels), and on the gateway corpus it took a third of the time:
a call has a fixed cost of about 0.6 ms, and a response has about 170 strings (bench/gateway_report.py, 2026-11-02).
What the caller then needs is each finding in the coordinates of its string, not of the JSON text, and that is what
this module gives:

    from maisecrets.detection.leaves import findings_by_leaf
    for leaf, m in findings_by_leaf(detector, response):
        leaf.path, m.start, m.end, m.type   # the path of the string (keys and list indices), the span in the string

The JSON text is the one `json.dumps(obj, ensure_ascii=False)` writes. A string that needs an escape (a quote, a
backslash, a control character) is mapped back character by character, so a span is always one of the string as
the caller holds it. A finding that starts in a key or in the structure belongs to no leaf (`leaf` is None); one
that starts in a string and runs past its end is cut at the end of the string.
"""
from __future__ import annotations

import dataclasses
import json

_SHORT = {'"': '\\"', "\\": "\\\\", "\n": "\\n", "\r": "\\r", "\t": "\\t", "\b": "\\b", "\f": "\\f"}


@dataclasses.dataclass(frozen=True)
class Leaf:
    """A string of the object: its path (dict keys and list indices, outermost first), the string, and where it sits
    in the JSON text."""
    path: tuple
    value: str
    start: int
    end: int
    places: tuple   # the JSON offset of each character of value, and of its end, relative to start


def _escape(s: str) -> tuple:
    out, places, n = [], [], 0
    for ch in s:
        places.append(n)
        e = _SHORT.get(ch) or (f"\\u{ord(ch):04x}" if ord(ch) < 0x20 else ch)
        out.append(e)
        n += len(e)
    places.append(n)
    return "".join(out), tuple(places)


def json_text(obj) -> tuple:
    """`(text, leaves)`: the object as JSON text, as json.dumps(obj, ensure_ascii=False) writes it, and its strings.
    Raises TypeError for a value JSON cannot hold and ValueError for a cycle, as json.dumps does."""
    parts, leaves, n, seen = [], [], 0, set()

    def put(s: str) -> None:
        nonlocal n
        parts.append(s)
        n += len(s)

    def walk(x, path: tuple) -> None:
        if isinstance(x, str):
            written, places = _escape(x)
            put('"')
            leaves.append(Leaf(path, x, n, n + len(written), places))
            put(written + '"')
        elif x is None or isinstance(x, (bool, int, float)):
            put(json.dumps(x))
        elif isinstance(x, (dict, list, tuple)):
            if id(x) in seen:
                raise ValueError("Circular reference detected")
            seen.add(id(x))
            if isinstance(x, dict):
                put("{")
                for i, (k, v) in enumerate(x.items()):
                    if not isinstance(k, (str, int, float, bool)) and k is not None:
                        raise TypeError(f"keys must be str, int, float, bool or None, not {type(k).__name__}")
                    key = k if isinstance(k, str) else json.dumps(k)
                    put((", " if i else "") + '"' + _escape(key)[0] + '": ')
                    walk(v, path + (key,))
                put("}")
            else:
                put("[")
                for i, v in enumerate(x):
                    put(", " if i else "")
                    walk(v, path + (i,))
                put("]")
            seen.discard(id(x))
        else:
            raise TypeError(f"Object of type {type(x).__name__} is not JSON serializable")
    walk(obj, ())
    return "".join(parts), leaves


def _back(places: tuple, offset: int, end: bool) -> int:
    """The character of the string at a JSON offset inside it: the last one that starts at or before it, or for an
    end the first one that starts at or after it."""
    lo, hi = 0, len(places) - 1
    while lo < hi:
        mid = (lo + hi + (0 if end else 1)) // 2
        if (places[mid] < offset) if end else (places[mid] <= offset):
            lo = mid + (1 if end else 0)
        else:
            hi = mid - (0 if end else 1)
    return lo


def findings_by_leaf(detector, obj, channel: str = "tool", **kwargs) -> list:
    """The findings of one scan of the object's JSON text, as `(leaf, match)`: `match.start`, `match.end` and
    `match.value` are those of the string `leaf.value`. Further keyword arguments go to `detector.findings`."""
    text, leaves = json_text(obj)
    out, k = [], 0
    for m in sorted(detector.findings(text, channel=channel, **kwargs), key=lambda m: m.start):
        while k < len(leaves) and leaves[k].end < m.start:
            k += 1
        leaf = leaves[k] if k < len(leaves) and leaves[k].start <= m.start < max(leaves[k].end, leaves[k].start + 1) \
            else None
        if leaf is None or leaf.start == leaf.end:
            out.append((None, m))
            continue
        s = _back(leaf.places, m.start - leaf.start, end=False)
        e = _back(leaf.places, min(m.end, leaf.end) - leaf.start, end=True)
        out.append((leaf, dataclasses.replace(m, start=s, end=e, value=leaf.value[s:e])))
    return out
