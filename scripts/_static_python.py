"""Read constants out of Python source without running it.

The sync scripts take regexes from upstream Python files (detect-secrets' keyword.py, the Presidio
recognizers). Executing that code ran upstream code in the job that holds the Renovate token (reviews,
2026-10-06). This evaluator knows only the forms those files build their regexes from: literals,
names bound before, f-strings, `+` on strings and sequences, `|` on flags, `str.format`, `str.join`,
`re.compile`, the `re` flags, and calls the caller names (such as `Pattern`). Anything else raises
`Unknown`, and the caller leaves that name out.
"""
from __future__ import annotations

import ast
import re
import string
from typing import Any, Callable, NamedTuple


class Unknown(Exception):
    """A form the evaluator does not know; the name it was bound to stays undefined."""


class Rx(NamedTuple):
    """What `re.compile` would have made, as data."""
    pattern: str
    flags: int


MAX_LEN = 200_000          # a regex source longer than this is no rule; every value in total stays below it
_RE_FLAGS = {"IGNORECASE": int(re.IGNORECASE), "I": int(re.I), "MULTILINE": int(re.MULTILINE), "M": int(re.M),
             "DOTALL": int(re.DOTALL), "S": int(re.S), "VERBOSE": int(re.VERBOSE), "X": int(re.X),
             "ASCII": int(re.ASCII), "A": int(re.A), "UNICODE": int(re.UNICODE), "U": int(re.U)}


def weight(v: Any, budget: list[int] | None = None) -> int:
    """Characters plus items of a value, counted through nested containers, shared references included
    (`A = [A, A]` doubles without growing `len`). Stops as soon as the total passes MAX_LEN."""
    budget = budget if budget is not None else [MAX_LEN]
    budget[0] -= len(v) if isinstance(v, str) else 1
    if budget[0] < 0:
        raise Unknown("too large")
    if isinstance(v, (tuple, list, set, frozenset)):
        for x in v:
            weight(x, budget)
    elif isinstance(v, dict):
        for k, x in v.items():
            weight(k, budget)
            weight(x, budget)
    return MAX_LEN - budget[0]


def evaluate(node: ast.AST, env: dict[str, Any], calls: dict[str, Callable[..., Any]] | None = None) -> Any:
    calls = calls or {}

    def sized(v: Any) -> Any:
        weight(v)
        return v

    def ev(n: ast.AST) -> Any:
        return sized(_ev(n))

    def _ev(n: ast.AST) -> Any:
        if isinstance(n, ast.Constant) and isinstance(n.value, (str, int, float, bool, type(None))):
            return n.value
        if isinstance(n, ast.Name):
            if n.id in env:
                return env[n.id]
            raise Unknown(n.id)
        if isinstance(n, ast.JoinedStr):
            parts = []
            for v in n.values:
                if isinstance(v, ast.Constant):
                    parts.append(v.value)
                elif isinstance(v, ast.FormattedValue) and v.conversion == -1 and v.format_spec is None:
                    value = ev(v.value)
                    if not isinstance(value, (str, int)):
                        raise Unknown("f-string value")
                    parts.append(str(value))
                else:
                    raise Unknown("f-string form")
            return "".join(parts)
        if isinstance(n, (ast.Tuple, ast.List)):
            items = [ev(e) for e in n.elts]
            return tuple(items) if isinstance(n, ast.Tuple) else items
        if isinstance(n, ast.Set):
            return {ev(e) for e in n.elts}
        if isinstance(n, ast.Dict):
            if any(k is None for k in n.keys):
                raise Unknown("dict unpacking")
            return {ev(k): ev(v) for k, v in zip(n.keys, n.values)}
        if isinstance(n, ast.BinOp):
            left, right = ev(n.left), ev(n.right)
            if isinstance(n.op, ast.Add) and type(left) is type(right) and isinstance(left, (str, tuple, list)):
                return left + right
            if isinstance(n.op, ast.BitOr) and isinstance(left, int) and isinstance(right, int):
                return left | right
            raise Unknown("operator")
        if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "re":
            if n.attr in _RE_FLAGS:
                return _RE_FLAGS[n.attr]
            raise Unknown(f"re.{n.attr}")
        if isinstance(n, ast.Call):
            args = [ev(a) for a in n.args]
            if any(k.arg is None for k in n.keywords):
                raise Unknown("keyword unpacking")
            kwargs = {k.arg: ev(k.value) for k in n.keywords}
            f = n.func
            if isinstance(f, ast.Attribute) and f.attr in ("format", "join"):
                base = ev(f.value)
                if not isinstance(base, str):
                    raise Unknown(f"{f.attr} on a non-string")
                if f.attr == "join":
                    if kwargs or len(args) != 1 or not all(isinstance(a, str) for a in args[0]):
                        raise Unknown("join form")
                    if sum(len(a) for a in args[0]) + len(base) * len(args[0]) > MAX_LEN:
                        raise Unknown("join too long")
                    return base.join(args[0])
                if not all(isinstance(v, (str, int)) for v in [*args, *kwargs.values()]):
                    raise Unknown("format argument")
                # a field name with `.` or `[` reads attributes of its argument: `{0.__class__}`
                fields = list(string.Formatter().parse(base))
                if any(f and ("." in f or "[" in f) for _, f, _, _ in fields):
                    raise Unknown("format field with an attribute")
                # a spec or a conversion (`{0:>400000000}`, `{0!r}`) is no form the rules use, and a width
                # builds a value of any size before its length could be checked
                if any(spec or conv for _, f, spec, conv in fields if f is not None):
                    raise Unknown("format spec")
                values = {**{str(i): a for i, a in enumerate(args)}, **kwargs}
                size, auto = len(base), 0
                for _, f, _, _ in fields:
                    if f is None:
                        continue
                    key = f if f else str(auto)
                    auto += f == ""
                    size += len(str(values.get(key, "")))
                if size > MAX_LEN:
                    raise Unknown("format too long")
                return base.format(*args, **kwargs)
            if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == "re" \
                    and f.attr == "compile":
                pattern = args[0] if args else kwargs.get("pattern")
                flags = args[1] if len(args) > 1 else kwargs.get("flags", 0)
                if not isinstance(pattern, str) or not isinstance(flags, int):
                    raise Unknown("re.compile form")
                return Rx(pattern, flags)
            if isinstance(f, ast.Name) and f.id in calls:
                return calls[f.id](*args, **kwargs)
            raise Unknown("call")
        raise Unknown(type(n).__name__)

    return ev(node)


def bind(body: list[ast.stmt], env: dict[str, Any], calls: dict[str, Callable[..., Any]] | None = None) -> None:
    """Evaluate each `NAME = value` (and `NAME: type = value`) of a module or class body into env, in
    order. A value the evaluator does not know leaves the name unbound, as an import error would."""
    for stmt in body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            target, value = stmt.targets[0].id, stmt.value
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
            target, value = stmt.target.id, stmt.value
        else:
            continue
        try:
            env[target] = evaluate(value, env, calls)
        except (Unknown, ValueError, KeyError, IndexError, TypeError):
            env.pop(target, None)
