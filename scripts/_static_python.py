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


MAX_LEN = 200_000          # a regex source longer than this is no rule; doubling by `+` stops here
_RE_FLAGS = {name: int(getattr(re, name)) for name in ("IGNORECASE", "I", "MULTILINE", "M", "DOTALL", "S",
                                                       "VERBOSE", "X", "ASCII", "A", "UNICODE", "U")}


def evaluate(node: ast.AST, env: dict[str, Any], calls: dict[str, Callable[..., Any]] | None = None) -> Any:
    calls = calls or {}

    def sized(v: Any) -> Any:
        if isinstance(v, (str, tuple, list)) and len(v) > MAX_LEN:
            raise Unknown("too long")
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
                    return base.join(args[0])
                if not all(isinstance(v, (str, int)) for v in [*args, *kwargs.values()]):
                    raise Unknown("format argument")
                # a field name with `.` or `[` reads attributes of its argument: `{0.__class__}`
                if any(f and ("." in f or "[" in f) for _, f, _, _ in string.Formatter().parse(base)):
                    raise Unknown("format field with an attribute")
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
