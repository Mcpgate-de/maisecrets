"""Fakes for the platform tools that PATH cannot replace on Windows.

Windows finds clip.exe and powershell.exe in System32 before any directory on PATH, so the PATH
tripwires of tests/_isolate.py never ran there: the tests wrote the clipboard of the CI runner and
read 11 characters of something else back (windows-latest, 2026-09-27). _isolate.py puts this
module on PYTHONPATH through a sitecustomize, so every Python child of a test imports it at start.

- `clip` writes to $MS_TEST_CLIP, `powershell ... Get-Clipboard` reads it; without MS_TEST_CLIP
  each one notes the call in the tripwire file and fails.
- any other `powershell` call (the Credential Locker store) notes the call and fails.
- `os.startfile` (the browser on Windows) appends the URL to $MS_TEST_OPENED.

MAISECRETS_NATIVE_BACKEND_TEST=1 keeps the real powershell, MAISECRETS_NATIVE_CLIPBOARD_TEST=1 the
real clip and powershell: the native tests use the real tools on purpose.
"""
import os
import subprocess
import sys

FAKE = os.path.abspath(__file__)
_REAL_INIT = subprocess.Popen.__init__


def _tripwire_path() -> str:
    return os.environ.get("MS_TEST_TRIPWIRE") or os.path.join(os.environ.get("MAISECRETS_TEST_TMP_OWNED", "."),
                                                              "tripwire")


def _faked() -> set:
    names = {"clip", "powershell"}
    if os.environ.get("MAISECRETS_NATIVE_CLIPBOARD_TEST") == "1":
        names = set()
    elif os.environ.get("MAISECRETS_NATIVE_BACKEND_TEST") == "1":
        names.discard("powershell")
    return names


def _name(args) -> str:
    first = args[0] if isinstance(args, (list, tuple)) and args else str(args).split(" ", 1)[0]
    base = os.path.basename(str(first)).lower()
    return base[:-4] if base.endswith(".exe") else base


def _init(self, args, *a, **kw):
    if not kw.get("shell") and _name(args) in _faked():
        rest = list(args[1:]) if isinstance(args, (list, tuple)) else []
        args = [sys.executable, FAKE, _name(args), *rest]
    _REAL_INIT(self, args, *a, **kw)


def install() -> None:
    subprocess.Popen.__init__ = _init
    if os.name == "nt":
        def startfile(path, *a, **kw):
            target = os.environ.get("MS_TEST_OPENED")
            with open(target or _tripwire_path(), "a", encoding="utf-8") as f:
                f.write(f"{path}\n" if target else f"os.startfile {path}\n")
        os.startfile = startfile


def _main(argv: list) -> int:
    tool, rest = argv[0], argv[1:]
    clip = os.environ.get("MS_TEST_CLIP")
    if tool == "clip" and clip:
        data = sys.stdin.buffer.read()
        text = data[2:].decode("utf-16-le") if data[:2] == b"\xff\xfe" else data.decode("utf-8")
        with open(clip, "w", encoding="utf-8") as f:
            f.write(text)
        return 0
    if tool == "powershell" and clip and "Get-Clipboard" in " ".join(rest):
        try:
            with open(clip, encoding="utf-8") as f:
                sys.stdout.buffer.write(f.read().encode("utf-8"))
        except FileNotFoundError:
            pass
        return 0
    with open(_tripwire_path(), "a", encoding="utf-8") as f:
        f.write(f"{tool} {' '.join(rest)}\n")
    return 1


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
