"""A password export read in a tool result: every cell of its password, TOTP and secret columns is masked. No other
rule finds a bare password in a cell, so an export read whole put every password in front of the model.

The table is told by its header row (a secret column next to an entry column such as url, username, name or title),
or by the file name of an export when the header has a secret column alone. A typed prompt keeps its decisions.

Run: python3 -m unittest tests.test_password_export -v
Every value is built at run time, so no literal sits in the tree and the tree scan stays clean.
"""
from __future__ import annotations

import os
import random
import string
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect  # noqa: E402

RNG = random.Random(55)
ESC = "\x1b"


def pw() -> str:
    return "".join(RNG.choice(string.ascii_letters + string.digits + "!#%") for _ in range(14))


SEED = "".join(RNG.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(32))


def masked(text: str, path: str = "", channel: str = "tool") -> list[str]:
    return [m.value for m in detect.scan(text, channel=channel, path=path) if m.kind == detect.EXPORT_RULE]


class ExportTests(unittest.TestCase):
    def test_the_password_column_of_each_known_export_is_masked(self):
        p = [pw() for _ in range(6)]
        exports = {
            "chrome": ("name,url,username,password,note\n"
                       f"example.com,https://example.com/login,alice,{p[0]},\n"
                       f"shop.test,https://shop.test/,bob,{p[1]},my note\n", [p[0], p[1]]),
            "firefox": ('"url","username","password","httpRealm","formActionOrigin","guid","timeCreated"\n'
                        f'"https://example.com","alice","{p[2]}",,"https://example.com","{{x-1}}","1700000000000"\n',
                        [p[2]]),
            "keepassxc": ('"Group","Title","Username","Password","URL","Notes","TOTP","Icon","Last Modified"\n'
                          f'"Root","Router","admin","{p[3]}","http://router.test","","","0","2026-01-01"\n', [p[3]]),
            "lastpass": ("url,username,password,totp,extra,name,grouping,fav\n"
                         f"https://example.com,alice,{p[4]},{SEED},,Example,,0\n", [p[4], SEED]),
            "german, semicolons": (f"Titel;Benutzername;Passwort;URL\nRouter;admin;{p[5]};http://router.test\n",
                                   [p[5]]),
        }
        for name, (text, values) in exports.items():
            with self.subTest(name=name):
                self.assertEqual(masked(text), values)

    def test_a_quoted_cell_with_a_line_break_keeps_the_columns_in_place(self):
        p = pw()
        text = ("folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"
                f',,login,Mail,"line one\nline, two",,0,https://mail.test,alice,{p},{SEED}\n')
        self.assertEqual(masked(text), [p, SEED])

    def test_a_doubled_quote_stays_inside_its_cell(self):
        p = 'ab""cd' + pw()
        text = f'"Title","Username","Password"\n"Bank","alice","{p}"\n'
        self.assertEqual(masked(text), [p])

    def test_a_bracket_in_a_password_is_masked_and_a_placeholder_is_not(self):
        p = pw()[:6] + "\u27e6" + pw()[:6]
        placeholder = "\u27e6" + "SECRET_c7" + "\u27e7"
        text = f"name,url,username,password\na,https://a.test,alice,{p}\nb,https://b.test,bob,{placeholder}\n"
        self.assertEqual(masked(text), [p])

    def test_a_password_around_a_placeholder_is_masked_and_the_placeholder_stays(self):
        a, b = pw()[:6], pw()[:6]
        placeholder = "\u27e6" + "SECRET_c7" + "\u27e7"
        text = f"name,url,username,password\nx,https://x.test,alice,{a}{placeholder}{b}\n"
        self.assertEqual(masked(text), [a, b])

    def test_a_header_in_colour_still_names_its_columns(self):
        p = pw()
        text = f"name,url,username,{ESC}[31mpassword{ESC}[0m\nexample.com,https://example.com,alice,{p}\n"
        self.assertEqual([m.value for m in detect.scan(text, channel="tool")], [p])

    def test_a_quote_that_opens_no_cell_does_not_swallow_the_next_row(self):
        a, b = pw(), pw()
        text = f'name,username,password\nsite1,alice,"{a}\n"site2",bob,{b}\n'
        self.assertEqual(masked(text), ['"' + a, b])

    def test_a_schema_or_a_masked_export_keeps_its_words(self):
        text = ("name,url,username,password\nfield,url,string,string\nflag,https://x.test,bool,false\n"
                "masked,https://y.test,alice,********\nnone,https://z.test,bob,null\n")
        self.assertEqual(masked(text), [])

    def test_a_quote_that_nothing_closes_ends_its_cell_at_the_line_end(self):
        p = '"' + pw()
        text = f"name,url,username,password\nexample.com,https://example.com,alice,{p}\nnext line stays text\n"
        self.assertEqual(masked(text), [p])

    def test_the_file_name_of_an_export_is_enough_for_a_password_column_alone(self):
        p = pw()
        text = f"password,comment\n{p},old router\n"
        self.assertEqual(masked(text), [], "a password column alone is no export")
        self.assertEqual(masked(f"user_name,password\nalice,{p}\n"), [p], "two plain column names")
        self.assertEqual(masked(f"user, password\nalice, {p}\n"), [], "two words of a sentence are no header")
        for path in ("/home/u/Downloads/passwords.csv", "C:\\Users\\u\\bitwarden_export_2026.csv",
                     "/tmp/1PasswordExport-2026.csv", "/tmp/lastpass_export.csv", "/tmp/keepass.tsv"):
            with self.subTest(path=path):
                self.assertEqual(masked(text, path), [p])

    def test_a_typed_prompt_keeps_its_decision(self):
        p = pw()
        text = f"name,url,username,password\nexample.com,https://example.com,alice,{p}\n"
        self.assertEqual(masked(text, channel="prompt"), [])

    def test_tables_that_are_no_export_stay_text(self):
        cases = {
            "sql": "SELECT name, password FROM users WHERE id = 1;\nSELECT url, username, password_hash FROM t;\n",
            "prose": "The export has the columns name,url,username,password.\nThen open it, check it, delete it.\n",
            "header only": "name,url,username,password\n",
            "flags": "id,name,is_secret,has_password\n1,alpha,true,false\n2,beta,false,true\n",
            "nlp": "id,text,token,label\n1,hello world,hello,greeting\n",
            "a hash column": "user,password_hash\nalice,abcdef0123456789\n",
            "empty cells": "name,url,username,password\nexample.com,https://example.com,alice,\n",
            "a signature": "def login(user, password):\n    session = open_session(user, timeout)\n"
                           "    return check(session, password)\n",
            "js": "function login(username, password, url) {\n  return post(url, username, password);\n}\n",
            "a list line": '    "user", "pass", "pwd", "name",\n    "max", "admin", "root", "guest",\n',
            "indented": "    name,url,username,password\n    a,b,c,d\n",
            "two words of prose": "username, password\nThen run it, and wait\n",
            "two columns of a schema": "name,password\nusername,minimum 8 characters\n",
            "a test table": "test name\tusername\tpassword\nrejects empty password\talice\tempty string\n",
            "a sentence of three columns": "Username, Email Address, Password\nAlice, she signs in, then logs out\n",
            "sql of three columns": "SELECT username, password, email FROM users\nWHERE a = 1, b = 2, c = 3\n",
        }
        for name, text in cases.items():
            with self.subTest(name=name):
                self.assertEqual(masked(text), [])

    def test_the_table_ends_at_an_empty_line_or_a_row_of_another_width(self):
        p = pw()
        for tail in ("\n\na,b,c,d\n", "\nsummary, two entries, one folder, no errors, done\na,b,c,d\n"):
            with self.subTest(tail=tail):
                text = f"name,url,username,password\nexample.com,https://example.com,alice,{p}" + tail
                self.assertEqual(masked(text), [p])

    def test_the_hook_masks_an_export_that_a_read_returns_and_passes_its_file_path(self):
        import json
        import tempfile
        from maisecrets import hooks
        Path(_isolate.HOME).mkdir(parents=True, exist_ok=True)
        Path(_isolate.HOME, "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')
        p = pw()
        content = f"password,comment\n{p},old router\n"   # a secret column alone: only the file name tells
        ctx = {"session_id": "S1", "prompt_id": "p1", "transcript_path": "", "cwd": tempfile.gettempdir()}
        for name, key, leaks in (("passwords.csv", "file_path", False), ("notes.csv", "file_path", True),
                                 ("passwords.csv", "path", False)):
            with self.subTest(name=name, key=key):
                path = os.path.join(tempfile.gettempdir(), name)
                out = hooks.post_tool({"tool_name": "Read", **ctx, "tool_input": {key: path},
                                       "tool_response": {"type": "text",
                                                         "file": {"filePath": path, "content": content}}})
                self.assertEqual(p in json.dumps(out) or not out, leaks)


if __name__ == "__main__":
    unittest.main()
