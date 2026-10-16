"""An address with its @ written as %40 in a CSV cell is an address when the header of its column names one.

0.6.24 took only a header with "mail" in it (review round 1 of 0.6.24: any cell of any row was too much, a locale
table and a package list gave false hits). A column of addresses under `contact`, `login`, `username`,
`recipient`, `courriel` or `correo` then passed. A header now counts when it names a mail address or the one an
address belongs to. A row without a header stays text, as before: its shape alone is the shape of a locale table.

Run: python3 -m unittest tests.test_encoded_mail_columns -v
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect  # noqa: E402

ADDRESS = "dana.okafor" + "%40" + "okafor-family.net"


def encoded(text: str, channel: str = "tool") -> list:
    return [text[m.start:m.end] for m in detect.scan(text, channel=channel) if m.kind == "email-percent-encoded"]


class EncodedMailColumnTests(unittest.TestCase):
    def test_a_column_named_for_the_owner_of_an_address_masks_it(self):
        for text in ("name,contact,phone\nDana," + ADDRESS + ",unknown",
                     "user_id,login,role\n4711," + ADDRESS + ",admin",
                     "id;username;created\n4711;" + ADDRESS + ";2026-01-02",
                     "sent_at\trecipient\tstatus\n2026-01-02\t" + ADDRESS + "\tdelivered",
                     'id,"User",role\n4711,"' + ADDRESS + '",admin',
                     "nom,courriel\nDana," + ADDRESS,
                     "nombre;correo\nDana;" + ADDRESS,
                     "navn,e-post\nDana," + ADDRESS,
                     "name,email,phone\nDana," + ADDRESS + ",unknown"):
            for channel in ("tool", "prompt"):
                with self.subTest(text=text.split("\n")[0], channel=channel):
                    self.assertEqual(encoded(text, channel), [ADDRESS])

    def test_another_column_and_a_row_without_a_header_stay_text(self):
        for text in ("locale,key,value\nen,contact%40acme-shop.dev,enabled",
                     "scope,package\n@angular,core%40angular.dev",
                     "id,kunde,status\n4711," + ADDRESS + ",open",
                     "Dana," + ADDRESS + ",unknown",
                     "package,from,to\nreact,react%40v17.dev,react%40v18.dev"):
            with self.subTest(text=text.split("\n")[0]):
                self.assertEqual(encoded(text), [])

    def test_an_asset_name_in_an_address_column_stays_text(self):
        # name%402x.png is an image at twice the size, also in a column of a contact table
        for text in ("contact_photo,size\nportrait%402x.jpg,2048", "user,avatar\navatar%403x.webp,1024"):
            with self.subTest(text=text):
                self.assertEqual(encoded(text), [])

    def test_a_title_line_above_the_header_does_not_hide_it(self):
        # the title has a comma and the word user: it is a line of its own, and the header below it still counts
        for title in ("Report for user list, generated 2026-10-01", "Login audit, page 1", "Contacts export, v2"):
            text = title + "\nid,email\n1," + ADDRESS + "\n"
            with self.subTest(title=title):
                self.assertEqual(encoded(text), [ADDRESS])

    def test_a_cell_with_spaces_around_it_is_a_cell(self):
        for row in ("Dana, " + ADDRESS + ",ok", 'Dana, "' + ADDRESS + '",ok', "Dana ; " + ADDRESS + " ; ok"):
            text = ("name;contact;status\n" if ";" in row else "name,contact,status\n") + row
            for channel in ("tool", "prompt"):
                with self.subTest(row=row, channel=channel):
                    self.assertEqual(encoded(text, channel), [ADDRESS])

    def test_an_owner_word_inside_a_longer_column_name_is_no_address_column(self):
        for text in ("end_user_id,status\npkg%40v2.dev,ok", "contact_asset,size\nreadme%40v2.dev,2048",
                     "login,dep\npkg%401.0.0-beta.rc,x", "user,file\nanim%402x.lottie,1"):
            with self.subTest(text=text.split("\n")[0]):
                self.assertEqual(encoded(text) + encoded(text, "prompt"), [])
        for head in ("login_user", "userName", "userPrincipalName", "reply_to"):
            with self.subTest(head=head):
                self.assertEqual(encoded("id," + head + "\n1," + ADDRESS), [ADDRESS])

    def test_a_data_row_is_no_header(self):
        # the first row holds an address on mailbox.org: data, not the header of a mail column
        text = "Dana," + "dana" + "@" + "mailbox-test.net,ok\nOmar,omar%40v2.dev,ok"
        self.assertEqual(encoded(text), [])


if __name__ == "__main__":
    unittest.main()
