"""#45: a password and an id number after a key in structured data (Privy, the Benchmark V3 sample): a JSON field, an
SQL comparison, an HTML table row and an XML element. The values are built at run time, so the tree holds no shape of
a real one."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _isolate  # noqa: E402,F401

from maisecrets.detection import core, key_values  # noqa: E402

PW = "Qx7" + "m"          # four characters with a digit, as Privy writes them
ID = "k" + "4817"


def kinds(text: str) -> list:
    return [(m.kind, text[m.start:m.end]) for m in core.scan(text, channel="tool")]


class PasswordAfterAKeyTests(unittest.TestCase):
    def test_each_form_and_each_password_key(self):
        for text in (f"<tr><th>key_store_password</th><td>{PW}</td></tr>",
                     f'<root><key__store__password type="str">{PW}</key__store__password></root>',
                     f'{{"keypassword": "{PW}", "api-version": "2"}}',
                     f"WHEN \"keypassword\"<>'{PW}' THEN 'less'",
                     f"<tr><th>current-password</th><td>{PW}</td></tr>"):
            with self.subTest(text=text):
                self.assertIn(("password-after-key", PW), kinds(text))
        # key=value: an older rule takes it first, and the value is masked all the same
        self.assertIn(PW, [v for _, v in kinds(f"db_pwd={PW}\n")])

    def test_a_state_a_reference_a_rule_and_a_hash_stay_text(self):
        for text in ('{"password": "required"}', '{"password": "${DB_PASSWORD}"}', '{"password_policy": "min8"}',
                     '{"passwordHash": "x7Fq2"}', '{"reset_password": "/reset/4kq"}', '{"password": "abcdef"}',
                     '<tr><th>password</th><td>***</td></tr>', '{"show_password": "false"}',
                     '{"password": "1234"}'):
            with self.subTest(text=text):
                self.assertNotIn("password-after-key", [k for k, _ in kinds(text)])

    def test_the_prompt_channel_is_unchanged(self):
        text = f"<tr><th>key_store_password</th><td>{PW}</td></tr>"
        self.assertNotIn("password-after-key", [m.kind for m in core.scan(text, channel="prompt")])


class IdNumberAfterAKeyTests(unittest.TestCase):
    def test_each_form_and_each_id_key(self):
        for text in (f'<driver-license type="str">{ID}</driver-license>',
                     f"<tr><th>driver&#x27;s-license</th><td>{ID}</td></tr>",
                     f'{{"driver_license": "{ID}", "contact-email": "x"}}',
                     f"WHEN \"national-identity\"='{ID}' OR",
                     f"<tr><th>identitydocument</th><td>{ID}</td></tr>",
                     f'<national__identity type="str">{ID}</national__identity>',
                     f'{{"document-number": "{ID}"}}',
                     f'<taxpayeridentificationnumber type="str">{ID}</taxpayeridentificationnumber>'):
            with self.subTest(text=text):
                self.assertIn(("id-number-after-label", ID), kinds(text))

    def test_a_date_a_specimen_a_word_and_a_thing_stay_text(self):
        for text in ('{"driver_license": "true"}', '{"document_number": "0000"}', '{"idnumber": "12-03-2024"}',
                     f"<product><passport>{ID}</passport></product>", '{"tax_id": "none"}'):
            with self.subTest(text=text):
                self.assertNotIn("id-number-after-label", [k for k, _ in kinds(text)])


class KeyFoldingTests(unittest.TestCase):
    def test_a_key_without_case_separators_and_apostrophes(self):
        for key in ("driver&#x27;s-license", "Driver's License", "driver&apos;s_license", "DRIVING-LICENCE"):
            with self.subTest(key=key):
                self.assertIn(key_values.fold(key), ("driverslicense", "drivinglicense"))
        self.assertTrue(key_values.password_key("key__store__password"))
        self.assertFalse(key_values.password_key("password_policy"))
        self.assertFalse(key_values.password_key("password_hash"))


if __name__ == "__main__":
    unittest.main()
