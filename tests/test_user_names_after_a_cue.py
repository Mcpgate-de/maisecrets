"""#51: a user name in prose after a user cue (`for user`, `User … logged in`, `Welcome,`, `my username is`) and after a
user-id key, in the tool channel. Invented handles."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect, regions  # noqa: E402


def scan(text: str, channel: str = "tool") -> list:
    active = regions.Active(regions=("generic", "de", "us"), languages=("en", "de"), source="test")
    with detect.Detector(regions=active).activate():
        return detect.scan(text, channel=channel)


def users(text: str, channel: str = "tool") -> list:
    return [text[m.start:m.end] for m in scan(text, channel) if m.kind == "username-after-label"]


class UserNameAfterACueTests(unittest.TestCase):
    def test_each_cue_and_each_handle_shape(self):
        for text, value in (("a problem with the login process for user kalin.orbek. Additionally", "kalin.orbek"),
                            ("Login successful. Welcome, kalin_orb_42.\n", "kalin_orb_42"),
                            ("Details: User kalin.orbek successfully logged in from", "kalin.orbek"),
                            ("My username is korbek. I am", "korbek"),
                            ("including the user KOrbek7.\n", "KOrbek7"),
                            ("the user KalinOrbek has reported", "KalinOrbek"),
                            ("<userID>korbek7</userID>", "korbek7"),
                            ('{"login_name": "kalin.orbek"}', "kalin.orbek")):
            with self.subTest(text=text):
                self.assertIn(value, users(text))

    def test_code_roles_versions_and_placeholders_stay_text(self):
        for text in ("for user in users:", "for user.name in names", "the user_id column", "by user root",
                     "the user admin1", "Welcome, Admin.", "Welcome, user.", "User profile updated",
                     "User main_thread failed", "for user john.doe", "the user test_user", "for user api-service",
                     "<userID>12345</userID>", '{"handle": "true"}', "from user data.json", "the user user.email",
                     "My username is admin.", "for user service_account", "by user ci-runner",
                     "the user default_reader01", "for user x86_64", "Welcome, Python3.", "for user v1.2.3",
                     "the user my_app", "User KOrbek7 Settings", "My username is visible."):
            with self.subTest(text=text):
                self.assertEqual([], users(text))

    def test_a_typed_prompt_keeps_its_rules(self):
        self.assertEqual([], users("for user kalin.orbek today", "prompt"))


if __name__ == "__main__":
    unittest.main()
