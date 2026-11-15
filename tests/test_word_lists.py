"""The word lists of the detection core as files (#54, detection/wordlists.py): each file is sorted, has no duplicate
and no blank entry, and a list that its head calls lower case holds no capital letter. A contributor who adds a word
keeps these rules; the test names the file and the line."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets.detection import wordlists  # noqa: E402


class WordListFileTests(unittest.TestCase):
    def test_every_file_is_sorted_unique_and_in_its_case(self):
        files = sorted(wordlists.WORDS_DIR.glob("*.txt"))
        self.assertGreaterEqual(len(files), 10)
        for f in files:
            with self.subTest(file=f.name):
                lines = f.read_text(encoding="utf-8").splitlines()
                head = [x for x in lines if x.startswith("#")]
                entries = [x for x in lines if x and not x.startswith("#")]
                self.assertTrue(head, "a head comment says what the list is")
                self.assertTrue(entries)
                self.assertEqual(entries, [x.strip() for x in entries], "no blanks around an entry")
                self.assertEqual(entries, sorted(set(entries)), "sorted, each entry once")
                if "lower case" in " ".join(head):
                    self.assertEqual([x for x in entries if x != x.lower()], [])

    def test_the_loader_reads_the_entries_and_skips_comments(self):
        got = wordlists.words("runner_words")
        self.assertIn("skipped", got)
        self.assertFalse(any(x.startswith("#") for x in got))
        self.assertIs(got, wordlists.words("runner_words"), "read once per process")


if __name__ == "__main__":
    unittest.main()
