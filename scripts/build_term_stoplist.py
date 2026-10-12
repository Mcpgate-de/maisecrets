#!/usr/bin/env python3
"""Build maisecrets/rules/term_stoplist.txt: the words a TEAM term list must not hold alone (maisecrets/terms.py).

A team list lives in a shared folder that an agent can write, so a term there has a floor: a single word on this list
is refused, because masking it would mask ordinary text. The list has two sources, both named in the file header:

1. The closed word classes of English and German, written out below by grammar class: articles, pronouns,
   prepositions, conjunctions, auxiliary and modal verbs, numerals, the days and the months (with their short forms),
   forms of address. These words stand in almost every sentence, and the classes are finite: a grammar names them.
2. The words of this repository's own prose and code (README, docs, commands, skills, maisecrets/*.py): every word of
   3 or more letters that 8 or more of these files use. These are the words that the tool output of a developer
   session holds (file, report, value, name, test), so a term equal to one of them would mask the session's text.
   The tests are left out: they hold the synthetic names.

Run: python3 scripts/build_term_stoplist.py          (writes the file)
     python3 scripts/build_term_stoplist.py --check  (exit 1 when the closed classes in the file are not complete)
"""
from __future__ import annotations

import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "maisecrets" / "rules" / "term_stoplist.txt"
MIN_FILES = 8

CLOSED = {
    "en articles and determiners": "a an the this that these those each every either neither some any no all both "
                                   "few many much more most other another such what which whose",
    "en pronouns": "i me my mine myself you your yours yourself yourselves he him his himself she her hers herself "
                   "it its itself we us our ours ourselves they them their theirs themselves who whom one ones "
                   "someone anyone everyone nobody somebody anybody everybody something anything everything nothing",
    "en prepositions": "about above across after against along among around at before behind below beneath beside "
                       "between beyond by down during except for from in inside into like near of off on onto out "
                       "outside over past since through throughout till to toward towards under until up upon via "
                       "with within without per",
    "en conjunctions and adverbs": "and but or nor so yet because although though while whereas if unless whether "
                                   "than then when where why how also just only not very too here there now again "
                                   "still already always never often ever even yes",
    "en verbs": "be am is are was were been being have has had having do does did done doing will would shall should "
                "can could may might must get got let make made say said see go went",
    "en numerals": "zero one two three four five six seven eight nine ten eleven twelve hundred thousand million first "
                   "second third last next",
    "en days and months": "monday tuesday wednesday thursday friday saturday sunday mon tue wed thu fri sat sun "
                          "january february march april may june july august september october november december "
                          "jan feb mar apr jun jul aug sep sept oct nov dec",
    "en address": "mr mrs ms miss dr prof sir madam dear hello hi regards thanks thank",
    "de Artikel und Determinative": "der die das den dem des ein eine einen einem einer eines kein keine keinen "
                                    "keinem keiner dieser diese dieses diesen diesem jener jene jenes jeder jede "
                                    "jedes jeden jedem alle allen aller manche mancher einige mehrere welche welcher "
                                    "welches solche",
    "de Pronomen": "ich mich mir mein meine meinen meinem meiner du dich dir dein deine er ihn ihm sein seine seinen "
                   "seinem seiner sie ihr ihre ihren ihrem ihrer es wir uns unser unsere euch euer eure man sich "
                   "jemand niemand etwas nichts alles wer wen wem wessen was",
    "de Präpositionen": "an auf aus bei bis durch für gegen hinter in mit nach neben ohne seit über um unter von vor "
                        "während wegen zu zum zur zwischen am im ins vom beim ab trotz statt laut gemäß",
    "de Konjunktionen und Adverbien": "und oder aber denn sondern doch weil dass ob wenn als wie falls obwohl damit "
                                      "sowie sowohl weder noch auch nur schon sehr nicht nie immer oft hier dort da "
                                      "jetzt dann heute morgen gestern ja nein bitte danke",
    "de Verben": "sein bin bist ist sind seid war waren gewesen haben habe hast hat habt hatte hatten gehabt werden "
                 "werde wirst wird werdet wurde wurden geworden kann kannst können könnte muss müssen musste soll "
                 "sollen sollte will wollen wollte darf dürfen mag mögen möchte",
    "de Zahlwörter": "null eins zwei drei vier fünf sechs sieben acht neun zehn elf zwölf hundert tausend erste "
                     "zweite dritte letzte nächste",
    "de Tage und Monate": "montag dienstag mittwoch donnerstag freitag samstag sonntag januar februar märz april mai "
                          "juni juli august september oktober november dezember mo di mi do fr sa so jän",
    "de Anrede": "herr herrn frau fräulein liebe lieber hallo grüße gruß geehrte geehrter sehr",
}


def closed_words() -> set[str]:
    return {w for text in CLOSED.values() for w in text.split()}


def corpus_words() -> set[str]:
    files = subprocess.run(["git", "-C", str(ROOT), "ls-files", "README.md", "docs", "commands", "skills",
                            "maisecrets/*.py"], capture_output=True, text=True, check=True).stdout.split()
    seen: Counter = Counter()
    for name in files:
        path = ROOT / name
        if path.suffix not in (".md", ".py") or not path.is_file():
            continue
        words = set(re.findall(r"[^\W\d_]{3,}", path.read_text(encoding="utf-8", errors="replace").lower()))
        seen.update(words)
    return {w for w, n in seen.items() if n >= MIN_FILES}


def main(argv: list[str]) -> int:
    if argv[1:] == ["--check"]:
        have = set(line.strip() for line in OUT.read_text(encoding="utf-8").splitlines()
                   if line.strip() and not line.startswith("#"))
        missing = sorted(closed_words() - have)
        print(f"{OUT.name}: {len(have)} words; closed classes complete: {'yes' if not missing else 'no'}")
        return 1 if missing else 0
    closed, corpus = closed_words(), corpus_words()
    words = sorted(closed | corpus)
    header = (f"# The single words a TEAM term list must not hold (maisecrets/terms.py). {len(words)} words.\n"
              f"# Built by scripts/build_term_stoplist.py from two sources, both named there:\n"
              f"# 1. the closed word classes of English and German ({len(closed)} words, by grammar class);\n"
              f"# 2. the words of 3+ letters that {MIN_FILES}+ files of this repository's README, docs, commands,\n"
              f"#    skills and maisecrets/*.py use ({len(corpus)} words): the words of a developer session.\n"
              "# A personal terms.txt has no such floor: the person decides.\n")
    OUT.write_text(header + "\n".join(words) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}: {len(words)} words ({len(closed)} closed class, {len(corpus)} corpus)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
