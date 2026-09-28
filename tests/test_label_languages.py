"""The label files of the languages that the pinned test locale does not turn on.

tests/detection_matrix.py takes the label files of the active languages only, and the tests pin
MAISECRETS_LOCALE=de_DE (tests/_isolate.py): English and German. Here each other label file runs
through the detector with its language on: every example, with generated values in the shapes of
the matrix, gives exactly its value (and the e-mail address after it); ordinary sentences with the
word as prose give no hit. The prose includes the words left out of the files on purpose (clave,
chiave, clé, klucz, anahtar, şifreleme: see docs/label-sources.md), so a later line that takes
one of them fails here.

Run: python3 -m unittest tests.test_label_languages -v
Every value is generated at run time, so no literal sits in the tree.
"""
from __future__ import annotations

import itertools
import random
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _isolate  # noqa: E402,F401  first: no client environment, a temp home and temp dir
sys.path.insert(0, str(ROOT))
from maisecrets import detect, regions  # noqa: E402
import detection_matrix as dm  # noqa: E402

# ordinary sentences per language: the label word in running text, a word that is left out of the
# file in a label position, or a separator followed by prose. None of them may give any hit.
PROSE = {
    "es": ["Olvidé la clave de acceso del portal y pedí una nueva ayer",
           "Palabra clave: sostenibilidad",
           "Las credenciales del servidor caducan cada noventa días",
           "La clave secreta de su éxito es la paciencia"],
    "it": ["Parola chiave: sostenibilità",
           "Ho dimenticato la chiave di accesso della cantina",
           "Le credenziali scadono dopo novanta giorni",
           "Chiave: sottozerobianco"],
    "fi": ["Unohdin salasanan eilen illalla",
           "Salasana vaihdetaan joka kolmas kuukausi",
           "Salaisuus: rakkausrunot",
           "Avain: ovimaton alla"],
    "sv": ["Jag glömde mitt lösenord igår kväll",
           "Byt lösenord var tredje månad",
           "Nyckel: hållbarhetsfrågor",
           "Autentiseringsuppgifter skickas per post"],
    "pl": ["Zapomniałem hasła do skrzynki wczoraj",
           "Hasło dnia to cierpliwość",
           "Klucz: bezpieczeństwo",
           "Poświadczenia wygasają po dziewięćdziesięciu dniach"],
    "tr": ["Şifreleme: AES-256-GCM",
           "Dosya şifrelenmiş: evet2024",
           "Şifremi dün unuttum",
           "Anahtar kelime: sürdürülebilirlik",
           "Deşifre: tamamlandı2024"],
    "ko": ["암호화: AES256GCM",
           "암호문: 3f9a7c2e1b",
           "비밀번호를 잊어버렸어요",
           "키: 180센티미터",
           "토큰이 만료되었습니다"],
    "th": ["ฉันลืมรหัสผ่านเมื่อวานนี้",
           "รหัสสินค้า: SKU2024ABC",
           "โทเค็นหมดอายุแล้ว"],
    "fr": ["Mot clé: référencement2024",
           "J'ai perdu la clé d'accès du garage hier soir",
           "Vos identifiants sont envoyés par courrier",
           "Identifiant: dupont2024",
           "Clé: sousleparapluie"],
    "nl": ["Ik ben mijn wachtwoord vergeten",
           "Sleutel: duurzaamheid2030",
           "Uw inloggegevens worden per post verstuurd"],
    "pt": ["Palavra-chave: sustentabilidade",
           "Esqueci a senha do banco ontem",
           "Chave: debaixodotapete",
           "As credenciais expiram em noventa dias"],
    "da": ["Jeg har glemt min adgangskode",
           "Nøgle: sikkerhedsregler",
           "Skift kodeord hver tredje måned"],
    "nb": ["Jeg glemte passordet mitt i går",
           "Nøkkel: sikkerhetsregler",
           "Påloggingsdetaljer sendes med posten"],
    "cs": ["Zapomněl jsem heslo k e-mailu",
           "Heslo dne: trpělivost",
           "Klíč: bezpečnostní2024",
           "Přihlašovací údaje vyprší za devadesát dní"],
}


def _other_languages() -> list[str]:
    active = set(detect.active_regions().languages)
    return [lang for lang in regions.label_languages_available() if lang not in active]


def _scan(languages: tuple[str, ...], texts: list[str]) -> list[list[tuple[str, str]]]:
    """The detector's result for each text with exactly these label languages on."""
    saved = detect._RULES
    active = regions.Active(regions=("generic",), languages=languages, source="test")
    try:
        detect._RULES = None
        with mock.patch.object(detect, "active_regions", return_value=active):
            return [[(m.type, m.value) for m in detect.scan(t)] for t in texts]
    finally:
        detect._RULES = saved


def _cases(lang: str, n: int = 300, seed: int = 28) -> list[dm.Case]:
    rnd = random.Random(f"{seed}-{lang}")
    examples = [ex for lab in regions.load_labels(lang) for ex in lab.examples]
    product = list(itertools.product(examples, dm.SEPARATORS, ["mixed", "two-letters", "special", "german"],
                                     dm.AFTER, dm.CONTEXTS))
    rnd.shuffle(product)
    # every example at least once, whatever the shuffle drew
    head = [next(p for p in product if p[0] == ex) for ex in examples]
    out = []
    for label, sep, shape, after, ctx in head + product[:max(0, n - len(head))]:
        value = dm._value(rnd, shape)
        mail = dm._mail(rnd) if "{mail}" in after else None
        x = f"{label}{sep}{value}{after.format(mail=mail) if mail else after}"
        out.append(dm.Case(ctx.format(x=x), value, mail, (label, sep, shape, after, ctx)))
    return out


class LabelLanguageTests(unittest.TestCase):
    def test_each_label_file_outside_the_matrix_has_prose_here(self):
        others = _other_languages()
        self.assertGreaterEqual(len(others), 14, "a population test must fail on a thin population")
        self.assertEqual(sorted(others), sorted(PROSE), "a new label file needs its prose here")

    def test_every_example_gives_exactly_its_value_and_its_mail(self):
        for lang in _other_languages():
            cases = _cases(lang)
            got = _scan(("en", lang), [c.text for c in cases])
            wrong = []
            for c, g in zip(cases, got):
                want = [("SECRET", c.secret)] + ([("EMAIL", c.mail)] if c.mail else [])
                if g != want:
                    wrong.append((c.combo, c.text, g))
            with self.subTest(lang=lang):
                self.assertEqual(wrong[:5], [], f"{lang}: {len(wrong)} of {len(cases)} combinations fail")

    def test_the_file_is_what_finds_its_labels(self):
        # with English only, the labels of a language that English does not share are no labels
        value = "Qz" + "".join(random.Random(7).choice("abcdefgh23456789") for _ in range(12))
        for lang in _other_languages():
            examples = [ex for lab in regions.load_labels(lang) for ex in lab.examples]
            texts = [f"{ex}: {value}" for ex in examples]
            on = _scan(("en", lang), texts)
            off = _scan(("en",), texts)
            with self.subTest(lang=lang):
                self.assertTrue(all(r == [("SECRET", value)] for r in on), lang)
                self.assertTrue(any(r == [] for r in off), f"{lang}: English alone finds every label")

    def test_prose_with_the_label_word_gives_no_hit(self):
        for lang, sentences in PROSE.items():
            for text, got in zip(sentences, _scan(("en", lang), sentences)):
                with self.subTest(lang=lang, text=text):
                    self.assertEqual(got, [], text)


if __name__ == "__main__":
    unittest.main()
