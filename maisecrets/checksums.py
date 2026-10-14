"""Check digits and checksums for the detector (detect.py): national identifiers that Presidio validates but whose
validators were not yet ported, the identifiers of regions Presidio has no rules for (Switzerland, Austria), the German
document number, and three kinds of crypto wallet secret (a BIP39 seed phrase, a WIF private key, a BIP32 extended
private key).

Each function takes the matched text and returns True only for a value whose checksum holds. A function that cannot
parse its value returns False. No function here reads a file except the BIP39 word list, once.

Sources of the algorithms: Presidio's validate_result of each recognizer (MIT, see rules/LICENSE-presidio) for PESEL,
NIF, NIE, NHS, ABA and the codice fiscale; ICAO Doc 9303 Part 3 for the 7-3-1 check digit; eCH-0097 for the Swiss UID;
the AHV number is an EAN-13; the Austrian numbers follow the published algorithms of the Hauptverband (VSNR) and of the
BMF (UID). The Swiss rules follow a fork of this project (Apache-2.0, see NOTICE). BIP39, BIP32 and the WIF format are
the Bitcoin Improvement Proposals 39 and 32 and the Base58Check encoding.
"""
from __future__ import annotations

import re
import string
from pathlib import Path

RULES_DIR = Path(__file__).resolve().parent / "rules"


def _digits(v: str) -> str:
    return re.sub(r"\D", "", v)


# ------------------------------------------------------------------ Germany --
# ICAO Doc 9303 Part 3, 4.9: a digit counts its value, A to Z count 10 to 35, the filler < counts 0; weights 7, 3, 1
def icao_check_digit(s: str) -> int:
    total = 0
    for i, c in enumerate(s):
        if c.isdigit():
            val = int(c)
        elif "A" <= c <= "Z":
            val = ord(c) - 55
        elif c == "<":
            val = 0
        else:
            raise ValueError(c)
        total += val * (7, 3, 1)[i % 3]
    return total % 10


# the characters of a German ID card or passport number since 2010/2007: the digits and the consonants
# C F G H J K L M N P R T V W X Y Z (no vowel and no B, D, Q or S, which a reader confuses with 8, 0, O and 5)
DE_DOCUMENT_CHARS = frozenset("CFGHJKLMNPRTVWXYZ" + string.digits)


def de_document_ok(v: str) -> bool:
    """A German ID card or passport number: 9 characters of DE_DOCUMENT_CHARS, as the card prints it, or the same 9
    and the ICAO check digit, as the machine-readable zone prints it. The check digit is not part of the printed number:
    its 9th character can be a letter (the official specimen card's number ends in a digit by chance)."""
    v = v.strip().upper()
    if len(v) not in (9, 10) or any(c not in DE_DOCUMENT_CHARS for c in v[:9]):
        return False
    if len(v) == 10:
        return v[9].isdigit() and icao_check_digit(v[:9]) == int(v[9])
    return True


# ---------------------------------------------------------------- Presidio --
def pl_pesel_ok(v: str) -> bool:
    """PESEL: weights 1 3 7 9 1 3 7 9 1 3, the check digit is (10 - sum mod 10) mod 10."""
    if len(v) != 11 or not v.isdigit():
        return False
    total = sum(int(d) * w for d, w in zip(v[:10], (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)))
    return (10 - total % 10) % 10 == int(v[10])


_NIF_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"


def es_nif_ok(v: str) -> bool:
    """Spanish DNI/NIF: the letter is _NIF_LETTERS[number mod 23] (Presidio removes - and spaces first)."""
    v = re.sub(r"[- ]", "", v.strip()).upper()
    digits = _digits(v)
    return bool(digits) and v[-1:] == _NIF_LETTERS[int(digits) % 23]


def es_nie_ok(v: str) -> bool:
    """Spanish NIE: X, Y or Z (read as 0, 1, 2), the digits, and the NIF letter of that whole number."""
    v = re.sub(r"[- ]", "", v.strip()).upper()
    if not 8 <= len(v) <= 9 or v[:1] not in ("X", "Y", "Z") or not v[1:-1].isdigit():
        return False
    return v[-1] == _NIF_LETTERS[int(str("XYZ".index(v[0])) + v[1:-1]) % 23]


def uk_nhs_ok(v: str) -> bool:
    """NHS number: the ten digits weighted 10 down to 1 sum to a multiple of 11."""
    d = re.sub(r"[- ]", "", v.strip())
    if len(d) != 10 or not d.isdigit() or len(set(d)) == 1:
        return False                    # 000 000 0000 passes the sum and is a placeholder
    return sum(int(c) * w for c, w in zip(d, range(10, 0, -1))) % 11 == 0


def us_aba_ok(v: str) -> bool:
    """ABA routing number: weights 3 7 1, the sum is a multiple of 10, and the first two digits a Federal Reserve
    routing symbol (00 to 12, 21 to 32, 61 to 72, 80). 000000000 passes the sum and is a placeholder."""
    d = re.sub(r"[- ]", "", v.strip())
    if len(d) != 9 or not d.isdigit() or len(set(d)) == 1:
        return False
    head = int(d[:2])
    if not (head <= 12 or 21 <= head <= 32 or 61 <= head <= 72 or head == 80):
        return False
    return sum(int(c) * w for c, w in zip(d, (3, 7, 1) * 3)) % 10 == 0


# codice fiscale: the value of a character at an odd place (1st, 3rd, ...); at an even place a digit counts its value
# and a letter its place in the alphabet from 0
_IT_ODD = dict(zip(string.digits + string.ascii_uppercase,
                   (1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6, 8,
                    12, 14, 16, 10, 22, 25, 24, 23)))


def it_fiscal_code_ok(v: str) -> bool:
    """Italian codice fiscale: the 16th character is the check letter of the first 15."""
    v = v.strip().upper()
    if not re.fullmatch(r"[A-Z0-9]{15}[A-Z]", v):
        return False
    total = sum(_IT_ODD[c] if i % 2 == 0 else (int(c) if c.isdigit() else ord(c) - 65) for i, c in enumerate(v[:15]))
    return chr(65 + total % 26) == v[15]
