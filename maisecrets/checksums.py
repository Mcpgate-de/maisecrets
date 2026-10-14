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
