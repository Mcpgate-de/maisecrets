"""Values that have the shape of personal data but name no person (learned from Cloakroom 1.4.0's safe.py, Apache-2.0):
a bank number that is a run or one repeated digit, a North American toll-free number, and a birth date more than 110
years ago or in the future. core.py drops a hit of these types on such a value. Kept out of personal.py, which is at
the size limit of a release file."""
from __future__ import annotations

import datetime
import re

# NANP toll-free area codes: business lines, never a person's own number
_TOLL_FREE = frozenset({"800", "833", "844", "855", "866", "877", "888"})
_YEAR_RE = re.compile(r"(?<!\d)(1[0-9]{3}|2[0-9]{3})(?!\d)")
_NUMBER_TYPES = ("US_BANK_NUMBER", "BANK_ACCOUNT", "ACCOUNT_NUMBER")


def _run(digits: str) -> bool:
    """One digit repeated, or a run up or down (12345678, 98765432)."""
    if len(set(digits)) == 1:
        return True
    return digits in "0123456789012345678901234567890" or digits in "9876543210987654321098765432109"


def no_person_value(value: str, typ: str, year: int | None = None) -> bool:
    digits = re.sub(r"\D", "", value)
    if typ in _NUMBER_TYPES and len(digits) >= 6 and _run(digits):
        return True
    if typ == "PHONE":
        national = digits[1:] if len(digits) == 11 and digits[0] == "1" else digits
        if len(national) == 10 and national[:3] in _TOLL_FREE:
            return True
    if typ == "BIRTH_DATE":
        m = _YEAR_RE.search(value)
        now = year or datetime.date.today().year
        if m and not (now - 110 <= int(m.group(1)) <= now):
            return True
    return False
