"""A name on the line directly above a bank block names the account holder (#40, part 3), apart from personal.py,
which the plugin directory reads only up to 200,000 bytes per file. core._personal_hits calls names_above_bank for
the name-after-label check of a tool result."""
from __future__ import annotations

import re

# a line of a bank block: its label, then a colon (Bank: …, IBAN: …, Kontonummer: …, Sort code: …)
_BANK_LINE = (r"[ \t]*(?i:bank(?:[ \t]?name)?|kreditinstitut|iban|bic|swift(?:[ \t]?code)?|blz|bankleitzahl"
              r"|konto(?:[ \t]?nr\.?|nummer)|account[ \t]?(?:number|no\.?|nr\.?)|sort[ \t]?code|routing[ \t]?number"
              r"|kontoinhaber(?:in)?|account[ \t]?holder)[ \t]*:[^\n]*")
# a block holds an account: an IBAN or an account number line, not a bank name alone
_ACCOUNT_LINE_RE = re.compile(r"(?im)^[ \t]*(?:iban|konto(?:[ \t]?nr\.?|nummer)|account[ \t]?(?:number|no\.?|nr\.?))"
                              r"[ \t]*:")
# a word of a heading above a bank block, not of a name (Bank Details, Zahlungsdaten, Monthly Invoice, Empfänger): the
# word list lacks many of them. Banks stays a surname
_HEADING_WORD_RE = re.compile(
    r"(?i)(?:bank|konto|account|payment|zahlung|rechnung|invoice|details?|daten|data|angaben|info|information|summary"
    r"|total|betrag|amount|transfer|wire|remittance|empf(?:ä|ae)nger|recipient|beneficiary|verwendungszweck|reference"
    r"|(?:bank|konto|zahlungs?|payment|(?:ü|ue)berweisung)\w{3,}|\w{3,}(?:daten|details?|angaben|verbindung|info))")
_RX: list = []


def _above_bank_re():
    """One to four name words alone on a line, then the bank block right below it (no blank line between)."""
    if not _RX:
        from .personal import _NAME_STEM
        _RX.append(re.compile(r"(?m)^[ \t]*(" + _NAME_STEM + r"(?:[ ](?:" + _NAME_STEM + r")){0,3})[ \t]*\n"
                              r"((?:" + _BANK_LINE + r"(?:\n|$)){1,8})"))
    return _RX[0]


def names_above_bank(text: str) -> list:
    """The spans of a person's name on the line directly above a bank block that holds an account: the line names the
    account holder, as a Slack message or a mail writes it. Not a heading or a sentence (words of the word list:
    Bankverbindung, Bank Details), not a company (a legal form), not a block of a bank name alone."""
    from .personal import _name_ok, _reads_as_words
    from .role_names import one_word_name
    out = []
    for m in _above_bank_re().finditer(text):
        if not _ACCOUNT_LINE_RE.search(m.group(2)):
            continue
        v = m.group(1)
        if any(_HEADING_WORD_RE.fullmatch(w) for w in v.split()):
            continue
        plain = re.sub(r"-[^\s]*", "", v)
        if (" " in v and _name_ok(v) and not (_reads_as_words(v, every=True) and _reads_as_words(plain, every=True))) \
                or (" " not in v and one_word_name(v)):
            out.append((m.start(1), m.end(1)))
    return out
