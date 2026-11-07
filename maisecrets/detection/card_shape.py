"""Is a number written as a card? The layouts and the issuer table that let a card number count in a tool result
without a card word."""
from __future__ import annotations

import re

from .lazy_regex import LazyRx as _LazyRx
from .text_index import field_start


# issuer prefixes and lengths (ISO/IEC 7812 IIN ranges of the networks): Visa, Mastercard, American Express, Discover,
# JCB (also its 15-digit 2131 and 1800), Diners Club, UnionPay
_CARD_ISSUERS = _LazyRx(r"4\d{15}|5[1-5]\d{14}|2(?:2[2-9]|[3-6]\d|7[01])\d{13}|2720\d{12}|3[47]\d{13}"
                           r"|6(?:011|5\d\d|4[4-9]\d)\d{12}|35(?:2[89]|[3-8]\d)\d{12}|3(?:0[0-5]|[68]\d)\d{11}|62\d{14}"
                           r"|(?:2131|1800)\d{11}")
_CARD_GROUPS = _LazyRx(r"\d{4}([ -])\d{4}\1\d{4}\1\d{4}|\d{4}([ -])\d{6}\2\d{5}|\d{4}([ -])\d{6}\3\d{4}")
# the first three groups of a UUID (8-4-4): a card number dressed as an object id in a link
_CARD_AS_UUID = _LazyRx(r"\d{8}-\d{4}-\d{4}")
_UUID_REST = _LazyRx(r"-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}(?!\w)")


# a label that names an id (order_id, event_id, "job_id", invoice no, imei, serial): the number after it is that id
_ID_LABEL_BEFORE_RE = _LazyRx(r"(?i)(?:(?:^|[^a-z])(?:imei|serial|reference|ref)|(?:id|no|nr|num|number|#))[\"']?"
                                 r"\s{0,3}[:=#]\s{0,3}[\"']?\s{0,3}$")


def _card_shaped(text: str, start: int, secret: str) -> bool:
    """A number written as a card: in groups of four (4-6-5 for Amex, 4-6-4 for Diners), in the first three groups of
    a UUID (8-4-4) or as one run, with the
    prefix and the length of a card network, and not part of a decimal, a phone number or a longer digit run. A float,
    a timestamp and an IMEI pass Luhn as often as a card does (review of 0.6.24); the issuer table keeps them out."""
    v = secret.strip()
    end = start + len(secret)
    sep = re.sub(r"\d", "", v)[:1]
    as_uuid = bool(_CARD_AS_UUID.fullmatch(v))
    # in a UUID the fourth group may be four digits; it is the UUID's, not a fifth card group
    fifth = bool(sep) and re.match(re.escape(sep) + r"\d{4}(?!\d)", text[end:end + 6]) \
        and not (as_uuid and _UUID_REST.match(text, end))
    # a comma before the number is a CSV cell (17,4532 0151 ...), not a decimal: a decimal is no group of four
    if start and text[start - 1] in "+.-0123456789" or text[end:end + 1].isalnum() \
            or re.match(r"\.\d", text[end:end + 2]) or fifth:
        return False   # a decimal, a phone number, a longer run, a fifth group (an expiry such as 12/28 may follow)
    if _ID_LABEL_BEFORE_RE.search(text, max(field_start(text, start), start - 30), start):
        return False   # order_id=4111 ...: an id that passes Luhn
    # an unbroken run too, with the prefix and the length of a card network: Benchmark V1, Gretel cards 299 to 431,
    # Mendeley +119, 14 more false alarms in Gretel, the false-alarm bank +0. A float, a timestamp, an IMEI and an
    # order id stay out by the checks above and by the issuer table (no 15-digit 35..., no 17...)
    return bool((_CARD_GROUPS.fullmatch(v) or as_uuid or v.isdigit()) and _CARD_ISSUERS.fullmatch(re.sub(r"\D", "", v)))
