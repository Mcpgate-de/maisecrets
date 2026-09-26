#!/usr/bin/env python3
"""Differential test: the ported checksum validators must agree with Presidio's.

Needs a Python with presidio-analyzer (see scripts/sync_presidio.py). Generates
random candidates per shape and compares "presidio keeps the hit" (True or
None) with our validator's verdict. Run after every sync_presidio.py.
"""
import random
import string
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from maisecrets import detect  # noqa: E402
from presidio_analyzer.predefined_recognizers import (  # noqa: E402
    DeBsnrRecognizer, DeHealthInsuranceRecognizer, DeIdCardRecognizer, DeLanrRecognizer,
    DePassportRecognizer, DeSocialSecurityRecognizer, DeTaxIdRecognizer, DeVatIdRecognizer,
)

random.seed(int(sys.argv[1]) if len(sys.argv) > 1 else 7)
D, L = string.digits, string.ascii_uppercase


def rnd(alpha, n):
    return "".join(random.choice(alpha) for _ in range(n))


GENS = {
    "de_tax_id": (DeTaxIdRecognizer(), lambda: rnd(D, 11)),
    "de_social_security": (DeSocialSecurityRecognizer(), lambda: rnd(D, 2) + f"{random.randint(0, 40):02d}"
                           + f"{random.randint(0, 13):02d}" + rnd(D, 2) + rnd(L, 1) + rnd(D, 3)),
    "de_id_card": (DeIdCardRecognizer(), lambda: rnd(L + D, 9)),
    "de_passport": (DePassportRecognizer(), lambda: rnd("CFGHJKLMNPRTVWXYZ" + D, 9)),
    "de_health_insurance": (DeHealthInsuranceRecognizer(), lambda: rnd(L, 1) + rnd(D, 9)),
    "de_lanr": (DeLanrRecognizer(), lambda: rnd(D, 9)),
    "de_bsnr": (DeBsnrRecognizer(), lambda: rnd(D, 9)),
    "de_vat_id": (DeVatIdRecognizer(), lambda: "DE" + rnd(D, 9)),
}
bad = 0
for name, (rec, gen) in GENS.items():
    disagree = 0
    for _ in range(4000):
        v = gen()
        if (rec.validate_result(v) is not False) != detect.VALIDATORS[name](v):
            disagree += 1
    print(f"{name:<22} disagree {disagree}/4000")
    bad += disagree
sys.exit(1 if bad else 0)
