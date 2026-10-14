"""Rules that a coverage measurement against other secret catalogs (Nosey Parker, Kingfisher, betterleaks, gitleaks,
trufflehog, GitLab's secret detection rules) showed missing or wrong in 0.6.19: a PEM private key in base64, four
vendored betterleaks rules, and token formats with a public prefix.

Run: python3 -m unittest tests.test_rules_from_the_catalogs -v
Every value is generated at run time from a seeded generator, so no literal sits in the tree. Each token rule has a
token that is a hit and a look-alike that is not.
"""
from __future__ import annotations

import base64
import os
import random
import string
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect  # noqa: E402

J = "".join
D = string.digits
L = string.ascii_lowercase
U = string.ascii_uppercase
AN = string.ascii_letters + D
HEXL = "0123456789abcdef"
B64U = AN + "_-"


def rd(r: random.Random, n: int, alphabet: str = D) -> str:
    return J(r.choice(alphabet) for _ in range(n))


def rd_mixed(r: random.Random, n: int, alphabet: str) -> str:
    """n characters of alphabet with at least one digit (the rules that need one)."""
    while True:
        v = rd(r, n, alphabet)
        if any(c.isdigit() for c in v):
            return v


def found(text: str, channel: str = "prompt") -> list:
    return [(m.kind, m.type, m.value) for m in detect.scan(text, channel=channel)]


def kinds_over(text: str, value: str, channel: str = "prompt") -> list:
    """The rule ids of the hits that overlap the value."""
    a = text.index(value)
    return [m.kind for m in detect.scan(text, channel=channel) if m.start < a + len(value) and m.end > a]


def _uuid(r: random.Random) -> str:
    return "-".join(rd(r, n, HEXL) for n in (8, 4, 4, 4, 12))


def _b64url(r: random.Random, n: int) -> str:
    return base64.urlsafe_b64encode(bytes(r.randrange(256) for _ in range(n))).decode().rstrip("=")


def _jwt(r: random.Random) -> str:
    head = base64.urlsafe_b64encode(b'{"alg":"RS256","typ":"JWT"}').decode().rstrip("=")
    return J([head, ".", _b64url(r, 300), ".", _b64url(r, 256)])


def _intercom(r: random.Random) -> str:
    """dG9rO is the base64 of "tok:"; the token is 60 characters of base64."""
    raw = J(["to", "k:"]).encode() + J([_uuid(r).replace("-", "_"), ":1:0"]).encode()
    return base64.b64encode(raw[:45]).decode()


# ------------------------------------------------------------ base64 PEM key --
def pem(r: random.Random, kind: str = "RSA PRIVATE KEY", body_bytes: int = 1190) -> bytes:
    body = base64.b64encode(bytes(r.randrange(256) for _ in range(body_bytes))).decode()
    lines = "\n".join(body[i:i + 64] for i in range(0, len(body), 64))
    dashes = "-" * 5
    return J([dashes, "BEGIN ", kind, dashes, "\n", lines, "\n", dashes, "END ", kind, dashes, "\n"]).encode()


def b64_pem(r: random.Random, kind: str = "RSA PRIVATE KEY") -> str:
    return base64.b64encode(pem(r, kind)).decode()


def k8s_secret(tls_key: str, cert: str) -> str:
    return ("apiVersion: v1\nkind: Secret\nmetadata:\n  name: web-tls\ntype: kubernetes.io/tls\ndata:\n"
            f"  tls.crt: {cert}\n  tls.key: {tls_key}\n")


class Base64PemTests(unittest.TestCase):
    KINDS = ("RSA PRIVATE KEY", "PRIVATE KEY", "EC PRIVATE KEY", "OPENSSH PRIVATE KEY", "ENCRYPTED PRIVATE KEY",
             "DSA PRIVATE KEY", "PGP PRIVATE KEY BLOCK")

    def test_a_private_key_in_a_kubernetes_secret_is_masked_whole(self):
        r = random.Random(30)
        cert = b64_pem(r, "CERTIFICATE")
        for kind in self.KINDS:
            key = b64_pem(r, kind)
            text = k8s_secret(key, cert)
            for channel in ("prompt", "tool"):
                with self.subTest(kind=kind, channel=channel):
                    hits = found(text, channel)
                    self.assertIn(("private-key-base64", "SECRET", key), hits)
                    # betterleaks' kubernetes-secret-yaml takes the first value of a Secret; no new rule takes the
                    # certificate
                    self.assertFalse(any(k == "private-key-base64" and (cert in v or v in cert) for k, _t, v in hits))

    def test_a_certificate_or_a_public_key_in_base64_stays_text(self):
        r = random.Random(31)
        for kind in ("CERTIFICATE", "PUBLIC KEY", "RSA PUBLIC KEY", "CERTIFICATE REQUEST", "PGP PUBLIC KEY BLOCK"):
            v = b64_pem(r, kind)
            with self.subTest(kind=kind):
                self.assertEqual(kinds_over(f"ca.crt: {v}\n", v), [])

    def test_a_wrapped_value_is_masked_over_all_its_lines(self):
        """codex Gate A of 0.6.20: a value wrapped at 40 columns was missed, and a last line of 4 characters stayed
        in the clear."""
        r = random.Random(32)
        for width in (40, 64, 76):
            for tail in (4, 8, 12, 0):
                n = 1190
                key = base64.b64encode(pem(r, body_bytes=n)).decode()
                # a key whose last line has `tail` characters; a full last line without padding when tail is 0
                while len(key) % width != tail or (tail == 0 and key.endswith("=")):
                    n += 1
                    key = base64.b64encode(pem(r, body_bytes=n)).decode()
                wrapped = "\n".join(key[i:i + width] for i in range(0, len(key), width))
                # after a full last line without padding, a further line of base64 alone could be its end: there a
                # following word such as "next" is taken too
                # a longer line of base64 alone is of another value in every case
                longer = "\n" + rd(r, width + 4, AN) + "\n"
                afters = ("\n$ echo done\n", "", longer) + (("\n0123456789abcdef\nnext\n", "\nnext\n") if tail else ())
                for after in afters:
                    text = f"$ base64 -w {width} server.key\n{wrapped}{after}"
                    with self.subTest(width=width, tail=tail, after=after[:6]):
                        self.assertIn(("private-key-base64", "SECRET", wrapped), found(text, "tool"))

    def test_an_indented_wrapped_value_in_yaml_is_masked_whole(self):
        r = random.Random(36)
        key = b64_pem(r)
        lines = [key[i:i + 64] for i in range(0, len(key), 64)]
        block = "\n    ".join(lines)
        text = f"data:\n  tls.key: |\n    {block}\n  tls.crt: abc\n"
        self.assertIn(("private-key-base64", "SECRET", block), found(text, "tool"))

    def test_a_banner_without_key_material_is_no_hit(self):
        dashes = "-" * 5
        prose = "not key material, only a banner in a document " * 8   # long enough to pass the length check
        fake = J([dashes, "BEGIN PRIVATE KEY", dashes, "\n", prose, "\n", dashes, "END PRIVATE KEY", dashes, "\n"])
        v = base64.b64encode(fake.encode()).decode()
        self.assertEqual(kinds_over(f"tls.key: {v}\n", v, "tool"), [])

    def test_escaped_line_breaks_a_bundle_and_a_byte_order_mark(self):
        """Gate B of 0.6.20: a value wrapped with \\n in a JSON string, a certificate chain with the key at its end, a
        byte order mark before the PEM."""
        r = random.Random(38)
        key = b64_pem(r)
        escaped = "\\n".join(key[i:i + 76] for i in range(0, len(key), 76))
        self.assertIn(("private-key-base64", "SECRET", escaped), found('{"key": "' + escaped + '"}', "tool"))
        bundle = base64.b64encode(pem(r, "CERTIFICATE") + pem(r, "CERTIFICATE") + pem(r)).decode()
        self.assertIn(("private-key-base64", "SECRET", bundle), found(f"tls.pem: {bundle}\n", "tool"))
        wrapped = "\n".join(bundle[i:i + 64] for i in range(0, len(bundle), 64))
        self.assertIn(("private-key-base64", "SECRET", wrapped), found(f"$ base64 bundle.pem\n{wrapped}\n", "tool"))
        bom = base64.b64encode(b"\xef\xbb\xbf" + pem(r)).decode()
        self.assertIn(("private-key-base64", "SECRET", bom), found(f"key: {bom}\n", "tool"))
        chain = base64.b64encode(pem(r, "CERTIFICATE") + pem(r, "CERTIFICATE")).decode()
        self.assertEqual(kinds_over(f"ca.pem: {chain}\n", chain, "tool"), [])

    def test_the_first_line_alone_is_masked_where_the_lines_are_quoted(self):
        """A Python or JavaScript string split over quoted lines: the first line decodes to the header."""
        r = random.Random(39)
        key = b64_pem(r)
        lines = [key[i:i + 64] for i in range(0, len(key), 64)]
        text = "KEY = (\n" + "".join(f'    "{x}"\n' for x in lines) + ")\n"
        self.assertIn(("private-key-base64", "SECRET", lines[0]), found(text, "tool"))

    def test_many_certificate_lines_take_linear_time(self):
        """Gate B of 0.6.20: each line that starts with the base64 of BEGIN walked all following lines."""
        r = random.Random(40)
        head = b64_pem(r, "CERTIFICATE")[:76]
        times = []
        for n in (500, 2000):
            text = "\n".join(head[:20] + rd(r, 56, AN) for _ in range(n)) + "\n"
            t0 = time.perf_counter()
            detect.scan(text, enabled={"private-key-base64"}, channel="tool")
            times.append(time.perf_counter() - t0)
        self.assertLess(times[1], 8 * times[0] + 0.05)

    def test_the_forms_a_value_takes(self):
        r = random.Random(33)
        key = b64_pem(r, "OPENSSH PRIVATE KEY")
        for text in (f'{{"data": {{"ssh-privatekey": "{key}"}}}}', f"SSH_KEY_B64={key}",
                     f"kubectl ... -o yaml\n  key: {key}", f"tls.key: '{key}'", key):
            with self.subTest(form=text[:20]):
                self.assertIn(("private-key-base64", "SECRET", key), found(text, "tool"))

    def test_a_large_yaml_is_fast_for_this_rule(self):
        r = random.Random(34)
        cert, key = b64_pem(r, "CERTIFICATE"), b64_pem(r)
        for docs, n in ((k8s_secret(cert, cert) * 400, 0), (k8s_secret(key, cert) * 400, 400)):   # 1.8 MB each
            t0 = time.perf_counter()
            hits = detect.scan(docs, enabled={"private-key-base64"}, channel="tool")
            with self.subTest(keys=n):
                self.assertLess(time.perf_counter() - t0, 1.0)
                self.assertEqual(len(hits), n)

    def test_the_validator_decodes_only_the_head(self):
        r = random.Random(35)
        key = b64_pem(r)
        self.assertTrue(detect.VALIDATORS["base64_pem"](key))
        self.assertTrue(detect.VALIDATORS["base64_pem"](key[:60] + "\n  " + key[60:]))
        self.assertFalse(detect.VALIDATORS["base64_pem"](b64_pem(r, "CERTIFICATE")))
        self.assertFalse(detect.VALIDATORS["base64_pem"](key[:20] + "%%%%" + key[24:]))


# ------------------------------------------------------- betterleaks patches --
class BetterleaksPatchTests(unittest.TestCase):
    def test_each_patch_applies_to_the_vendored_rule_it_names(self):
        """After a re-sync that changes one of these rules, this goes red: check the correction against the new rule
        and drop it if upstream fixed the gap."""
        import json
        cfg = json.loads((detect.RULES_DIR / "betterleaks.json").read_text(encoding="utf-8"))
        vendored = {r["id"]: r for r in cfg["rules"]}
        loaded = {r.id: r for r in detect._load_betterleaks()}
        for rule_id, patch in detect.BETTERLEAKS_PATCHES.items():
            with self.subTest(rule=rule_id):
                self.assertIn(rule_id, vendored)
                self.assertIn(rule_id, loaded)
                for kw in patch.get("add_keywords", ()):
                    self.assertNotIn(kw, vendored[rule_id].get("keywords") or [])
                    self.assertIn(kw, loaded[rule_id].keywords)
                if "regex" in patch:
                    self.assertEqual(vendored[rule_id]["regex"], patch["expect"])
                    self.assertEqual(loaded[rule_id].regex.pattern, detect._re2_to_python(patch["regex"]))

    def test_a_bare_token_without_the_providers_name_is_found(self):
        b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        r = random.Random(40)
        for _ in range(20):
            cases = {
                "resend-api-key.1": J(["r", "e_"]) + rd(r, 8, b58) + "_" + rd(r, 24, b58),
                "ionic-personal-access-token": J(["io", "n_"]) + rd(r, 42, AN),
                "airtable-personnal-access-token": J(["pa", "t"]) + rd(r, 14, AN) + "." + rd(r, 64, HEXL),
                "wakatime-api-key.2": J(["wak", "a_"]) + r.choice([_uuid(r), rd(r, 40, L + D)]),
            }
            for rule_id, tok in cases.items():
                for text in (tok, f"here it is: {tok} thanks\n", f"echo '{tok}' | tool\n"):
                    with self.subTest(rule=rule_id, text=text[:12]):
                        self.assertIn(rule_id, kinds_over(text, tok, "tool"))

    def test_a_posix_class_of_re2_becomes_a_python_class(self):
        self.assertEqual(detect._re2_to_python(r"\b(pat[[:alnum:]]{14})"), r"\b(pat[A-Za-z0-9]{14})")
        self.assertEqual(detect._re2_to_python(r"[[:xdigit:]_-]"), r"[0-9A-Fa-f_-]")

    def test_a_waka_key_is_masked_whole(self):
        r = random.Random(41)
        tok = J(["wak", "a_"]) + _uuid(r)
        self.assertIn(("wakatime-api-key.2", "SECRET", tok), found(f"use {tok} here\n"))


if __name__ == "__main__":
    unittest.main()
