"""User names in prose after a user cue and in a user-id element (#51, the gap to Cloakroom 1.4.0 on the V3 samples:
Nemotron 82 values), read by key_values.hits in the tool channel. Kept out of personal.py, which is at the size limit
of a release file; it imports personal.py only when it runs."""
from __future__ import annotations

import re

# a handle: parts joined by . _ or -, or letters with digits at the end; a word alone is no handle
_HANDLE = r"(?:[A-Za-z][A-Za-z0-9]{0,20}(?:[._-][A-Za-z0-9]{1,20}){1,3}|[A-Za-z]{2,20}\d{1,6})"
# a CamelCase pair (KalinOrbek) names a person only before a login verb; else it is a class or a product name
_CAMEL = r"[A-Z][a-z]{1,15}[A-Z][a-z0-9]{1,15}"
# the cues: `for user kalin.orbek`, `for invalid user k.orbek` (sshd), `User kalin.orbek successfully logged in` (also
# after a log prefix), `Welcome, kalin_orb_42.` and `Welcome back, ...`
# matched only where str.find saw `user` or `welcome`: one regex pass over a megabyte cost 0.09 s (#51)
_AT_RE = re.compile(r"(?i:user|welcome(?: back)?,)[ \t]+(" + _HANDLE + "|" + _CAMEL + r")(?=[.,;:!?)\s]|$)")
_STRONG = ("for", "by", "from", "the", "a", "invalid")       # `for user x` needs no verb of a login after it
_LOGIN_VERB_RE = re.compile(r"[ \t]+(?:successfully|logged|signed|accessed|failed|was|has|reported|attempted)\b")
_IS_RE = re.compile(r"(?i)user ?name is[ \t]+([A-Za-z][A-Za-z0-9._-]{1,30}?)(?=[.,;:!?)\s]|$)")


def user_names(text: str) -> list:
    """(start, end) of a user name after a cue in prose."""
    low = text.lower()
    starts = _at(low, "user") + _at(low, "welcome")
    if not starts:
        return []
    from .core import _word_set
    from .personal import _username_value_ok
    out = []
    for pos in sorted(starts):
        before = low[max(0, pos - 9):pos].split()
        m = _AT_RE.match(text, pos)
        if m is not None:
            v = m.group(1)
            login = bool(_LOGIN_VERB_RE.match(text, m.end(1)))
            # `user x` alone names an account only before a verb of a login (`User k.orbek logged in`)
            weak = low.startswith("user", pos) and not (before and before[-1] in _STRONG and low[pos - 1] == " ")
            if (weak or re.fullmatch(_CAMEL, v)) and not login:
                continue
            if _username_value_ok(v, False, " ") and _handle_ok(v, _word_set()):
                out.append((m.start(1), m.end(1)))
            continue
        if before and before[-1] == "my":
            m = _IS_RE.match(text, pos)
            if m is not None:
                v = m.group(1).rstrip("._-")
                # _username_value_ok refuses a word of the word list of 3 letters or more (`my username is visible`)
                if len(v) > 2 and _username_value_ok(v, False, " "):
                    out.append((m.start(1), m.start(1) + len(v)))
    return out


def _at(low: str, word: str) -> list:
    """The starts of `word` at the start of a word in the lowercased text (str.find, no regex pass)."""
    out, i = [], low.find(word)
    while i >= 0:
        if i == 0 or not (low[i - 1].isalnum() or low[i - 1] == "_"):
            out.append(i)
        i = low.find(word, i + 1)
    return out


# a part that names a daemon, a tool or a bot, not a person: `user kibana8`, `codecov-commenter`, `jira-integration2`
_TOOL_PARTS = frozenset(
    "bot bots svc service daemon cron cronjob runner deploy deployer integration commenter webhook kibana zabbix "
    "nagios pgbouncer grafana prometheus elastic elasticsearch logstash redis mongo mongodb mariadb postgres "
    "mysql jenkins gitlab github bitbucket jira confluence sonar sonarqube nexus artifactory ansible terraform "
    "docker podman kube kubernetes helm vault consul nomad airflow celery rabbitmq kafka zookeeper hadoop spark "
    "nginx apache httpd tomcat jetty ubuntu debian centos fedora alpine admin root guest webmaster postmaster "
    "backup monitor monitoring codecov dependabot renovate travis circleci".split())


def _handle_ok(v: str, known) -> bool:
    """A person's handle, not a device, a hex id or words of the word list: each part is letters with digits at the
    end at most, a part of letters is not all capitals, longer than two letters and no word of the list, and one
    has four letters or more (x86_64, v1.2.3, my_app, django_app, john.doe, eth0, SAML2, utf-8 and
    pod-7f9c stay text). An initial may lead (k.orbek, a corporate login)."""
    parts = [p for p in re.split(r"[._-]|(?<=[a-z])(?=[A-Z])", v) if p]
    if any(not re.fullmatch(r"[A-Za-z]+\d*|\d+", p) for p in parts):
        return False
    letters = [re.sub(r"\d+$", "", p) for p in parts if not p.isdigit()]
    if not letters or max(len(w) for w in letters) < 4:
        return False
    if len(letters) > 1 and len(letters[0]) == 1 and letters[0].islower():
        letters = letters[1:]                       # k.orbek: the initial of a given name
    return all(len(w) > 2 and not w.isupper() and w.lower() not in known and w.lower() not in _TOOL_PARTS
               for w in letters)


# a key whose value is a user name and that personal.py's username label does not read (#51); not `handle` or
# `screenName`, which name product slugs and app screens as often
USER_ID_KEYS = frozenset({"userid", "userlogin", "loginname", "loginid"})


def user_id_ok(v: str) -> bool:
    from .core import _word_set
    from .personal import _username_value_ok
    # _username_value_ok refuses a service user (ftpuser2), as on the cue path
    return bool(re.fullmatch(_HANDLE, v)) and _username_value_ok(v, False, " ") and _handle_ok(v, _word_set())
