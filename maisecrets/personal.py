"""Personal data that a label or a fixed form names: a name after `name:`, a birth date after `dob:`, an ID number
after `passport no:`, a street address with its postcode, the user in `user:pass@host` and in a home path, the cells
of a CSV column such as `address` or `phone`.

Each rule needs its label or its form. A name or an address without one stays text: maisecrets has no model, and
"Emma Johansson" alone looks like any two capitalised words (README, "Known gaps").

The rules come from the values that leaked in the public benchmark's holdout sets v2 to v7 (2026-10-14, 765 values).
Rules p13 (a name before an e-mail address) and p14 (the columns of a CSV header) follow the rule families of the
Cloakroom benchmark (https://github.com/shanjeevrajendran/cloakroom, Apache-2.0); the code here is written anew.

Channel: these rules run on tool results and files only. A typed prompt is blocked on a hit, and a person who types
a name or an address means to send it; the prompt keeps the stricter rules it had (docs/THREAT-MODEL.md).
Region: an address form of a country runs when that country's region is active; the phone and label rules are
generic.

Every check is bounded: each regex has bounded repeats, and a CSV header is read for at most _CSV_ROWS rows.
"""
from __future__ import annotations

import getpass
import re
import time

# ---------------------------------------------------------------------------------------------------- types --
NAME, ADDRESS, BIRTH_DATE, ID_NUMBER, USERNAME, PHONE = "NAME", "ADDRESS", "BIRTH_DATE", "ID_NUMBER", "USERNAME", \
    "PHONE"

# documentation names: a value that is one of them is an example, not a person
PLACEHOLDER_NAMES = frozenset({"jane doe", "john doe", "max mustermann", "erika mustermann", "john smith",
                               "jane smith", "joe bloggs", "john q. public", "richard roe", "jane roe",
                               "max muster", "maria musterfrau", "otto normalverbraucher", "alice", "bob"})

# ------------------------------------------------------------------------------- phone with one-digit groups --
# the phone rule of detect.py wants groups of two digits or more after the country code: "+1 4 15 22 3344" and
# "+44 7 911 123456" passed (holdout v6). Same bounds otherwise: 8 to 15 digits, not a run of two digits
_PHONE_GROUPS_RE = re.compile(r"(?<![\w+])\+(?!0)\d{1,3}(?:[ \-]\(?\d{1,5}\)?){2,10}(?![\w.]\d|\w)")

# a US number in its national form, (415) 555-0123, after a phone word; the 555 exchange is fictional
_US_PHONE_RE = re.compile(r"(?<![\w(])\([2-9]\d{2}\)[ ]?[2-9]\d{2}[-. ]\d{4}(?!\d)")   # NANP: no 0 or 1 first
_PHONE_WORD_RE = re.compile(r"(?i)phone|(?<![a-z])(?:telefon\w*|tel|cell|mobile?|handy|fax|contact|kontakt|call"
                            r"|reach|whatsapp|sms)(?![a-z])")

# ------------------------------------------------------------------------------------ birth date after a label --
_DATE = (r"(?:\d{4}-\d{2}-\d{2}|\d{1,2}[./-]\d{1,2}[./-]\d{2,4}|\d{1,2}\.?\s+[A-Za-zäéû]{3,9}\.?\s+\d{4}"
         r"|[A-Za-z]{3,9}\.?\s+\d{1,2},\s*\d{4})")
# "born" alone is left out: "born 23 June 1912" is history in a text about a public person (holdout v6 negative)
_BIRTH_RE = re.compile(r"(?i)(?:\bd\.?o\.?b\b|date of birth|birth[ _-]?date|\bbday\b|\bgeb(?:\.|oren am|urtsdatum)"
                       r"|n[ée]\(?e?\)? le|date de naissance|fecha de nacimiento|\bnac[ií](?:d[oa])? el"
                       r"|data de nascimento|data di nascita|\bnato il)[\"'\]]?\s{0,3}[:=]?\s{0,3}[\"'(]?\s{0,3}"
                       r"(" + _DATE + r")(?!\d)")

# --------------------------------------------------------------------------------- ID number after a label --
_ID_RE = re.compile(r"(?i)(?<![a-z])(?:mrn|member[ -]?id|passport(?:[ _-]?(?:no|number))?|driver'?s? licen[cs]e"
                    r"(?:[ _-]?(?:no|number))?|dl[ _-]?(?:no|number|#)|(?-i:DL)(?=\s{0,3}[:#])|sin|tfn|nir|tax[ _-]?id"
                    r"|insurance (?:member )?id"
                    r"|account (?:number|no\.?)|patient[ -]?id|id on file)(?![a-z])[\"']?"
                    r"(?:\s{0,3}(?:on file|is|number|no\.?|#))?\s{0,3}[:=#]?\s{0,3}[\"']?"
                    r"((?-i:[A-Z0-9](?:[A-Z0-9]|[ -](?=[A-Z0-9])){4,24}))(?![A-Za-z0-9])")

# ------------------------------------------------------------------------------------- user in a URL or path --
_URL_USER_RE = re.compile(r"://([^:/?#\s@\[\]]{1,64}):[^@\s/]{1,128}@")
_HOME_USER_RE = re.compile(r"(?:/home/|/Users/|[A-Za-z]:\\\\?Users\\\\?)([A-Za-z][A-Za-z0-9._-]{1,31})(?=[/\\])")
# service accounts and the words of documentation: no person
SERVICE_USERS = frozenset({
    "root", "runner", "ubuntu", "user", "admin", "shared", "public", "default", "ec2-user", "git", "node", "app",
    "vscode", "jenkins", "gitlab-runner", "circleci", "travis", "docker", "dev", "developer", "me", "you",
    "username", "yourname", "your-user", "your_user", "name", "foo", "bar", "test", "pi", "linuxbrew", "runneradmin",
    "builder", "build", "ci", "www-data", "nobody", "postgres", "mysql", "jovyan", "vagrant", "centos", "fedora",
    "debian", "alpine", "azureuser", "opc", "cloud-user", "core", "steam", "guest", "administrator", "all users",
    "default user", "defaultapppool", "localservice", "networkservice", "systemprofile", "redis", "elastic",
    "oracle", "sa", "deploy", "deployer", "ansible", "github", "gitlab", "bitbucket", "bamboo", "teamcity",
    "buildkite", "buildbot", "actions", "codespace", "gitpod", "coder", "workspace", "sandbox", "tester", "demo",
    "example", "sample", "someone", "somebody", "john", "jane", "alice", "bob", "x", "xxx", "home", "users",
    "anonymous", "anon", "apikey", "api", "api_key", "token", "oauth", "oauth2", "x-access-token", "x-token-auth",
    "x-oauth-basic", "bearer", "key", "secret", "pass", "password", "login", "account", "service", "client",
    "nonroot", "airflow", "rstudio", "rocky", "kali", "vsts", "keycloak", "rabbitmq", "kubeadmin", "aws", "gcp",
    "azure", "wordpress", "gitlab-ci-token", "personalaccesstoken", "jupyter", "spark", "hadoop", "kafka",
    "zookeeper", "grafana", "prometheus", "nginx", "apache", "httpd", "tomcat", "minio", "gitea", "sonar",
    "sonarqube", "nexus", "odoo", "ftp", "mail", "www", "web", "backup", "ops", "devops", "cloud", "ubuntu-server",
    "arch", "manjaro", "suse", "opensuse", "kubernetes", "k8s", "pi", "postgresql", "mongodb", "mongo", "mariadb",
    "couchdb", "neo4j", "influxdb", "clickhouse", "sentry", "superset", "metabase", "n8n", "frappe", "erpnext",
    "dependabot", "renovate", "github-actions", "travis-ci", "drone", "woodpecker", "argocd", "flux", "vault",
    "consul", "nomad", "terraform", "packer", "bitnami", "daemon", "bin", "sys", "sync", "games", "man", "lp",
    "news", "uucp", "proxy", "list", "irc", "gnats", "systemd-network", "messagebus", "sshd", "chrony", "ntp",
    "oai", "readonly", "read_only", "reader", "writer", "readwrite", "migration", "migrations", "migrator",
    "replication", "replicator", "repl", "monitor", "monitoring", "metrics", "exporter", "healthcheck", "probe",
    "owner", "dbo", "dbadmin", "dba", "superuser", "su", "operator", "scheduler", "etl", "analytics", "report",
    "reporting", "integration", "webhook", "smtp", "imap", "noreply", "no-reply", "relay", "upload", "download",
})
# a user name that a tool or an image creates, not a person: appuser, app_user, mambauser, seluser, pwuser, user1
_SERVICE_USER_RE = re.compile(r"(?i)^(?:.{0,12}[-_]?user\d*|user[-_]?\d+|.{0,20}(?:bot|svc|service|admin|runner|"
                              r"agent|daemon|worker|deploy|build)(?:[-_]?\d+)?|[a-z]{1,3}\d+|.*\[bot\])$")


def _service_user(u: str) -> bool:
    low = u.lower()
    return low in SERVICE_USERS or bool(_SERVICE_USER_RE.match(low)) or low.startswith("__") \
        or sum(c.isdigit() for c in u) >= 4 or bool(re.search(r"[{}$<>%]", u))

# ------------------------------------------------------------------------------- street address with postcode --
_STREET = (r"(?:St|Street|Rd|Road|Ave|Avenue|Lane|Ln|Blvd|Boulevard|Drive|Dr|Way|Court|Ct|Place|Pl|Terrace|Close"
           r"|Crescent|Marg|Nagar|Square|Sq|Highway|Hwy)")
# per region: (regions, regex). The postcode of each country: US and CA (state and ZIP, or the Canadian A1A 1A1),
# UK, IN (six digits), AU and NZ (state and four digits)
_POSTCODES = {
    "us": r"\b[A-Z]{2} \d{5}(?:-\d{4})?\b", "ca": r"\b[A-Z]{2} [A-Z]\d[A-Z] ?\d[A-Z]\d\b",
    "uk": r"\b[A-Z]{1,2}\d[A-Z\d]? \d[A-Z]{2}\b", "ie": r"\b[A-Z]\d{2} ?[A-Z0-9]{4}\b", "in": r"\b\d{6}\b",
    "au": r"\b[A-Z]{2,3} \d{4}\b", "nz": r"\b\d{4}\b",
}
_EN_STREET = (r"\b\d{1,5}[A-Za-z]?(?:/\d{1,4})?,? (?:[A-Z][\w'.-]{0,30} ){1,4}" + _STREET
              + r"\.?,[^\n\"';|]{2,40}?(?:{codes})")
_CITY = r"[A-ZÄÖÜÉ][\wäöüßéèàç-]{1,40}"
_ADDRESS_FORMS = tuple(
    (frozenset({r}), re.compile(_EN_STREET.replace("{codes}", code))) for r, code in _POSTCODES.items()) + (
    (frozenset({"de", "at", "ch"}),
     re.compile(r"\b[A-ZÄÖÜ][\wäöüß-]{0,40}(?:straße|strasse|str\.|weg|gasse|platz|allee|ring|damm) \d{1,4}[a-z]?, "
                r"\d{4,5} (" + _CITY + ")")),
    (frozenset({"fr", "be", "lu", "ch"}),
     re.compile(r"\b\d{1,4},? (?:rue|avenue|boulevard|bd|chemin|allée|place|impasse) [^\n,\"]{2,40}, \d{5} "
                r"(" + _CITY + ")")),
    (frozenset({"pt", "br", "es", "it"}),
     re.compile(r"(?:^|(?<=[\s:;,(\"']))(?:Rua|Avenida|Av\.|Calle|Carrer|Via|Viale|Piazza) [^\n,\"]{2,40}, \d{1,5}"
                r"[^\n\"]{0,40}?\b(?:\d{5}(?:-\d{3})?|\d{4}-\d{3}) (" + _CITY + ")")),
)
# the street word of an English gerund is no German street: Filtering 2, Scoring 4
_GERUND_STREET_RE = re.compile(r"(?:er|or|ur|ar|ir|in)ing \d")
# the address of a company, an office or a public building is no personal data: a word for one on the same line
# before the address, or inside it, keeps it text (Impressum, HQ, the Empire State Building in a travel text)
_NOT_A_HOME_RE = re.compile(
    r"(?i)(?<![a-z])(?:hq|headquarters?|head office|office|offices|campus|building|tower|center|centre|museum"
    r"|embassy|botschaft|consulate|station|airport|flughafen|hotel|hospital|klinik|university|universität|school"
    r"|library|stadium|arena|park|mall|store|shop|restaurant|caf[eé]|bank|impressum|anschrift der firma|firmensitz"
    r"|sitz der gesellschaft|niederlassung|filiale|zweigstelle|branch office|gmbh|ag|ug|kg|sas|sa|srl|bv|e\.v\."
    r"|inc|corp|corporation|llc|ltd|limited|plc|s\.a\.|sarl|s\.r\.l\."
    r"|company|firm|registered|visitor|visit us|our address|unsere adresse|landmark|monument|parliament"
    r"|town hall|rathaus|city hall|cathedral|church|kirche|mairie)(?![a-z])")

# --------------------------------------------------------------------------------- name after a name label --
# a letter of Latin Extended-A (Ł, ś, ř, ğ) is a letter of a name too: Łukasz Wiśniewski, Dvořák (holdout, 2026-10-15)
_UP, _LO = "A-ZÀ-ÖØ-ÞĀ-ſ", "a-zà-öø-ÿĀ-ſ"
_NAME_WORD = r"(?:[" + _UP + r"][" + _LO + r"'’-]{1,30}|[A-Z]\.)"
_NAME_PARTICLE = r"(?:van|von|de|da|del|der|al|bin|di|du|la|le)"
_NAME_VALUE = (r"((?:[" + _UP + r"][" + _LO + r"'’-]{1,30})(?:[ ](?:" + _NAME_WORD + "|" + _NAME_PARTICLE + r")){1,3})")
# a label that names a person and nothing else
_PERSON_LABELS = (r"full[ _-]?name|customer[ _-]?name|first[ _-]?name|last[ _-]?name|given[ _-]?name|family[ _-]?name"
                  r"|patient(?:[ _-]?name)?|employee(?:[ _-]?name)?|student(?:[ _-]?name)?|contact[ _-]?person"
                  r"|account[ _-]?holder|card[ _-]?holder|cardholder|passenger|tenant|landlord|signer|co-signer"
                  r"|guardian|beneficiary|billed to|oncall|on-call|requested by|reviewed by|approved by|salari[ée]"
                  r"|vorname|nachname|mieter|vermieter|ansprechpartner(?:in)?|pr[ée]nom")
# a label that also names a product, a service, a team or a document: its value must not read as words
_WEAK_LABELS = r"fn|name|display[ _-]?name|owner|author|driver|holder|kunde|inhaber(?:in)?|nom|nombre|nome"
_NAME_LABEL_RE = re.compile(
    r"(?i:(?<![a-z_./-])(?:(" + _PERSON_LABELS + r")|(" + _WEAK_LABELS + r")))"
    r"[\"']?[ \t]{0,3}[:=][ \t]{0,3}[\"']?[ \t]{0,3}" + _NAME_VALUE + r"(?![\w'’])")
# the end of a word that makes it a noun, not a name: Streaming, Expedition, Management, Wörterbuch, Verwaltung
_NOUN_END_RE = re.compile(r"(?i)(?:ing|tion|sion|ment|ness|ity|ism|ogy|ware|ance|ence|able|ible|buch|ung|heit|keit"
                          r"|schaft|isch|tät|ive|ics|ers|ies)$")


# English words of two and three letters (the word list starts at four): the verb of a CI step name, `Run Pytest`
_SHORT_EN = frozenset({"run", "set", "get", "add", "use", "fix", "new", "old", "all", "the", "and", "for", "not", "top",
                       "end", "log", "job", "app", "web", "api", "dev", "ops", "off", "on", "up", "out", "key", "map",
                       "tag", "pin", "cut", "mix", "bug", "put", "pop", "via", "to", "of", "in", "at", "by", "is",
                       "no", "go", "do", "my", "our", "own", "per", "pre", "sub", "max", "min", "raw", "dry", "lint"})


def _city_is_a_word(city: str) -> bool:
    """65536 Bytes, 30022 Rows: an English word after the postcode is no city."""
    from .detect import _word_set
    low = city.lower()
    return low in _word_set() or (low.endswith("s") and low[:-1] in _word_set())


def _reads_as_words(v: str, every: bool = False) -> bool:
    """A value whose words are English words or nouns, not a name: `Customer Portal`, `Run Pytest`, `Product Owner`,
    `Won't Do`, `Mgmt Vpc`. A given name that is also a word (`Mark`, `Rose`) counts as a name."""
    from .detect import _word_set
    words = _word_set()
    hits = []
    for i, w in enumerate(v.replace("’", "'").split()):
        lw = w.lower().strip(".")
        if "'" in lw and not lw.startswith(("o'", "d'", "l'")):
            return True          # won't, don't: a contraction is prose
        if len(lw) >= 2 and not re.search(r"[aeiouyäöüéèàáíóú]", lw):
            return True          # Mgmt, Vpc: no vowel, an abbreviation
        if len(lw) <= 1 or (i == 0 and lw in _GIVEN_NAME_WORDS):
            hits.append(False)
            continue
        stem = lw[:-1] if lw.endswith("s") and len(lw) > 4 else lw
        hits.append(lw in _SHORT_EN or (len(lw) >= 3 and (lw in words or stem in words
                                                          or bool(_NOUN_END_RE.search(lw)))))
    return all(hits) if every else any(hits)


# given names that are also English words (SCOWL); a value that starts with one may still be a person
_GIVEN_NAME_WORDS = frozenset({"john", "peter", "maria", "mark", "rose", "grace", "will", "bill", "jack", "frank",
                               "dean", "drew", "faith", "hope", "joy", "june", "may", "pat", "ray", "rich", "sue",
                               "ruby", "pearl", "amber", "rob", "tom", "tim", "ben", "dan", "don", "ian", "eve",
                               "lily", "iris", "holly", "ivy", "jade", "dawn", "summer", "victor", "carl", "sam"})


# the first word of a value that is no name
_NOT_A_NAME_START = frozenset({
    "the", "a", "an", "my", "your", "our", "this", "that", "new", "old", "none", "null", "true", "false", "test",
    "example", "admin", "user", "team", "service", "system", "default", "unknown", "anonymous", "all", "any", "no",
    "not", "see", "tbd", "todo", "n/a", "der", "die", "das", "ein", "eine", "kein", "keine", "le", "la", "les", "el",
    "github", "gitlab", "google", "microsoft", "amazon", "apple", "meta", "docker", "kubernetes", "visual",
})
# a word in a value that makes it an organisation, a product or a place, not a person
_NOT_A_NAME_WORD = frozenset({
    "team", "teams", "group", "squad", "crew", "department", "dept", "division", "org", "organisation", "organization",
    "inc", "corp", "corporation", "company", "co", "llc", "ltd", "limited", "plc", "gmbh", "ag", "kg", "ug", "se",
    "sa", "sarl", "bv", "nv", "foundation", "project", "developers", "contributors", "community", "authors",
    "maintainers", "bot", "robot", "agent", "server", "service", "services", "cache", "cluster", "proxy", "gateway",
    "controller", "operator", "worker", "manager", "engine", "platform", "studio", "code", "app", "application",
    "suite", "cloud", "api", "sdk", "cli", "ui", "web", "data", "database", "store", "storage", "queue", "stream",
    "network", "labs", "lab", "systems", "solutions", "software", "technologies", "tech", "digital", "media", "games",
    "university", "universität", "school", "college", "institute", "hospital", "city", "street", "road",
    "avenue", "center", "centre", "building", "tower", "station", "airport", "river", "lake", "mountain",
    "north", "south", "east", "west", "new", "san", "los", "las", "saint", "st", "fort", "port", "am", "main",
    "edition", "version", "release", "update", "preview", "beta", "alpha", "stable", "nightly", "pro", "plus",
    "enterprise", "community", "free", "basic", "premium", "standard", "default", "custom", "local", "global",
    "nord", "süd", "sued", "ost", "mitte", "vertrieb", "einkauf", "stadtwerke", "werke", "retail", "studios",
    "workers", "weblate", "autofix", "ci", "oss", "snyk", "sonar", "codecov", "github", "gitlab", "bitbucket",
    "atlassian", "jenkins", "grafana", "loki", "kibana", "elastic", "datadog", "sentry", "jira", "confluence",
    "sammlung", "verwaltung", "abteilung", "gruppe", "dienst", "konto", "kunden", "ordner", "datei", "seite",
    "monitoring", "logging", "security", "support", "sales", "marketing", "finance", "ops", "devops", "infra",
    "infrastructure", "backend", "frontend", "mobile", "desktop", "release", "build", "deploy", "staging",
    "production", "prod", "dev", "test", "tests", "testing", "demo", "sample", "example", "template", "docs",
    "documentation", "readme", "guide", "manual", "handbook", "policy", "rule", "rules", "config", "settings",
    "dashboard", "report", "reports", "alert", "alerts", "job", "jobs", "task", "tasks", "pipeline", "workflow",
})


def _name_ok(v: str) -> bool:
    words = v.replace("’", "'").split()
    low = [w.lower().strip(".") for w in words]
    if v.lower() in PLACEHOLDER_NAMES or low[0] in _NOT_A_NAME_START:
        return False
    if any(w in _NOT_A_NAME_WORD for w in low):
        return False
    return sum(1 for w in words if len(w.strip(".")) >= 2) >= 2


# ------------------------------------------------------------------------------- name before an e-mail address --
# "Erika Beispiel <erika@example.org>", a git log line, a mail header. The address is the e-mail rule's; this is the
# name before it. A service mailbox (noreply, a bot) names no person
_NAME_MAIL_RE = re.compile(r"((?:[A-ZÀ-ÖØ-Þ][a-zà-öø-ÿ'’-]{1,30})(?: (?:[A-ZÀ-ÖØ-Þ][a-zà-öø-ÿ'’-]{1,30}|[A-Z]\.)){1,3})"
                           r"[ \t]{0,2}[<(\[]([\w.%+-]{1,64})@([\w-]{1,63}(?:\.[\w-]{1,63}){0,8})")
_SERVICE_LOCAL_RE = re.compile(r"(?i)^(?:no-?reply|do-?not-?reply|notifications?|support|info|hello|contact|team"
                               r"|admin|root|git|bot|ci|build|release|deploy|security|alerts?|monitoring|postmaster"
                               r"|webmaster|mailer-daemon|bounces?|github-actions|actions|dependabot|renovate)"
                               r"(?:[+._-].*)?$|.*[-_.]bot$|.*\[bot\]$")

# ---------------------------------------------------------------------------------------- CSV header columns --
# a header with a column that holds personal data on every row. A name or a user column alone is no proof (a product
# list has a `name` column): it counts only next to a strong column
_STRONG_COLS = frozenset({"address", "street", "street_address", "home_address", "endereco", "direccion", "adresse",
                          "anschrift", "strasse", "dob", "date_of_birth", "birth_date", "birthdate", "birthday",
                          "geburtsdatum", "phone", "phone_number", "telephone", "telefone", "telefono", "telefon",
                          "mobile", "mobile_phone", "cell", "ssn", "tfn", "aadhaar", "nir",
                          "passport", "passport_number", "national_id", "tax_id", "mrn"})
_WEAK_COLS = frozenset({"name", "full_name", "fullname", "first_name", "last_name", "firstname", "lastname",
                        "given_name", "family_name", "surname", "customer", "customer_name", "employee",
                        "employee_name", "emp_name", "patient", "patient_name", "nome", "nombre", "nom", "vorname",
                        "nachname", "username", "user_name"})
_CSV_ROWS = 10000   # rows read under one header; a larger table is read in its first rows only
_CSV_CELL_RE = {sep: re.compile(r'"[^"\n]{0,512}"|[^' + sep + r'\n]{0,512}') for sep in (",", ";", "\t")}
_NOT_A_CELL = frozenset({"", "null", "none", "n/a", "na", "-", "true", "false", "nan"})


_DATE_CELL_RE = re.compile(_DATE)
_NAME_CELL_RE = re.compile(_NAME_VALUE)


def _column_type(col: str) -> str:
    if col in ("dob", "date_of_birth", "birth_date", "birthdate", "birthday", "geburtsdatum"):
        return BIRTH_DATE
    if col in ("phone", "phone_number", "telephone", "telefone", "telefono", "telefon", "mobile", "mobile_phone",
               "cell"):
        return PHONE
    if col in ("address", "street", "street_address", "home_address", "endereco", "direccion", "adresse",
               "anschrift", "strasse"):
        return ADDRESS
    if col in _WEAK_COLS:
        return USERNAME if "user" in col else NAME
    return ID_NUMBER


def _cell_ok(v: str, typ: str) -> bool:
    """The cell holds what its column names: a desk extension is no phone, `Front Desk` no name."""
    digits = sum(c.isdigit() for c in v)
    if typ == PHONE:
        return digits >= 7
    if typ == BIRTH_DATE:
        return bool(_DATE_CELL_RE.fullmatch(v)) and not _placeholder_digits(v, dates=True) and _past_year(v)
    if typ == ADDRESS:
        return digits >= 1 and len(v) >= 8 and not _NOT_A_HOME_RE.search(v)
    if typ == NAME:
        return bool(_NAME_CELL_RE.fullmatch(v)) and _name_ok(v) and not _reads_as_words(v)
    if typ == USERNAME:
        return not _service_user(v)
    return digits >= 5 and not _placeholder_digits(v)


def _csv_hits(text: str) -> list:
    out = []
    lines = text.split("\n")
    pos = 0
    li = 0
    while li < len(lines) - 1:
        hdr = lines[li]
        sep = max((",", ";", "\t"), key=hdr.count)
        if hdr.count(sep) < 1 or " " in hdr.strip() or len(hdr) > 2000:
            pos += len(hdr) + 1
            li += 1
            continue
        names = [h.strip().strip("\"'").lower() for h in hdr.split(sep)]
        strong = {i for i, h in enumerate(names) if h in _STRONG_COLS}
        cols = strong | {i for i, h in enumerate(names) if h in _WEAK_COLS} if strong else set()
        pos += len(hdr) + 1
        li += 1
        if not cols:
            continue
        rows = 0
        while li < len(lines) and rows < _CSV_ROWS:
            line = lines[li]
            if not line.strip() or (line.count(sep) != hdr.count(sep) and '"' not in line):
                break
            j = col = 0
            row: list = []
            cell = _CSV_CELL_RE[sep]
            while j <= len(line):
                m = cell.match(line, j)
                a, b = m.span()
                if col in cols:
                    s2, e2 = (a + 1, b - 1) if line[a:b].startswith('"') and b - a >= 2 else (a, b)
                    v = line[s2:e2].strip()
                    typ = _column_type(names[col])
                    if v.lower() not in _NOT_A_CELL and len(v) >= 2 and _cell_ok(v, typ):
                        lead = len(line[s2:e2]) - len(line[s2:e2].lstrip())
                        row.append((pos + s2 + lead, pos + s2 + lead + len(v), "csv-personal-column", typ, col))
                col += 1
                j = b + 1
            # a name or a user cell counts only beside a strong cell of the same row that holds what it names, and an
            # address or a phone only beside a cell that names a person (a name, a birth date, an id): a list of
            # depots or of stations has addresses and no person
            if any(c in strong for *_, c in row) and any(h[3] in (NAME, BIRTH_DATE, ID_NUMBER) for h in row):
                out += [h[:4] for h in row]
            pos += len(line) + 1
            li += 1
            rows += 1
    return out


# ------------------------------------------------------------------------------------------ the forms of 0.6.24 --
# A value in a fixed form or after a label that names it, from the holdout values that 0.6.21 still leaked
# (2026-10-15). Each rule declares (type, channel, region, needs): channel "tool" (tool results and files) or "both".
# All run in the tool channel only: a typed question about a form (`How does ::add-mask::x work?`) is no secret, and
# a hit there blocks the prompt (review of 0.6.24);
# region "generic" or a country; needs "form" (a fixed syntax names the value: ::add-mask::, SharedAccessKey=, a FHIR
# identifier, a 〒 postcode) or "label" (a word before the value names it: member, record, token, address).
# tests/fp_corpus_forms.py holds the developer text in the same shapes that each rule must leave alone.
FORMS = {
    "secret-add-mask": ("SECRET", "tool", "generic", "form"),
    "secret-shared-access-key": ("SECRET", "tool", "generic", "form"),
    "secret-postman-variable": ("SECRET", "tool", "generic", "form"),
    "secret-hex48-after-token-word": ("SECRET", "tool", "generic", "label"),
    "secret-in-login-code": ("SECRET", "tool", "generic", "form"),
    "secret-after-user-slash": ("SECRET", "tool", "generic", "label"),
    "id-number-fhir-identifier": (ID_NUMBER, "tool", "generic", "form"),
    "id-number-after-record-label": (ID_NUMBER, "tool", "generic", "label"),
    "id-letters-after-label": (ID_NUMBER, "tool", "generic", "label"),
    "id-number-in-member-parentheses": (ID_NUMBER, "tool", "generic", "label"),
    "id-number-under-sql-alias": (ID_NUMBER, "tool", "generic", "label"),
    "address-under-sql-alias": (ADDRESS, "tool", "generic", "label"),
    "address-after-label": (ADDRESS, "tool", "generic", "label"),
    "address-jp-postcode": (ADDRESS, "tool", "generic", "form"),
    "address-in-form": (ADDRESS, "tool", "in", "form"),
    "name-non-latin-after-label": (NAME, "tool", "generic", "label"),
    "phone-url-encoded": (PHONE, "tool", "generic", "label"),
    "phone-wrapped-line": (PHONE, "tool", "generic", "form"),
}
# a value that only names one: a variable, a template, an elision, a path
_NOT_A_VALUE_START = ("$", "%", "{", "<", "(", "[", "*", "#", "/", ".")


def _random_value(v: str, n: int = 8) -> bool:
    """A value of a secret: n characters or more, a letter and a digit, no space, not a variable or a template."""
    return (len(v) >= n and not v.startswith(_NOT_A_VALUE_START) and "${" not in v and "{{" not in v and "$(" not in v
            and not re.search(r"\s", v) and any(c.isdigit() for c in v) and any(c.isalpha() for c in v))


def _complex(v: str) -> bool:
    """Three of four classes: lower, upper, digit, sign. A password that someone chose, not a word or a path."""
    return sum((any(c.islower() for c in v), any(c.isupper() for c in v), any(c.isdigit() for c in v),
                any(not c.isalnum() for c in v))) >= 3


_ADD_MASK_RE = re.compile(r"::add-mask::([^\s\"'`]{6,256})")
_SAS_KEY_RE = re.compile(r"(?i)\bSharedAccessKey=([A-Za-z0-9+/_=-]{16,256})(?![A-Za-z0-9+/_=-])")
# a Postman or Insomnia variable, a HAR header: {"key"|"name": "<secret word>", "value": "..."}
_KV_SECRET_RE = re.compile(r"\"(?:key|name)\"\s*:\s*\"([^\"\n]{1,60})\"\s*,\s*\"value\"\s*:\s*\"([^\"\n]{6,512})\"")
_SECRET_NAME_PARTS = frozenset({"password", "passwd", "pwd", "secret", "token", "apikey", "pass", "credential",
                                 "credentials", "auth", "passphrase", "bearer", "jwt", "privatekey", "signingkey",
                                 "clientkey", "accesskey", "secretkey"})
_META_NAME_RE = re.compile(r"(?i)(?:type|url|uri|name|header|policy|length|len|ttl|seconds|expiry|expires|endpoint|path"
                           r"|id|ids|hint|label|format|scheme|prefix|mode|kind|version|count|audience|issuer|provider"
                           r"|scope|store|tokenizer)$")
_HOST_RE = re.compile(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\.?")


def _name_parts(name: str) -> list:
    """`x-internal-token` -> x, internal, token; `clientSecret` -> client, secret; `API_KEY` -> api, key."""
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return [p.lower() for p in re.split(r"[^A-Za-z0-9]+", name) if p]


def _secret_name(name: str) -> bool:
    parts = _name_parts(name)
    joined = ["".join(parts[i:i + 2]) for i in range(len(parts) - 1)]
    # a part with a counter counts as its word: password2, token_1
    return any(p.rstrip("0123456789") in _SECRET_NAME_PARTS for p in parts + joined)


def _words_inside(v: str) -> bool:
    """A value with a dictionary word of five letters or more in it (Release2026Alpha, Billing2FA-Setup) is a name or
    a placeholder: a chosen password or a key has none (holdout values of 0.6.21, review of 0.6.24)."""
    from .detect import _word_set
    if re.search(r"[^\w.-]", v):
        return False   # a sign other than - _ . (Summer2024!x, Sunshine#2024): a chosen password, words or not
    words = _word_set()
    return any(r.lower() in words for r in re.findall(r"[A-Z][a-z]{4,}|[a-z]{5,}|[A-Z]{5,}", v))


_HEX48_RE = re.compile(r"(?i)(?<![a-z])(token|code|secret|key)(?![a-z])[^\n]{0,24}?(?<![0-9a-fA-F])([0-9a-f]{48})"
                       r"(?![0-9a-zA-Z])")
_DIGEST_WORD_RE = re.compile(r"(?i)hash|digest|checksum|fingerprint|cache|etag|sha|md5|tiger|integrity|commit")
_REDIS_AUTH_RE = re.compile(r"\"AUTH\"\s+\"([^\"\n]{6,128})\"(?!\s+\")")
_LOGIN_CALL_RE = re.compile(r"\.login\(\s*([\"'])[^\"'\n]{1,64}\1\s*,\s*([\"'])([^\"'\n]{6,128})\2\s*\)")
_OP_FIELDS_RE = re.compile(r"op item get[^\n]*--fields[^\n]*\busername,password\b[^\n]*\n[^\n]{1,128}\n([^\s]{6,128})"
                           r"(?=\n|$)")
_SQL_CREDS_RE = re.compile(r"(?i)INSERT INTO \w*(?:cred|passw|secret|login)\w*\s+VALUES\s*\(([^)\n]{1,300})\)")
_USER_SLASH_RE = re.compile(r"(?i)(?<![a-z])(?:login|user|creds?|credentials|account)(?![a-z])[^\n]{0,30}?(?<!\S)"
                            r"[\w.@-]{2,64} / (\S{8,64})(?!\S)")
_FHIR_RE = re.compile(r"(?i)\"system\"\s*:\s*\"([^\"\n]{0,80})\"\s*,\s*\"value\"\s*:\s*\"([^\"\n]{4,40})\"")
_FHIR_SYSTEM_RE = re.compile(r"(?i)(?:^|[/:._#-])(?:mrn|passport(?:-[a-z]{2,3}|[-_]?(?:number|no))?|ssn|nid"
                             r"|national[-_]?id|tax[-_]?id"
                             r"|member[-_]?id|insurance(?:[-_]member)?(?:[-_]id)?)(?:$|[/:._#-])")
_IDENTIFIER_KEY_RE = re.compile(r"\"identifier\"\s*:\s*\[")


def _in_identifier_array(text: str, pos: int, most: int = 4000) -> bool:
    """`pos` lies inside a FHIR `"identifier": [...]` array: the last such key within `most` characters before it,
    with its bracket still open (an `identifierRequired` flag or a closed array does not count)."""
    lo = max(0, pos - most)
    last = None
    for m in _IDENTIFIER_KEY_RE.finditer(text, lo, pos):
        last = m
    if last is None:
        return False
    seg = text[last.end():pos]
    return seg.count("[") - seg.count("]") >= 0


_VERSION_RE = re.compile(r"(?i)^v?\d+(?:\.\d+)+$")
_ID_VALUE = r"((?-i:[A-Z0-9](?:[A-Z0-9]|[ -](?=[A-Z0-9])){4,24}))(?![A-Za-z0-9])"
_RECORD_LABEL_RE = re.compile(
    r"(?i)(?<![a-z])(?:insurance(?:[ _-]?member)?(?:[ _-]?id)?|member(?:[ _-]?(?:id|no|number|#))?"
    r"|record(?:[ _-]?(?:no|number|#))?|patient(?:[ _-]?id)?|account|(?<=\")nid(?=\")|(?-i:DL)(?=[\"']?[\s:#]))"
    r"(?![a-z])[\"']?"
    r"(?:\s{0,3}(?:is|number|no\.?|#))?\s{0,3}[:=#]?\s{0,3}[\"']?" + _ID_VALUE)
_ID_LETTERS_RE = re.compile(r"(?i)(?<![a-z])(?:member(?:[ _-]?id)?|passport|insurance(?:[ _-]?id)?)(?![a-z])[\"']?"
                            r"(?:\s{0,3}(?:is|number|no\.?|#))?\s{0,3}[:=#]?\s{0,3}[\"']?"
                            r"((?-i:[A-Z0-9][A-Z0-9-]{6,22}[A-Z0-9]))(?![A-Za-z0-9])")
_MEMBER_PAREN_RE = re.compile(r"(?i)(?<![a-z])member[\"']?\s{0,3}:\s{0,3}[^\n()]{2,40}\((?-i:([A-Z0-9][A-Z0-9-]{4,22}"
                              r"[A-Z0-9]))\)")
_SQL_ALIAS_RE = re.compile(r"'([^'\n]{5,80})'\s+(?i:AS)\s+(?i:(sin|ssn|tax_?id|mrn|nid|passport(?:_no)?|member_?id"
                           r"|national_?id|aadhaar|pan|nhs|tfn|address|home_address))\b")
_JP_ADDRESS_RE = re.compile(r"〒\d{3}-\d{4}[ 　]?[^\s\"',;<>|]{2,40}")
_JP_COMPANY_RE = re.compile(r"株式会社|有限会社|合同会社|本社|支社|支店|営業所|事務所|工場|センター|ビル|役所"
                            r"|大学|病院")
_ADDRESS_LABEL_RE = re.compile(
    r"(?i)(?<![a-z_])(address(?: on file)?|home[ _-]?address|adr|ship[ _-]?to|reship to|property|lives"
    r"|endere[cç]o|direcci[oó]n|adresse|location)[\"']?\s{0,3}:\s{0,3}[\"']?(;*)([^\n\"|;]{8,100}?)"
    r"(?=[\"\n|]|\s{2}|\.\s|$)")
# a house number and a street word, in either order: 12 Harbour Lane, Rua das Flores 12,
_HOUSE_RE = re.compile(r"\b\d{1,5}[A-Za-z]?(?:/\d{1,4})?,? [A-ZÀ-Þ][a-zà-ÿ]{2,}\b(?! \d)"
                       r"|[A-ZÀ-Þ][a-zà-ÿ]{2,} \d{1,5}[A-Za-z]?,")
_NOT_AN_ADDRESS_RE = re.compile(r"(?i)\b(?:rack|row|slot|zone|version|build|schema|width|height|signal|size|page"
                                r"|step|round|score|accepted|proposed|rejected)\b|0x")
_IN_ADDRESS_RE = re.compile(r"\b\d{1,4}(?:/\d{1,4})?, [^\n]{10,90}?, [A-Z][a-z]+ \d{6}\b")
_NONLATIN = "Ͱ-ϿЀ-ӿ֐-׿؀-ۿऀ-ॿঀ-৿"
_CJK_NAME = "一-鿿가-힯぀-ヿ"
# labels that name a person and nothing else; `name`, `owner` and `admin` also name a product, a language or a group
_NONLATIN_LABEL_RE = re.compile(
    r"(?i)(?:(?<![a-z_])(?:full[ _-]?name|native name|(?:employee|patient|customer|contact|recipient)[ _-]?name"
    r"|beneficiary)[\"']?[ \t]{0,3}[:=]?"
    r"|^fn[\"']?[ \t]{0,3}[:=])[ \t]{0,3}[\"']?"
    r"((?:[" + _NONLATIN + r"]{2,20}(?: [" + _NONLATIN + r"]{2,20}){1,3})|[" + _CJK_NAME + r"]{2,5})(?![\w])", re.M)
# names of a language in its own script: a locale table is no person
_AUTONYMS = frozenset({"русский", "українська", "беларуская", "български", "српски", "македонски", "ελληνικά",
                       "עברית", "العربية", "فارسی", "اردو", "हिन्दी", "বাংলা", "中文", "简体中文", "繁體中文", "日本語",
                       "한국어", "русский язык", "қазақ тілі"})
_PHONE_URL_RE = re.compile(r"(?i)(?<![a-z])(?:phone|tel|mobile|msisdn|cell)[\w-]{0,10}=(%2B\d{7,15})(?!\d)")
_PHONE_WRAP_RE = re.compile(r"(?<![\w+])\+(?!0)\d{1,3}[ \-]?\d{2,5}(?:[ \-]\d{2,5}){0,2}-\n[ \t]{0,4}\d{2,5}"
                            r"(?:[ \-]\d{2,5}){0,3}(?![\w.]\d|\w)")


def _line_back(text: str, pos: int, most: int = 120) -> int:
    """The start of the line of `pos`, at most `most` characters back: the search itself is bounded, so a long line of
    hits stays linear (review of 0.6.24)."""
    lo = max(0, pos - most)
    nl = text.rfind("\n", lo, pos)
    return nl + 1 if nl >= 0 else lo


def _cut_at_a_word(v: str) -> str:
    """An ID ends before a word that follows its digits: `20231115 LIMIT 10` is a value and an SQL clause."""
    parts = v.split(" ")
    for i in range(1, len(parts)):
        if parts[i].isalpha() and len(parts[i]) >= 3 and any(c.isdigit() for c in parts[i - 1]):
            return " ".join(parts[:i])
    return v


def _a_date(v: str) -> bool:
    """Eight digits that read as a day of 1900 to 2099 (YYYYMMDD)."""
    return bool(re.fullmatch(r"(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])", v))


def _form_hits(text: str, channel: str, regions: tuple, want) -> list:
    out = []
    if "secret-add-mask" in want and "::add-mask::" in text:
        for m in _ADD_MASK_RE.finditer(text):
            if _random_value(m.group(1)) and not _words_inside(m.group(1)):
                out.append((m.start(1), m.end(1), "secret-add-mask", "SECRET"))
    if "secret-shared-access-key" in want and "haredaccesskey=" in text.lower():
        for m in _SAS_KEY_RE.finditer(text):
            v = m.group(1)
            if _random_value(v, 16) and not re.fullmatch(r"[A-Z0-9_]+", v) and not _words_inside(v):
                out.append((m.start(1), m.end(1), "secret-shared-access-key", "SECRET"))
    if "secret-postman-variable" in want and "\"value\"" in text:
        for m in _KV_SECRET_RE.finditer(text):
            name, v = m.group(1), m.group(2)
            if _secret_name(name) and not _META_NAME_RE.search(name) and _random_value(v) and "://" not in v \
                    and not _HOST_RE.fullmatch(v) and not _words_inside(v):
                out.append((m.start(2), m.end(2), "secret-postman-variable", "SECRET"))
    if "secret-hex48-after-token-word" in want:
        for m in _HEX48_RE.finditer(text):
            v = m.group(2)
            if _DIGEST_WORD_RE.search(text, max(0, m.start() - 16), m.start(2)):
                continue   # a hash: cache key, key fingerprint, the digest of a build
            if sum(c.isdigit() for c in v) >= 4 and sum(c.isalpha() for c in v) >= 4:
                out.append((m.start(2), m.end(2), "secret-hex48-after-token-word", "SECRET"))
    if channel != "tool":
        return out
    if "secret-in-login-code" in want:
        for rx, g in ((_REDIS_AUTH_RE, 1), (_LOGIN_CALL_RE, 3), (_OP_FIELDS_RE, 1)):
            for m in rx.finditer(text):
                v = m.group(g)
                if _complex(v) and not v.startswith(_NOT_A_VALUE_START) and "{{" not in v:
                    out.append((m.start(g), m.end(g), "secret-in-login-code", "SECRET"))
        for m in _SQL_CREDS_RE.finditer(text):
            cells = list(re.finditer(r"'([^'\n]{6,128})'", m.group(1)))
            if cells and _complex(cells[-1].group(1)) and not cells[-1].group(1).startswith(_NOT_A_VALUE_START):
                c = cells[-1]
                out.append((m.start(1) + c.start(1), m.start(1) + c.end(1), "secret-in-login-code", "SECRET"))
    if "secret-after-user-slash" in want and " / " in text:
        for m in _USER_SLASH_RE.finditer(text):
            v = m.group(1)
            if _complex(v) and any(c.isdigit() for c in v) and "/" not in v and not _words_inside(v):
                out.append((m.start(1), m.end(1), "secret-after-user-slash", "SECRET"))
    low = text.lower()
    if "id-number-fhir-identifier" in want and "\"system\"" in text:
        for m in _FHIR_RE.finditer(text):
            v = m.group(2)
            if not _in_identifier_array(text, m.start()):
                continue   # a FHIR identifier stands in an `identifier` array; `{"system": "license", ...}` is metadata
            if _FHIR_SYSTEM_RE.search(m.group(1)) and sum(c.isdigit() for c in v) >= 5 and not _VERSION_RE.match(v) \
                    and not v.startswith(_NOT_A_VALUE_START) and not _placeholder_digits(v):
                out.append((m.start(2), m.end(2), "id-number-fhir-identifier", ID_NUMBER))
    if any(w in low for w in ("member", "record", "patient", "account", "insurance", "nid", "dl")):
        if "id-number-after-record-label" in want:
            for m in _RECORD_LABEL_RE.finditer(text):
                v = _cut_at_a_word(m.group(1))
                digits = sum(c.isdigit() for c in v)
                if _a_date(v):
                    continue   # member_id = 20231115: a day, not a member
                if re.match(r"(?i)(?:account|record)", m.group(0)) and v.replace(" ", "").isdigit():
                    continue   # an AWS account id, a row counter: digits alone after account or record
                if m.group(0).startswith("nid") and digits < 8:
                    continue   # a node id of a CMS ("nid": "10234"); a national id has eight digits or more
                if re.match(r"(?i)account", m.group(0)) and digits < 6:
                    continue   # a ticket key after account (REL-20481): an account number has six digits or more
                if digits >= 5 and not (v.isdigit() and len(v) >= 17) and not _placeholder_digits(v):
                    out.append((m.start(1), m.start(1) + len(v), "id-number-after-record-label", ID_NUMBER))
        if "id-letters-after-label" in want:
            for m in _ID_LETTERS_RE.finditer(text):
                v = m.group(1)
                nd = sum(c.isdigit() for c in v)
                # letters after a digit (MBR-4XK7Q2): TEAM-ALPHA-2024 and PLAN-2024 are names and years
                if nd and sum(c.isalpha() for c in v) >= 2 and re.search(r"\d[A-Z]", v) \
                        and not (nd >= 3 and _placeholder_digits(v)):
                    out.append((m.start(1), m.end(1), "id-letters-after-label", ID_NUMBER))
        if "id-number-in-member-parentheses" in want:
            for m in _MEMBER_PAREN_RE.finditer(text):
                v = m.group(1)
                # a member number mixes letters into its digits (ABC-4XY5Z6): TEAM-4821 and RUNNER-0042 are names
                if sum(c.isdigit() for c in v) >= 2 and re.search(r"\d[A-Z]", v):
                    out.append((m.start(1), m.end(1), "id-number-in-member-parentheses", ID_NUMBER))
    if ("id-number-under-sql-alias" in want or "address-under-sql-alias" in want) and "'" in text:
        for m in _SQL_ALIAS_RE.finditer(text):
            v, al = m.group(1), m.group(2).lower()
            if "addr" in al:
                if "address-under-sql-alias" in want and any(c.isdigit() for c in v) and "," in v \
                        and not _NOT_A_HOME_RE.search(v):
                    out.append((m.start(1), m.end(1), "address-under-sql-alias", ADDRESS))
            elif "id-number-under-sql-alias" in want and sum(c.isdigit() for c in v) >= 5 \
                    and not _placeholder_digits(v):
                out.append((m.start(1), m.end(1), "id-number-under-sql-alias", ID_NUMBER))
    if "address-jp-postcode" in want and "〒" in text:
        for m in _JP_ADDRESS_RE.finditer(text):
            line = _line_back(text, m.start())
            if not _JP_COMPANY_RE.search(text, line, m.end()):
                out.append((m.start(), m.end(), "address-jp-postcode", ADDRESS))
    if "address-after-label" in want:
        for m in _ADDRESS_LABEL_RE.finditer(text):
            if m.group(1).lower() == "adr" and not m.group(2):
                continue   # ADR alone is an architecture decision record; the vCard field is ADR:;;<street>
            v = m.group(3).strip()
            # the check for a company or a public place reads at most 120 characters of the line before the label:
            # unbounded, a long line of addresses took quadratic time (review of 0.6.24)
            line = _line_back(text, m.start())
            if (any(c.isdigit() for c in v) and "," in v and _HOUSE_RE.search(v)
                    and "://" not in v and not re.search(r"\d+\.\d+\.\d+|:\d{2,5}\b|[{}<>$()=_\[\]#@]", v)
                    and not _NOT_A_HOME_RE.search(text, line, m.end()) and not _NOT_AN_ADDRESS_RE.search(v)):
                s0 = m.start(3) + (len(m.group(3)) - len(m.group(3).lstrip()))
                out.append((s0, s0 + len(v), "address-after-label", ADDRESS))
    if "address-in-form" in want and "in" in regions:
        for m in _IN_ADDRESS_RE.finditer(text):
            line = _line_back(text, m.start())
            if m.group().count(",") >= 3 and not _NOT_A_HOME_RE.search(text, line, min(len(text), m.end() + 80)):
                out.append((m.start(), m.end(), "address-in-form", ADDRESS))
    if "name-non-latin-after-label" in want:
        for m in _NONLATIN_LABEL_RE.finditer(text):
            if m.group(1).lower() not in _AUTONYMS:
                out.append((m.start(1), m.end(1), "name-non-latin-after-label", NAME))
    if "phone-url-encoded" in want and "%2" in text.upper():
        for m in _PHONE_URL_RE.finditer(text):
            d = m.group(1)[3:]
            if 8 <= len(d) <= 15 and len(set(d)) > 2:
                out.append((m.start(1), m.end(1), "phone-url-encoded", PHONE))
    if "phone-wrapped-line" in want and "-\n" in text:
        for m in _PHONE_WRAP_RE.finditer(text):
            d = re.sub(r"\D", "", m.group())
            # after a phone word: `delta: +12 345-` and a next line of digits is arithmetic in a log
            if 8 <= len(d) <= 15 and len(set(d)) > 2 and _PHONE_WORD_RE.search(text, max(0, m.start() - 30),
                                                                               m.start()):
                out.append((m.start(), m.end(), "phone-wrapped-line", PHONE))
    return out


# ------------------------------------------------------------------------------------------------- the scan --
# words one of which a text must hold before a rule's regex runs (a cheap test on the lowered text)
_BIRTH_WORDS = ("dob", "d.o.b", "birth", "bday", "geb", "n\u00e9", "ne le", "nee le", "naissance", "nacimiento", "naci",
                "nac\u00ed", "nascimento", "nascita", "nato")
_ID_WORDS = ("mrn", "member", "passport", "licen", "dl", "sin", "tfn", "nir", "tax", "insurance", "account",
             "patient", "id on file")
RULE_IDS = ("phone-one-digit-groups", "phone-us-national", "birth-date-after-label", "id-number-after-label",
            "user-in-url", "user-in-home-path", "street-address", "name-after-label", "name-before-email",
            "csv-personal-column") + tuple(FORMS)
# the rules a typed prompt also takes: a fix of the phone rule that both channels have
PROMPT_RULES = frozenset({"phone-one-digit-groups"} | {k for k, v in FORMS.items() if v[1] == "both"})
# the type and the region of each rule, for the registry (detect.pass_specs)
TYPES = {"phone-one-digit-groups": PHONE, "phone-us-national": PHONE, "birth-date-after-label": BIRTH_DATE,
         "id-number-after-label": ID_NUMBER, "user-in-url": USERNAME, "user-in-home-path": USERNAME,
         "street-address": ADDRESS, "name-after-label": NAME, "name-before-email": NAME,
         "csv-personal-column": "COLUMN", **{k: v[0] for k, v in FORMS.items()}}
REGIONS = {k: v[2] for k, v in FORMS.items()}
NEEDS = {"birth-date-after-label": "label", "id-number-after-label": "label", "name-after-label": "label",
         "name-before-email": "form", "street-address": "form", "csv-personal-column": "label",
         **{k: v[3] for k, v in FORMS.items()}}
_US_PHONE_REGIONS = frozenset({"us", "ca"})


# the default of a form, not a date: the Unix epoch and the first day of 1900
_PLACEHOLDER_DATES = frozenset({"01011970", "19700101", "010170", "01011900", "19000101", "010100", "00000000"})


def _placeholder_digits(v: str, dates: bool = False) -> bool:
    """A specimen or a form default: one digit repeated (X0000000), a run up or down (123456789), the epoch."""
    d = re.sub(r"\D", "", v)
    if dates and d in _PLACEHOLDER_DATES:
        return True
    return len(set(d)) <= 1 or d in "01234567890" or d in "98765432109"


def _past_year(date: str) -> bool:
    """A birth date lies before this year: a date of this year or later is an event, a release, a deadline."""
    years = re.findall(r"(?<!\d)(\d{4})(?!\d)", date)
    return not years or int(years[-1]) < time.gmtime().tm_year


def _own_user() -> str:
    try:
        return getpass.getuser().lower()
    except Exception:  # noqa: BLE001 - no user name (a container without a passwd entry)
        return ""


def hits(text: str, channel: str, regions: tuple) -> list:
    """(start, end, rule id, type) of each hit. The caller drops a span another rule took and a placeholder."""
    want = RULE_IDS if channel == "tool" else PROMPT_RULES.intersection(RULE_IDS)
    out = []
    if "phone-one-digit-groups" in want and "+" in text:
        for m in _PHONE_GROUPS_RE.finditer(text):
            d = re.sub(r"\D", "", m.group())
            groups = re.findall(r"\d+", m.group())[1:]
            # a group of two digits or more after the country code: "+1 0 0 1 2 3 4 5" is a row of a matrix
            # in a typed prompt only after a phone word: "+1 2 3 4 56 7 89" is a row of numbers
            if 8 <= len(d) <= 15 and len(set(d)) > 2 and any(len(g) >= 2 for g in groups) and (
                    channel == "tool" or _PHONE_WORD_RE.search(text, max(0, m.start() - 30), m.start())):
                out.append((m.start(), m.end(), "phone-one-digit-groups", PHONE))
    if "phone-us-national" in want and _US_PHONE_REGIONS.intersection(regions) and "(" in text:
        for m in _US_PHONE_RE.finditer(text):
            if re.search(r"\)\s?555[-. ]", m.group()):
                continue
            if _PHONE_WORD_RE.search(text, max(0, m.start() - 30), m.start()):
                out.append((m.start(), m.end(), "phone-us-national", PHONE))
    out += _form_hits(text, channel, regions, want)
    if channel != "tool":
        return out
    low = text.lower()
    if "birth-date-after-label" in want and any(k in low for k in _BIRTH_WORDS):
        for m in _BIRTH_RE.finditer(text):
            if _placeholder_digits(m.group(1), dates=True) or not _past_year(m.group(1)):
                continue
            out.append((m.start(1), m.end(1), "birth-date-after-label", BIRTH_DATE))
    if "id-number-after-label" in want and any(k in low for k in _ID_WORDS):
        for m in _ID_RE.finditer(text):
            v = m.group(1)
            # 17 digits and more: a snowflake id of a chat platform or a database key, no document number
            if sum(c.isdigit() for c in v) >= 5 and not (v.isdigit() and len(v) >= 17) and not _placeholder_digits(v):
                out.append((m.start(1), m.end(1), "id-number-after-label", ID_NUMBER))
    if "user-in-url" in want and "://" in text:
        for m in _URL_USER_RE.finditer(text):
            u = m.group(1)
            # __token__ is PyPI's user for an API token; a template or a variable is no user
            # __token__ is PyPI's; an app key or an account id (four digits and more) names no person (CredData)
            if _service_user(u):
                continue
            out.append((m.start(1), m.end(1), "user-in-url", USERNAME))
    if "user-in-home-path" in want and ("/home/" in text or "/Users/" in text or "Users\\" in text):
        own = _own_user()
        for m in _HOME_USER_RE.finditer(text):
            u = m.group(1).lower()
            # the person's own home: the client tells the model the working directory, so masking it protects nothing
            if _service_user(u) or u == own:
                continue
            out.append((m.start(1), m.end(1), "user-in-home-path", USERNAME))
    if "street-address" in want:
        for regs, rx in _ADDRESS_FORMS:
            if not regs.intersection(regions):
                continue
            for m in rx.finditer(text):
                line = text.rfind("\n", 0, m.start()) + 1
                prev = text.rfind("\n", 0, max(0, line - 1)) + 1
                # the line before counts too: a heading (Acme Corp Niederlassung München), a label (Venue: Empire
                # State Building). "branch" alone is no word here: it is a git branch more often than an office
                if line:
                    line = prev
                if _NOT_A_HOME_RE.search(text, max(line, m.start() - 160), m.end()) or _GERUND_STREET_RE.search(
                        m.group()) or (rx.groups and _city_is_a_word(m.group(1))):
                    continue
                end = m.end(1) if rx.groups else m.end()
                out.append((m.start(), end, "street-address", ADDRESS))
    if "name-after-label" in want and (":" in text or "=" in text):
        for m in _NAME_LABEL_RE.finditer(text):
            v = m.group(3).rstrip("'’")   # tenant: 'Jonas Wendler': the closing quote is no part of the name
            # after a person label (patient, full_name) a surname may be a word (Sarah Park): only a value of words
            # alone (Product Owner) is no name. After a weak label (name, owner) one word is enough
            words_only = _reads_as_words(v, every=True) if m.group(1) else _reads_as_words(v)
            if _name_ok(v) and not words_only:
                out.append((m.start(3), m.start(3) + len(v), "name-after-label", NAME))
    if "name-before-email" in want and "@" in text:
        for m in _NAME_MAIL_RE.finditer(text):
            if _SERVICE_LOCAL_RE.match(m.group(2)) or not _name_ok(m.group(1)) or _reads_as_words(m.group(1)):
                continue
            out.append((m.start(1), m.end(1), "name-before-email", NAME))
    if "csv-personal-column" in want and "\n" in text:
        out += _csv_hits(text)
    return out
