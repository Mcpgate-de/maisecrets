# ruff: noqa: E501
"""False-hit corpus for the forms of 0.6.24: ordinary developer text in exactly the shapes the new rules look for.

The rules of 0.6.24 read a value from a fixed form or after a label: an ID number after `member id`, `record no`,
`account`, `DL`; an identifier in a FHIR `"system"`/`"value"` pair; a SQL literal under an alias such as `AS ssn`; a
GitHub Actions `::add-mask::` value; an Azure `SharedAccessKey=`; a Postman variable with a secret key; a 48-digit
hex value after a token word; a phone number that is URL-encoded or wrapped over two lines; an address after an
address label; a name in a non-Latin script after a name label; a Japanese postcode with its address.

FORMS_NO_HIT is text in those shapes whose value is NOT a secret and NOT personal data: an ID-like label over a
count, a version or a ticket key; a FHIR code; a SQL placeholder; a mask of a variable; a key name; a Postman
template; an address of a server or a room; a product, a language or a company in a non-Latin script; a 48-digit
hex digest. Every entry must stay silent in both channels. FORMS_HIT holds synthetic true hits for each rule: each
entry is (id, text, [values]), and each value is the exact substring that must be masked in the tool channel.

All values are synthetic. A hex value is built at import from a hash, so no literal of a secret shape sits here.
"""
import hashlib


def _hex(seed: str, n: int = 48) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()[:n]


def _sid(seed: str) -> str:
    return "AC" + hashlib.md5(seed.encode()).hexdigest()


H1, H2, H3, H4 = _hex("digest-one"), _hex("digest-two"), _hex("digest-three"), _hex("digest-four")
T1, T2 = _hex("token-one"), _hex("token-two")
S1 = _sid("fixture-sid")

FORMS_NO_HIT = [
    # ---------------------------------------------------------------- ID-like labels in developer text
    ("member id count", "Fetched 48213 rows; member id column has 48213 distinct values."),
    ("member_id variable", "member_id = request.args.get('member_id')\nif not member_id:\n    abort(400)"),
    ("member id type", "member_id: int  # primary key of the members table, 32 bit"),
    ("record no log", "INFO batch: record no 104233 of 250000 processed (41.6%)"),
    ("record number progress", "Record number 20481 skipped: duplicate key"),
    ("record # changelog", "- Fixed record # handling in the CSV importer (#4821)"),
    ("account aws id", "Account: 123456789012\nRegion: eu-central-1\nRole: ReadOnlyAccess"),
    ("account arn", "arn:aws:iam::210987654321:role/deploy, account 210987654321"),
    ("account jira", "Account: PLATFORM-2291 (billing migration)"),
    ("account number of ledger", "account: 4000 (Revenue), 5000 (Cost of goods), 6000 (Operating expenses)"),
    ("patient id param", "GET /api/v2/patients/{patient_id}/encounters?limit=50"),
    ("patient id schema", "patient_id UUID NOT NULL REFERENCES patients(id)"),
    ("mrn column doc", "The MRN column is a string of up to 20 characters; see HL7 v2.5 PID-3."),
    ("passport no field", "passport_no: str = Field(..., min_length=6, max_length=9)"),
    ("passport number validator", "Passport number must match ^[A-Z0-9]{6,9}$ (ICAO 9303)."),
    ("tax id placeholder", "tax_id: ${TAX_ID}\nvat_rate: 19"),
    ("tax id format doc", "Tax ID format: 2 letters, then 9 to 12 digits (EU VIES)."),
    ("DL download size", "DL: 1024 MB, UL: 256 MB, ping 12 ms"),
    ("DL as download in table", "| file | DL | size |\n|---|---|---|\n| release-2.4.1.tar.gz | 18234 | 4.2 MB |"),
    ("insurance member id type", "insurance_member_id = models.CharField(max_length=32, blank=True)"),
    ("member tag build", "member: build-agents (RUNNER-0042)"),
    ("member paren team", "member: Platform Team (TEAM-4821)"),
    ("member paren version", "Member: core-maintainers (v2.14.0)"),
    ("nid json key", '{"nid": "node-4821", "type": "article", "status": 1}'),
    ("insurance version", "insurance_api: v2.3.1 (2026-01-15)"),
    ("passport build", "passport.js 0.7.0 with passport-local 1.0.0"),
    ("member id header doc", "Send the header X-Member-ID with the value of /me. Example: X-Member-ID: <member-id>"),
    ("account ticket", "Account REL-20481 is closed; see PROJ-1124."),
    ("record id uuid", "Record ID: 0b9c3f2e-5f1a-4b8e-9d3c-7a2e1f0c4b6d"),
    ("member since year", "Member since 2019, 4821 posts"),
    # ---------------------------------------------------------------- FHIR identifiers that are codes
    ("fhir type coding", '{"type": {"coding": [{"system": "http://terminology.hl7.org/CodeSystem/v2-0203", "code": "MR"}]}, "system": "urn:oid:1.2.36.146.595.217.0.1", "value": "{{mrn}}"}'),
    ("fhir license version", '{"system": "http://example.org/fhir/license-versions", "value": "v4.0.1"}'),
    ("fhir passport template", '{"system": "http://hl7.org/fhir/sid/passport-USA", "value": "${PASSPORT}"}'),
    ("fhir insurance plan code", '{"system": "http://example.org/insurance-plan-codes", "value": "PLAN"}'),
    ("fhir nid elided", '{"system": "urn:oid:2.16.840.1.113883.4.1/nid", "value": "XXXXXXXX"}'),
    ("fhir mrn sample", '{"system": "http://hospital.example.org/mrn", "value": "123456789"}'),
    # ---------------------------------------------------------------- SQL literals under an alias that are no value
    ("sql na ssn", "SELECT id, 'N/A' AS ssn, created_at FROM customers_archive;"),
    ("sql masked ssn", "SELECT '***-**-****' AS ssn FROM dual;"),
    ("sql redacted tax", "SELECT '[REDACTED]' AS tax_id, name FROM vendors;"),
    ("sql unknown address", "SELECT 'unknown address' AS address FROM orders WHERE address IS NULL;"),
    ("sql placeholder digits", "SELECT '000000000' AS member_id UNION ALL SELECT '123456789' AS member_id;"),
    ("sql date alias", "SELECT '2024-01-01' AS passport_no_valid_from"),
    ("sql company address", "SELECT 'Headquarters, 1 Market Street, Suite 300' AS address FROM company_info;"),
    # ---------------------------------------------------------------- add-mask of a variable
    ("add-mask env", 'echo "::add-mask::$API_TOKEN"'),
    ("add-mask braces", 'echo "::add-mask::${{ steps.login.outputs.token }}"'),
    ("add-mask shell braces", 'echo "::add-mask::${PASSWORD}"\necho "password=${PASSWORD}" >> "$GITHUB_OUTPUT"'),
    ("add-mask doc", "Use `::add-mask::<value>` to hide a value in the log."),
    ("add-mask subshell", 'echo "::add-mask::$(cat token.txt)"'),
    ("add-mask percent", 'echo "::add-mask::%TOKEN%"'),
    # ---------------------------------------------------------------- Azure key names and templates
    ("sas key name", "Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=<your-key>"),
    ("sas template braces", "Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=send;SharedAccessKey={key}"),
    ("sas env", "SharedAccessKey=${SAS_KEY};EntityPath=orders"),
    ("sas stars", "SharedAccessKey=********;EntityPath=orders"),
    ("sas doc prose", "The SharedAccessKey=value pair is the key of the policy; rotate it in the portal."),
    ("sas your key", "SharedAccessKey=YOUR_SHARED_ACCESS_KEY_HERE"),
    ("sas signature template", "SharedAccessSignature=sv=2022-11-02&ss=b&srt=sco&sp=r&se=${EXPIRY}&sig=${SIG}"),
    # ---------------------------------------------------------------- Postman variables that are no secret
    ("postman template", '{"key": "password", "value": "{{password}}", "type": "default"}'),
    ("postman token type", '{"key": "token_type", "value": "Bearer", "enabled": true}'),
    ("postman password policy", '{"key": "password_policy", "value": "strong", "enabled": true}'),
    ("postman secret name", '{"key": "secretName", "value": "my-app-secrets", "type": "default"}'),
    ("postman api key header", '{"key": "api_key_header", "value": "X-API-Key", "type": "default"}'),
    ("postman token url", '{"key": "token_url", "value": "https://auth.example.com/oauth/token"}'),
    ("postman env var", '{"key": "apiKey", "value": "$API_KEY"}'),
    ("postman angle", '{"key": "access_token", "value": "<access-token>"}'),
    ("postman min length", '{"key": "password_min_length", "value": "12"}'),
    ("postman token ttl", '{"key": "token_ttl_seconds", "value": "3600000"}'),
    # ---------------------------------------------------------------- 48 hex digits that are a hash
    ("digest after key word", f"cache key: {H1}"),
    ("tiger digest", f"tiger192,3 = {H2}"),
    ("hash in test vector", f"self.assertEqual(h.hexdigest(), '{H3}')"),
    ("bytes fromhex", f"data = bytes.fromhex('{H4}')"),
    ("code hash", f"code_hash = '{H1}'  # sha of the compiled module"),
    ("signature digest prose", f"The signature digest of the build is {H2} (SHA-384 truncated)."),
    ("etag", f'ETag: "{H3}"'),
    ("key fingerprint", f"Key fingerprint: {H4}"),
    ("hex in a checksum list", f"{H1}  dist/app-1.4.2.tar.gz\n{H2}  dist/app-1.4.2.whl"),
    # ---------------------------------------------------------------- phone-like encoded and wrapped numbers
    ("phone param version", "GET /search?phone_model=%2B12&tel_version=%2B3"),
    ("tel range", "for tel in range(1, 49): print(tel)"),
    ("phone wrapped math", "result = +4 3-\n  2 1"),
    ("phone wrapped version", "+1 2.4-\n  stable"),
    # ---------------------------------------------------------------- addresses that are no person's
    ("address listen", "address: 0.0.0.0:8080, 127.0.0.1:9090"),
    ("address ip list", "address: 10.0.0.1, 10.0.0.2, 10.0.0.3"),
    ("address server room", "Location: Frankfurt, Rack 12, Unit 4"),
    ("address office company", "Address: Acme Corp Headquarters, 100 Market Street, San Francisco, CA 94105"),
    ("address mac", "address: 00:1a:2b:3c:4d:5e, link/ether"),
    ("location region", "location: eu-west-1, eu-central-1"),
    ("address of a field doc", "address: str  # street, number, postcode and city, comma separated (max 200)"),
    ("address bitcoin doc", "address: bc1q, 42 chars, Bech32 (BIP 173)"),
    ("property version", "property: Build 4821, Version 2.3"),
    ("ship to doc", "ship_to: Address  # see schema v3, field 12, nullable"),
    ("indian office", "Registered office: 4/12, Tech Park Road, Whitefield, Bengaluru 560066 (Acme Software Pvt Ltd)"),
    ("japanese company postcode", "株式会社サンプル 本社 〒100-0005 東京都千代田区丸の内1-1-1"),
    # ---------------------------------------------------------------- non-Latin names that are products, languages, companies
    ("locale table zh", '{"code": "zh-CN", "name": "简体中文"}\n{"code": "ja-JP", "name": "日本語"}\n{"code": "ko-KR", "name": "한국어"}'),
    ("locale table ru", '{"code": "ru-RU", "name": "Русский язык", "native name": "Русский"}'),
    ("product name ru", "name: Яндекс Браузер\nversion: 24.4.1"),
    ("product name zh", "app_name: 微信\npackage: com.tencent.mm"),
    ("owner company", "owner: 阿里巴巴\nrepo: dragonwell8"),
    ("admin group", "admin: 管理员组\nmembers: 12"),
    ("name of a font", "name: 思源黑体\nfile: SourceHanSans.otf"),
    ("name of a city", "name: 東京\ntimezone: Asia/Tokyo"),
    ("arabic product", "name: متجر التطبيقات\nplatform: ios"),
    ("hindi language", "name: हिन्दी\ncode: hi-IN"),
    ("greek product", "name: Ελληνικά\ncode: el-GR"),
    ("hebrew language", "name: עברית\ncode: he-IL"),
    # ---------------------------------------------------------------- Latin names with diacritics that are words
    ("name label word diacritic", "name: Résumé Builder\nversion: 3"),
    ("name label product", "name: Ångström Toolkit"),
    ("owner team", "owner: Équipe Plateforme"),
    # ---------------------------------------------------------------- e-mail encoded in a URL that is no address
    ("enc mail to version", "Upgrade to pkg%40v2.1.0 before 2027"),
    ("enc mail cell scope", "scope,package\n@angular,core%40angular.dev"),
    # ---------------------------------------------------------------- password-like code that is no value
    ("login call variables", "client.login(user, password)"),
    ("login call template", 'client.login("{{user}}", "{{password}}")'),
    ("redis auth env", 'redis-cli -h cache "AUTH" "$REDIS_PASSWORD"'),
    ("user slash path", "login via user / Settings / Security and set a new password"),
    ("user slash fraction", "account 3 / 12 users active, credentials / 4 rotated"),
    ("sql creds placeholder", "INSERT INTO credentials VALUES (1, 'admin', '<hash>')"),
    # ---------------------------------------------------------------- Twilio-like ids that are no account
    ("twilio doc template", "Your Account SID starts with AC; copy it from the console (ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx)."),
    ("uppercase AC hex in a dump", "0x0010: AC12 FF00 9A3B 4C5D 6E7F 8091 A2B3 C4D5"),
]

FORMS_HIT = [
    ("add-mask literal", 'echo "::add-mask::' + "q7Lr" + "Pz2mK9vXw" + '"', ["q7Lr" + "Pz2mK9vXw"]),
    ("sas key", "Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=send;SharedAccessKey=" + "x+Q_4" + "pZ9kL2_m" + ";EntityPath=orders", ["x+Q_4" + "pZ9kL2_m"]),
    ("postman secret", '{"key": "password", "value": "' + "8fK2" + "qLw9Zx4Rp7Tn" + '"}', ["8fK2" + "qLw9Zx4Rp7Tn"]),
    ("har header", '{"name": "x-internal-token", "value": "' + T2 + '"}', [T2]),
    ("hex48 token prose", "the session token was " + T1 + " until the rotation", [T1]),
    ("redis auth", '1729000200.000 [0 10.0.0.5:51236] "AUTH" "' + "Wq%7r" + "Tz9Lp2Kx" + '"', ["Wq%7r" + "Tz9Lp2Kx"]),
    ("login call", 'server.login("' + "ops.mailer" + '", "' + "Rz%4" + "mKq9Lw" + '")', ["Rz%4" + "mKq9Lw"]),
    ("user slash", "also my login " + "jdoe.ops" + " / " + "7Kq_" + "mZr9Lw-x", ["7Kq_" + "mZr9Lw-x"]),
    ("fhir mrn", '{"system": "http://hospital.example.org/fhir/mrn", "value": "' + "MRN-" + "4471-2290" + '"}', ["MRN-" + "4471-2290"]),
    ("insurance member", "Insurance member " + "44719" + "02265", ["44719" + "02265"]),
    ("member id letters", "Member ID: " + "XKR" + "4471902", ["XKR" + "4471902"]),
    ("member parentheses", "Member: Dana Okafor (" + "MBR-" + "4XK7Q2" + ")", ["MBR-" + "4XK7Q2"]),
    ("sql alias tax", "SELECT '" + "44718" + "902265" + "' AS tax_id FROM staff", ["44718" + "902265"]),
    ("sql alias address", "SELECT '" + "12 Harbour Lane, Brookfield, 4471" + "' AS address FROM staff", ["12 Harbour Lane, Brookfield, 4471"]),
    ("address after label", "Address: " + "7 Rosemount Gardens, Dunmore, Wexford 4471", ["7 Rosemount Gardens, Dunmore, Wexford 4471"]),
    ("jp postcode", "住所: 〒" + "150-0002" + " 東京都渋谷区渋谷2-21-1", ["〒" + "150-0002" + " 東京都渋谷区渋谷2-21-1"]),
    ("indian address", "Ship to " + "14/2, Lakshmi Colony, Adyar, Chennai 600020", ["14/2, Lakshmi Colony, Adyar, Chennai 600020"]),
    ("name cyrillic", "patient: " + "Ирина" + " Соколова", ["Ирина" + " Соколова"]),
    ("name cjk", "Employee: " + "王" + "小明", ["王" + "小明"]),
    ("name latin ext", "full_name: " + "Łukasz" + " Wiśniewski", ["Łukasz" + " Wiśniewski"]),
    ("phone encoded", "GET /verify?phone=" + "%2B4915" + "123987654" + "&lang=de", ["%2B4915" + "123987654"]),
    ("phone wrapped", "Phone: +49 " + "1523-" + "\n4471-902 (mobile)", ["+49 " + "1523-" + "\n4471-902"]),
    ("encoded mail sent to", "Receipt sent to " + "dana.okafor" + "%40mailbox-test.net", ["dana.okafor" + "%40mailbox-test.net"]),
    ("encoded mail csv cell", "name,email,phone\nDana," + "dana.okafor" + "%40mailbox-test.net,unknown", ["dana.okafor" + "%40mailbox-test.net"]),
]
