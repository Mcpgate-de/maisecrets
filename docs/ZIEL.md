# Ziel: Secrets und PII erreichen kein Cloud-Modell

Stand: 2026-09-26. Auftrag von Andi. Dieses Dokument hält das Ziel fest.
Die Zerlegung in Teilaufgaben folgt später.

## Das Ziel in einem Satz

Ein Secret oder ein personenbezogenes Datum, das auf dem Rechner eines
Mitarbeiters liegt, verlässt den Rechner nicht im Klartext in Richtung eines
Cloud-Modells. Der Agent arbeitet trotzdem damit. Ein lokaler Vault hält den
Wert. Der Wert wird erst in den echten API-Aufruf eingesetzt.

## Was gelten muss

1. **Alle Clients.** Claude Code, Claude Desktop/Cowork, ChatGPT, Codex.
   Mac und Windows. Mobile, wenn erreichbar. Zugeständnisse sind erlaubt und
   werden benannt.
2. **Vor dem Client, nicht im Modell.** Die Ersetzung geschieht lokal und
   deterministisch, bevor Daten den Rechner verlassen.
3. **Rehydrierung.** Ein API-Aufruf oder Tool-Aufruf, der einen Platzhalter
   trägt, bekommt den echten Wert eingesetzt. Das Modell sieht den Wert nie.
4. **Ein lokaler Vault pro Nutzer.** Sicher, mit UI, mit Zwischenablage,
   anschließbar an den ai-gateway (der Gateway rehydriert dann seinerseits).
5. **Zukunftssicher.** Die Lösung darf nicht an einem Feature eines Clients
   hängen, das der Hersteller entfernen kann.

## Was schon existiert (Bezug: ai-gateway origin/main 579949288)

- **#1180** Secret handling. Messung: 185 echte Credentials in 3254 Sessions.
  5 % im Tool-Argument, 15 % aus Gateway-Antworten, **80 % nie am Gateway**
  (Read/Bash von .env und Quellcode). Phase 0/1 auf prod: Store-Werte kommen
  als undurchsichtiger Marker, kein Reveal-Endpunkt. Offen: Deposit-Call,
  Scope-Bindung, lokale Schicht.
- **#1388** AWS/SES-Connector (Oleg). Olegs Vorschlag: OOB put/get gegen den
  Gateway mit Referenz. Session-Empfehlung: Paste-URL statt CLI-put. Andi hat
  Oleg noch nicht geantwortet.
- **#1396** Auflösbares Token `<EMAIL_1:ma***@gmail.com>` statt `mask`.
  Noch kein Code. Prod läuft auf `mask`. Das heutige E-Mail-Regex zerstört
  das Token.
- **Wrapper-Skizze 15.09.** `secure_read`/`secure_bash` als MCP-Tools, native
  Tools per deny sperren, Platzhalter `<<SECRET:xxxx>>`, Vault pro Session.
- **Kostenanalyse** (~/llm-cost-analysis): ein Modell-Router pro Schritt
  spart wenig. Aufteilung an Aufgabengrenzen spart ~30 %.

## Was die Recherche vom 26.09. ergab

### Zwei Annahmen aus früheren Sessions sind falsch

1. "Claude Code Hooks können nur blocken." Falsch. `PreToolUse.updatedInput`
   ersetzt Argumente, `PostToolUse.updatedToolOutput` ersetzt jedes
   Tool-Ergebnis, bevor es zum Modell geht. Nur der getippte Prompt ist nicht
   umschreibbar. Die 80-%-Klasse ist damit per Hook erreichbar.
2. "Abo-Login geht nicht über ein Gateway." Falsch. `ANTHROPIC_BASE_URL`
   ohne Gateway-Credential behält das Abo. Live-Test: der volle
   `/v1/messages`-Body samt OAuth-Header kam auf `http://127.0.0.1` an.

### Abfangpunkte je Client

| Client | Eigener Endpunkt | Inhalt umschreiben | Mobile |
|---|---|---|---|
| Claude Code | ja, `ANTHROPIC_BASE_URL`, per MDM erzwingbar | Hooks für Tools; Prompt nur per Proxy | n/a |
| Claude Desktop/Cowork, claude.ai-Login | nein | nein | — |
| Claude Desktop **3P-Modus** | ja, `inferenceGatewayBaseUrl` per MDM | nein, Redaktion im Gateway | verliert Mobile und claude.ai-Web |
| Codex CLI | ja, `openai_base_url`, ChatGPT-Login möglich | Hooks für Tools | n/a |
| ChatGPT Desktop und Mobile | nein, Zertifikats-Pinning (Ausnahmen seit 2026-04 weg) | nein | nein |
| ChatGPT Web / claude.ai Web | nur Browser-DLP, keine Rehydrierung | nein | — |
| OpenCode | ja, `baseURL` | ja, `experimental.chat.messages.transform` | n/a |

### Werkzeuge am Markt

- **Proxies mit Rehydrierung:** PrivAiTe (BSD-3, Anthropic + OpenAI +
  Responses, restauriert Tool-Argumente), claude-code-redact `rdx`
  (Apache-2.0, deterministische Tokens), pii-hole. Alle früh, Mapping meist
  nur pro Request.
- **Secret-Injektion auf Egress:** Infisical Agent Vault (MIT, MITM-Proxy,
  Platzhalter wird im ausgehenden Request ersetzt, SQLite verschlüsselt,
  Web-UI), OneCLI (Rust). Nur Secrets, keine PII im Text.
- **Kommerziell:** Private AI, Protecto, Skyflow, Kong Enterprise. Keines
  dokumentiert die Restaurierung von Tool-Aufrufen.
- **LiteLLM + Presidio** hatte 2026 einen stillen Bug: Tool-Argumente werden
  nicht restauriert. LLM Guard ist archiviert.
- **MCP-Spec 2025-11-25:** Elicitation für Secrets MUSS URL-Modus sein.
- **1Password for Claude** (Juli 2026): injiziert Credentials außerhalb des
  Modellkontexts in die Webseite. Claude Code nicht genannt.

### Warum clientseitige Redaktion trotz Enterprise-Vertrag nötig bleibt

ZDR gilt nicht für Cowork, claude.ai-Chat und MCP-Server. Geflaggte
Sessions hält Anthropic bis zu 2 Jahre.

## Offene Fragen an Andi

Siehe Chat vom 26.09.2026. Die Antworten kommen in dieses Dokument.

## Entscheidungen vom 26.09.2026

- **Scheibe 1 ist der Hook-Weg, nicht der Proxy.** Ein `UserPromptSubmit`-Hook
  erkennt deterministisch, legt den Wert im Vault ab, blockt den Prompt und
  legt den Ersatz-Prompt in die Zwischenablage. Gemessen: ein geblockter
  Prompt erzeugt keinen API-Request. Deckt Claude Code und Codex ab, nicht
  Cowork und ChatGPT. Der Proxy ist Scheibe 2.
- **Zwei Fallen aus dem Test gehören in den Bau:** der Klartext steht im
  Transkript als `queue-operation`-Record, und der Hook-Timeout (30 s) ist
  fail-open. `suppressOriginalPrompt` gehört unter `hookSpecificOutput`.
- **#1396 und #1388 sind Vorbereitung, keine Blocker.** Andi bearbeitet #1396.
- **anonym.legal ist keine Lösung** (zweite Cloud, MCP greift zu spät, der
  publizierte Hook ändert den Prompt nicht). Die Tool-Form
  anonymize/detokenize/list_sessions/delete_session ist ein brauchbares Muster.
- **Vault, Scheibe 1: Betriebssystem-Speicher** (macOS Keychain ohne
  Sync-Flag, Windows Credential Manager) über `keyring`, plus eigene
  Index-Datei für Typ, Zweck, Ablauf. Vier Funktionen: put, get, list, expire.
  Backend austauschbar.
- **Nicht auf LastPass bauen.** phase6 nutzt LastPass, die Zukunft ist offen.
  `lastpass-cli`: letztes Release v1.6.1 (2024-11-14), letzter Commit
  2025-04-22, 219 offene Issues, keine Secret-Referenzen. LastPass selbst
  (Blog 2026-05-15): "LastPass doesn't authenticate AI agents, issue OAuth
  tokens, or manage machine identities." Die Wahl des Passwortmanagers ist eine
  eigene Entscheidung und darf dieses Projekt nicht blockieren.
- **Lebensdauer im Vault:** jeder Eintrag hat eine TTL (Start 24 h, wie das
  Gateway-Mapping). Jede Nutzung verlängert sie. Nach Ablauf wird nur der
  Wert gelöscht; der Metadaten-Eintrag (Typ, Fingerabdruck, Anlagezeit,
  letzte Nutzung, Sitzung) bleibt als Protokoll. Ein abgelaufener Platzhalter
  schlägt mit "abgelaufen" fehl, ein unbekannter mit "unbekannt"; keiner
  läuft durch. Werte liegen nur im Schlüsselbund, die Index-Datei unter
  `~/.ai-vault/` enthält keinen Wert. Dauer-Secrets gehören in den
  Passwortmanager, nicht in den ephemeren Vault.
- **TTL ist konfigurierbar**, auf drei Ebenen: Voreinstellung pro Typ in
  `~/.ai-vault/config`, Wert pro Eintrag beim Ablegen (Zweck), und eine
  Obergrenze, die auch die Verlängerung durch Nutzung nicht überschreitet
  (Vorschlag 30 Tage). Die Verlängerung bei Nutzung ist ein eigener Schalter.

## Form des Werkzeugs (Scheibe 1)

Kein Skill: das Modell darf die Ersetzung nicht steuern. Drei Bausteine:

1. **`ai-vault`, ein Binary** (brew / winget). Enthält Detektor, Schlüsselbund-
   Zugriff und die Hook-Befehle `hook prompt`, `hook pre-tool`, `hook post-tool`,
   dazu `list`, `get <ref>`, `expire`.
2. **Claude-Code-Plugin `ai-vault`**: nur die Hook-Registrierung auf das
   Binary (`claude plugin install ai-vault@phase6`). Codex: derselbe Eintrag
   in `~/.codex/config.toml`. Beides per MDM erzwingbar.
3. **Deposit-Endpunkt im ai-gateway** (`POST /api/vault/deposit`) plus ein
   persönlicher Vault-Schlüssel pro Nutzer aus den Gateway-Einstellungen.

Alltag: `claude` wie immer. Bei einem Treffer: Block-Hinweis, Ersatz-Prompt
in der Zwischenablage, Cmd+V, Enter. Nachschau mit `ai-vault get` (Touch ID).

## Gateway-Fluss: der Wert wandert vor dem Tool-Aufruf ins Gateway-Mapping

1. Modell ruft ein Gateway-Tool mit `<EMAIL_1>` auf.
2. `PreToolUse` erkennt am MCP-Servernamen den Gateway und den Platzhalter.
3. Hook ruft `POST /api/vault/deposit` (Referenz, Wert, Typ, TTL) mit dem
   Vault-Schlüssel. Wert landet im bestehenden verschlüsselten Nutzer-Mapping
   (Redis, KMS). Das ist Olegs "put" (#1388) und #1180 Phase 2, maschinell.
4. Tool-Aufruf geht unverändert mit `<EMAIL_1>` an den Gateway; der Gateway
   rehydriert (heute nur `*_write_actions`; Leseaktionen brauchen Opt-in pro
   Feld).
5. Antwort: der Scrubber kennt den Wert und schreibt denselben Platzhalter
   zurück.
6. `PostToolUse` prüft lokal auf Klartext (zweites Netz).

Der Wert geht nur über TLS an den Gateway, nie an Anthropic. Keine Verbindung
vom Gateway zurück zum Client nötig.

**Für #1396:** Client-geprägte Referenzen brauchen einen eigenen Bereich
(z. B. `<EMAIL_c1:…>`), den der Gateway nie prägt. Sonst überschreibt ein
Deposit einen fremden Gateway-Eintrag mit gleichem Zähler.

## Markt und Verteilung (Recherche 26.09.)

- **Kein fertiges Werkzeug macht genau das.** Der offizielle Marketplace
  (340 Plugins) hat kein Privacy-Plugin. Nächste Vorarbeit:
  `l-mb/claude-code-redaction-hooks` (Apache-2.0, Python): block/redact je
  Hook, Mapping-Datei, Audit-Log, Schema-Drift-Harness. Ohne Rehydrierung,
  ohne Vault, ohne Gateway. Kandidat zum Forken oder als Referenz.
- **Belegter Bypass:** `@datei` im Prompt inlined den Inhalt an allen Hooks
  vorbei. Gegenmaßnahme: `@<pfad>` blocken, expliziten Read erzwingen.
  Ebenso: Tool-Output über 50K Zeichen liegt als Datei, die der Hook nicht
  umschreibt.
- **Plugin-Hooks laufen in Cowork** (Session auf dem Rechner), nicht im Chat
  und nicht mobil. Ein auf dem claude.ai-Account installiertes Plugin
  erscheint in Claude Code als synced plugin; ein Owner kann es "Required"
  setzen. Verteilung ohne MDM für Claude Code und Cowork. Nicht verifiziert:
  ob UserPromptSubmit in Cowork für den Cowork-Prompt feuert. Ein Binary in
  `bin/` lässt sich in Cowork nicht installieren; das Skript liegt unter
  `hooks/` im Plugin.
- **Vault-Backend austauschbar:** OS-Schlüsselbund als Voreinstellung,
  1Password (`op`), Bitwarden (`bw`) und Infisical als weitere Backends
  hinter put/get/list/expire.

## Erzwingen durch die Firma (Doku 26.09.)

Zwei Wege, kombinierbar (claude.com/docs/plugins/org-rollout):

1. **claude.ai-Konsole** (Team/Enterprise, Owner): Organization settings >
   Plugins & skills, eigenes Marketplace-Repo (GitHub/GitLab) oder Zip,
   Verfügbarkeit **Required** = "installed and always on, members can't turn
   it off or remove it". Gilt in claude.ai, Cowork und in Claude-Code-Sessions,
   die den Account synchronisieren. Gruppenweise Zuweisung auf Enterprise.
2. **Managed Settings für Claude Code** (Konsole, MDM-plist
   `com.anthropic.claudecode`, Registry, oder `managed-settings.json`):
   `extraKnownMarketplaces` + `enabledPlugins` installieren und aktivieren
   auf jedem Rechner; "disabling one at their own scope doesn't stop it from
   loading". `strictKnownMarketplaces` + `disableSideloadFlags` sperren
   fremde Quellen. `allowManagedHooksOnly` lässt nur Hooks aus Managed
   Settings laufen. Ein Base-URL-Wechsel in der Shell schaltet
   server-managed Settings ab, also für den Proxy-Fall MDM oder Datei.

Codex: `requirements.toml` mit `[hooks]`, `allow_managed_hooks_only = true`,
per MDM oder Cloud-Policy.

Nicht erzwingbar: Chat in claude.ai, Mobile, ChatGPT-Apps.

## Produkt und Schutz (26.09.)

Andi will es als kostenloses Plugin/Service anbieten. Trivial und in einem
Tag nachbaubar: Block-Hook, Zwischenablage, Schlüsselbund put/get, Regex,
Manifest. Nicht trivial, sammelt sich an: (1) Abdeckungskarte der Leckpfade
je Client-Version mit Testharness gegen Golden-Payloads, (2) das Protokoll
Client–Gateway aus #1180 (Namensraum, Fähigkeiten je Eintrag, Scope-Bindung,
TTL, Deposit, blinder Vergleich), (3) die Messung vorher/nachher,
(4) deutscher PII-Korpus, (5) der Gateway als Ausführungsort. Schutz über
Marke, Lizenz (Plugin Apache-2.0, Gateway-Seite BSL), Referenzimplementierung,
installierte Basis (anonymer Opt-in-Zähler im Plugin). Eigentumsfrage
phase6/mcpgate vor Veröffentlichung klären.

**Selbstinstallation des Vaults:** `Setup`- oder `SessionStart`-Hook prüft
`~/.ai-vault/`, lädt das signierte Binary nach, prüft die Signatur. Bis
dahin blockt der Prompt-Hook jeden Treffer (fail closed). Kein `bin/` im
Plugin (Cowork), Skript unter `hooks/`. Cloud-Sessions und WSL laden keine
lokalen Plugins.

## Träger und Name (26.09.)

- **Privat entwickelt.** Repo auf gitlab.com/Sprinterli mit Spiegel nach
  github.com. Plugin, Vault und Protokoll-Spezifikation liegen dort. Der
  Gateway-Teil (Deposit, Rehydrierung für Leseaktionen) implementiert die
  Spezifikation im ai-gateway; phase6 ist der erste Nutzer. Dieses Dokument
  zieht ins Repo um.
- **Codex parallel.** Codex-Plugins haben dieselben Teile (Skills, MCP,
  Browser-Erweiterungen, Hooks in `hooks/hooks.json`), Marketplace aus einem
  GitHub-Repo, Managed Hooks per `requirements.toml` mit
  `allow_managed_hooks_only` und `[features].hooks = true`. Nicht-verwaltete
  Plugin-Hooks muss der Nutzer einmal freigeben. Plugin-Installation über
  das Web deployt keine Hook-Skripte; Selbstinstallation des Binaries ist
  Pflicht. Ein Kern, ein Adapter je Client (Codex: PostToolUse ersetzt via
  block-Feedback, updatedMCPToolOutput nicht unterstützt).
- **Name.** Metapher Garderobe (Mantel abgeben, Marke bekommen, am Ausgang
  zurückholen). Kandidaten nach Prüfung 26.09. (NS-basiert, "free?" nicht
  bewiesen): Garderobe (.dev/.com free?, npm/PyPI frei), coatcheck (.dev
  free?, npm vergeben), ticketstub (.dev/.ai/.io free?), vaultstub (alles
  frei, blass). Understudy, Cloakroom, Decoy, StuntDouble vergeben.
  Empfehlung: Garderobe. Nichts registriert.
- **Andis Vorschlag: `maisecrets`** (26.09., geprüft): GitHub-User frei,
  0 Repos mit dem Namen, npm/PyPI/Homebrew frei, gitlab.com-User frei,
  .dev/.ai/.io/.de ohne Nameserver; nur .com hat Nameserver (Parking).
  Sagt, was es ist; deckt PII nur über die Lesart "my AI secrets".
- **Homepage/Domain:** für Scheibe 1 und für die Verteilung über ein
  Marketplace-Repo nicht nötig (Claude-Directory verlangt ein öffentliches
  GitHub-Repo; Codex-Plugins kommen aus einem Marketplace-Repo). Binaries
  über GitHub Releases, Doku im README. Eine Domain wird nötig für
  Directory-Einreichung (Datenschutzerklärung, Support-Kontakt; Checklisten
  nicht gelesen) und für den Verkauf. Hedge: die .dev reservieren, sobald der
  Name steht.
- **Weitere Clients, nach Nachfrage:** OpenCode (Plugin mit
  `experimental.chat.messages.transform`, kann den Prompt umschreiben,
  besser als Hooks), Cursor Hooks (beforeSubmitPrompt kann blocken;
  Umschreiben unverifiziert), GitHub Copilot CLI Hooks, Gemini CLI, Kiro,
  Claude Agent SDK und Codex SDK (dieselben Hooks), headless `-p` in CI.
  Alle außer OpenCode unverifiziert.
- **Name jetzt?** Nein. Arbeitsname `maisecrets`. Spätestens vor der ersten
  fremden Installation festlegen: der Plugin-Name steht danach in fremden
  `enabledPlugins`-Einträgen und in der Homebrew-Formel. Repo-Umbenennung
  ist billig (Redirects).

## Store-Anforderungen und Vorgehen (26.09.)

**Claude-Directory** (pre-submission-checklist): öffentliches GitHub-Repo,
`.claude-plugin/plugin.json`, README ≥ 40 Wörter, LICENSE. Alles, was ein
Hook ausführt, liegt im Plugin-Ordner. Keine kompilierten Executables (Halt
für Reviewer), keine Launcher/Paketinstallation in Hook-Skripten, Kommandos
als voller Pfad ab `${CLAUDE_PLUGIN_ROOT}`, keine Credentials aus der
Umgebung, README beschreibt alles, was läuft/sendet/lädt. Validierung im
Developer-Portal ohne Einreichung möglich.

**OpenAI-Directory**: verifizierte Identität, veröffentlichte
Datenschutzerklärung; für Remote-MCP-Plugins Website/Support/Terms-URLs und
5+3 Testfälle. Ob ein reines Hook-Plugin die URLs braucht: nicht gefunden.

**Für phase6 und erste Nutzer reicht ein eigenes Marketplace-Repo**
(enabledPlugins/Required bei Claude, Workspace-Marketplace bei Codex).

**Konsequenz: der Vault wird nicht nachinstalliert, sondern mitgebracht** —
lesbarer Quelltext im Plugin (Hook-Skript oder lokaler MCP-Server
`node ${CLAUDE_PLUGIN_ROOT}/vault/server.js`), Schlüsselbund direkt über
`security` (macOS) und PowerShell (Windows), keine Abhängigkeiten.
SessionStart legt nur `~/.maisecrets/` an. Offen: welcher Interpreter auf
Windows sicher vorhanden ist (python3 fehlt, node liegt Claude Code nicht
mehr bei) — vor dem Packen messen.

**Vorgehen:** Tag 1 Hooks in `~/.claude/hooks/` + JSON-Vault
`~/.maisecrets/vault.json` (0600, Testmodus) + Detektor aus pii_scrubber +
Zwischenablage + Listener-Harness. Tag 2–3 Schlüsselbund-Backend, TTL/Index,
PreToolUse-Einsetzen in Bash, PostToolUse-Scrub, Mutationsprobe je Hook.
Woche 2 Plugin-Ordner, Portal-Validierung, Marketplace-Repo
`Sprinterli/maisecrets`, 2–3 phase6-Macs, Codex hooks.json, Cowork-Test.
Danach Gateway-Deposit, OpenCode, Datenschutzerklärung/Domain, Directory.
Erster Baustein: die Harness (Golden-Payloads gegen Hook-Drift).

## Provider-Abdeckung (26.09.)

Ein Kern (Detektor, Vault, Platzhalter), je Provider ein Adapter (Manifest,
Hook-Namen, Block-/Rewrite-Felder). Belegt: Claude Code/Cowork/Desktop-Code
(Hooks: Prompt blocken, Tool-I/O umschreiben), Codex CLI und Codex in der
ChatGPT-App (gleiches Format; Ausgabe über Block-Feedback). Doku, ungetestet:
ChatGPT Work-Modus führt Plugin-Hooks in der Codex-Runtime aus. OpenCode:
eigenes npm-Plugin, kann den Prompt umschreiben. Ungeprüft: Cursor, Copilot
CLI, Gemini CLI, Kiro. Kein Adapter: Claude Chat, ChatGPT Chat, Web, Mobile.
