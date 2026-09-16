# OSINT Monitoring & Change Detection System

A modular OSINT (Open Source Intelligence) engine that scans a target — a **domain**, **email**, **phone number**, or **username** — pulls together findings from multiple recon modules, tracks how that target's attack surface changes over time, and raises alerts when something notable shows up.

Built around a pluggable module system: every module inherits from `BaseModule`, declares which target types it supports, and returns a list of `Finding` objects that flow through a shared correlation, enrichment, filtering, and alerting pipeline.

## Features

- **Automatic target detection** — figures out whether you gave it a domain, email, phone number, or username, and only runs the relevant modules.
- **Subdomain enumeration** — combines an internal enumerator (certificate transparency, DNS bruteforce, zone transfers, etc.) with optional `amass` and `subfinder` integrations, each result tagged with a per-source confidence score.
- **DNS & HTTP enrichment** — resolves and probes discovered hosts to confirm they're real and live.
- **Change detection** — compares each scan against the previous one and reports added/removed subdomains, plus page-level content/link changes for the target's website (snapshots are stored under `snapshots/`).
- **Correlation & verification** — merges duplicate findings from different sources and flags which ones are DNS-verified.
- **Prioritization & filtering** — score-based prioritization, with `--only-live`, `--only-verified`, and `--min-confidence` flags to cut down noise.
- **Severity & alert engine** — turns raw changes (new/removed subdomains, page changes, vulnerability findings, VirusTotal hits) into severity-tagged alerts.
- **Trend analysis** — tracks metrics over time across repeated scans.
- **Attack surface summary** — groups live findings by shared infrastructure (e.g. by IP).
- **Optional integrations**:
  - `--wapiti` — runs the [Wapiti](https://wapiti-scanner.github.io/) web vulnerability scanner (active or `--passive` mode) and generates a PDF report.
  - `--vt` — checks discovered domains against the [VirusTotal](https://www.virustotal.com/) reputation API.
- **Phone / email / username OSINT** — dedicated modules for phone lookups, email-based recon, and username enumeration across social platforms.
- **Email reporting** — sends a daily summary report by email when scanning a domain (SMTP-based).
- **CSV / report output** — findings and daily reports are written to `reports/`.

## Requirements

- Python 3.10+
- The Python packages in `requirements.txt`
- Optional external tools, only needed for the features that use them:
  - [`amass`](https://github.com/owasp-amass/amass) — for the Amass subdomain module
  - [`subfinder`](https://github.com/projectdiscovery/subfinder) — for the Subfinder subdomain module
  - [`wapiti`](https://wapiti-scanner.github.io/) — for `--wapiti`

If a module's underlying binary isn't installed, that module fails gracefully and the scan continues with the remaining modules.

## Installation

```bash
git clone <this-repo-url>
cd OSINT-Monitoring-and-Change-Detection-System-main
pip install -r requirements.txt
```

Then create a `.env` file in the project root for the optional integrations (only fill in what you use — **leave unused variables out of the file entirely rather than blank**, see [Known issues](#known-issues)):

```
OSINT_SMTP_SERVER=smtp.example.com
OSINT_SMTP_PORT=587
OSINT_SMTP_USER=you@example.com
OSINT_SMTP_PASSWORD=your-app-password
OSINT_ALERT_SENDER=you@example.com
OSINT_ALERT_RECIPIENTS=alerts@example.com
VT_API_KEY=your-virustotal-api-key
```

## Usage

```bash
python run.py <target> [options]
```

`<target>` can be a domain (`example.com`), an email address, a phone number (`+15551234567`), or a username.

### Options

| Flag | Description |
|---|---|
| `--wapiti` | Run the Wapiti vulnerability scanner against the target |
| `--passive` | Run Wapiti in passive mode (only applies with `--wapiti`) |
| `--vt` | Check discovered domains against the VirusTotal reputation API |
| `--only-live` | Show only hosts that responded live over HTTP |
| `--only-verified` | Show only DNS-verified hosts |
| `--min-confidence FLOAT` | Filter out findings below this confidence score (0.0–1.0) |

### Examples

```bash
# Basic domain scan
python run.py example.com

# Domain scan with vulnerability scanning and VirusTotal checks
python run.py example.com --wapiti --passive --vt

# Only show verified, live subdomains with high confidence
python run.py example.com --only-live --only-verified --min-confidence 0.7

# Phone number lookup
python run.py +15551234567

# Username OSINT
python run.py someusername
```

Each domain scan is saved to `osint_engine.db` (SQLite) so the next scan can diff against it. Website snapshots go to `snapshots/<domain>/`, and reports go to `reports/`.

## Project structure

```
core/            Shared pipeline: models, orchestrator, correlation, enrichment,
                 filtering, prioritization, alerts, severity, trends, storage
modules/         Pluggable recon modules (subdomains, phone, email, username, web)
snapshots/       Saved HTML snapshots per domain, used for change detection
reports/         Generated daily reports and Wapiti PDF reports
run.py           CLI entry point
```

## Known issues

- **Blank `.env` values crash startup.** If a variable like `OSINT_SMTP_PORT` is present in `.env` but left empty (`OSINT_SMTP_PORT=`), `core/notifier.py` will raise `ValueError: invalid literal for int()` on import, because `os.getenv(..., "587")` only falls back to the default when the variable is *unset*, not when it's empty. Either give it a real value or remove the line from `.env` entirely.

## Security note

This tool collects and caches real personal data (phone numbers, names, tokens from third-party lookup services) into local files such as `modules/PhoneOSINTModule/cache.json`, `modules/PhoneOSINTModule/session.json`, `osint_engine.db`, and any `.txt`/report output. **Do not commit these to a public repository.** Add a `.gitignore` before pushing, e.g.:

```
.env
*.db
snapshots/
reports/
modules/PhoneOSINTModule/cache.json
modules/PhoneOSINTModule/session.json
*.txt
__pycache__/
```

## Disclaimer

This is an OSINT reconnaissance tool. Only run it against targets you own or are authorized to assess.
