<p align="center">
    <img src="https://devanghacks.in/agneyastra/agneyastra_logo.png" alt="agneyastra logo" width="200">
  <br>
</p>
<p align="center">
<a href="https://www.gnu.org/licenses/gpl-3.0.en.html/"><img src="https://img.shields.io/badge/license-GPL_3.0-_red.svg"></a>
<a href="https://go.dev"><img src="https://img.shields.io/github/go-mod/go-version/JA3G3R/agneyastra"></a>
<a href="https://twitter.com/BhavarthKr"><img src="https://img.shields.io/twitter/follow/BhavarthKr.svg?logo=twitter"></a>
</p>

# agneyastra — Google/Firebase API-key blast-radius scanner

Google reuses one API-key format (`AIza…`) across all of its services, so a single leaked key can
expose far more than Firebase. **Agneyastra** takes a key and measures its complete blast radius:

- **Firebase** — Auth (which sign-in providers are enabled), Cloud Firestore, Realtime Database, and
  Cloud Storage — checked for **read/list** and, with `--active`, **write/delete**.
- **The `auth → privileged access` chain** — it escalates through auth levels
  (public → anonymous → self-signup → custom-token → real credentials) and records the *lowest*
  level that unlocks each resource, so you see exactly how an attacker would reach the data.
- **The generic Google API surface** — Maps Platform (~20 endpoints), Gemini/Generative Language,
  Cloud Translation, YouTube Data, Safe Browsing, and Custom Search — reporting which the key is
  *unrestricted* for (billing/quota abuse or data access).

It is **accurate** (every resource is existence-probed before it can be reported — no more false
positives on legacy numeric project IDs; both `.appspot.com` and `.firebasestorage.app` buckets are
checked), **fast** (concurrent, REST-based), and **safe by default** (read-only unless you pass
`--active`).

---

## Install / build

```bash
go install github.com/JA3G3R/agneyastra/cmd/agneyastra@latest
# or, from a clone:
go build -o agneyastra ./cmd/agneyastra
```
Go 1.22+. Config and the HTML template are embedded — no network access at startup.

---

## Usage

```bash
# Full read-only scan, JSON to stdout
agneyastra --key AIza...

# Human-readable summary
agneyastra --key AIza... -o table

# Many keys (one `key[,projectID,...]` per line; '-' = stdin)
agneyastra --key-file keys.txt -o table
cat keys.txt | agneyastra --key-file -

# Authorized ACTIVE test (adds write/delete probes) + an HTML report
agneyastra --key AIza... --active --report-html report.html

# Only the generic Google blast radius (no project needed)
agneyastra --key AIza... google

# One service family (each also does the auth stage for escalation)
agneyastra --key AIza... bucket
agneyastra --key AIza... firestore

# Extract secrets from any world-readable data, and correlate to a target
agneyastra --key AIza... --secrets-extract --correlate --pentest-data target.json
```

`--active` is the only switch that changes state on the target (uploads then deletes marker
objects/documents/keys, and — if `--send-link-email` is set — sends a real sign-in email). The
default run never writes target data. See `agneyastra --help` for all flags.

---

## Output

Clean, flat JSON (default) — by default only real hits (`status: vulnerable`) are shown; add `-v`
for `safe`/`not_applicable`/`not_tested` results.

```jsonc
{
  "tool": "agneyastra", "version": "2.0.0",
  "scan": { "duration_ms": 4595, "active_mode": false, "keys_scanned": 1 },
  "results": [{
    "api_key_masked": "AIzaSyBv...gVEI",
    "key_format": "google_api_key",
    "valid": true,
    "projects": [{ "id": "my-project", "id_source": "authorized_domain", "validated": true }],
    "auth_providers": { "anonymous": true, "email_password_signup": false },
    "findings": [{
      "service": "firebase.storage", "check": "read", "resource": "my-project.appspot.com",
      "access": "public", "status": "vulnerable", "severity": "high", "confidence": "confirmed",
      "title": "Storage bucket contents are listable",
      "evidence": { "item_count": 15, "sample": ["invoice.pdf", "backup.sql"] },
      "remediation": "Set Storage rules to require proper authorization ...",
      "poc": "curl 'https://firebasestorage.googleapis.com/v0/b/my-project.appspot.com/o?maxResults=15'"
    }],
    "blast_radius": [
      { "api": "Geocoding", "category": "maps", "enabled": true, "severity": "medium",
        "poc": "curl 'https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key=AIza...'" }
    ]
  }],
  "summary": { "findings": 3, "vulnerable_keys": 1, "by_severity": { "high": 2, "medium": 1 } }
}
```

**Severity** reflects attacker-reachability: `public`, `anon` and `signup` access is self-serviceable
by anyone → **high** (or **medium** for an empty read); `custom-token` / `user-creds` access needs
something the attacker must already hold → **low**. An enabled auth provider alone is **info** — the
real impact is the service finding whose `auth_chain` names the provider that unlocked it.

`-o html` (or `--report-html PATH`) renders a self-contained, theme-aware HTML report.

---

## Configuration

Optional inputs (sign-up creds, a custom token, real credentials, the storage upload file) can be
set via flags (`--signup-email`, `--custom-token`, `--user-email`/`--user-password`, …) or in
`~/.config/agneyastra/config.yaml` (a default is written on first run). Flags take precedence.

---

## Requirements

- Go 1.22+

## Disclaimer

Agneyastra is for **authorized security testing and education only**. Scanning keys/projects you do
not own or have permission to test may be illegal. Blast-radius Maps probes incur trivial billable
usage on the target's project. Use responsibly.

## Contact

Created by [Bhavarth Karmarkar](https://github.com/JA3G3R).
