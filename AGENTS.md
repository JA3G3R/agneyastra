# AGENTS.md — `agneyastra`

## What this is
`agneyastra` is a fast Go scanner that assesses the **blast radius of a leaked Google/Firebase API
key** (`AIza…`). Google reuses one key format across all of its APIs, so a single key can expose far
more than Firebase. Given a key it:

1. **Resolves the project identity** — the real *string* project ID (from the key's authorized
   domains), keeping the numeric project *number* as metadata only.
2. **Checks Firebase services** — Auth (which sign-in providers are enabled + token acquisition),
   Cloud Firestore, Realtime Database, and Cloud Storage — for **read/list** (default) and, with
   `--active`, **write/delete**. It escalates through auth levels (public → anonymous → self-signup →
   custom-token → real creds) and records the *lowest* level that unlocks each resource — i.e. it
   proves whether the `auth → privileged access` chain is viable.
3. **Sweeps the generic Google API surface** — Maps Platform (~20 endpoints), Gemini/Generative
   Language, Cloud Translation, YouTube Data, Safe Browsing, Custom Search — reporting which the key
   is *unrestricted* for (billing/quota abuse or data access).

Output is clean JSON (triage-friendly) plus an optional HTML report.

## When an agent should use it
- Triage found a Google/Firebase API key (in JS, an APK, a mobile config, a leak) and you need its
  real impact: *what can an attacker actually reach with it, and at what privilege?*
- You have many keys to assess at once (`--key-file`, or piped from `loot`/`secretscan`).
- **Do NOT** run `--active` (write/delete probes, sign-in emails) without explicit authorization —
  those mutate the target. The default run is read-only w.r.t. target *data*.

## Build
```bash
# from this directory
go build -o agneyastra ./cmd/agneyastra
```
Go 1.22+. Config and the HTML template are embedded — the tool runs offline except for the checks
themselves (no startup downloads, unlike older versions).

## Input
- Single key: `--key AIza…` (optionally `--project-id id1,id2` to force specific projects).
- Bulk: `--key-file keys.txt`, one entry per line as `key[,projectID,...]`; `#` comments and blank
  lines are skipped; duplicate keys are de-duped; `--key-file -` reads **stdin**.
- Project IDs are usually auto-resolved from the key; supply them only when the key's Identity
  Toolkit access is restricted (so authorized domains can't be read) or to test extra projects.

## CLI reference (verified against source)
| Flag | Default | Meaning |
|------|---------|---------|
| `--key` | — | A single Google/Firebase API key |
| `--key-file` | — | File of keys `key[,projectID,...]` per line (`-` = stdin) |
| `--project-id` | — | Comma-separated project IDs for a single `--key` |
| `--active` | off | **Enable state-changing probes**: write/delete (create-then-delete) and the email-link probe. Off = read-only |
| `-o, --output` | `json` | stdout format: `json` \| `table` \| `html` |
| `--out` | — | Write the chosen output to a file instead of stdout |
| `--report-html` | — | Additionally write a standalone HTML report to this path |
| `-v, --verbose` | off | Include `safe`/`not_applicable`/`not_tested` results (default shows only real hits) |
| `--concurrency` | auto | Keys scanned in parallel (`min(8, #keys)`) |
| `--timeout` | 15 | Per-request timeout (seconds) |
| `--show-key` | off | Emit the full key, not just a masked form |
| `--secrets-extract` | off | Scan data read from open RTDB/Storage for secrets (offline default detectors) |
| `--secrets-regex-file` | — | Custom detectors (JSON/YAML `name: pattern`) |
| `--correlate` / `--pentest-data f.json` | off | Score recovered data against a target profile (emails/domains/IPs) |
| `--signup-email/-password`, `--custom-token`, `--user-email/-password`, `--send-link-email` | — | Auth inputs (also settable in `~/.config/agneyastra/config.yaml`) |
| `--config`, `--template-file` | — | Custom config / HTML template |

Subcommands run one family only (each still does the auth stage for token escalation, except
`google`): `agneyastra bucket|rtdb|firestore|auth|google [flags]`. No subcommand = **all** services.

```bash
# full read-only scan, JSON to stdout
agneyastra --key AIza…

# many keys, human summary
agneyastra --key-file keys.txt -o table

# authorized active test, JSON + HTML artifact
agneyastra --key AIza… --active --report-html report.html

# just the generic Google blast radius (no project needed)
agneyastra --key AIza… google
```

## Output schema (JSON)
Top level: `tool`, `version`, `scan{…}`, `results[]`, `summary{findings, vulnerable_keys,
by_severity, by_service, blast_radius_enabled}`. Each `results[]` entry:

```jsonc
{
  "api_key_masked": "AIzaSyBv...gVEI",
  "key_format": "google_api_key",        // or "unknown"
  "valid": false,                          // is the KEY itself live (expired/invalid => false)
  "projects": [{"id":"proj","number":"104…","id_source":"authorized_domain","numeric":false,"validated":true}],
  "authorized_domains": ["proj.firebaseapp.com", …],
  "auth_providers": {"anonymous":true,"email_password_signup":false,"email_link":false,"custom_token":false},
  "findings": [
    {
      "service":"firebase.storage","check":"read","resource":"proj.appspot.com",
      "access":"public",                   // lowest auth level that unlocked it
      "status":"vulnerable","severity":"high","confidence":"confirmed",
      "title":"Storage bucket contents are listable",
      "auth_chain":["anon"],               // present when a token (not public) unlocked it
      "evidence":{"item_count":15,"sample":["…"]},
      "remediation":"…","poc":"curl '…AIzaSyBv...gVEI'"   // masked by default — see note below
    }
  ],
  "blast_radius": [{"api":"Geocoding","category":"maps","enabled":true,"severity":"medium","poc":"curl '…AIzaSyBv...gVEI'"}],
  "errors": ["…"]                          // e.g. "no resolvable string project ID … skipped"
}
```

**Reading it for triage:**
- `status: "vulnerable"` = access was actually obtained (real finding). By default only these are
  emitted; `safe` / `not_applicable` / `not_tested` appear only under `-v`.
- **Severity** is driven by attacker-reachability: `public`, `anon` and `signup` are self-serviceable
  by anyone → **high** (write/delete/read-with-data) / **medium** (empty read); `custom-token` and
  `user-creds` need something the attacker must already hold → **low**. Auth-provider-enabled
  findings are **info** on their own (a precondition); the real impact is the service finding whose
  `auth_chain` names the provider that unlocked it.
- `confidence: "confirmed"` means the tool performed the action (listed/read/create-then-deleted),
  not merely inferred it.
- `blast_radius[]` entries mean the key is unrestricted for that Google API → **billing/quota abuse**
  (Maps/Translation), **model-cost/data** (Gemini), etc. Remediation is always "restrict the key".
- **`poc` (and `detail`, defensively) follow the exact same `--show-key` gating as `api_key`/
  `api_key_masked`, in both `findings[]` and `blast_radius[]`.** By default (no `--show-key`) the
  live key is stripped from every `poc`/`detail` string and replaced with the same masked form as
  `api_key_masked`; pass `--show-key` to get a live, directly-runnable curl command instead. **This
  was NOT true before 2026-08-18** (see `todos/agneyastra.md`'s 2026-08-18 entry, RESOLVED same
  date): `poc` used to carry the raw, live key unconditionally — regardless of `--show-key` —
  because it (and an error-path `detail`) is built from the literal HTTP request/error that was
  actually sent, which necessarily contains the key as a `?key=` query param for the Google
  blast-radius sweep and Firestore's read check. **A JSON result file produced before this fix may
  still contain a live key inside `poc`/`detail` even though `api_key`/`api_key_masked` looks
  masked — do not assume `poc` is safe to read/paste in full from an old/cached result just because
  the top-level key fields are masked; only output produced after this fix (2026-08-18) carries
  that guarantee.**

## Accuracy / false-positive notes (why this version is trustworthy)
- **Legacy numeric project IDs no longer false-positive.** The Identity Toolkit config endpoint
  returns the numeric project *number* as `projectId` for older projects; the previous version fed
  that into `<number>.appspot.com` / `<number>-default-rtdb.firebaseio.com`, which 404, and reported
  the 404s as vulnerable deletes. Now every resource is **existence-probed first** — a 404 is
  `not_applicable`, never a finding — and only real *string* project IDs (from authorized domains)
  seed resource URLs. Numeric IDs are labelled `"numeric": true` and simply yield nothing.
- **Both Storage bucket schemes** are checked: `<id>.firebasestorage.app` (default since Oct 2024)
  and `<id>.appspot.com` (legacy).
- **Delete is proven, never inferred.** Write/delete run only with `--active`; delete requires a
  successful create-then-delete of the tool's *own* marker — a bare 404 is never a delete finding.
- **Firestore uses the v1 REST API** (which enforces security rules), replacing the old fragile
  gRPC-channel scraper — a 200 means the rules genuinely allowed it.
- `valid:false` can coexist with real findings: public Firebase reads are governed by security
  rules, not key validity, so an expired/invalid key can still surface world-readable resources.

## Safety
- Default = read-only w.r.t. target data. Token acquisition creates throwaway anonymous/self-signup
  users (needed to test the auth chain). `--active` additionally uploads then deletes marker
  objects/documents/keys and (if `--send-link-email` is set) sends a real sign-in email.
- Blast-radius Maps probes incur trivial billable usage on the *target's* project (inherent to
  testing whether the API responds). Only run against keys you're authorized to assess.
- **Output OPSEC:** every live key is masked by default, consistently — `api_key`/`api_key_masked`
  at the top level, and `poc`/`detail` inside `findings[]`/`blast_radius[]` (fixed 2026-08-18; see
  the Output schema section above). `--show-key` is the one, explicit switch that reveals the live
  key anywhere in the output; nothing else should. If you add a new check or blast-radius endpoint,
  do not build its `poc`/`detail` string and assume masking is automatic upstream of you — it is
  (via `internal/scanner.redactKeyResult` → `internal/report.RedactPoCs`, applied to every
  `Finding`/`BlastRadiusEntry` after all checks for a key finish) — but a **new field** that also
  happens to carry request/error text (not `poc`/`detail`) would NOT be covered and needs the same
  treatment.

## Filing bugs (triage-toolsmith)
File issues in `todos/agneyastra.md`. Rough ownership: identity/existence/FP logic →
`internal/keyinfo` + `internal/firebase`; a Google API mis-classified enabled/denied →
`internal/google/endpoints.go`; output/schema → `internal/report`; blast-radius endpoint list →
`internal/google/endpoints.go`; `--show-key`/masking of the live key anywhere in the output
(`api_key`, and — since 2026-08-18 — `poc`/`detail`) → `internal/report/redact.go`
(`RedactPoCs`, the string-replace core) + `internal/scanner/scanner.go` (`redactKeyResult`, the
per-key wiring/gate — the single call site, right after every finding for a key is collected). For
deep secret analysis of dumped data, prefer piping it through the sibling `secretscan`/`loot` (249
detectors) rather than the built-in lightweight set.
