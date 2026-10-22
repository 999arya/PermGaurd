# PermGuard

## Deploy on Vercel

The Vercel version uses a static web interface and a stateless Python API.
The existing Streamlit dashboard remains available for local use.

1. Import this GitHub repository at https://vercel.com/new.
2. Select the directory containing `vercel.json` as **Root Directory**. If the
   repository contains the outer project folder, select `PROJECT PERMGUARD 2`.
3. Use framework preset **Other**. The checked-in configuration sets the output
   directory to `public`, skips a frontend build, and routes `/api/*` to Python.
4. Deploy. No API keys, database, Docker or MobSF server are required.
5. Open the site and choose **Try flashlight demo**. `/api/health` should return
   `{"status":"ok"}`. Upload a report and verify JSON/CSV/PDF downloads.

Hosted uploads are limited to **4 MB** (below Vercel's 4.5 MB request limit).
The function has a 60-second timeout; use the local dashboard for larger or
long-running APK scans. Report responses are also limited to 4 MB.
Uploads are transmitted to the hosting service, parsed using temporary storage,
and deleted. The hosted adapter does not persist scan history, cached results,
or reports. It is not an offline service. MobSF permission dictionaries are
accepted, but MobSF scores are not mixed into PermGuard scoring.

The hosted interface supports upload, category/depth selection, findings and
report exports. The Streamlit comparison/history tabs remain local-only.
Vercel platform request metadata retention is governed by your hosting settings.

For local development install `requirements-local.txt`; `requirements.txt`
contains only the dependencies needed by the serverless runtime.

```powershell
py -3.13 -m venv .venv-windows
.venv-windows/Scripts/python -m pip install -r requirements-local.txt
.venv-windows/Scripts/python -m pytest tests -q
.venv-windows/Scripts/python -m streamlit run app.py
```

To preview the Vercel routes locally with Node.js and the Vercel CLI:
`npx vercel dev` (the CLI may ask you to sign in and link a project).

**Excessive-permission analysis for Android apps.**

A complete, working, **100 % local** Android permission & privacy-risk analyser.
Upload an APK → extract its manifest with a **pure-Python binary-AXML decoder**
(no Android SDK, no Java, no external tools) → match permissions against four
policy layers → flag suspicious/unnecessary permissions → deterministic 0–100
risk score → colour-coded, priority-ordered PDF report + Streamlit dashboard.

---

## What it does

| Stage | Detail |
|---|---|
| **1. Upload** | APK / manifest XML / JSON / CSV report. Hostile-input hardening: size caps, zip-bomb & path-traversal rejection, in-memory parsing, **file deleted immediately after scan**. |
| **2. Purpose** | You declare the **app category** (pre-filled from package name/label, you confirm) and the **environment criticality**. The **criticality / scan-depth** choice (auto / basic / deep) is offered **only when the environment is high** — a low environment runs the automatic (triage) scan with no extra question. |
| **3. Extract** | Pure-Python AXML decoder → permissions, components, SDK levels, debuggable/allowBackup/cleartext/sharedUserId, native libs, staged ELF assets, APK signing schemes. Deep scans add a DEX string scanner (root/kernel/CVE/exploit indicators). |
| **4. Match — 4 layers** | ① **Google Play policy** rules (with official source URLs) ② **OWASP-informed** checks (honestly labelled — *not* official OWASP tests) ③ **category necessity** (26 category profiles) ④ **organisational policy** (allow/deny lists, sensitivity caps, blocked combos — `config/orgpolicy.yaml`). |
| **5. Detect** | Per-permission verdicts (JUSTIFIED / PLAUSIBLE / UNEXPECTED / UNDETERMINED), suspicious **combinations** (location+contacts, mic+background, files+network …), **privilege-escalation** surface (exported components, sharedUserId, debuggable, weak custom permissions …), **kernel/root indicators** (static strings only — never proof). |
| **6. Score** | Transparent deterministic 0–100 (LOW 0–29 / MED 30–59 / HIGH 60–100). Every point explained; anti-double-counting via correlation keys; score floors prevent a CRITICAL finding from ever reading LOW. |
| **7. Report** | Colour-coded PDF (critical at top → high → medium → passed), JSON, CSV. Includes executive summary, evidence, source links, limitations, corrective actions, disclaimer. |

## Quick start

```bash
# environment (already set up in .venv)
.venv/bin/python -m pip install -r requirements-local.txt

# build the five synthetic demo APKs
.venv/bin/python tools/build_fixtures.py

# run the test suite (120 tests)
.venv/bin/python -m pytest tests/ -q

# launch the dashboard
.venv/bin/streamlit run app.py
```

Then open the shown localhost URL, upload one of the demo APKs from
`data/sampleapps/` (e.g. `flashlight_overprivileged.apk`), pick the category
**Flashlight**, and click **Run analysis**. A clean shopping app
(`shopping.apk`) scores in the **MEDIUM (~40)** band — realistic, near-minimal
permissions with no unexpected findings.

## Project structure

```
app.py                        Streamlit dashboard (7 tabs)
config/
  appconfig.yaml              limits, scan policy, storage
  riskthresholds.yaml         scoring weights, bands, floors
  orgpolicy.yaml              organisation allow/deny lists & combos
knowledgebase/
  androidpermissions.json     67 permission definitions + sensitivity tiers
  googleplayrules.json        8 Google Play policy rules (+ official URLs)
  owasprules.json             5 OWASP-informed checks (MASVS-PRIVACY mapped)
  suspiciouscombinations.json 9 co-occurrence patterns
  appcategories.json          26 category profiles (expected permissions)
src/
  axmldecoder.py              pure-Python binary Android XML decoder
  manifestparser.py           manifest → models
  apkextractor.py             ZIP/manifest/DEX/signature extraction
  dexscanner.py               stdlib DEX string-table scanner
  security.py                 upload validation & archive hardening
  inputparsers.py             JSON/CSV/XML alternative inputs
  knowledgebase.py            versioned rule loader
  models.py                   Pydantic schema (Finding, RiskReport, …)
  permissionclassifier.py     KB context per permission
  purposeanalyzer.py          purpose inference + per-permission verdicts
  policyengine.py             Google Play rules
  owaspengine.py              OWASP-informed rules
  orgpolicyengine.py          organisation policy
  combinationdetector.py      suspicious combinations
  escalationdetector.py       privilege-escalation surface
  kernelrootdetector.py       kernel/root static indicators
  riskengine.py               deterministic scoring with breakdown
  recommendationengine.py     prioritised corrective actions
  pipeline.py                 end-to-end orchestration
  reportgenerator.py          PDF / JSON / CSV
  storage.py                  SQLite scan history
tools/build_fixtures.py       synthetic APK builder (own AXML writer)
tests/                        120 pytest tests incl. precision/recall harness
data/sampleapps/              5 synthetic APKs + reviewed expectations.json
reports/                      generated reports (gitignored)
```

## Test & evaluation highlights

* **120 tests, all passing** — extraction, parsing, every engine, scoring
  invariants (determinism, dedup, floors, 0–100 bounds, config sensitivity),
  report formats & PDF content, hostile-input handling, privacy (uploads
  deleted; no network imports anywhere in `src/`).
* **5 synthetic APK fixtures** with a manually reviewed `expectations.json`
  (risk band, expected findings, per-permission verdicts).
* **Over-privilege precision/recall harness**: on the reviewed fixtures —
  **precision 1.00, recall 1.00** (TP=9, FP=0, FN=0, TN=16).
* **AXML round-trip**: fixtures are written with a from-scratch AXML *writer*
  and read by the AXML *decoder* — validating both without any Android tool.

## Privacy & honesty guarantees

* Runs entirely offline — **no network calls** (enforced by a test that greps
  `src/` for networking imports).
* Uploaded files are validated, parsed in memory and **deleted immediately**
  (success *and* failure paths); `.apk`, the scan DB and reports are
  gitignored.
* Findings carry status **PASS / POTENTIAL_CONCERN / NEEDS_REVIEW /
  INSUFFICIENT_EVIDENCE / NOT_APPLICABLE** (FAIL only with definitive
  evidence), plus severity, confidence, evidence, source links and
  **limitations** — every finding states what the analysis *cannot* prove.
* Combination, escalation and kernel/root findings are labelled **indicators
  for review, not proof** of malicious behaviour.
* OWASP checks are labelled *application-specific rules informed by OWASP* —
  never presented as official OWASP automated tests.

> **Disclaimer:** This report is an automated, evidence-based assessment. It
> is not an official Google Play compliance determination, an OWASP
> certification, or proof that an application is malicious. Manifest analysis
> alone cannot establish actual runtime behaviour.

## Scan history

Every scan is stored in `data/scans.db` (local SQLite, gitignored) and shown
in the **Comparison** tab with a ranked bar chart and filterable table —
compare a legitimate app against an over-privileged one to see the score gap.
Delete any or all stored scans from the sidebar at any time.
