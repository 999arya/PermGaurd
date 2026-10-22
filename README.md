# PermGuard

Android permission and privacy-risk analysis. The original dashboard presentation and analysis flow are preserved in `dashboard.py`; its UI import now targets the Flask renderer instead of Streamlit. The original labels, defaults, sample selection, organisation-policy controls, reports, and charts remain in that source.

## Run locally

```powershell
py -3.12 -m venv .venv-windows
.venv-windows/Scripts/python -m pip install -r requirements-local.txt
.venv-windows/Scripts/python app.py
```

Open http://127.0.0.1:8501. The existing VS Code **Run PermGuard** task uses the same entry point. Local scans use SQLite history and the original file cache. Uploaded files are removed by the scan pipeline after analysis. Local folder scanning and MobSF remain available as in the original dashboard.

## Deploy on Vercel

1. Import https://github.com/999arya/PermGaurd into Vercel.
2. Select the repository root containing `app.py`, `requirements.txt`, and `vercel.json`. Choose the **Flask** framework preset. Clear any old `public` Output Directory override or old static-site build settings.
3. Add `PERMGUARD_SESSION_SECRET` in Vercel Environment Variables: a random secret of at least 32 characters. Use the same value for every instance of an environment. Generate one locally with `python -c "import secrets; print(secrets.token_urlsafe(48))"`. Do not commit its value.
4. Deploy. Vercel detects the Flask `app` exported by `app.py`. `/api/health` returns `{"status":"ok"}` once configuration is complete.
5. Select **Flashlight**, then **Analyze Permissions**. Verify Summary/Apps/Details and **Prepare PDF**.

Vercel serves the same original dashboard rather than a separate reduced frontend. Static scripts, fonts, and Plotly are served from `public/_ui`.

### Hosted constraints

- Total request and response bodies are limited to **4 MB** in this app, below Vercel's platform limit. The function timeout is **60 seconds**. Use the local app for large APKs, large batches, long live MobSF scans, or oversized PDF reports.
- Vercel has a read-only application directory and temporary workers. Dashboard state, scan summaries and a bounded cache travel in signed browser-held state between requests, rather than relying on a worker's memory or SQLite. This survives worker changes and is isolated to the browser session. Reloading or closing the page starts a new dashboard session. Hosted history is not a durable shared database.
- A path entered in the local-folder box refers to the server, not the visitor's computer. On Vercel, upload files instead. MobSF must be reachable from Vercel; `localhost:8000` refers to the Vercel worker, not your laptop.
- Files uploaded to the hosted app are transmitted to Vercel. They are parsed in temporary storage and deleted after analysis. Optional live MobSF sends the APK to your configured MobSF server. MobSF scores never affect PermGuard scoring.
- Set the session secret before deployment. Missing configuration returns a clear setup response instead of silently losing sessions. Changing the secret invalidates existing signed state.

Official deployment guide: https://vercel.com/docs/frameworks/backend/flask

## Project layout

- `app.py`: Flask entry point and asset/health routes.
- `dashboard.py`: original dashboard code, with its Streamlit import replaced by the Flask UI adapter.
- `src/webui.py`: rendering of the dashboard's existing widget and layout calls.
- `src/webruntime.py`: request lifecycle, local sessions, and signed hosted state.
- `src/webstate.py`: hosted state encoding and per-browser history/cache.
- `src/`: original extraction, validation, policy, scoring, evidence, and reporting engines.
- `public/_ui/`: browser runtime, original fonts, and Plotly renderer.
- `config/`, `knowledgebase/`: original policy and permission definitions.
- `data/sampleapps/`, `samples/`: small synthetic APK and MobSF fixtures for the demo controls.
- `tests/`, `tools/build_fixtures.py`: validation suite and reproducible fixture generator.

## Verification

```powershell
.venv-windows/Scripts/python -m pytest tests -q
```

The suite covers the analysis engine, original dashboard controls and defaults, scan selection, all report branches, PDF generation, upload limits, request validation, and signed state across simulated Vercel worker changes.

Static findings are indicators for review, not proof of malicious behavior, an official Google Play compliance decision, or OWASP certification. The contact form retains the original message that no delivery service is configured.
