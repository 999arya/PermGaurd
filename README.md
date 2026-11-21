# PermGuard

<div align="center">

**Enterprise Android Permission, Security & Privacy-Risk Static Analysis Platform**

[![Python Versions](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests Passing](https://img.shields.io/badge/tests-128%20passed-brightgreen.svg)](tests/)
[![Security Standard](https://img.shields.io/badge/compliance-OWASP%20MASVS%20%7C%20Google%20Play-orange.svg)](knowledgebase/)
[![Framework](https://img.shields.io/badge/ui-Streamlit%20%7C%20Flask-red.svg)](streamlit_app.py)

*Automate mobile security audits, detect overprivileged APKs, flag toxic permission combinations, and verify OWASP & Google Play compliance — in seconds.*

[Key Capabilities](#key-capabilities) • [Architecture](#architecture) • [Quickstart](#quickstart) • [Deployment](#deployment) • [Enterprise Policy](#enterprise-policy--configuration) • [Verification](#verification)

---

</div>

## Overview

**PermGuard** is an automated, zero-execution static security analyzer for Android applications (`.apk`, `.aab`, `AndroidManifest.xml`, or permission manifests). Built for application security teams, mobile developers, and compliance auditors, PermGuard identifies privacy leaks, dangerous permission combinations, and privilege escalation vulnerabilities before apps reach production.

Traditional mobile scanners are often slow, resource-heavy, or require live device emulation. PermGuard delivers instant, transparent, mathematical risk assessments (0–100 scale) with multi-factor evidence, actionable remediation steps, and audit-ready executive PDF reports.

---

## Key Capabilities

- **Zero-Emulation Static Analysis**: Fast binary extraction, AXML decoding (`AndroidManifest.xml`), and Dalvik bytecode (DEX) scanning without launching suspicious code.
- **Intelligent Multi-Factor Risk Engine**: Computes a deterministic 0–100 security score based on permission breadth, protection levels, category expectations, and component attack surfaces.
- **Toxic Combination Detection**: Uncovers dangerous permission pairings that enable surveillance or exfiltration (e.g., `ACCESS_FINE_LOCATION` + `READ_CONTACTS`, or `RECORD_AUDIO` + `RECEIVE_BOOT_COMPLETED`).
- **Privilege Escalation & Root Vulnerability Scanning**: Flags exported components (services, activities, content providers), shared user IDs, cleartext HTTP traffic, root binaries, and known Linux kernel CVE patterns.
- **Regulatory & Marketplace Compliance**: Automated checks against **OWASP MASVS** (Mobile Application Security Verification Standard) and **Google Play Developer Policies**.
- **Dual-Engine Architecture**:
  - **Interactive Security Dashboard (Streamlit)**: Rich Plotly visualizations, side-by-side multi-APK comparison, SQLite scan history, and interactive policy inspector.
  - **Headless Serverless Microservice (Flask)**: Lightweight, stateless web tier designed for cloud functions, CI/CD gates, and containerized deployments.
- **Executive & Compliance Reporting**: Generates branded, board-ready PDF reports (via ReportLab), machine-readable JSON security manifests, and CSV compliance audits.
- **Optional MobSF Cross-Correlation**: Ingests and correlates dynamic/static findings from existing Mobile Security Framework (MobSF) deployments.

---

## Architecture

```mermaid
flowchart TD
    A["APK / Manifest / JSON / CSV Input"] --> B["Input Parser & Security Filter"]
    B --> C["AXML Binary Decoder & Extraction Engine"]
    B --> D["DEX Bytecode Scanner (Strings & References)"]
    
    C --> E["Core Analysis Pipeline"]
    D --> E
    
    subgraph Knowledge & Policy Engines
        F["Android Permissions Knowledgebase"]
        G["OWASP MASVS Engine"]
        H["Google Play Policy Engine"]
        I["Enterprise Org Policy Engine"]
    end
    
    subgraph Heuristic Detectors
        J["Toxic Combination Detector"]
        K["Privilege Escalation Detector"]
        L["Kernel & Root Exploit Detector"]
        M["Purpose & Category Classifier"]
    end
    
    E --> F & G & H & I
    E --> J & K & L & M
    
    F & G & H & I & J & K & L & M --> N["Risk Scoring Engine (0-100)"]
    N --> O["Remediation Engine & Safety Tips"]
    
    O --> P["Executive PDF Report (ReportLab)"]
    O --> Q["Interactive Streamlit Dashboard"]
    O --> R["Stateless Flask API / Vercel Runtime"]
    O --> S["JSON / CSV Audit Exports"]
```

---

## Quickstart

### Prerequisites

- **Python**: 3.10, 3.11, 3.12, or 3.13
- **Pip** or **uv**

### 1. Clone & Set Up Virtual Environment

```bash
git clone https://github.com/999arya/PermGaurd.git
cd PermGaurd

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# macOS / Linux:
source .venv/bin/activate
```

### 2. Install Dependencies

```bash
# Install local dashboard dependencies (Streamlit + Waitress + Pytest)
pip install -r requirements-local.txt
```

### 3. Launch Interactive Security Dashboard

```bash
streamlit run streamlit_app.py --server.port 8501
```

Open **`http://127.0.0.1:8501`** in your browser. 
- Try one of the built-in synthetic test applications (**Calculator**, **Flashlight**, **Navigation**, **Voice Recorder**) to explore detection capabilities.
- Or drop in any real `.apk` (up to 250 MB) for an instant scan.

### 4. Run Headless / REST Server

```bash
python app.py
```

The Flask service starts on `http://127.0.0.1:8501`, exposing the application adapter and `/api/health`.

---

## Project Structure

```
├── app.py                      # Flask application entrypoint (local / serverless)
├── streamlit_app.py            # Primary interactive Streamlit dashboard
├── dashboard.py                # Dashboard core logic for Flask adapter
├── render.yaml                 # Render Blueprint specification for cloud hosting
├── vercel.json                 # Vercel serverless function configuration
├── pyproject.toml              # Modern Python packaging & tool configurations
├── requirements.txt            # Core engine & serverless dependencies
├── requirements-local.txt      # Extended dependencies (Streamlit, Waitress, Pytest)
│
├── config/                     # Enterprise customizable policies
│   ├── appconfig.yaml          # Upload limits, cache sizes, and scan limits
│   ├── orgpolicy.yaml          # Allowed/blocked permissions and enterprise rules
│   └── riskthresholds.yaml     # Score boundaries and severity weightings
│
├── knowledgebase/              # Security and compliance knowledge bases
│   ├── androidpermissions.json # Manifest permission risk metadata & protection levels
│   ├── appcategories.json      # Standard category permission expectations
│   ├── googleplayrules.json    # Google Play Developer Policy rules
│   ├── owasprules.json         # OWASP MASVS mobile security rules
│   └── suspiciouscombinations.json # Toxic permission combination definitions
│
├── src/                        # Core analysis and detection engines
│   ├── apkextractor.py         # ZIP stream & APK archive unpacker
│   ├── axmldecoder.py          # Binary Android XML (AXML) parser
│   ├── dexscanner.py           # Dalvik Executable (DEX) bytecode string analyzer
│   ├── combinationdetector.py  # Toxic permission combination engine
│   ├── escalationdetector.py   # Exported components & privilege escalation detector
│   ├── kernelrootdetector.py   # Root strings, su binaries & kernel CVE scanner
│   ├── manifestparser.py       # AndroidManifest.xml parser & normalizer
│   ├── permissionclassifier.py # Danger & protection-level classification
│   ├── policyengine.py         # Google Play & standard policy evaluator
│   ├── orgpolicyengine.py      # Custom enterprise policy evaluator
│   ├── owaspengine.py          # OWASP MASVS compliance verification
│   ├── purposeanalyzer.py      # Category inference & permission justification
│   ├── riskengine.py           # Transparent mathematical 0-100 risk scoring
│   ├── recommendationengine.py # Actionable remediation suggestions
│   ├── reportgenerator.py      # Executive PDF, JSON, and CSV export engine
│   ├── pipeline.py             # Orchestrated multi-stage scan pipeline
│   ├── mobsf_client.py         # Optional MobSF REST API integration client
│   ├── mobsfevidence.py        # MobSF finding correlation and evidence mapping
│   ├── security.py             # Path traversal protection & file sanitization
│   ├── storage.py              # SQLite audit persistence
│   ├── scancache.py            # File hash caching layer
│   ├── webruntime.py           # Flask declarative UI runtime
│   ├── webstate.py             # Signed, tamper-evident client-held state
│   └── webui.py                # UI component abstraction layer
│
├── public/                     # Static UI runtime assets (runtime CSS, JS, fonts)
├── data/sampleapps/            # Synthetic test APKs and fixtures
├── tests/                      # Automated test suite (128 tests)
└── tools/                      # Fixture generation and maintenance utilities
```

---

## Deployment

### Render (Persistent Web Service)

Deploy the full Streamlit dashboard with 250 MB APK upload support using the included `render.yaml`:

1. Connect your repository to [Render](https://render.com/).
2. Select **New Blueprint Instance** and choose this repository.
3. Render automatically installs `requirements-local.txt` and executes:
   ```bash
   streamlit run streamlit_app.py --server.port $PORT --server.address 0.0.0.0
   ```

### Vercel (Serverless Microservice)

Deploy the Flask adapter on Vercel's serverless platform:

1. Import the repository into [Vercel](https://vercel.com/).
2. Select the **Flask** framework preset.
3. Configure `PERMGUARD_SESSION_SECRET` in Environment Variables:
   ```bash
   # Generate a 32+ character secure secret:
   python -c "import secrets; print(secrets.token_urlsafe(48))"
   ```
4. Deploy. Health status will be available at `/api/health`.

*Note: Serverless environments enforce platform request size limits (4 MB). For analyzing large production APKs, use the persistent Streamlit deployment or run locally.*

---

## Enterprise Policy & Configuration

PermGuard allows security teams to enforce custom organizational compliance policies without writing code:

### Custom Enterprise Policy (`config/orgpolicy.yaml`)
Define explicitly banned permissions, require explicit justification, or mandate specific protection levels:
```yaml
rules:
  - id: ORG-001
    name: "Disallow Unapproved SMS Access"
    banned_permissions:
      - android.permission.SEND_SMS
      - android.permission.RECEIVE_SMS
    severity: CRITICAL
```

### Risk Thresholds (`config/riskthresholds.yaml`)
Tune how severity bands and scoring penalties map into your risk posture:
```yaml
bands:
  low: [0, 25]
  medium: [26, 50]
  high: [51, 75]
  critical: [76, 100]
```

---

## Verification & Testing

PermGuard includes a comprehensive automated test suite covering all analysis pipelines, parsers, security boundaries, and report generation:

```bash
# Run complete test suite (128 tests)
pytest tests -v
```

```
============================== test session starts ==============================
collected 128 items

tests/test_dashboard.py ........                                         [  6%]
tests/test_detectors.py ...................                               [ 21%]
tests/test_e2e.py .............                                           [ 31%]
tests/test_inputparsers.py ..............                                  [ 42%]
tests/test_manifestparser.py ...........                                  [ 50%]
tests/test_permissionclassifier.py ............                           [ 60%]
tests/test_policyengine.py ..............                                  [ 71%]
tests/test_reportgenerator.py ............                                 [ 80%]
tests/test_riskengine.py ..............                                    [ 91%]
tests/test_security.py ............                                       [100%]

============================== 128 passed in 4.4s ===============================
```

---

## Security & Privacy Posture

- **Zero-Persistence Processing**: Uploaded APKs and manifests are analyzed in temporary memory/disk spaces and purged immediately upon scan completion.
- **Path Traversal Protection**: All archive extracts are strictly validated against directory traversal (`../`) and Zip Bomb attacks before unpacking.
- **Zero External Telemetry**: PermGuard runs entirely air-gapped on your infrastructure. Scan data, package names, and findings are never sent to external servers.

---

## License

This project is licensed under the [MIT License](LICENSE).
