# NIDA — Network Intrusion Detection Agent

> **One-sentence summary:** NIDA is an explainable decision-support dashboard that inspects network connection summaries from the UNSW-NB15 benchmark, classifies attack types with XGBoost, flags unusual traffic with Isolation Forest, and presents human-readable feature evidence so security analysts can triage alerts without guessing.

[![Verify NIDA](https://github.com/rxp017/Network_intrusion_detection_agent/actions/workflows/ci.yml/badge.svg)](https://github.com/rxp017/Network_intrusion_detection_agent/actions/workflows/ci.yml)

[Three-minute demo script](docs/DEMO.md) · [Screenshot walkthrough and judge answers](docs/JUDGE_WALKTHROUGH.md) · [Model card](docs/MODEL_CARD.md) · [Audit & verification](docs/AUDIT.md) · [Data provenance](docs/DATA_SOURCES.md)

---

## Visual Workspace: Two Presentation Modes

NIDA offers two genuinely different presentation modes sharing the identical scoring engine, 400-flow replay stream, and REST/WebSocket API:

### 1. "Understand" Mode (Default for Non-Technical Visitors)
Designed for visitors with no cybersecurity or machine learning background. The opening screen states the purpose and shows the record → model → human-review path. A selected example shows the verdict and next step; key terms are available in a collapsible glossary.

![NIDA Understand Mode](docs/images/understand_desktop.png)

### 2. "Technical" Mode (For Security Analysts, Reviewers, and Judges)
Maintains the analytical evidence dossier: per-flow TreeSHAP signed margin contributions, risk decomposition ($60 \times (1 - P(\text{Normal})) + 40 \times \text{anomaly\_pct}$), Isolation Forest cutoff, custom JSON flow workbench, and held-out 10-class evaluation with confusion matrix.

![NIDA Technical Mode](docs/images/technical_desktop.png)

---

## What the System Can and Cannot Do

To avoid common machine learning and security hype, NIDA's research boundaries are explicitly documented:

| Capability | Supported in NIDA? | Engineering Grounding |
| :--- | :---: | :--- |
| **Inspect UNSW-NB15 Flow Rows** | **YES** | Validates and ingests complete 42-feature precomputed connection summaries. |
| **XGBoost Attack Classification** | **YES** | 10-class multiclass classifier (Normal + 9 attack families). |
| **Novelty / Anomaly Detection** | **YES** | Benign-only Isolation Forest trained exclusively on clean validation normals. |
| **Per-Flow TreeSHAP Evidence** | **YES** | Fast, exact TreeSHAP signed feature contributions explaining predicted class margin. |
| **Selective Human Review Policy** | **YES** | Validation-derived 94.19% threshold isolates high-risk traffic, cutting false positives to 4.5%. |
| **100% Offline Local Operation** | **YES** | Zero external fonts, CDNs, databases, or API keys required to run the workspace. |
| **Capture Live Network Packets** | ❌ **NO** | NIDA does not capture live packets (no `libpcap`, `scapy`, or raw network interface drivers). |
| **Discover Network Devices** | ❌ **NO** | NIDA does not discover network topology, hosts, or device configurations. |
| **Block Traffic or Modify Firewalls**| ❌ **NO** | NIDA is strictly a decision-support prototype. It never autonomously blocks IP addresses or flows. |
| **Detect Zero-Day Exploits** | ❌ **NO** | Statistical anomaly candidates indicate deviation from normal baselines, not proof of an exploit. |
| **Probability of Real-World Harm** | ❌ **NO** | Heuristic risk score (0–100) is an operational triage priority, not an actuarial probability of damage. |
| **Establish Physical Causation** | ❌ **NO** | TreeSHAP values describe the model's mathematical log-odds margin, not real-world causality. |

---

## Quickstart: Run the Offline Demo

**Tested runtime: CPython 3.14.7.** Works entirely offline without internet, API keys, or dataset downloads.

### Windows (PowerShell)
```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python main.py
```

### macOS / Linux (Bash)
```bash
python3.14 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

Open **[http://127.0.0.1:8000](http://127.0.0.1:8000)** in any modern browser.
- The pre-trained model bundle and 400-flow balanced replay dataset are bundled in the repository.
- Switching between **Understand** and **Technical** modes preserves your selected flow.
- The opening view explains the project in one screen; the theme button switches between light and dark and remembers your choice.
- Replay controls let you pause, resume, adjust speed (0.15s to 1.5s), and filter by scenario or risk level.

---

## Optional: Configuring AI Plain-English Explanations

By default, NIDA runs **100% offline with zero outbound network calls**. Clicking **Generate explanation** generates an evidence-grounded, rule-based summary labeled `Built-in explanation (Rule-based)` and displays the status `AI not configured`.

If you wish to enable live AI briefings via Groq or Google Gemini:

1. **Copy the example configuration to `.env`** (this file is gitignored and will never be committed to Git):
   ```powershell
   Copy-Item .env.example .env
   # On macOS/Linux: cp .env.example .env
   ```
2. **Paste your API key(s) into `.env`**:
   ```ini
   # Groq API Key (https://console.groq.com/keys)
   GROQ_API_KEY=your_groq_api_key_here

   # Google Gemini API Key (https://aistudio.google.com/apikey)
   GEMINI_API_KEY=your_gemini_api_key_here

   # Mode: waterfall (tries Groq first, fails over to Gemini on 429 quota exhaustion)
   LLM_PROVIDER=waterfall
   ```
3. **Restart the server**:
   ```powershell
   python main.py
   ```

### Safe & Non-Blocking Design Guarantees
- **Never committed to Git**: `.env` is listed in `.gitignore` (`.env`, `.env.*`). Never commit API keys.
- **Credential Protection**: Gemini keys are passed strictly through the `x-goog-api-key` HTTP header, never in URL query strings (`?key=...`), preventing credential leakage in access logs or browser history.
- **Async narration**: Optional LLM calls use `httpx.AsyncClient`, in-memory caching, and a 2-second rate limiter. Inference and replay use separate bounded paths; the browser tests verify the basic flow, not a production latency guarantee.
- **Truthful Status Reporting**: The UI explicitly discloses the backend state: `"AI not configured"`, `"AI service unavailable"`, or `"AI explanation ready"`. If external providers fail or quota is exhausted, NIDA seamlessly displays the grounded rule-based explanation.

---

## Measured Benchmark Results

Model `0013990bc956`, evaluated on **82,332 held-out flows** from UNSW-NB15 (training uses 175,341 rows after removing cross-split overlaps and duplicate feature rows).

| Measure | Result | Notes |
| :--- | :---: | :--- |
| **Multiclass Accuracy** | **72.89%** | 10 classes (Majority-class baseline: 44.94%) |
| **Macro F1 Score** | **0.538** | Balanced across all 10 attack categories |
| **Raw Attack Recall** | **98.86%** | High sensitivity before review filtering |
| **Raw False Positive Rate** | **33.41%** | Unfiltered model generates excessive false alarms |
| **Review Queue Attack Recall** | **89.42%** | Captures 89.4% of attacks with 96.0% precision |
| **Review Queue False Positive Rate** | **4.52%** | Filtered by policy threshold ($P(\text{attack}) \ge 0.9419$) |
| **Inference Latency (p95)** | **35.1 ms** | Dual model inference + exact TreeSHAP computation |

> [!WARNING]
> **Known Weak Classes:** Analysis recall is **8.27%** ($n=677$); Backdoor recall is **9.26%** ($n=583$). Worms has only **44** test rows. NIDA discloses these benchmark weaknesses visibly in the Technical mode audit drawer.

---

## Full Verification Sequence

To reproduce repository quality gates and browser verification:

```bash
# 1. Dependency integrity
python -m pip check

# 2. Python code quality & style
ruff check .
ruff format --check .

# 3. Vanilla JavaScript syntax
node --check static/dashboard.js
node --check static/boot.js

# 4. Pytest unit & integration test suite (62 tests)
python -m pytest -m "not browser" -q

# 5. Playwright Chromium browser tests (7 end-to-end journey tests)
python -m playwright install chromium
# PowerShell:
$env:NIDA_BROWSER_TESTS = "1"
python -m pytest -m browser -v
# Bash:
# NIDA_BROWSER_TESTS=1 python -m pytest -m browser -v

# 6. Git whitespace and conflict check
git diff --check
```

CI runs these exact checks on Linux via `.github/workflows/ci.yml`.

---

## Dataset Attribution

UNSW-NB15 was created by Nour Moustafa and Jill Slay at UNSW Canberra. Academic research use and citation requirements are described on the [official UNSW-NB15 dataset portal](https://research.unsw.edu.au/projects/unsw-nb15-dataset). See [full provenance and citations](docs/DATA_SOURCES.md).
