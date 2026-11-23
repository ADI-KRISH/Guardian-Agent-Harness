# Running GuardianAI From a Fresh Git Clone

This step-by-step guide walks you through setting up and running GuardianAI after cloning the repository.

---

## 1. Prerequisites

Before starting, ensure you have:
- **Python 3.11+** (`python3 --version`)
- **Git** (`git --version`)
- **Node.js & npm** (optional, recommended for automatic lockfile resolution on repositories lacking lockfiles like Juice Shop)
- *(Optional)* **Ollama** running locally if you wish to enable the AI investigator step (`ollama serve`)
- *(Optional)* **Trivy** if you want container image layer vulnerability scanning (`trivy --version`)

---

## 2. Clone the Repository

```bash
git clone <YOUR_GIT_REPO_URL>
cd bosh
```

---

## 3. Setup Virtual Environment & Install

Create an isolated Python virtual environment and install the required dependencies:

```bash
# 1. Create a virtual environment
python3 -m venv .venv

# 2. Activate the virtual environment
# On macOS / Linux:
source .venv/bin/activate
# On Windows (cmd/PowerShell):
# .venv\Scripts\activate

# 3. Upgrade pip and install GuardianAI in editable mode
pip install --upgrade pip
pip install -e .
```

*Note: All core web assets (including Cytoscape.js) are already included locally in `guardian/static/` — no internet CDN or npm install is required to run the UI.*

---

## 4. Run the Web Dashboard (Recommended)

Start the local server:

```bash
python3 -m guardian serve
```

Output:
```
GuardianAI is running at http://127.0.0.1:8787
```

Open your browser and navigate to:
👉 **[http://127.0.0.1:8787](http://127.0.0.1:8787)**

### What you can do in the Web UI:
1. **Try Planted Demo**: Click **"Try planted demo"** on the welcome screen to instantly load a sample project with synthetic dependencies and deliberate security violations.
2. **Scan Any Local Repository**: Click **"＋ New scan"**, enter the absolute path to any local project folder (e.g., `/Users/username/my-project`), and click **"Run analysis →"**.
3. **Scan a Public GitHub Repo**: In the scan dialog, enter a public URL (e.g., `https://github.com/OWASP/juice-shop`) to clone and scan it in a temporary sandbox.
4. **Interactive Knowledge Graph**: Click the **"Knowledge graph"** tab to view the Cytoscape visualization with risk focus, direct dependency views, and ecosystem breakdowns.
5. **Print-Ready PDF Report**: Click **"⎙ PDF report"** in the top bar to generate a security assessment report formatted for printing or saving as PDF.
6. **CycloneDX SBOM Export**: Click **"↓ Export JSON"** to download the full report including the CycloneDX 1.5 SBOM.

---

## 5. Command-Line (CLI) Usage

You can also run scans and inspect results directly from the terminal.

### Run a Scan via CLI
```bash
# Scan a local folder
python3 -m guardian scan /path/to/repository

# Scan a public GitHub repository
python3 -m guardian scan https://github.com/OWASP/juice-shop

# Run offline using cached advisories only
python3 -m guardian scan /path/to/repository --offline

# Save output to a JSON file
python3 -m guardian scan /path/to/repository --output report.json
```

### List Past Scans
```bash
python3 -m guardian list
```

### Export SBOM or Markdown Report
```bash
# Export standard CycloneDX 1.5 SBOM
python3 -m guardian export <SCAN_ID> --format sbom --output sbom.json

# Export Human-Readable Markdown Report
python3 -m guardian export <SCAN_ID> --format markdown --output summary.md
```

### Promote a Baseline (for "What Changed" Detection)
```bash
# Mark a scan as the trusted baseline
python3 -m guardian baseline <SCAN_ID> --actor "Security Lead" --reason "Approved v1.0 release"
```

---

## 6. Run Regression & Verification Tests

To verify all deterministic security rules and policy guardrails are passing:

```bash
# Run the internal evaluation suite
python3 -m guardian eval

# Run the unit test suite
python3 -m unittest discover tests
```

---

## 7. Optional: Enable Local AI Investigation (Ollama)

GuardianAI includes an optional AI investigator agent that provides contextual explanations for findings using local models without sending source code to the cloud:

1. Install and start Ollama:
   ```bash
   ollama serve
   ```
2. Pull a local model:
   ```bash
   ollama pull mistral
   ```
3. In the GuardianAI web scan dialog, check the **"AI investigation"** checkbox before starting a scan.

---

## 8. Summary of Ports & Paths

| Item | Default Location / Port |
|---|---|
| **Web UI** | `http://127.0.0.1:8787` |
| **Persistent DB / Cache** | `.guardian/` (created automatically in workspace) |
| **Static Assets** | `guardian/static/` |
| **Documentation** | `README.md`, `README2.md`, `agentic-workflow.md` |

