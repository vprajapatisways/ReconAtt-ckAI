🚀 ReconAtt&ckAI — Automated Nmap → CVE → MITRE ATT&CK Intelligence Engine

ReconAtt&ckAI is an AI-assisted security analysis pipeline that transforms raw Nmap scan results into a fully enriched vulnerability report, complete with CVE intelligence, MITRE ATT&CK mappings, prioritized attack paths, and an interactive Streamlit dashboard.


**Disclaimer**
 This READ-me content is written by chat-gpt

This tool supports automated execution (one-command pipeline) as well as manual execution for fine-grained control.

📦 Installation
1. Install Python Requirements
**pip install -r requirements.txt**


This installs Streamlit, CVE lookup dependencies, parsing libraries, and refinement logic.

🔐 Authentication Setup

The dashboard uses a simple authentication system.

You have two options:

Option A — Use the default login
username: admin  
password: admin

Option B — Set your own credentials

Edit or create auth.json in the project root:

{
  "users": {
    "yourusername": "sha256_hash_of_password"
  }
}


(You can generate a SHA256 password hash using any online tool or Python.)

⚙️ Usage

ReconAtt&ckAI supports two ways to run the system:

✅ Method 1 — Fully Automated Pipeline (Recommended)

Everything (analysis → refinement → dashboard launch) runs from a single command using automate_pipeline.py.

Basic Run
**python automate_pipeline.py --input sam1.xml**

Change Streamlit Port
**python automate_pipeline.py --input sam1.xml --port 8502**

Enable Optional NVD Keyword Search
**python automate_pipeline.py --input sam1.xml --use-nvd**


You may also check available options:

python automate_pipeline.py --help

🛠 Method 2 — Manual Execution (3 Commands)

For users who want direct control:

Step 1 — Run Nmap Analyzer

Converts Nmap XML → CVE-enriched report.

python nmap_vuln_analyzer.py -i scan.xml -o report.json

Step 2 — Refine & Score Report

Adds MITRE mappings, risk scoring, and prioritized attack paths.

python refine_report.py -i report.json -o refined_report.json

Step 3 — Launch Streamlit Dashboard
streamlit run app_streamlit.py -- -i refined_report.json


You may check usage:

python nmap_vuln_analyzer.py --help
python refine_report.py --help

📊 Dashboard Features

Interactive vulnerability triage

CVE severity scoring

MITRE ATT&CK mapping

Prioritized testing path

Host & service breakdown

Executable security action list

Exportable refined reports

🧩 File Structure
automate_pipeline.py      # Full automation engine
nmap_vuln_analyzer.py     # XML → CVE parser
refine_report.py          # Risk scoring + MITRE mapping
app_streamlit.py          # Dashboard UI
auth.json                 # User credentials
requirements.txt          # Python dependencies
