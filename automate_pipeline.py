#!/usr/bin/env python3
"""
automate_pipeline.py

Automates:
  1) python nmap_vuln_analyzer.py -i <scan.xml> -o <report.json>
  2) python refine_report.py -i <report.json> -o <refined_report.json>
  3) streamlit run app_streamlit.py -- -i <refined_report.json>

Usage:
  python automate_pipeline.py --input sam1.xml
  python automate_pipeline.py --input /path/to/scan.xml --no-streamlit
  python automate_pipeline.py --input sam1.xml --port 8502 --use-nvd

Notes:
  - This script assumes the helper scripts are in the same directory (/mnt/data).
  - It runs the commands as subprocesses and streams stdout/stderr to the console.
  - Only run scans against authorized targets.
"""
import argparse
import os
import sys
import subprocess
import shutil
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

NMAP_ANALYZER = BASE_DIR / "nmap_vuln_analyzer.py"
REFINE_SCRIPT = BASE_DIR / "refine_report.py"
STREAMLIT_APP = BASE_DIR / "app_streamlit.py"

def run_cmd(cmd, env=None):
    print(f">>> Running: {' '.join(cmd)}")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, text=True)
    try:
        for line in proc.stdout:
            print(line, end='')
        proc.wait()
        if proc.returncode != 0:
            raise RuntimeError(f"Command {' '.join(cmd)} exited with code {proc.returncode}")
    finally:
        if proc.stdout:
            proc.stdout.close()
    return proc.returncode

def ensure_exists(path: Path, desc: str):
    if not path.exists():
        print(f"ERROR: {desc} not found: {path}", file=sys.stderr)
        sys.exit(2)

def main():
    p = argparse.ArgumentParser(description="Automate nmap_vuln_analyzer -> refine_report -> streamlit pipeline")
    p.add_argument("--input", "-i", required=True, help="Input nmap XML file (e.g., sam1.xml)")
    p.add_argument("--report", "-r", default="report.json", help="Output report filename")
    p.add_argument("--refined", "-f", default="refined_report.json", help="Output refined report filename")
    p.add_argument("--no-streamlit", action="store_true", help="Do not start the Streamlit dashboard")
    p.add_argument("--port", type=int, default=8501, help="Streamlit port to use when starting the dashboard")
    p.add_argument("--use-nvd", action="store_true", help="Pass --use-nvd flag to the analyzer (optional)")
    p.add_argument("--nvd-key", default=None, help="Pass NVD API key to analyzer via --nvd-key (optional)")
    args = p.parse_args()

    input_xml = Path(args.input)
    ensure_exists(input_xml, "Input nmap XML")

    # ensure helper scripts exist
    ensure_exists(NMAP_ANALYZER, "nmap_vuln_analyzer.py")
    ensure_exists(REFINE_SCRIPT, "refine_report.py")
    ensure_exists(STREAMLIT_APP, "app_streamlit.py")

    report_path = Path(args.report).resolve()
    refined_path = Path(args.refined).resolve()

    # 1) Run the nmap_vuln_analyzer.py
    cmd = [sys.executable, str(NMAP_ANALYZER), "-i", str(input_xml), "-o", str(report_path)]
    if args.use_nvd:
        cmd.append("--use-nvd")
        if args.nvd_key:
            cmd += ["--nvd-key", args.nvd_key]
    try:
        run_cmd(cmd)
    except Exception as e:
        print(f"Analyzer failed: {e}", file=sys.stderr)
        sys.exit(3)

    # 2) Run refine_report.py
    if not report_path.exists():
        print(f"Expected report not found at {report_path}", file=sys.stderr)
        sys.exit(4)
    cmd2 = [sys.executable, str(REFINE_SCRIPT), "-i", str(report_path), "-o", str(refined_path)]
    try:
        run_cmd(cmd2)
    except Exception as e:
        print(f"Refine step failed: {e}", file=sys.stderr)
        sys.exit(5)

    if not refined_path.exists():
        print(f"Refined report not found at {refined_path}", file=sys.stderr)
        sys.exit(6)

    # copy refined into fixed spot used by the Streamlit app for convenience
    fixed_refined = BASE_DIR / "refined_report.json"
    try:
        shutil.copy2(refined_path, fixed_refined)
        print(f"Copied refined report to {fixed_refined}")
    except Exception as e:
        print(f"Warning: could not copy refined report to {fixed_refined}: {e}")

    # 3) Optionally start Streamlit app
    if not args.no_streamlit:
        # Build streamlit command. Use -- to pass args to the app.
        streamlit_cmd = ["streamlit", "run", str(STREAMLIT_APP), "--server.port", str(args.port), "--", "-i", str(fixed_refined)]
        print("Starting Streamlit app...")
        try:
            # Start streamlit as an independent process so this script can exit while streamlit stays up.
            proc = subprocess.Popen(streamlit_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            # Print a few lines of streamlit output for user feedback, then detach.
            start_time = time.time()
            timeout = 6.0
            while True:
                if proc.stdout is None:
                    break
                line = proc.stdout.readline()
                if not line:
                    if (time.time() - start_time) > timeout:
                        break
                    time.sleep(0.1)
                    continue
                print(line, end='')
                # break early after some boot lines
                if "Running on" in line or "Network URL" in line:
                    break
            print(f"Streamlit started (pid {proc.pid}). If you want the logs, attach to the process or check its output.")
            print(f"Open http://localhost:{args.port} in your browser.")
        except FileNotFoundError:
            print("ERROR: 'streamlit' command not found in PATH. Install requirements and ensure streamlit is on PATH.", file=sys.stderr)
            sys.exit(7)
        except Exception as e:
            print(f"Failed to start Streamlit: {e}", file=sys.stderr)
            sys.exit(8)
    else:
        print("Skipping Streamlit startup (--no-streamlit given). Pipeline complete.")

if __name__ == "__main__":
    main()
