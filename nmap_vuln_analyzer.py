#!/usr/bin/env python3
"""
nmap_vuln_analyzer.py
- Parse nmap XML (-oX) files
- Lookup CVEs with CIRCL (fallback) and optional NVD usage
- Produce JSON report and a human-readable prioritized testing path

Usage:
    python nmap_vuln_analyzer.py -i scan.xml -o report.json
Requirements:
    pip install requests defusedxml
Optional:
    set env NVD_API_KEY or pass --nvd-key for NVD queries (reduces CIRCL false positives and rate limits)
Notes:
    Use only on authorized targets.
"""

import argparse
import json
import os
import re
import time
from collections import defaultdict
from datetime import datetime
import requests
from defusedxml.ElementTree import parse as xml_parse

# --- Config ---
CIRCL_BASE = "https://cve.circl.lu/api"
NVD_BASE = "https://services.nvd.nist.gov/rest/json"
# NVD note: rate-limited and may require API key for heavy usage
NVD_API_KEY = os.getenv("NVD_API_KEY")

# --- Helpers ---

def parse_nmap_xml(filename):
    """Parse nmap XML and return a list of hosts with ports/services."""
    tree = xml_parse(filename)
    root = tree.getroot()
    ns = ''  # nmap XML doesn't require namespaces for simple parsing
    hosts = []
    for h in root.findall('host'):
        addr = None
        hostnames = []
        for a in h.findall('address'):
            if a.get('addrtype') == 'ipv4' or a.get('addrtype') == 'ipv6':
                addr = a.get('addr')
                break
        hn = h.find('hostnames')
        if hn is not None:
            for name in hn.findall('hostname'):
                hostnames.append(name.get('name'))
        ports_out = []
        ports = h.find('ports')
        if ports is None:
            continue
        for p in ports.findall('port'):
            state = p.find('state')
            if state is None or state.get('state') != 'open':
                continue
            portid = p.get('portid')
            proto = p.get('protocol')
            svc = p.find('service')
            service = {}
            if svc is not None:
                service = {
                    'name': svc.get('name'),
                    'product': svc.get('product'),
                    'version': svc.get('version'),
                    'extrainfo': svc.get('extrainfo'),
                    'oss': svc.get('ostype'),
                    'method': svc.get('method'),
                    'conf': svc.get('conf')
                }
            # grab script outputs (banners) if present
            scripts = {}
            for script in p.findall('script'):
                scripts[script.get('id')] = script.get('output')
            ports_out.append({
                'port': int(portid),
                'proto': proto,
                'service': service,
                'scripts': scripts
            })
        hosts.append({'ip': addr, 'hostnames': hostnames, 'ports': ports_out})
    return hosts

def normalize_product(product):
    """Simple normalizer for product names for vendor/product search (best-effort)."""
    if not product:
        return None
    # remove trademark symbols and extra punctuation
    p = product.strip()
    p = re.sub(r'[\u2122\u00AE]', '', p)
    p = re.sub(r'[^A-Za-z0-9\-\._ ]+', ' ', p)
    p = re.sub(r'\s+', ' ', p).strip()
    return p

# --- CIRCL queries ---
def circl_search_by_vendor_product(vendor, product):
    """Query cve.circl.lu API: /api/search/<vendor>/<product>"""
    url = f"{CIRCL_BASE}/search/{vendor}/{product}"
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return []

def circl_search_by_product(product):
    """Query cve.circl.lu API: /api/search/<product> (fallback)"""
    url = f"{CIRCL_BASE}/search/{product}"
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return []

# --- NVD queries (optional) ---
def nvd_query_cpes(product_string, api_key=None):
    """
    High-level: Query NVD for product string using the 'cves/2.0' endpoint with keyword search.
    Note: NVD matching to exact CPE is complex. This does a keyword search to fetch candidate CVEs.
    """
    params = {'keywordSearch': product_string, 'resultsPerPage': 20}
    headers = {}
    if api_key:
        headers['apiKey'] = api_key
    try:
        r = requests.get(NVD_BASE + "/cvss/2.0", params=params, headers=headers, timeout=15)
        # fallback: use cvss endpoint? The NVD endpoint schema may vary; using cves/2.0 is more correct.
    except Exception:
        return []
    # Fallback: attempt the cvssless path below is left simplistic due to NVD schema complexity
    return []

def nvd_search_cves_by_keyword(keyword, api_key=None):
    """Use the NVD CVE API v2 keywordSearch to get CVE entries."""
    url = f"{NVD_BASE}/cves/2.0"
    params = {'keywordSearch': keyword, 'startIndex': 0, 'resultsPerPage': 20}
    headers = {}
    if api_key:
        headers['apiKey'] = api_key
    try:
        r = requests.get(url, params=params, headers=headers, timeout=20)
        if r.status_code == 200:
            return r.json().get('vulnerabilities', [])
    except Exception:
        pass
    return []

# --- Prioritization heuristics ---
def score_cve_entry(cve):
    """
    Compute a numeric score for a CVE entry:
    - Use CVSSv3 if present, else CVSSv2.
    - Favor more recent CVEs slightly.
    - Public exploit metadata increases score.
    """
    base = 0.0
    cvss = None
    published = None
    exploit_pub = 0.0
    # CIRCL entries vary in shape; attempt multiple keys
    try:
        # CIRCL returns list of dicts with fields like 'cvss' (float) and 'id' and 'summary' and 'Published'
        cvss = float(cve.get('cvss')) if cve.get('cvss') else None
    except Exception:
        cvss = None
    # NVD entries use different schema; caller may standardize beforehand
    if not cvss:
        # try nested NVD structure
        try:
            impact = cve.get('cve', {}).get('metrics', {})
            # too variable; skip complex extraction here
        except Exception:
            pass
    if cvss:
        base = cvss
    # published date
    try:
        published = cve.get('Published') or cve.get('PublishedDate') or cve.get('published')
        if published:
            pd = datetime.fromisoformat(published.split('T')[0])
            # favor newer CVEs slightly
            age_days = (datetime.utcnow() - pd).days
            base += max(0, (3650 - age_days) / 3650) * 0.5  # up to +0.5 for recent
    except Exception:
        pass
    # exploit flag (CIRCL field 'exploit' or 'exploit-db' presence)
    if cve.get('exploit') or ('exploit-db' in (cve.get('references', '') or '').lower()):
        base += 1.0
    return round(base, 2)

# --- Main analysis flow ---
def analyze_hosts(hosts, use_nvd=False, nvd_key=None):
    """
    For each host->port->service, attempt to find CVEs via CIRCL and optionally NVD.
    Return structured report and prioritized testing path (no exploit steps).
    """
    report = {'generated_at': datetime.utcnow().isoformat() + 'Z', 'hosts': []}
    findings = []
    for h in hosts:
        h_entry = {'ip': h['ip'], 'hostnames': h['hostnames'], 'services': []}
        for p in h['ports']:
            svc = p['service'] or {}
            product = normalize_product(svc.get('product') or svc.get('name') or '')
            version = svc.get('version') or ''
            svc_entry = {
                'port': p['port'],
                'proto': p['proto'],
                'service_name': svc.get('name'),
                'product': product,
                'version': version,
                'extrainfo': svc.get('extrainfo'),
                'scripts': p.get('scripts', {}),
                'cves': []
            }
            if product:
                # Heuristic: try vendor/product split if product contains vendor-like token (e.g., "Apache httpd")
                tokens = product.split()
                vendor = tokens[0].lower() if tokens else None
                product_token = product.replace(' ', '_').lower()
                # CIRCL vendor/product query attempt
                circl_results = []
                if vendor and len(tokens) > 1:
                    circl_results = circl_search_by_vendor_product(vendor, product_token)
                if not circl_results:
                    circl_results = circl_search_by_product(product_token)
                # Normalize CIRCL results (list of dicts)
                standardized = []
                if isinstance(circl_results, list):
                    for c in circl_results:
                        # CIRCL returns CVE dicts with id, cvss, summary, Published, Modified, references
                        standardized.append({
                            'id': c.get('id') or c.get('CVE'),
                            'summary': c.get('summary') or c.get('summary'),
                            'cvss': c.get('cvss'),
                            'Published': c.get('Published'),
                            'Modified': c.get('Modified'),
                            'references': c.get('references') or c.get('References'),
                        })
                svc_entry['cves'] = standardized
            # Optionally query NVD as additional source (keyword search)
            if use_nvd and product:
                nvd_hits = nvd_search_cves_by_keyword(product + " " + (version or ''))
                # nvd_hits are structured; convert to compact dicts
                for nvd_v in nvd_hits:
                    # NVD returned structure is nested; attempt to extract cve id and description
                    try:
                        vuln = nvd_v.get('cve')
                        cve_id = vuln.get('id') if vuln else nvd_v.get('cveId')
                        desc = ''
                        if vuln:
                            desc = vuln.get('descriptions', [{}])[0].get('value', '')
                        svc_entry['cves'].append({
                            'id': cve_id,
                            'summary': desc,
                            'cvss': None,
                            'Published': nvd_v.get('published'),
                            'references': []
                        })
                    except Exception:
                        pass
            # Score CVEs and mark service-level flags
            for c in svc_entry['cves']:
                c['score'] = score_cve_entry(c)
            # set a "likely_vulnerable" flag if any CVE score >= 7 or CVE affects specific version (best-effort)
            svc_entry['likely_vulnerable'] = any((c.get('score') or 0) >= 7 for c in svc_entry['cves'])
            h_entry['services'].append(svc_entry)
            # aggregate for host-level prioritization
            for c in svc_entry['cves']:
                findings.append({
                    'host': h['ip'],
                    'port': p['port'],
                    'service': svc_entry['service_name'],
                    'product': product,
                    'version': version,
                    'cve': c
                })
        report['hosts'].append(h_entry)

    # Prioritize findings: sort by CVE score, public exploit indicator and exposedness (port)
    def exposure_weight(port):
        # simple: internet-exposed services commonly high-risk (80, 443, 22, 3389, 445, 3306)
        if port in (80, 443, 22, 3389, 445, 3306, 5432):
            return 1.0
        if port < 1024:
            return 0.6
        return 0.3

    for f in findings:
        f['priority'] = (f['cve'].get('score') or 0) * exposure_weight(f['port'])

    findings_sorted = sorted(findings, key=lambda x: x['priority'], reverse=True)

    # Build a human-friendly prioritized testing path
    testing_path = []
    seen_targets = set()
    for f in findings_sorted:
        target_key = (f['host'], f['port'], f['product'])
        if target_key in seen_targets:
            continue
        seen_targets.add(target_key)
        testing_path.append({
            'host': f['host'],
            'port': f['port'],
            'service': f['service'],
            'product': f['product'],
            'version': f['version'],
            'top_cve': f['cve'].get('id'),
            'cve_summary': f['cve'].get('summary'),
            'score': f['cve'].get('score'),
            'priority': round(f['priority'], 2)
        })

    return report, testing_path

# --- CLI ---
def main():
    ap = argparse.ArgumentParser(description="Nmap to CVE analyzer (reporting/prioritization only).")
    ap.add_argument('-i', '--input', required=True, help='nmap XML file')
    ap.add_argument('-o', '--output', required=False, help='output JSON filename (default: report.json)', default='report.json')
    ap.add_argument('--nvd-key', required=False, help='NVD API key (optional)')
    ap.add_argument('--use-nvd', action='store_true', help='Enable NVD keyword search (optional, slower)')
    args = ap.parse_args()

    if not os.path.exists(args.input):
        print("Input file not found:", args.input)
        return

    hosts = parse_nmap_xml(args.input)
    report, testing_path = analyze_hosts(hosts, use_nvd=args.use_nvd, nvd_key=(args.nvd_key or NVD_API_KEY))
    # attach testing path to report
    report['testing_path'] = testing_path

    with open(args.output, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"Report written to {args.output}")
    print("\nTop prioritized testing targets (summary):\n")
    for i, t in enumerate(testing_path[:20], start=1):
        print(f"{i}. {t['host']}:{t['port']} - {t['product']} {t['version']} - CVE {t['top_cve']} (score {t['score']}) priority {t['priority']}")

if __name__ == '__main__':
    main()
