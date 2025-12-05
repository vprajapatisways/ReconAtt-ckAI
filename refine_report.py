#!/usr/bin/env python3
# \"\"\"refine_report.py (with MITRE ATT&CK mapping)

# This is the updated refinement/triage script that adds MITRE ATT&CK mappings and playbook templates.
# Usage:
#     python refine_report.py -i report.json -o refined_report.json
# \"\"\"

import argparse
import json
import re
from datetime import datetime
from packaging import version as pkg_version
from pathlib import Path

# --- Config: quick version thresholds for heuristics ---
OUTDATED_THRESHOLDS = {
    "openssh": "7.4",
    "apache": "2.4",
    "vsftpd": "3.0",
    "mysql": "5.6",
    "postgresql": "9.5",
    "bind": "9.8",
    "samba": "4.0",
    "tomcat": "7.0",
    "unrealircd": "3.2.9"
}

EXPOSED_PORTS = {22, 80, 443, 3389, 445, 3306, 5432, 21, 23, 25, 5900}

EXPOSURE_WEIGHT = 1.0
OUTDATED_WEIGHT = 6.0
SCRIPT_FLAG_WEIGHT = 1.5
CVE_WEIGHT = 1.0

# ---------------- MITRE ATT&CK MAPPING DATA ----------------
MITRE_KEYWORD_MAP = [
    (("rce","remote code","exec","command execution","command injection"), "T1203", "Impact", "Exploitation for Client Execution"),
    (("sql","sql injection","sqli"), "T1190", "Initial Access", "Exploit Public-Facing Application"),
    (("xss","cross-site scripting"), "T1059", "Execution", "Command and Scripting Interpreter"),
    (("ldap","smb","samba","msrpc"), "T1179", "Resource Development", "Lateral Movement via SMB"),
    (("authentication bypass","weak auth","default creds","default password","credential"), "T1078", "Initial Access", "Valid Accounts"),
    (("telnet","cleartext","plaintext"), "T1040", "Discovery", "Network Sniffing"),
    (("anonymous_ftp","anonymous ftp","ftp anonymous"), "T1102", "Command and Control", "Web Service"),
    (("ssl","sslv2","weak_ssl_ciphers","cipher"), "T1176", "Defense Evasion", "Deobfuscate/Decode Files or Information"),
    (("smbv1","smbv2","samba_old_range"), "T1077", "Lateral Movement", "Windows Admin Shares"),
    (("buffer overflow","stack overflow","heap overflow"), "T1203", "Impact", "Exploitation for Client Execution"),
]

MITRE_PLAYBOOKS = {
    "T1203": {
        "name": "Exploitation for Client Execution",
        "tactic": "Impact",
        "playbook": [
            "Identify affected service binary and version; confirm exploitability via vendor advisories.",
            "Contain: isolate host from network segments, apply firewall rules to block offending ports.",
            "Remediate: apply vendor patch or upgrade to a non-affected version.",
            "Detect: enable EDR rules to catch abnormal child processes and suspicious commands.",
            "Verify: run non-destructive scans and compare process trees before/after tests."
        ]
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "playbook": [
            "Confirm vulnerable application endpoints and review public exploits or PoCs.",
            "Contain: apply WAF rules and rate-limit suspicious input patterns.",
            "Remediate: patch application or fix vulnerable code paths; sanitize inputs.",
            "Detect: enable webserver logging, monitor for anomalous POST/GET payloads and 500s.",
            "Verify: use non-intrusive checks and code review to validate fix."
        ]
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "playbook": [
            "Detect scripts launched by unexpected users or from abnormal locations.",
            "Contain: restrict script execution permissions and apply execution policies.",
            "Remediate: remove or harden scripts; restrict upload directories.",
            "Verify: monitor for new scheduled tasks or persistent autoruns."
        ]
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access",
        "playbook": [
            "Audit accounts, remove defaults, rotate credentials and enable MFA.",
            "Contain: disable compromised accounts; force password resets and session revocations.",
            "Detect: monitor for unusual login sources and impossible travel.",
            "Verify: confirm no unauthorized persistent access remains."
        ]
    },
    "T1040": {
        "name": "Network Sniffing",
        "tactic": "Discovery",
        "playbook": [
            "Eliminate cleartext protocols (replace telnet/plain FTP with SSH/SFTP).",
            "Detect: inspect network taps for large numbers of plaintext credentials.",
            "Remediate: enforce encryption, apply ACLs to limit management interfaces."
        ]
    },
    "T1102": {
        "name": "Web Service",
        "tactic": "Command and Control",
        "playbook": [
            "Limit external connections, inspect for exfiltration over HTTP/HTTPS.",
            "Detect: review outbound connections to odd domains or high-volume hosts.",
            "Remediate: restrict network egress and implement proxy/inspection."
        ]
    },
}

# ---------------- Helpers ----------------
def numeric_version_from_banner(vstr):
    if not vstr:
        return None
    v = vstr.strip().split()[0]
    v = v.replace("p", ".p")
    v = re.sub(r'^[^0-9]+', '', v)
    v = re.sub(r'[^0-9A-Za-z\\._\\-]', '', v)
    return v or None

def is_product_old(product, version_str):
    if not product:
        return False
    p = product.lower()
    for key, min_ver in OUTDATED_THRESHOLDS.items():
        if key in p:
            if not version_str:
                return True
            try:
                vnorm = numeric_version_from_banner(version_str)
                if not vnorm:
                    return True
                if pkg_version.parse(vnorm) < pkg_version.parse(min_ver):
                    return True
                return False
            except Exception:
                return True
    return False

def exposure_weight(port):
    try:
        port = int(port)
    except Exception:
        port = 0
    return EXPOSURE_WEIGHT if port in EXPOSED_PORTS else (0.6 if port < 1024 else 0.3)

def parse_script_flags(scripts: dict):
    flags = []
    score = 0.0
    for k, v in (scripts or {}).items():
        if not v:
            continue
        low = v.lower()
        if ("anonymous ftp login allowed" in low) or ("anonymous ftp" in k.lower()) or ("anonymous" in low and "ftp" in low):
            flags.append("anonymous_ftp_allowed")
            score += SCRIPT_FLAG_WEIGHT
        if "vsftp" in low or "vsftpd" in low:
            if "2.3.4" in low:
                flags.append("vsftpd_2_3_4_banner")
                score += SCRIPT_FLAG_WEIGHT * 2
        if "sslv2" in k.lower() or "sslv2" in low:
            flags.append("sslv2_supported")
            score += SCRIPT_FLAG_WEIGHT * 1.5
        if ("not valid after" in low) or ("not valid before" in low) or ("certificate" in k.lower()):
            years = re.findall(r'20\\d{2}', v)
            if years:
                cur_year = datetime.utcnow().year
                yrs = []
                for y in years:
                    try:
                        yrs.append(int(y))
                    except Exception:
                        continue
                if any(y < cur_year for y in yrs):
                    flags.append("cert_mismatch_or_expired")
                    score += SCRIPT_FLAG_WEIGHT
            else:
                if ("not valid" in low) or ("expired" in low) or ("invalid" in low):
                    flags.append("cert_issue")
                    score += SCRIPT_FLAG_WEIGHT
        if "ssl-date" in k.lower() and "-" in low:
            flags.append("ssl_date_skew")
            score += SCRIPT_FLAG_WEIGHT * 0.5
        if "export40" in low or "rc4" in low or "des" in low:
            flags.append("weak_ssl_ciphers")
            score += SCRIPT_FLAG_WEIGHT
        if "telnet" in k.lower() or "telnet" in low:
            flags.append("telnet_service_detected")
            score += SCRIPT_FLAG_WEIGHT
        if "vnc authentication" in low or "vnc" in k.lower():
            flags.append("vnc_auth")
            score += SCRIPT_FLAG_WEIGHT * 0.5
        if "samba" in low or "smb" in low:
            try:
                if "3.x" in low or ("3." in low and "4." in low):
                    flags.append("samba_old_range")
                    score += SCRIPT_FLAG_WEIGHT
            except Exception:
                pass
    return flags, score

def compute_service_score(svc):
    score = 0.0
    reasons = []
    for c in svc.get("cves", []):
        s = c.get("score") or 0
        try:
            s = float(s)
        except Exception:
            s = 0
        score += s * CVE_WEIGHT
        if s >= 7:
            reasons.append(f"High severity CVE {c.get('id')}")
    port = svc.get("port") or 0
    ew = exposure_weight(port)
    score += ew
    if ew >= 1.0:
        reasons.append(f"Well-known/exposed port {port}")
    flags, flag_score = parse_script_flags(svc.get("scripts", {}))
    score += flag_score
    if flags:
        reasons.append("Script flags: " + ", ".join(flags))
    if is_product_old(svc.get("product") or "", svc.get("version") or ""):
        score += OUTDATED_WEIGHT
        reasons.append("Outdated product/version (heuristic)")
    proto = (svc.get("service_name") or "").lower()
    if proto in ("telnet", "exec", "login", "rsh", "rexec", "rlogin"):
        score += 2.0
        reasons.append("Cleartext remote-login service detected")
    if "anonymous_ftp_allowed" in flags:
        score += 2.5
        reasons.append("Anonymous FTP allowed")
    score = round(score, 2)
    if score >= 8:
        risk = "HIGH"
    elif score >= 4:
        risk = "MEDIUM"
    elif score > 0:
        risk = "LOW"
    else:
        risk = "INFO"
    likely = False
    if risk == "HIGH":
        likely = True
    if svc.get("cves"):
        likely = True
    if any(f in ["vsftpd_2_3_4_banner", "sslv2_supported", "telnet_service_detected", "samba_old_range"] for f in flags):
        likely = True
    return score, risk, reasons, flags, likely

def map_service_to_mitre(svc):
    mapped = {}
    evidence_text = "".join([
        str(svc.get("product") or ""),
        " ",
        str(svc.get("service_name") or ""),
        " ",
        str(svc.get("version") or ""),
    ])
    for f in svc.get("script_flags", []):
        evidence_text += " " + f
    for c in svc.get("cves", []):
        evidence_text += " " + (str(c.get("summary") or "")[:200])
    ev = evidence_text.lower()
    for keywords, tech_id, tactic, shortname in MITRE_KEYWORD_MAP:
        for kw in keywords:
            if kw in ev:
                if tech_id not in mapped:
                    play = MITRE_PLAYBOOKS.get(tech_id)
                    mapped[tech_id] = {
                        "id": tech_id,
                        "name": play["name"] if play else shortname,
                        "tactic": play["tactic"] if play else tactic,
                        "evidence": kw,
                        "playbook": play["playbook"] if play else []
                    }
                break
    for f in svc.get("script_flags", []):
        if f == "anonymous_ftp_allowed":
            mapped.setdefault("T1102", {
                "id": "T1102",
                "name": MITRE_PLAYBOOKS.get("T1102", {}).get("name", "Web Service"),
                "tactic": MITRE_PLAYBOOKS.get("T1102", {}).get("tactic", "Command and Control"),
                "evidence": f,
                "playbook": MITRE_PLAYBOOKS.get("T1102", {}).get("playbook", [])
            })
        if f == "telnet_service_detected":
            mapped.setdefault("T1040", {
                "id": "T1040",
                "name": MITRE_PLAYBOOKS.get("T1040", {}).get("name", "Network Sniffing"),
                "tactic": MITRE_PLAYBOOKS.get("T1040", {}).get("tactic", "Discovery"),
                "evidence": f,
                "playbook": MITRE_PLAYBOOKS.get("T1040", {}).get("playbook", [])
            })
    return list(mapped.values())

def generate_action_list_for_service(host_ip, svc, score, risk, reasons, flags, likely):
    actions = []
    port = svc.get("port")
    svc_label = f"{host_ip}:{port} - {svc.get('product') or svc.get('service_name')}"
    actions.append({
        "id": f"{host_ip}-{port}-authz",
        "title": "Ensure written authorization",
        "priority": "High",
        "do_or_not": "Do",
        "details": "Confirm you have written permission to perform further testing on this host."
    })
    actions.append({
        "id": f"{host_ip}-{port}-collect",
        "title": "Collect non-intrusive evidence",
        "priority": "High" if risk in ("HIGH","MEDIUM") else "Medium",
        "do_or_not": "Do",
        "details": "Collect banners, TLS ciphers, SSH KEX/cipher lists and service configs using non-destructive methods. Document everything for the owner."
    })
    actions.append({
        "id": f"{host_ip}-{port}-verifyver",
        "title": "Verify reported version",
        "priority": "High" if risk == "HIGH" else "Medium",
        "do_or_not": "Do",
        "details": "Validate the banner with multiple probes (nmap -sV, service-specific safe queries). Banners can be faked."
    })
    if "anonymous_ftp_allowed" in flags:
        actions.append({
            "id": f"{host_ip}-{port}-disable-anon-ftp",
            "title": "Disable anonymous FTP or restrict it",
            "priority": "High",
            "do_or_not": "Do",
            "details": "If anonymous FTP is not required, disable anonymous logins. If required, restrict to chrooted directories and logging."
        })
    if "sslv2_supported" in flags or "weak_ssl_ciphers" in flags:
        actions.append({
            "id": f"{host_ip}-{port}-tls-hardening",
            "title": "Harden TLS/disable SSLv2/weak ciphers",
            "priority": "High",
            "do_or_not": "Do",
            "details": "Disable SSLv2 and other weak protocols/ciphers; enable strong TLS versions and ciphers. Use a non-intrusive TLS scanner to verify."
        })
    if "telnet_service_detected" in flags:
        actions.append({
            "id": f"{host_ip}-{port}-remove-telnet",
            "title": "Remove/disable telnet and use SSH",
            "priority": "High",
            "do_or_not": "Do",
            "details": "Telnet sends credentials in cleartext; replace with SSH. If telnet is required, restrict access and monitor closely."
        })
    if is_product_old(svc.get("product") or "", svc.get("version") or ""):
        actions.append({
            "id": f"{host_ip}-{port}-plan-upgrade",
            "title": "Plan upgrade/patch for outdated product",
            "priority": "High",
            "do_or_not": "Do",
            "details": "Schedule update/patch. Test in staging, ensure backups and rollbacks. If immediate patching is impossible, apply network mitigations (ACLs/firewall)."
        })
    actions.append({
        "id": f"{host_ip}-{port}-dont-exploit",
        "title": "Do not attempt to exploit vulnerabilities",
        "priority": "High",
        "do_or_not": "Don't",
        "details": "This output is for triage and remediation planning only. Do not run exploit payloads without explicit authorization and controls."
    })
    if svc.get("cves"):
        for c in svc.get("cves"):
            actions.append({
                "id": f"{host_ip}-{port}-review-{c.get('id')}",
                "title": f"Review CVE {c.get('id')}",
                "priority": "High" if (c.get("score") or 0) >= 7 else "Medium",
                "do_or_not": "Do",
                "details": "Read vendor advisory / CVE details and map applicability to the exact product/version. Document proof if applicable."
            })
    actions.append({
        "id": f"{host_ip}-{port}-log-monitor",
        "title": "Enable monitoring and alerting",
        "priority": "Medium",
        "do_or_not": "Do",
        "details": "Ensure auth/logging is in place and that alerts are generated for suspicious activity or crashes."
    })

    mitre_mappings = map_service_to_mitre({
        **svc,
        "script_flags": flags,
        "cves": svc.get("cves", [])
    })

    for a in actions:
        if mitre_mappings:
            a["mitre_attack"] = mitre_mappings
    return actions, mitre_mappings

def refine_report(report):
    refined = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "hosts": [],
        "testing_path": []
    }
    all_actions = []

    for host in report.get("hosts", []):
        host_ip = host.get("ip")
        refined_host = {"ip": host_ip, "hostnames": host.get("hostnames", []), "services": []}
        for svc in host.get("services", []):
            score, risk, reasons, flags, likely = compute_service_score(svc)
            svc_updated = dict(svc)
            svc_updated["risk_score"] = score
            svc_updated["risk"] = risk
            svc_updated["reasons"] = reasons
            svc_updated["script_flags"] = flags
            svc_updated["likely_vulnerable"] = bool(likely) or svc.get("likely_vulnerable", False)
            refined_host["services"].append(svc_updated)

            actions, mitre_mappings = generate_action_list_for_service(host_ip, svc, score, risk, reasons, flags, likely)
            for a in actions:
                a["target_host"] = host_ip
                a["target_port"] = svc.get("port")
                a["service_name"] = svc.get("service_name")
                a["risk"] = risk
                a["risk_score"] = score
            all_actions.extend(actions)

            refined_entry = {
                "host": host_ip,
                "port": svc.get("port"),
                "service": svc.get("service_name"),
                "product": svc.get("product"),
                "version": svc.get("version"),
                "risk": risk,
                "risk_score": score,
                "top_reasons": reasons[:3]
            }
            if mitre_mappings:
                refined_entry["mitre_attack"] = mitre_mappings
            refined["testing_path"].append(refined_entry)

        refined["hosts"].append(refined_host)

    refined["testing_path"] = sorted(refined["testing_path"], key=lambda x: x["risk_score"], reverse=True)

    priority_order = {"High": 3, "Medium": 2, "Low": 1}
    def action_sort_key(a):
        return (
            priority_order.get(a.get("priority","Low"), 1),
            0 if a.get("do_or_not") == "Do" else -1,
            a.get("risk_score", 0)
        )
    all_actions_sorted = sorted(all_actions, key=action_sort_key, reverse=True)
    refined["actions"] = all_actions_sorted

    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for h in refined["hosts"]:
        for s in h["services"]:
            r = s.get("risk")
            if r == "HIGH":
                counts["high"] += 1
            elif r == "MEDIUM":
                counts["medium"] += 1
            elif r == "LOW":
                counts["low"] += 1
            else:
                counts["info"] += 1
    refined["summary"] = {"host_count": len(refined["hosts"]), "service_counts": counts, "generated_at": datetime.utcnow().isoformat() + "Z"}
    return refined

def main():
    ap = argparse.ArgumentParser(description="Refine and triage nmap/CVE JSON output into prioritized testing_path and actions (with MITRE mappings).")
    ap.add_argument("-i", "--input", required=True, help="Input JSON file (report.json)")
    ap.add_argument("-o", "--output", required=False, default="refined_report.json", help="Output refined JSON filename")
    args = ap.parse_args()

    if not Path(args.input).exists():
        print("Input file not found:", args.input)
        return

    with open(args.input, "r", encoding="utf-8") as f:
        report = json.load(f)

    refined = refine_report(report)
    with open(args.output, "w", encoding="utf-8") as fo:
        json.dump(refined, fo, indent=2)

    print(f"Refined report written to {args.output}")
    print("Summary:")
    print(f"  Hosts: {refined['summary']['host_count']}")
    sc = refined['summary']['service_counts']
    print(f"  Services - High: {sc['high']} Medium: {sc['medium']} Low: {sc['low']} Info: {sc['info']}")
    print("\nTop prioritized testing_path:")
    for i, t in enumerate(refined['testing_path'][:10], start=1):
        mitre = ','.join([m['id'] for m in t.get('mitre_attack', [])]) if t.get('mitre_attack') else ''
        print(f"{i}. {t['host']}:{t['port']} {t['product']} {t['version']} -> risk={t['risk']} score={t['risk_score']} mitre={mitre} reasons={t['top_reasons']}")
    print("\nTop actions (Do / High priority):")
    printed = 0
    for a in refined['actions']:
        if a['do_or_not'] == "Do" and a['priority'] == "High":
            printed += 1
            mitre = ','.join([m['id'] for m in a.get('mitre_attack', [])]) if a.get('mitre_attack') else ''
            print(f"{printed}. [{a['target_host']}:{a['target_port']}] {a['title']} ({a['service_name']}) - {a['details']} mitre={mitre}")
            if printed >= 10:
                break
    if printed == 0:
        print("No high-priority Do actions found. Review actions in the output JSON.")

if __name__ == '__main__':
    main()
