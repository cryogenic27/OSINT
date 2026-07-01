#!/usr/bin/env python3
"""
SpiderFoot OSINT Report Generator — v2 (Premium UI)
Generates an HTML report from SpiderFoot CSV export.
Analysis framed around F3EAD, JTC, and MITRE ATT&CK.

Usage: python3 generate_spiderfoot_report_v2.py <input.csv> [output.html]
"""

import sys
import json
import pandas as pd
from pathlib import Path

# ── MITRE ATT&CK mappings ─────────────────────────────────────────────────────
MITRE_MAP = {
    "TCP_PORT_OPEN":              {"id": "T1046",    "name": "Network Service Discovery",              "tactic": "Discovery"},
    "TCP_PORT_OPEN_BANNER":       {"id": "T1046",    "name": "Network Service Discovery",              "tactic": "Discovery"},
    "WEBSERVER_BANNER":           {"id": "T1592",    "name": "Gather Victim Host Information",         "tactic": "Reconnaissance"},
    "WEBSERVER_TECHNOLOGY":       {"id": "T1592",    "name": "Gather Victim Host Information",         "tactic": "Reconnaissance"},
    "SSL_CERTIFICATE_ISSUED":     {"id": "T1596",    "name": "Search Open Technical Databases",        "tactic": "Reconnaissance"},
    "SSL_CERTIFICATE_MISMATCH":   {"id": "T1596",    "name": "Search Open Technical Databases",        "tactic": "Reconnaissance"},
    "CLOUD_STORAGE_BUCKET":       {"id": "T1530",    "name": "Data from Cloud Storage Object",         "tactic": "Collection"},
    "CLOUD_STORAGE_BUCKET_OPEN":  {"id": "T1530",    "name": "Data from Cloud Storage Object",         "tactic": "Collection"},
    "INTERESTING_FILE":           {"id": "T1213",    "name": "Data from Information Repositories",     "tactic": "Collection"},
    "INTERESTING_FILE_HISTORIC":  {"id": "T1213",    "name": "Data from Information Repositories",     "tactic": "Collection"},
    "URL_PASSWORD":               {"id": "T1078",    "name": "Valid Accounts",                         "tactic": "Initial Access"},
    "URL_PASSWORD_HISTORIC":      {"id": "T1078",    "name": "Valid Accounts",                         "tactic": "Initial Access"},
    "URL_UPLOAD":                 {"id": "T1190",    "name": "Exploit Public-Facing Application",      "tactic": "Initial Access"},
    "URL_FORM":                   {"id": "T1598",    "name": "Phishing for Information",               "tactic": "Reconnaissance"},
    "SOCIAL_MEDIA":               {"id": "T1593",    "name": "Search Open Websites/Domains",           "tactic": "Reconnaissance"},
    "ACCOUNT_EXTERNAL_OWNED":     {"id": "T1589",    "name": "Gather Victim Identity Information",     "tactic": "Reconnaissance"},
    "USERNAME":                   {"id": "T1589.003","name": "Gather Victim Identity: Employee Names",  "tactic": "Reconnaissance"},
    "HUMAN_NAME":                 {"id": "T1589.003","name": "Gather Victim Identity: Employee Names",  "tactic": "Reconnaissance"},
    "PGP_KEY":                    {"id": "T1589",    "name": "Gather Victim Identity Information",     "tactic": "Reconnaissance"},
    "PUBLIC_CODE_REPO":           {"id": "T1593.003","name": "Search Open Websites: Code Repositories","tactic": "Reconnaissance"},
    "AFFILIATE_EMAILADDR":        {"id": "T1589.002","name": "Gather Victim Identity: Email Addresses","tactic": "Reconnaissance"},
    "INTERNET_NAME":              {"id": "T1590",    "name": "Gather Victim Network Information",      "tactic": "Reconnaissance"},
    "IP_ADDRESS":                 {"id": "T1590",    "name": "Gather Victim Network Information",      "tactic": "Reconnaissance"},
    "SIMILARDOMAIN":              {"id": "T1584.001","name": "Compromise Infrastructure: Domains",     "tactic": "Resource Development"},
    "WEBSERVER_STRANGEHEADER":    {"id": "T1592",    "name": "Gather Victim Host Information",         "tactic": "Reconnaissance"},
    "PHYSICAL_ADDRESS":           {"id": "T1591",    "name": "Gather Victim Org Information",          "tactic": "Reconnaissance"},
}

# ── F3EAD phase mappings ───────────────────────────────────────────────────────
F3EAD_MAP = {
    "FIND": [
        "INTERNET_NAME","IP_ADDRESS","TCP_PORT_OPEN","TCP_PORT_OPEN_BANNER",
        "DOMAIN_NAME","DOMAIN_NAME_PARENT","AFFILIATE_INTERNET_NAME",
        "AFFILIATE_IPADDR","SIMILARDOMAIN","PROVIDER_DNS","PROVIDER_HOSTING",
        "BGP_AS_MEMBER","NETBLOCK_MEMBER","GEOINFO","COUNTRY_NAME",
        "PHYSICAL_ADDRESS","PHYSICAL_COORDINATES",
    ],
    "FIX": [
        "WEBSERVER_BANNER","WEBSERVER_TECHNOLOGY","WEBSERVER_HTTPHEADERS",
        "WEBSERVER_STRANGEHEADER","URL_WEB_FRAMEWORK","WEBSERVER_BANNER",
        "SSL_CERTIFICATE_ISSUED","SSL_CERTIFICATE_MISMATCH","SSL_CERTIFICATE_RAW",
        "TCP_PORT_OPEN_BANNER","RAW_DNS_RECORDS","DNS_TEXT","DNS_SPF",
    ],
    "FINISH": [
        "TCP_PORT_OPEN","URL_UPLOAD","URL_PASSWORD","URL_FORM",
        "CLOUD_STORAGE_BUCKET_OPEN","INTERESTING_FILE","SSL_CERTIFICATE_MISMATCH",
        "WEBSERVER_STRANGEHEADER",
    ],
    "EXPLOIT": [
        "URL_PASSWORD","URL_UPLOAD","CLOUD_STORAGE_BUCKET_OPEN",
        "INTERESTING_FILE","URL_PASSWORD_HISTORIC","INTERESTING_FILE_HISTORIC",
    ],
    "ANALYZE": [
        "HUMAN_NAME","USERNAME","ACCOUNT_EXTERNAL_OWNED","AFFILIATE_EMAILADDR",
        "SOCIAL_MEDIA","PUBLIC_CODE_REPO","PGP_KEY","PHONE_NUMBER",
        "WIKIPEDIA_PAGE_EDIT","HASH","RAW_FILE_META_DATA",
    ],
    "DISSEMINATE": [
        "COMPANY_NAME","AFFILIATE_COMPANY_NAME","LEI","IBAN_NUMBER",
        "PHYSICAL_ADDRESS","GEOINFO","AFFILIATE_DESCRIPTION_CATEGORY",
        "AFFILIATE_DESCRIPTION_ABSTRACT",
    ],
}

# ── JTC phase mappings ─────────────────────────────────────────────────────────
JTC_MAP = {
    "Target Development": [
        "INTERNET_NAME","IP_ADDRESS","DOMAIN_NAME","AFFILIATE_INTERNET_NAME",
        "SIMILARDOMAIN","CO_HOSTED_SITE","BGP_AS_MEMBER",
    ],
    "Target Analysis": [
        "WEBSERVER_BANNER","WEBSERVER_TECHNOLOGY","SSL_CERTIFICATE_ISSUED",
        "SSL_CERTIFICATE_MISMATCH","TCP_PORT_OPEN","TCP_PORT_OPEN_BANNER",
        "URL_WEB_FRAMEWORK","WEBSERVER_STRANGEHEADER",
    ],
    "Decision": [
        "URL_UPLOAD","URL_PASSWORD","CLOUD_STORAGE_BUCKET_OPEN",
        "INTERESTING_FILE","TCP_PORT_OPEN",
    ],
    "Execution": [
        "URL_UPLOAD","URL_PASSWORD","CLOUD_STORAGE_BUCKET_OPEN",
        "INTERESTING_FILE","URL_FORM",
    ],
    "Assessment": [
        "INTERESTING_FILE_HISTORIC","URL_PASSWORD_HISTORIC",
        "ACCOUNT_EXTERNAL_OWNED","PUBLIC_CODE_REPO","SOCIAL_MEDIA",
    ],
}

# Default severity for an open bucket when NO sensitive data is detected.
# Open buckets are common; we only escalate to CRITICAL when the bucket
# actually exposes sensitive/confidential content (see SENSITIVE_KEYWORDS).
SEVERITY_MAP = {
    "CLOUD_STORAGE_BUCKET_OPEN": "HIGH",
    "URL_UPLOAD":                "CRITICAL",
    "URL_PASSWORD":              "HIGH",
    "INTERESTING_FILE":          "HIGH",
    "TCP_PORT_OPEN":             "HIGH",
    "SSL_CERTIFICATE_MISMATCH":  "HIGH",
    "URL_PASSWORD_HISTORIC":     "MEDIUM",
    "INTERESTING_FILE_HISTORIC": "MEDIUM",
    "TCP_PORT_OPEN_BANNER":      "MEDIUM",
    "WEBSERVER_STRANGEHEADER":   "MEDIUM",
    "SIMILARDOMAIN":             "MEDIUM",
    "ACCOUNT_EXTERNAL_OWNED":    "LOW",
    "USERNAME":                  "LOW",
    "HUMAN_NAME":                "LOW",
    "SOCIAL_MEDIA":              "LOW",
    "PUBLIC_CODE_REPO":          "LOW",
    "PGP_KEY":                   "LOW",
    "AFFILIATE_EMAILADDR":       "LOW",
}

# ── Port exemptions ───────────────────────────────────────────────────────────
# Open TCP ports listed here are treated as expected/normal and are NOT counted
# toward severity (they are downgraded to "INFO"). Add or remove ports as your
# environment's baseline requires. Example: 443 = HTTPS, 80 = HTTP.
EXEMPT_PORTS = {
    443,   # HTTPS
    # 80,  # HTTP  (uncomment to also exempt plain HTTP)
}

# Keywords that indicate sensitive / confidential content. If an open bucket's
# contents or name match any of these, it is escalated to CRITICAL. Otherwise an
# open-but-non-sensitive bucket stays HIGH (publicly readable, but no confirmed
# sensitive data exposed).
SENSITIVE_KEYWORDS = [
    "secret", "secrets", "password", "passwd", "credential", "cred",
    "private", "confidential", "internal", "backup", "dump", "key", "keys",
    "token", "apikey", "api_key", ".env", "config", "configuration",
    "ssh", "rsa", "pem", ".pfx", ".p12", "keystore", "vault",
    "financ", "salary", "payroll", "invoice", "tax", "ssn", "passport",
    "contract", "nda", "legal", "hr", "employee", "personnel", "pii",
    "database", "db_", "dbdump", ".sql", ".bak", "firewall", "vpn",
    "business_plan", "businessplan", "acquisition", "merger", "patient",
    "medical", "health", "customer", "client_data", "user_data",
]

def classify_bucket_severity(bucket_source, related_files):
    """
    Decide an open bucket's severity.
    - CRITICAL: bucket name OR any file under it matches a sensitive keyword.
    - HIGH:     bucket is open but no sensitive content is confirmed.
    Returns (severity, matched_keywords).
    """
    haystack = bucket_source.lower()
    for f in related_files:
        haystack += " " + str(f).lower()
    matched = sorted({kw for kw in SENSITIVE_KEYWORDS if kw in haystack})
    if matched:
        return "CRITICAL", matched
    return "HIGH", []

def port_from_finding(data_value):
    """
    Pull the port number out of a TCP_PORT_OPEN value like
    'host:443' or '1.2.3.4:8080'. Returns an int, or None if not parseable.
    """
    try:
        return int(str(data_value).strip().split(":")[-1])
    except (ValueError, IndexError):
        return None

def load_data(csv_path):
    return pd.read_csv(csv_path)

def build_json_payload(df):
    def get(type_name, cols=None):
        sub = df[df['Type'] == type_name].drop_duplicates(subset=['Data'])
        if cols:
            return sub[cols].values.tolist()
        return sub['Data'].tolist()

    def get_multi(type_names, cols=None):
        sub = df[df['Type'].isin(type_names)].drop_duplicates(subset=['Type','Data'])
        if cols:
            return sub[cols].values.tolist()
        return sub[['Type','Data']].values.tolist()

    type_counts = df['Type'].value_counts().to_dict()

    # ── Per-bucket severity classification ───────────────────────────────────
    # An open bucket is CRITICAL only when it exposes sensitive content;
    # otherwise it is HIGH. We inspect the bucket name plus any INTERESTING_FILE
    # URLs that reference the same bucket host.
    raw_buckets = get("CLOUD_STORAGE_BUCKET_OPEN", ["Source", "Data"])
    all_file_urls = (
        get("INTERESTING_FILE")
        + get("INTERESTING_FILE_HISTORIC")
        + [r[1] for r in get("URL_UPLOAD", ["Source", "Data"])]
    )
    bucket_records = []
    bucket_crit_count = 0
    bucket_high_count = 0
    for src, data in raw_buckets:
        # Bucket host without scheme, e.g. "pentest-ground-bucket.s3.amazonaws.com"
        host = str(src).replace("https://", "").replace("http://", "").split("/")[0].lower()
        # Only associate files that are actually served FROM this bucket host.
        # (SpiderFoot web-directory files live on the main site, not the bucket,
        #  so we must match the full bucket host to avoid false escalation.)
        related = [u for u in all_file_urls if host and host in str(u).lower()]
        sev_level, matched = classify_bucket_severity(str(src) + " " + str(data), related)
        if sev_level == "CRITICAL":
            bucket_crit_count += 1
        else:
            bucket_high_count += 1
        bucket_records.append({
            "source": src,
            "data": data,
            "severity": sev_level,
            "matched": matched,
        })

    # ── Per-port severity for open TCP ports ─────────────────────────────────
    # Each open port is HIGH, EXCEPT ports in EXEMPT_PORTS (e.g. 443/HTTPS),
    # which are downgraded to INFO and excluded from the HIGH total.
    raw_ports = get("TCP_PORT_OPEN", ["Source", "Data"])
    port_high_count = 0
    port_exempt_count = 0
    for _src, pdata in raw_ports:
        if port_from_finding(pdata) in EXEMPT_PORTS:
            port_exempt_count += 1
        else:
            port_high_count += 1

    sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for t, s in SEVERITY_MAP.items():
        # Buckets and TCP ports are counted separately below (per-item logic).
        if t in ("CLOUD_STORAGE_BUCKET_OPEN", "TCP_PORT_OPEN"):
            continue
        sev[s] = sev.get(s, 0) + type_counts.get(t, 0)
    sev["CRITICAL"] += bucket_crit_count
    sev["HIGH"] += bucket_high_count
    sev["HIGH"] += port_high_count
    sev["INFO"] += port_exempt_count

    f3ead_counts = {phase: sum(type_counts.get(t, 0) for t in types) for phase, types in F3EAD_MAP.items()}
    jtc_counts   = {phase: sum(type_counts.get(t, 0) for t in types) for phase, types in JTC_MAP.items()}

    tactic_counts = {}
    for t, info in MITRE_MAP.items():
        tactic = info['tactic']
        tactic_counts[tactic] = tactic_counts.get(tactic, 0) + type_counts.get(t, 0)

    findings = []
    for t, mitre in MITRE_MAP.items():
        cnt = type_counts.get(t, 0)
        if cnt > 0:
            if t == "CLOUD_STORAGE_BUCKET_OPEN":
                # Use the highest severity observed across individual buckets.
                fsev = "CRITICAL" if bucket_crit_count > 0 else "HIGH"
            elif t == "TCP_PORT_OPEN":
                # Only non-exempt ports carry severity; show that count instead.
                cnt = port_high_count
                fsev = SEVERITY_MAP.get(t, "INFO")
                if cnt == 0:
                    continue  # every open port was exempt — drop the row
            else:
                fsev = SEVERITY_MAP.get(t, "INFO")
            findings.append({
                "type": t,
                "count": cnt,
                "severity": fsev,
                "mitre_id": mitre["id"],
                "mitre_name": mitre["name"],
                "tactic": mitre["tactic"],
                "url": f"https://attack.mitre.org/techniques/{mitre['id'].replace('.', '/')}",
            })
    findings.sort(key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x["severity"]))

    exposures = {
        "cloud_buckets": bucket_records,
        "interesting_files": get("INTERESTING_FILE"),
        "interesting_files_historic": get("INTERESTING_FILE_HISTORIC"),
        "tcp_ports": [{"source": r[0], "data": r[1]} for r in get("TCP_PORT_OPEN", ["Source","Data"])],
        "tcp_banners": [{"source": r[0], "data": r[1]} for r in get("TCP_PORT_OPEN_BANNER", ["Source","Data"])],
        "ssl_mismatches": [{"source": r[0], "data": r[1]} for r in get("SSL_CERTIFICATE_MISMATCH", ["Source","Data"])],
        "url_passwords": get("URL_PASSWORD"),
        "url_passwords_historic": get("URL_PASSWORD_HISTORIC"),
        "url_uploads": get("URL_UPLOAD"),
        "subdomains": get("INTERNET_NAME"),
        "ip_addresses": [{"source": r[0], "data": r[1]} for r in get("IP_ADDRESS", ["Source","Data"])],
        "technologies": get("WEBSERVER_TECHNOLOGY"),
        "banners": list(set(get("WEBSERVER_BANNER")))[:10],
        "usernames": get("USERNAME")[:40],
        "human_names": get("HUMAN_NAME")[:40],
        "social_media": get("SOCIAL_MEDIA")[:20],
        "code_repos": get("PUBLIC_CODE_REPO")[:15],
        "similar_domains": get("SIMILARDOMAIN"),
        "pgp_keys": get_multi(["PGP_KEY"]),
        "accounts_external": get("ACCOUNT_EXTERNAL_OWNED")[:30],
        "url_forms": get("URL_FORM"),
        "physical_addresses": get("PHYSICAL_ADDRESS"),
        "emails": [e for e in get("AFFILIATE_EMAILADDR") if not any(
            x in e.lower() for x in ['abuse','privacy','protect','gdpr','masking','withheld','registrar']
        )][:25],
    }

    scan_name = df['Scan Name'].iloc[0] if len(df) > 0 else "Unknown"
    scan_date = df['Updated'].max() if 'Updated' in df.columns else "Unknown"

    return {
        "scan_name": scan_name,
        "scan_date": str(scan_date),
        "total_findings": len(df),
        "severity": sev,
        "type_counts": type_counts,
        "f3ead_counts": f3ead_counts,
        "jtc_counts": jtc_counts,
        "tactic_counts": tactic_counts,
        "findings": findings,
        "exposures": exposures,
        "f3ead_map": F3EAD_MAP,
        "jtc_map": JTC_MAP,
        "exempt_ports": sorted(EXEMPT_PORTS),
    }

# ═════════════════════════════════════════════════════════════════════════════
# HTML TEMPLATE — Premium UI v2
# ═════════════════════════════════════════════════════════════════════════════
HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Spiderfoot Analyzer — {scan_name}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
/* ── Reset & Tokens ─────────────────────────────────────────────────────── */
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:        #141924;
  --surface:   #1C2537;
  --surface2:  #212D42;
  --surface3:  #283550;
  --border:    rgba(255,255,255,0.07);
  --border2:   rgba(255,255,255,0.12);

  --text:      #E2E8F0;
  --text2:     #8B9DB5;
  --text3:     #556070;
  --mono:      'JetBrains Mono', 'Consolas', monospace;

  --accent:    #4F8EF7;
  --accent-glow: rgba(79,142,247,0.15);

  --c-critical: #DC2626;
  --c-high:     #EA580C;
  --c-medium:   #D97706;
  --c-low:      #059669;
  --c-info:     #4F8EF7;

  --radius:    10px;
  --radius-sm: 6px;
}}
html{{scroll-behavior:smooth}}
body{{
  background:var(--bg);
  color:var(--text);
  font-family:'Inter',system-ui,sans-serif;
  font-size:13.5px;
  line-height:1.6;
  -webkit-font-smoothing:antialiased;
}}

/* ── Scrollbar ──────────────────────────────────────────────────────────── */
::-webkit-scrollbar{{width:5px;height:5px}}
::-webkit-scrollbar-track{{background:var(--surface)}}
::-webkit-scrollbar-thumb{{background:var(--surface3);border-radius:99px}}

/* ── Layout ─────────────────────────────────────────────────────────────── */
.app{{display:flex;min-height:100vh}}

/* ── Sidebar ─────────────────────────────────────────────────────────────── */
.sidebar{{
  width:220px;flex-shrink:0;
  background:var(--surface);
  border-right:1px solid var(--border);
  display:flex;flex-direction:column;
  position:fixed;top:0;left:0;height:100vh;
  z-index:200;overflow-y:auto;
}}
.sidebar-brand{{
  padding:22px 20px 18px;
  border-bottom:1px solid var(--border);
}}
.brand-label{{
  font-size:10px;font-weight:600;letter-spacing:1.5px;
  text-transform:uppercase;color:var(--text3);margin-bottom:4px;
}}
.brand-name{{
  font-size:14px;font-weight:700;color:var(--text);
  display:flex;align-items:center;gap:8px;
}}
.brand-dot{{
  width:8px;height:8px;border-radius:50%;
  background:var(--accent);
  box-shadow:0 0 8px var(--accent);
  flex-shrink:0;
}}
.sidebar-meta{{
  padding:14px 20px;border-bottom:1px solid var(--border);
  font-size:11px;color:var(--text3);line-height:1.8;
}}
.sidebar-meta strong{{color:var(--text2);font-weight:500}}
.sidebar-nav{{padding:12px 0;flex:1}}
.nav-section-label{{
  font-size:9.5px;font-weight:700;letter-spacing:1.5px;
  text-transform:uppercase;color:var(--text3);
  padding:12px 20px 6px;
}}
.nav-item{{
  display:flex;align-items:center;gap:10px;
  padding:9px 20px;cursor:pointer;
  font-size:12.5px;font-weight:500;color:var(--text2);
  border-left:2px solid transparent;
  transition:all .15s;
  background:none;border-top:none;border-right:none;border-bottom:none;
  width:100%;text-align:left;
}}
.nav-item:hover{{color:var(--text);background:rgba(255,255,255,0.03)}}
.nav-item.active{{
  color:var(--accent);
  border-left-color:var(--accent);
  background:var(--accent-glow);
}}
.nav-icon{{width:16px;text-align:center;opacity:.7;font-size:13px}}
.nav-item.active .nav-icon{{opacity:1}}

/* ── Main content ────────────────────────────────────────────────────────── */
.main{{margin-left:220px;flex:1;min-height:100vh}}
.tab-panel{{display:none;padding:32px 36px;max-width:1320px}}
.tab-panel.active{{display:block}}

/* ── Page header ─────────────────────────────────────────────────────────── */
.page-hdr{{margin-bottom:28px;padding-bottom:20px;border-bottom:1px solid var(--border)}}
.page-hdr h1{{
  font-size:20px;font-weight:700;color:var(--text);
  letter-spacing:-.3px;margin-bottom:4px;
}}
.page-hdr p{{font-size:12px;color:var(--text3)}}
.page-hdr .badge-row{{display:flex;gap:8px;margin-top:10px;flex-wrap:wrap}}

/* ── Metric cards ────────────────────────────────────────────────────────── */
.metric-grid{{
  display:grid;
  grid-template-columns:repeat(5,1fr);
  gap:12px;margin-bottom:24px;
}}
.metric-card{{
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:var(--radius);
  padding:18px 20px;
  position:relative;overflow:hidden;
}}
.metric-card::before{{
  content:'';position:absolute;top:0;left:0;right:0;height:2px;
}}
.metric-card.total::before{{background:var(--accent)}}
.metric-card.critical::before{{background:var(--c-critical)}}
.metric-card.high::before{{background:var(--c-high)}}
.metric-card.medium::before{{background:var(--c-medium)}}
.metric-card.low::before{{background:var(--c-low)}}
.metric-icon{{font-size:18px;margin-bottom:10px;opacity:.6}}
.metric-value{{
  font-size:30px;font-weight:700;line-height:1;margin-bottom:5px;
}}
.metric-card.total .metric-value{{color:var(--accent)}}
.metric-card.critical .metric-value{{color:var(--c-critical)}}
.metric-card.high .metric-value{{color:var(--c-high)}}
.metric-card.medium .metric-value{{color:var(--c-medium)}}
.metric-card.low .metric-value{{color:var(--c-low)}}
.metric-label{{font-size:10.5px;font-weight:600;letter-spacing:.8px;text-transform:uppercase;color:var(--text3)}}

/* ── Chart cards ─────────────────────────────────────────────────────────── */
.chart-grid{{display:grid;gap:16px;grid-template-columns:1fr 1fr;margin-bottom:24px}}
.chart-card{{
  background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius);padding:20px 22px;
}}
.chart-card.wide{{grid-column:span 2}}
.chart-hdr{{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px}}
.chart-title{{
  font-size:11px;font-weight:600;letter-spacing:.9px;
  text-transform:uppercase;color:var(--text2);
}}
.chart-wrap{{position:relative}}

/* ── Section headers ─────────────────────────────────────────────────────── */
.sec-hdr{{
  display:flex;align-items:center;gap:10px;
  margin:28px 0 14px;
}}
.sec-hdr h2{{
  font-size:13px;font-weight:600;color:var(--text);letter-spacing:-.1px;
}}
.count-pill{{
  font-size:10px;font-weight:600;padding:2px 8px;
  border-radius:99px;background:var(--surface3);color:var(--text3);
  border:1px solid var(--border);
}}

/* ── Exposure group header ────────────────────────────────────────────────── */
.group-header{{
  display:flex;align-items:center;justify-content:space-between;gap:12px;
  margin:38px 0 6px;padding:14px 18px;
  background:var(--surface);
  border:1px solid var(--border2);
  border-left:3px solid var(--accent);
  border-radius:var(--radius);
}}
.group-header:first-child{{margin-top:8px}}
.group-title{{
  display:flex;align-items:center;gap:10px;
  font-size:16px;font-weight:700;color:var(--text);letter-spacing:-.2px;
}}
.group-icon{{font-size:17px;opacity:.85}}
.group-meta{{display:flex;align-items:center;gap:10px;flex-wrap:wrap;justify-content:flex-end}}
.group-desc{{font-size:11.5px;color:var(--text3);max-width:380px;text-align:right}}
@media(max-width:860px){{
  .group-header{{flex-direction:column;align-items:flex-start}}
  .group-meta{{justify-content:flex-start}}
  .group-desc{{text-align:left;max-width:none}}
}}

/* ── Alert banner ────────────────────────────────────────────────────────── */
.alert-banner{{
  border-radius:var(--radius-sm);
  padding:12px 16px;margin-bottom:16px;
  font-size:12px;border-left:3px solid;
  display:flex;align-items:flex-start;gap:10px;
}}
.alert-banner .alert-icon{{font-size:14px;flex-shrink:0;margin-top:1px}}
.alert-banner .alert-body strong{{display:block;font-size:12px;margin-bottom:2px}}
.alert-banner .alert-body span{{color:var(--text2)}}
.alert-critical{{background:rgba(220,38,38,.07);border-color:var(--c-critical)}}
.alert-critical .alert-body strong{{color:var(--c-critical)}}
.alert-high{{background:rgba(234,88,12,.07);border-color:var(--c-high)}}
.alert-high .alert-body strong{{color:var(--c-high)}}

/* ── Data table ──────────────────────────────────────────────────────────── */
.data-table-wrap{{
  border:1px solid var(--border);border-radius:var(--radius);
  overflow:hidden;margin-bottom:20px;
}}
table{{width:100%;border-collapse:collapse}}
thead tr{{background:var(--surface2)}}
th{{
  padding:10px 16px;text-align:left;
  font-size:10px;font-weight:700;letter-spacing:.9px;
  text-transform:uppercase;color:var(--text3);
  border-bottom:1px solid var(--border);
  white-space:nowrap;
}}
td{{
  padding:10px 16px;
  border-bottom:1px solid var(--border);
  font-size:12.5px;color:var(--text);
}}
tbody tr:last-child td{{border-bottom:none}}
tbody tr:nth-child(even){{background:rgba(255,255,255,.018)}}
tbody tr:hover td{{background:rgba(79,142,247,.06);transition:background .1s}}

/* url cells */
.url-val{{
  font-family:var(--mono);font-size:11.5px;color:#7EB3FF;
  max-width:480px;display:block;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
}}
.url-val:hover{{white-space:normal;word-break:break-all}}
.mono-val{{font-family:var(--mono);font-size:11.5px}}

/* repo URL cell: keep on one line, ellipsis, never wrap (so copy stays put) */
.repo-url-cell{{max-width:380px}}
.repo-url{{
  display:inline-block;max-width:360px;vertical-align:middle;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
  text-decoration:none;
}}
.repo-url:hover{{white-space:nowrap;text-decoration:underline}}
/* fixed copy cell: narrow, button always visible, right aligned */
.copy-cell{{width:36px;text-align:center;white-space:nowrap}}
.copy-cell .copy-btn{{opacity:.55}}
tr:hover .copy-cell .copy-btn{{opacity:1}}

/* null/undefined display */
.null-val{{color:var(--text3);font-style:italic;font-size:11px}}

/* copy button */
.copy-btn{{
  background:none;border:none;cursor:pointer;
  color:var(--text3);font-size:11px;padding:2px 5px;
  border-radius:3px;opacity:0;transition:opacity .15s;
  vertical-align:middle;
}}
tr:hover .copy-btn{{opacity:1}}
.copy-btn:hover{{color:var(--accent);background:var(--accent-glow)}}

/* ── Severity badges ─────────────────────────────────────────────────────── */
.sev{{
  display:inline-flex;align-items:center;gap:4px;
  font-size:10px;font-weight:700;padding:3px 8px;
  border-radius:99px;text-transform:uppercase;letter-spacing:.4px;
  white-space:nowrap;
}}
.sev::before{{content:'';width:5px;height:5px;border-radius:50%;flex-shrink:0}}
.sev-CRITICAL{{background:rgba(220,38,38,.12);color:var(--c-critical);border:1px solid rgba(220,38,38,.25)}}
.sev-CRITICAL::before{{background:var(--c-critical);box-shadow:0 0 4px var(--c-critical)}}
.sev-HIGH{{background:rgba(234,88,12,.12);color:var(--c-high);border:1px solid rgba(234,88,12,.25)}}
.sev-HIGH::before{{background:var(--c-high)}}
.sev-MEDIUM{{background:rgba(217,119,6,.12);color:var(--c-medium);border:1px solid rgba(217,119,6,.25)}}
.sev-MEDIUM::before{{background:var(--c-medium)}}
.sev-LOW{{background:rgba(5,150,105,.12);color:var(--c-low);border:1px solid rgba(5,150,105,.25)}}
.sev-LOW::before{{background:var(--c-low)}}
.sev-INFO{{background:rgba(79,142,247,.12);color:var(--c-info);border:1px solid rgba(79,142,247,.25)}}
.sev-INFO::before{{background:var(--c-info)}}

/* ── MITRE badge ─────────────────────────────────────────────────────────── */
.mitre-tag{{
  display:inline-block;font-family:var(--mono);
  font-size:10.5px;font-weight:500;
  padding:3px 8px;border-radius:var(--radius-sm);
  background:rgba(79,142,247,.1);color:#7EB3FF;
  border:1px solid rgba(79,142,247,.25);text-decoration:none;
  transition:background .15s;
}}
.mitre-tag:hover{{background:rgba(79,142,247,.2)}}

/* tactic */
.tactic-tag{{
  display:inline-block;font-size:10px;font-weight:500;
  padding:3px 9px;border-radius:99px;
  background:rgba(139,157,181,.08);color:var(--text2);
  border:1px solid var(--border2);
}}

/* ── Category chips ──────────────────────────────────────────────────────── */
.chip{{
  display:inline-block;font-size:10px;font-weight:600;
  padding:2px 8px;border-radius:99px;
  background:var(--surface3);color:var(--text3);border:1px solid var(--border);
}}

/* ── Provider badges ─────────────────────────────────────────────────────── */
.prov-aws{{background:rgba(255,153,0,.1);color:#FFAD33;border:1px solid rgba(255,153,0,.25)}}
.prov-gcp{{background:rgba(66,133,244,.1);color:#7EB3FF;border:1px solid rgba(66,133,244,.25)}}
.prov-cloud{{background:var(--surface3);color:var(--text2);border:1px solid var(--border)}}

/* ── Search bar ──────────────────────────────────────────────────────────── */
.search-bar{{
  display:flex;align-items:center;gap:8px;
  background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius-sm);padding:0 14px;
  width:340px;margin-bottom:16px;
}}
.search-bar svg{{color:var(--text3);flex-shrink:0}}
.search-bar input{{
  background:none;border:none;outline:none;
  color:var(--text);font-size:12.5px;padding:9px 0;width:100%;
  font-family:'Inter',sans-serif;
}}
.search-bar input::placeholder{{color:var(--text3)}}

/* ── Phase cards (F3EAD) ─────────────────────────────────────────────────── */
.phase-grid{{display:grid;gap:14px;grid-template-columns:repeat(3,1fr);margin-bottom:24px}}
.phase-card{{
  background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius);padding:18px;
  position:relative;overflow:hidden;
}}
.phase-card::after{{
  content:'';position:absolute;inset:0;
  opacity:.04;border-radius:inherit;pointer-events:none;
}}
.phase-hdr{{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:6px}}
.phase-name{{
  font-size:11px;font-weight:700;letter-spacing:1px;text-transform:uppercase;
}}
.phase-count{{
  font-size:22px;font-weight:700;line-height:1;margin-bottom:8px;
}}
.phase-desc{{font-size:11px;color:var(--text3);line-height:1.5;margin-bottom:12px}}
.phase-items{{list-style:none}}
.phase-item{{
  display:flex;justify-content:space-between;align-items:center;
  padding:5px 0;border-bottom:1px solid var(--border);font-size:11.5px;
}}
.phase-item:last-child{{border-bottom:none}}
.phase-item-name{{color:var(--text2);font-family:var(--mono);font-size:10.5px}}
.phase-item-cnt{{font-weight:600;font-size:11px}}

/* ── JTC pipeline ────────────────────────────────────────────────────────── */
.jtc-pipeline{{
  display:flex;gap:0;margin-bottom:24px;
  border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;
}}
.jtc-stage{{
  flex:1;padding:14px 16px;text-align:center;
  border-right:1px solid var(--border);
  position:relative;
}}
.jtc-stage:last-child{{border-right:none}}
.jtc-stage-name{{font-size:9.5px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;color:var(--text3);margin-bottom:4px}}
.jtc-stage-count{{font-size:22px;font-weight:700}}

/* ── PGP viewer ──────────────────────────────────────────────────────────── */
.pgp-block{{
  background:#0D1117;border:1px solid var(--border);
  border-radius:var(--radius);overflow:hidden;margin-bottom:16px;
}}
.pgp-hdr{{
  background:var(--surface2);border-bottom:1px solid var(--border);
  padding:10px 16px;display:flex;align-items:center;gap:8px;
}}
.pgp-hdr .pgp-dot{{width:8px;height:8px;border-radius:50%;background:var(--c-low)}}
.pgp-hdr .pgp-label{{font-size:11px;font-weight:600;color:var(--text2);font-family:var(--mono)}}
.pgp-body{{
  padding:14px 16px;font-family:var(--mono);font-size:10.5px;
  color:#8FB3D3;line-height:1.7;overflow-x:auto;
  max-height:180px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;
}}

/* ── Overview alerts list ────────────────────────────────────────────────── */
.alert-row{{
  display:flex;align-items:center;gap:12px;
  background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius-sm);padding:12px 16px;
  margin-bottom:8px;
}}
.alert-row .ar-sev{{flex-shrink:0}}
.alert-row .ar-type{{
  font-family:var(--mono);font-size:11.5px;color:var(--text);flex:1;
  min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
}}
.alert-row .ar-meta{{display:flex;align-items:center;gap:8px;flex-shrink:0}}
.alert-row .ar-count{{
  font-size:11px;font-weight:700;color:var(--text2);
  background:var(--surface3);padding:2px 8px;border-radius:99px;
}}

/* ── Multi-col grid (identity) ───────────────────────────────────────────── */
.two-col{{display:grid;gap:16px;grid-template-columns:1fr 1fr}}
.name-grid{{
  display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));
  gap:8px;margin-bottom:20px;
}}
.name-chip{{
  background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius-sm);padding:8px 12px;
  font-size:12px;color:var(--text2);
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
}}
.name-chip.mono-chip{{font-family:var(--mono);font-size:11px}}

/* ── Subdomain / infra chips ─────────────────────────────────────────────── */
.host-grid{{
  display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));
  gap:8px;margin-bottom:20px;
}}
.host-chip{{
  background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius-sm);padding:9px 12px;
  font-family:var(--mono);font-size:11px;color:#7EB3FF;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
}}

/* ── Status bar (bottom) ─────────────────────────────────────────────────── */
.status-bar{{
  position:fixed;bottom:0;left:220px;right:0;
  background:var(--surface);border-top:1px solid var(--border);
  padding:6px 24px;font-size:10.5px;color:var(--text3);
  display:flex;align-items:center;gap:16px;z-index:100;
}}
.status-bar .sb-dot{{width:6px;height:6px;border-radius:50%;background:var(--c-low);box-shadow:0 0 5px var(--c-low)}}

/* ── Responsive ──────────────────────────────────────────────────────────── */
@media(max-width:1100px){{
  .metric-grid{{grid-template-columns:repeat(3,1fr)}}
  .phase-grid{{grid-template-columns:repeat(2,1fr)}}
}}
@media(max-width:860px){{
  .sidebar{{width:100%;height:auto;position:relative;flex-direction:row;flex-wrap:wrap}}
  .main{{margin-left:0}}
  .tab-panel{{padding:20px 16px}}
  .chart-grid{{grid-template-columns:1fr}}
  .chart-card.wide{{grid-column:span 1}}
  .two-col{{grid-template-columns:1fr}}
  .metric-grid{{grid-template-columns:repeat(2,1fr)}}
  .phase-grid{{grid-template-columns:1fr}}
  .jtc-pipeline{{flex-direction:column}}
  .status-bar{{left:0}}
}}
</style>
</head>
<body>
<div class="app">

<!-- ═══════════════════════════════════════════════════
     SIDEBAR
═══════════════════════════════════════════════════════ -->
<aside class="sidebar">
  <div class="sidebar-brand">
    <div class="brand-label">Spiderfoot Analyzer</div>
    <div class="brand-name"><span class="brand-dot"></span><span id="sb-target"></span></div>
  </div>
  <div class="sidebar-meta">
    <div>Scan Date: <strong id="sb-date"></strong></div>
    <div>Records: <strong id="sb-records"></strong></div>
  </div>
  <nav class="sidebar-nav">
    <div class="nav-section-label">Dashboards</div>
    <button class="nav-item active" onclick="showTab('overview',this)">
      <span class="nav-icon">◈</span> Overview
    </button>
    <button class="nav-item" onclick="showTab('exposures',this)">
      <span class="nav-icon">⚠</span> Exposures
    </button>
    <div class="nav-section-label">Frameworks</div>
    <button class="nav-item" onclick="showTab('f3ead',this)">
      <span class="nav-icon">◉</span> F3EAD
    </button>
    <button class="nav-item" onclick="showTab('jtc',this)">
      <span class="nav-icon">◈</span> JTC
    </button>
    <button class="nav-item" onclick="showTab('mitre',this)">
      <span class="nav-icon">⬡</span> MITRE ATT&CK
    </button>
    <div class="nav-section-label">Intelligence</div>
    <button class="nav-item" onclick="showTab('identity',this)">
      <span class="nav-icon">◎</span> Identity & Personnel
    </button>
    <button class="nav-item" onclick="showTab('infra',this)">
      <span class="nav-icon">⬡</span> Infrastructure
    </button>
  </nav>
</aside>

<!-- ═══════════════════════════════════════════════════
     DATA
═══════════════════════════════════════════════════════ -->
<script>const DATA={data_json};</script>

<!-- ═══════════════════════════════════════════════════
     MAIN CONTENT
═══════════════════════════════════════════════════════ -->
<main class="main">

<!-- TAB: OVERVIEW -->
<div id="tab-overview" class="tab-panel active">
  <div class="page-hdr">
    <h1>Exposure Overview</h1>
    <p>Aggregated findings from SpiderFoot passive OSINT scan. Review critical items first.</p>
  </div>
  <div class="metric-grid" id="metric-grid"></div>
  <div class="chart-grid">
    <div class="chart-card">
      <div class="chart-hdr"><span class="chart-title">Severity Distribution</span></div>
      <div class="chart-wrap" style="height:230px"><canvas id="chartSev"></canvas></div>
    </div>
    <div class="chart-card">
      <div class="chart-hdr"><span class="chart-title">Top Finding Types</span></div>
      <div class="chart-wrap" style="height:230px"><canvas id="chartTypes"></canvas></div>
    </div>
  </div>
  <div class="sec-hdr"><h2>Critical &amp; High Priority Findings</h2></div>
  <div id="critical-alerts"></div>
</div>

<!-- TAB: EXPOSURES -->
<div id="tab-exposures" class="tab-panel">
  <div class="page-hdr">
    <h1>External Exposures</h1>
    <p>High-value attack surface items requiring immediate review and remediation.</p>
  </div>
  <div id="exposures-content"></div>
</div>

<!-- TAB: F3EAD -->
<div id="tab-f3ead" class="tab-panel">
  <div class="page-hdr">
    <h1>F3EAD Cycle Analysis</h1>
    <p>Find · Fix · Finish · Exploit · Analyze · Disseminate — findings mapped to targeting cycle phases.</p>
  </div>
  <div class="chart-grid">
    <div class="chart-card">
      <div class="chart-hdr"><span class="chart-title">Findings by Phase (Polar)</span></div>
      <div class="chart-wrap" style="height:240px"><canvas id="chartF3EAD"></canvas></div>
    </div>
    <div class="chart-card">
      <div class="chart-hdr"><span class="chart-title">Phase Coverage (Radar)</span></div>
      <div class="chart-wrap" style="height:240px"><canvas id="chartF3EADLine"></canvas></div>
    </div>
  </div>
  <div class="phase-grid" id="f3ead-phases"></div>
</div>

<!-- TAB: JTC -->
<div id="tab-jtc" class="tab-panel">
  <div class="page-hdr">
    <h1>Joint Targeting Cycle (JTC)</h1>
    <p>Target Development → Target Analysis → Decision → Execution → Assessment</p>
  </div>
  <div class="chart-grid">
    <div class="chart-card wide">
      <div class="chart-hdr"><span class="chart-title">Findings per JTC Phase</span></div>
      <div class="chart-wrap" style="height:240px"><canvas id="chartJTC"></canvas></div>
    </div>
  </div>
  <div class="jtc-pipeline" id="jtc-pipeline"></div>
  <div id="jtc-phases"></div>
</div>

<!-- TAB: MITRE -->
<div id="tab-mitre" class="tab-panel">
  <div class="page-hdr">
    <h1>MITRE ATT&amp;CK Mapping</h1>
    <p>SpiderFoot finding types mapped to ATT&amp;CK techniques and tactics.</p>
  </div>
  <div class="chart-grid">
    <div class="chart-card wide">
      <div class="chart-hdr"><span class="chart-title">Findings by ATT&amp;CK Tactic</span></div>
      <div class="chart-wrap" style="height:260px"><canvas id="chartTactics"></canvas></div>
    </div>
  </div>
  <div class="search-bar">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
    <input type="text" id="mitre-search" placeholder="Filter technique, tactic, or finding type…" oninput="filterMitreTable()">
  </div>
  <div class="data-table-wrap">
    <table id="mitre-table">
      <thead><tr>
        <th>Severity</th><th>Finding Type</th><th>Count</th>
        <th>ATT&amp;CK ID</th><th>Technique</th><th>Tactic</th>
      </tr></thead>
      <tbody id="mitre-tbody"></tbody>
    </table>
  </div>
</div>

<!-- TAB: IDENTITY -->
<div id="tab-identity" class="tab-panel">
  <div class="page-hdr">
    <h1>Identity &amp; Personnel Exposure</h1>
    <p>Usernames, names, accounts, and social presence enumerated during scan.</p>
  </div>
  <div id="identity-content"></div>
</div>

<!-- TAB: INFRA -->
<div id="tab-infra" class="tab-panel">
  <div class="page-hdr">
    <h1>Infrastructure Intelligence</h1>
    <p>Hosts, IPs, subdomains, technologies, and network artifacts discovered.</p>
  </div>
  <div id="infra-content"></div>
</div>

</main><!-- /main -->

<!-- STATUS BAR -->
<div class="status-bar">
  <span class="sb-dot"></span>
  <span>SpiderFoot OSINT Report</span>
  <span style="color:var(--border2)">|</span>
  <span id="sb-status">Loaded</span>
</div>

</div><!-- /app -->

<!-- ═══════════════════════════════════════════════════
     JAVASCRIPT
═══════════════════════════════════════════════════════ -->
<script>
/* ── Helpers ─────────────────────────────────────────────────────────────── */
function esc(s){{return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}}
function safeVal(v){{return(v===null||v===undefined||v==='undefined'||String(v).trim()==='')
  ?'<span class="null-val">—</span>':esc(v)}}
function sev(s){{return`<span class="sev sev-${{s}}">${{s}}</span>`}}
function mitreBadge(id){{
  const url='https://attack.mitre.org/techniques/'+id.replace('.','/');
  return`<a class="mitre-tag" href="${{url}}" target="_blank" rel="noopener">${{id}}</a>`;
}}
function copyBtn(text){{
  return`<button class="copy-btn" title="Copy" onclick="copyText(event,'${{esc(text)}}')">⎘</button>`;
}}
function copyText(e,t){{
  navigator.clipboard?.writeText(t);
  e.target.textContent='✓';setTimeout(()=>e.target.textContent='⎘',1200);
}}
function showTab(name,btn){{
  document.querySelectorAll('.tab-panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(b=>b.classList.remove('active'));
  document.getElementById('tab-'+name).classList.add('active');
  if(btn)btn.classList.add('active');
}}
function tbl(headers,rows){{
  const ths=headers.map(h=>`<th>${{h}}</th>`).join('');
  return`<div class="data-table-wrap"><table><thead><tr>${{ths}}</tr></thead><tbody>${{rows}}</tbody></table></div>`;
}}

/* ── Sidebar meta ────────────────────────────────────────────────────────── */
document.getElementById('sb-target').textContent=DATA.scan_name;
document.getElementById('sb-date').textContent=DATA.scan_date.slice(0,10);
document.getElementById('sb-records').textContent=DATA.total_findings.toLocaleString();
document.getElementById('sb-status').textContent=
  `${{DATA.total_findings.toLocaleString()}} records · ${{DATA.severity.CRITICAL||0}} critical`;

/* ── Overview: metric cards ──────────────────────────────────────────────── */
const sevDefs=[
  {{cls:'total', icon:'⬡', label:'Total Records', val:DATA.total_findings}},
  {{cls:'critical',icon:'◉', label:'Critical',     val:DATA.severity.CRITICAL||0}},
  {{cls:'high',   icon:'▲', label:'High',          val:DATA.severity.HIGH||0}},
  {{cls:'medium', icon:'◆', label:'Medium',        val:DATA.severity.MEDIUM||0}},
  {{cls:'low',    icon:'◎', label:'Low',           val:DATA.severity.LOW||0}},
];
const mg=document.getElementById('metric-grid');
sevDefs.forEach(d=>{{
  mg.innerHTML+=`<div class="metric-card ${{d.cls}}">
    <div class="metric-icon">${{d.icon}}</div>
    <div class="metric-value">${{d.val.toLocaleString()}}</div>
    <div class="metric-label">${{d.label}}</div>
  </div>`;
}});

/* ── Overview: critical alert rows ──────────────────────────────────────── */
const critEl=document.getElementById('critical-alerts');
DATA.findings.filter(f=>f.severity==='CRITICAL'||f.severity==='HIGH').forEach(f=>{{
  critEl.innerHTML+=`<div class="alert-row">
    <div class="ar-sev">${{sev(f.severity)}}</div>
    <div class="ar-type">${{esc(f.type)}}</div>
    <div class="ar-meta">
      ${{mitreBadge(f.mitre_id)}}
      <span class="tactic-tag">${{esc(f.tactic)}}</span>
      <span class="ar-count">${{f.count}}</span>
    </div>
  </div>`;
}});

/* Chart defaults */
Chart.defaults.color='#8B9DB5';
Chart.defaults.font.family='Inter,system-ui,sans-serif';
Chart.defaults.font.size=11;

const GRID_COLOR='rgba(255,255,255,0.09)';
const SEV_COLORS=['#DC2626','#EA580C','#D97706','#059669'];

/* ── Chart: Severity Donut ───────────────────────────────────────────────── */
const sevLabels=['CRITICAL','HIGH','MEDIUM','LOW'];
const sevData=sevLabels.map(s=>DATA.severity[s]||0);
const totalSev=sevData.reduce((a,b)=>a+b,0);
new Chart(document.getElementById('chartSev'),{{
  type:'doughnut',
  data:{{labels:sevLabels,datasets:[{{
    data:sevData,
    backgroundColor:SEV_COLORS,
    borderColor:SEV_COLORS,borderWidth:2,hoverOffset:4
  }}]}},
  options:{{
    cutout:'72%',responsive:true,maintainAspectRatio:false,
    plugins:{{
      legend:{{position:'right',labels:{{boxWidth:10,padding:14,color:'#8B9DB5'}}}},
      tooltip:{{callbacks:{{label:ctx=>`${{ctx.label}}: ${{ctx.parsed}}`}}}},
    }},
    animation:{{animateRotate:true,duration:600}}
  }},
  plugins:[{{
    id:'center-text',
    afterDraw(chart){{
      const{{ctx,chartArea:{{width,height,left,top}}}}=chart;
      ctx.save();
      const cx=left+width/2,cy=top+height/2;
      ctx.textAlign='center';ctx.textBaseline='middle';
      ctx.fillStyle='#E2E8F0';ctx.font='bold 22px Inter';
      ctx.fillText(totalSev,cx,cy-8);
      ctx.fillStyle='#8B9DB5';ctx.font='10px Inter';
      ctx.fillText('findings',cx,cy+10);
      ctx.restore();
    }}
  }}]
}});

/* ── Chart: Top Types Horizontal Bar ─────────────────────────────────────── */
const topTypes=Object.entries(DATA.type_counts).sort((a,b)=>b[1]-a[1]).slice(0,12);
new Chart(document.getElementById('chartTypes'),{{
  type:'bar',
  data:{{
    labels:topTypes.map(t=>t[0].replace(/_/g,' ')),
    datasets:[{{
      data:topTypes.map(t=>t[1]),
      backgroundColor:'#4F8EF7',
      borderColor:'#3A7AE0',
      borderWidth:1,borderRadius:4,borderSkipped:false
    }}]
  }},
  options:{{
    indexAxis:'y',responsive:true,maintainAspectRatio:false,
    plugins:{{legend:{{display:false}},tooltip:{{callbacks:{{label:ctx=>`${{ctx.parsed.x}} records`}}}}}},
    scales:{{
      x:{{ticks:{{color:'#556070'}},grid:{{color:GRID_COLOR}}}},
      y:{{ticks:{{color:'#8B9DB5',font:{{size:10}}}},grid:{{display:false}}}}
    }},
    animation:{{duration:500}}
  }}
}});

/* ── Render Exposures ────────────────────────────────────────────────────── */
function renderExposures(){{
  const el=document.getElementById('exposures-content');
  const E=DATA.exposures;

  // Severity rank for sorting (lower = more severe = shown first)
  const SEV_RANK={{CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4}};

  // Each finding block is built as {{sev, banner, body}} then slotted into a group.
  // Within a group, blocks are sorted Critical -> Info.
  const groups={{
    'Domain and Infrastructure':[],
    'Personnel Exposure':[],
    'Technology Stack':[],
    'Third Party Surface':[],
    'Cloud and SaaS Footprint':[],
  }};
  const add=(group,sevLevel,blockHtml)=>groups[group].push({{sev:sevLevel,html:blockHtml}});

  /* ── Cloud buckets → Cloud and SaaS Footprint ─────────────────────────── */
  if(E.cloud_buckets.length){{
    const critBuckets=E.cloud_buckets.filter(b=>b.severity==='CRITICAL');
    const highBuckets=E.cloud_buckets.filter(b=>b.severity!=='CRITICAL');
    const blockSev=critBuckets.length?'CRITICAL':'HIGH';
    let b='';
    b+=`<div class="sec-hdr"><h2>Cloud Storage Buckets</h2><span class="count-pill">${{E.cloud_buckets.length}}</span></div>`;
    if(critBuckets.length){{
      b+=`<div class="alert-banner alert-critical">
        <div class="alert-icon">⚠</div>
        <div class="alert-body"><strong>CRITICAL — Sensitive Data in Open Buckets (${{critBuckets.length}})</strong>
        <span>One or more publicly accessible buckets expose sensitive or confidential content. Immediate closure and review required.</span></div>
      </div>`;
    }}
    if(highBuckets.length){{
      b+=`<div class="alert-banner alert-high">
        <div class="alert-icon">⬡</div>
        <div class="alert-body"><strong>HIGH — Open Cloud Storage Buckets (${{highBuckets.length}})</strong>
        <span>Publicly readable buckets with no confirmed sensitive content. Still a misconfiguration — restrict access and confirm contents.</span></div>
      </div>`;
    }}
    let rows='';
    E.cloud_buckets.forEach(bk=>{{
      const prov=bk.source.includes('amazonaws')?`<span class="chip prov-aws">AWS S3</span>`:
                 bk.source.includes('googleapis')?`<span class="chip prov-gcp">GCS</span>`:
                 `<span class="chip prov-cloud">Cloud</span>`;
      const reason=(bk.matched&&bk.matched.length)
        ? bk.matched.slice(0,6).map(m=>`<span class="chip" style="color:#FCA5A5;border-color:rgba(220,38,38,.35)">${{esc(m)}}</span>`).join(' ')
        : `<span class="null-val">no sensitive indicators</span>`;
      rows+=`<tr>
        <td>${{sev(bk.severity)}}</td>
        <td>${{prov}}</td>
        <td><span class="url-val">${{esc(bk.source)}}</span>${{copyBtn(bk.source)}}</td>
        <td>${{esc(bk.data)}}</td>
        <td>${{reason}}</td>
      </tr>`;
    }});
    b+=tbl(['Severity','Provider','Bucket Endpoint','Result','Sensitivity Match'],rows);
    add('Cloud and SaaS Footprint',blockSev,b);
  }}

  /* ── Upload endpoints → Technology Stack ──────────────────────────────── */
  if(E.url_uploads.length){{
    let b='';
    b+=`<div class="sec-hdr"><h2>File Upload Endpoints</h2><span class="count-pill">${{E.url_uploads.length}}</span></div>`;
    b+=`<div class="alert-banner alert-critical">
      <div class="alert-icon">⇑</div>
      <div class="alert-body"><strong>CRITICAL — Unrestricted File Upload</strong>
      <span>Exposed upload functionality is a primary vector for web shell upload and RCE.</span></div>
    </div>`;
    b+=tbl(['Upload URL'],E.url_uploads.map(u=>`<tr><td><span class="url-val">${{esc(u)}}</span>${{copyBtn(u)}}</td></tr>`).join(''));
    add('Technology Stack','CRITICAL',b);
  }}

  /* ── Interesting files → Personnel Exposure ───────────────────────────── */
  if(E.interesting_files.length){{
    let b='';
    b+=`<div class="sec-hdr"><h2>Publicly Accessible Sensitive Files</h2><span class="count-pill">${{E.interesting_files.length}}</span></div>`;
    b+=`<div class="alert-banner alert-high">
      <div class="alert-icon">⬡</div>
      <div class="alert-body"><strong>HIGH — Sensitive Documents Exposed</strong>
      <span>Files with sensitive naming (aws_secrets, passwords, firewall_rules, config) are directly reachable via HTTP.</span></div>
    </div>`;
    let rows='';
    E.interesting_files.forEach(f=>{{
      const cat=f.includes('/internal/')?`<span class="chip" style="color:#DC2626;border-color:rgba(220,38,38,.3)">Internal</span>`:
                f.includes('/employees/')?`<span class="chip" style="color:#EA580C;border-color:rgba(234,88,12,.3)">Employee</span>`:
                `<span class="chip">Company</span>`;
      rows+=`<tr><td>${{cat}}</td><td><span class="url-val">${{esc(f)}}</span>${{copyBtn(f)}}</td></tr>`;
    }});
    b+=tbl(['Category','URL'],rows);
    add('Personnel Exposure','HIGH',b);
  }}

  /* ── TCP Ports → Domain and Infrastructure ────────────────────────────── */
  if(E.tcp_ports.length){{
    const exempt=new Set((DATA.exempt_ports||[]).map(Number));
    // block severity = HIGH unless every port is exempt
    const anyNonExempt=E.tcp_ports.some(p=>!exempt.has(Number(String(p.data).split(':').pop())));
    let b='';
    b+=`<div class="sec-hdr"><h2>Open TCP Ports</h2><span class="count-pill">${{E.tcp_ports.length}}</span></div>`;
    let rows='';
    E.tcp_ports.forEach(p=>{{
      const parts=String(p.data).split(':');
      const port=parts[parts.length-1]||'';
      const isExempt=exempt.has(Number(port));
      const banner=E.tcp_banners.find(bn=>bn.source===p.data);
      const bannerVal=banner?`<span class="mono-val" style="color:#8B9DB5">${{esc(banner.data.trim())}}</span>`:`<span class="null-val">—</span>`;
      const portBadge=isExempt
        ? `<span class="sev sev-INFO" style="font-family:var(--mono)">${{esc(port)||'—'}}</span> <span class="chip" style="margin-left:4px">exempt</span>`
        : `<span class="sev sev-HIGH" style="font-family:var(--mono)">${{esc(port)||'—'}}</span>`;
      rows+=`<tr>
        <td><span class="mono-val">${{safeVal(p.source)}}</span></td>
        <td>${{portBadge}}</td>
        <td>${{bannerVal}}</td>
      </tr>`;
    }});
    b+=tbl(['Host','Port','Service Banner'],rows);
    add('Domain and Infrastructure',anyNonExempt?'HIGH':'INFO',b);
  }}

  /* ── SSL mismatches → Domain and Infrastructure ───────────────────────── */
  if(E.ssl_mismatches.length){{
    let b='';
    b+=`<div class="sec-hdr"><h2>SSL Certificate Mismatches</h2><span class="count-pill">${{E.ssl_mismatches.length}}</span></div>`;
    b+=tbl(['Host','Mismatch Detail'],E.ssl_mismatches.map(s=>`<tr>
      <td><span class="mono-val">${{safeVal(s.source)}}</span></td>
      <td><span class="mono-val" style="color:#D97706">${{safeVal(s.data)}}</span></td>
    </tr>`).join(''));
    add('Domain and Infrastructure','HIGH',b);
  }}

  /* ── Auth pages → Domain and Infrastructure ───────────────────────────── */
  if(E.url_passwords.length||E.url_passwords_historic.length){{
    const all=[...E.url_passwords,...E.url_passwords_historic];
    const blockSev=E.url_passwords.length?'HIGH':'MEDIUM';
    let b='';
    b+=`<div class="sec-hdr"><h2>Login / Auth Endpoints</h2><span class="count-pill">${{all.length}}</span></div>`;
    let rows='';
    E.url_passwords.forEach(u=>{{rows+=`<tr><td>${{sev('HIGH')}}<span style="margin-left:6px;font-size:10px;color:var(--text3)">LIVE</span></td><td><span class="url-val">${{esc(u)}}</span>${{copyBtn(u)}}</td></tr>`;}});
    E.url_passwords_historic.forEach(u=>{{rows+=`<tr><td>${{sev('MEDIUM')}}<span style="margin-left:6px;font-size:10px;color:var(--text3)">ARCHIVED</span></td><td><span class="url-val">${{esc(u)}}</span>${{copyBtn(u)}}</td></tr>`;}});
    b+=tbl(['Status','URL'],rows);
    add('Domain and Infrastructure',blockSev,b);
  }}

  /* ── Similar domains → Third Party Surface ────────────────────────────── */
  if(E.similar_domains.length){{
    let b='';
    b+=`<div class="sec-hdr"><h2>Lookalike / Similar Domains</h2><span class="count-pill">${{E.similar_domains.length}}</span></div>`;
    b+=tbl(['Domain','Severity','Risk'],E.similar_domains.map(d=>`<tr>
      <td><span class="mono-val">${{esc(d)}}</span></td>
      <td>${{sev('MEDIUM')}}</td>
      <td><span class="chip">Possible Typosquat</span></td>
    </tr>`).join(''));
    add('Third Party Surface','MEDIUM',b);
  }}

  /* ── Code repositories → Third Party Surface ──────────────────────────── */
  if(E.code_repos.length){{
    let b='';
    b+=`<div class="sec-hdr"><h2>Public Code Repositories</h2><span class="count-pill">${{E.code_repos.length}}</span></div>`;
    let rows=E.code_repos.map(r=>{{
      const raw=Array.isArray(r)?(r[1]||r[0]):r;
      const text=String(raw);
      const nameM=text.match(/Name:\s*(.*)/i);
      const urlM=text.match(/URL:\s*(\S+)/i);
      const descM=text.match(/Description:\s*([\s\S]*)/i);
      const name=nameM?nameM[1].trim():'';
      const url=urlM?urlM[1].trim():(text.startsWith('http')?text.trim():'');
      const desc=descM?descM[1].trim():'';
      const urlCell=url
        ? `<a class="url-val repo-url" href="${{esc(url)}}" target="_blank" rel="noopener">${{esc(url)}}</a>`
        : `<span class="url-val repo-url">${{esc(text)}}</span>`;
      return`<tr>
        <td>${{name?`<span class="mono-val">${{esc(name)}}</span>`:`<span class="null-val">—</span>`}}</td>
        <td class="repo-url-cell">${{urlCell}}</td>
        <td>${{desc?`<span style="color:var(--text2);font-size:12px">${{esc(desc)}}</span>`:`<span class="null-val">—</span>`}}</td>
        <td class="copy-cell">${{copyBtn(url||text)}}</td>
      </tr>`;
    }}).join('');
    b+=tbl(['Name','Repository URL','Description','&nbsp;'],rows);
    add('Third Party Surface','LOW',b);
  }}

  /* ── Technologies & banners → Technology Stack ────────────────────────── */
  if(E.technologies.length){{
    let b='';
    b+=`<div class="sec-hdr"><h2>Technologies Detected</h2><span class="count-pill">${{E.technologies.length}}</span></div>`;
    b+=tbl(['Technology / Framework'],E.technologies.map(t=>`<tr><td><span class="chip">${{esc(t)}}</span></td></tr>`).join(''));
    add('Technology Stack','LOW',b);
  }}
  if(E.banners.length){{
    let b='';
    b+=`<div class="sec-hdr"><h2>Server Banners</h2><span class="count-pill">${{[...new Set(E.banners)].length}}</span></div>`;
    b+=tbl(['Banner String'],[...new Set(E.banners)].map(bn=>`<tr><td><span class="mono-val" style="color:#8B9DB5">${{esc(bn)}}</span></td></tr>`).join(''));
    add('Technology Stack','LOW',b);
  }}

  /* ── Render groups in fixed order; sort blocks within each by severity ─── */
  const groupMeta={{
    'Domain and Infrastructure':{{icon:'🌐',desc:'Hosts, ports, certificates, and authentication surfaces.'}},
    'Personnel Exposure':{{icon:'◎',desc:'People-related documents and data reachable publicly.'}},
    'Technology Stack':{{icon:'⚙',desc:'Software, frameworks, server signals, and app surfaces.'}},
    'Third Party Surface':{{icon:'⬡',desc:'External code, lookalike domains, and supplier-linked assets.'}},
    'Cloud and SaaS Footprint':{{icon:'☁',desc:'Cloud storage and hosted service exposure.'}},
  }};

  let html='';
  Object.keys(groups).forEach(name=>{{
    const blocks=groups[name];
    if(!blocks.length) return;
    blocks.sort((a,b)=>SEV_RANK[a.sev]-SEV_RANK[b.sev]);
    const topSev=blocks[0].sev;
    const meta=groupMeta[name];
    html+=`<div class="group-header">
      <div class="group-title"><span class="group-icon">${{meta.icon}}</span>${{esc(name)}}</div>
      <div class="group-meta">
        <span class="group-desc">${{meta.desc}}</span>
        ${{sev(topSev)}}
        <span class="count-pill">${{blocks.length}} ${{blocks.length===1?'area':'areas'}}</span>
      </div>
    </div>`;
    blocks.forEach(blk=>{{html+=blk.html;}});
  }});

  if(!html) html=`<div class="alert-banner alert-high"><div class="alert-icon">i</div><div class="alert-body"><strong>No exposures recorded</strong><span>This scan returned no findings in the tracked exposure categories.</span></div></div>`;

  el.innerHTML=html;
}}
renderExposures();

/* ── Render F3EAD ────────────────────────────────────────────────────────── */
function renderF3EAD(){{
  const phases=['FIND','FIX','FINISH','EXPLOIT','ANALYZE','DISSEMINATE'];
  const colors=['#4F8EF7','#7C6AF7','#C061C2','#DC2626','#D97706','#059669'];
  const phaseDesc={{
    FIND:'Locate & identify the target — domains, IPs, subdomains, geography.',
    FIX:'Fingerprint services, versions, certificates, and infrastructure.',
    FINISH:'Identify actionable attack vectors — open ports, auth pages, uploads.',
    EXPLOIT:'Leverage exposed assets — open buckets, login forms, leaked files.',
    ANALYZE:'Build human intelligence — names, usernames, social accounts.',
    DISSEMINATE:'Context for decisions — org structure, addresses, relationships.',
  }};

  /* Polar chart */
  new Chart(document.getElementById('chartF3EAD'),{{
    type:'polarArea',
    data:{{
      labels:phases,
      datasets:[{{
        data:phases.map(p=>DATA.f3ead_counts[p]||0),
        backgroundColor:colors,
        borderColor:colors,borderWidth:1.5
      }}]
    }},
    options:{{
      responsive:true,maintainAspectRatio:false,
      plugins:{{legend:{{labels:{{boxWidth:10,padding:12}}}}}},
      scales:{{r:{{
        ticks:{{backdropColor:'transparent',color:'#556070',font:{{size:10}}}},
        grid:{{color:GRID_COLOR}},
        angleLines:{{color:GRID_COLOR}}
      }}}},
      animation:{{duration:600}}
    }}
  }});

  /* Radar chart */
  new Chart(document.getElementById('chartF3EADLine'),{{
    type:'radar',
    data:{{
      labels:phases,
      datasets:[{{
        label:'Findings',
        data:phases.map(p=>DATA.f3ead_counts[p]||0),
        backgroundColor:'#4F8EF7',
        borderColor:'#3A7AE0',pointBackgroundColor:'#4F8EF7',
        borderWidth:1.5,pointRadius:3,pointHoverRadius:5,
        tension:.2
      }}]
    }},
    options:{{
      responsive:true,maintainAspectRatio:false,
      plugins:{{legend:{{display:false}}}},
      scales:{{r:{{
        ticks:{{backdropColor:'transparent',color:'#556070',font:{{size:10}}}},
        grid:{{color:GRID_COLOR}},
        angleLines:{{color:GRID_COLOR}},
        pointLabels:{{color:'#8B9DB5',font:{{size:11}}}}
      }}}},
      animation:{{duration:600}}
    }}
  }});

  /* Phase cards */
  const grid=document.getElementById('f3ead-phases');
  phases.forEach((phase,i)=>{{
    const types=DATA.f3ead_map[phase]||[];
    const color=colors[i];
    let items='';
    types.forEach(t=>{{
      const cnt=DATA.type_counts[t]||0;
      if(cnt>0)items+=`<li class="phase-item">
        <span class="phase-item-name">${{t.replace(/_/g,' ')}}</span>
        <span class="phase-item-cnt" style="color:${{color}}">${{cnt}}</span>
      </li>`;
    }});
    if(!items)items=`<li class="phase-item"><span class="phase-item-name" style="color:var(--text3)">No findings</span></li>`;
    grid.innerHTML+=`<div class="phase-card">
      <div class="phase-hdr">
        <span class="phase-name" style="color:${{color}}">${{phase}}</span>
        <span class="count-pill">${{DATA.f3ead_counts[phase]||0}}</span>
      </div>
      <div class="phase-count" style="color:${{color}}">${{DATA.f3ead_counts[phase]||0}}</div>
      <div class="phase-desc">${{phaseDesc[phase]}}</div>
      <ul class="phase-items">${{items}}</ul>
    </div>`;
  }});
}}
renderF3EAD();

/* ── Render JTC ──────────────────────────────────────────────────────────── */
function renderJTC(){{
  const phases=Object.keys(DATA.jtc_counts);
  const colors=['#4F8EF7','#7C6AF7','#059669','#DC2626','#D97706'];
  const jtcDesc={{
    'Target Development':'Identify and catalogue the target — external presence, network blocks, affiliated infrastructure.',
    'Target Analysis':'Understand the target deeply — exposed services, technology stack, certificate posture.',
    'Decision':'Determine actionability — what can be exploited immediately with the gathered intelligence.',
    'Execution':'Intelligence that directly enables action — upload endpoints, auth pages, cloud buckets.',
    'Assessment':'Post-collection review — archived exposures, account enumeration, digital footprint scope.',
  }};

  /* Bar chart */
  new Chart(document.getElementById('chartJTC'),{{
    type:'bar',
    data:{{
      labels:phases,
      datasets:[{{
        label:'Findings',
        data:phases.map(p=>DATA.jtc_counts[p]||0),
        backgroundColor:colors,
        borderColor:colors,borderWidth:1.5,
        borderRadius:6,borderSkipped:false
      }}]
    }},
    options:{{
      responsive:true,maintainAspectRatio:false,
      plugins:{{legend:{{display:false}},tooltip:{{callbacks:{{label:ctx=>`${{ctx.parsed.y}} findings`}}}}}},
      scales:{{
        x:{{ticks:{{color:'#8B9DB5'}},grid:{{color:GRID_COLOR}}}},
        y:{{ticks:{{color:'#556070'}},grid:{{color:GRID_COLOR}}}}
      }},
      animation:{{duration:500}}
    }}
  }});

  /* Pipeline strip */
  const pipeline=document.getElementById('jtc-pipeline');
  phases.forEach((phase,i)=>{{
    pipeline.innerHTML+=`<div class="jtc-stage">
      <div class="jtc-stage-name">${{esc(phase)}}</div>
      <div class="jtc-stage-count" style="color:${{colors[i]}}">${{DATA.jtc_counts[phase]||0}}</div>
    </div>`;
  }});

  /* Phase breakdown tables */
  const el=document.getElementById('jtc-phases');
  phases.forEach((phase,i)=>{{
    const types=DATA.jtc_map[phase]||[];
    const color=colors[i];
    let rows='';
    types.forEach(t=>{{
      const cnt=DATA.type_counts[t]||0;
      if(cnt>0){{
        const m=DATA.findings.find(f=>f.type===t)||{{}};
        rows+=`<tr>
          <td>${{sev(m.severity||'INFO')}}</td>
          <td><span class="mono-val">${{esc(t)}}</span></td>
          <td><strong>${{cnt}}</strong></td>
          <td>${{m.mitre_id?mitreBadge(m.mitre_id):'<span class="null-val">—</span>'}}</td>
          <td><span class="tactic-tag">${{esc(m.tactic||'—')}}</span></td>
        </tr>`;
      }}
    }});
    el.innerHTML+=`
      <div class="sec-hdr" style="margin-top:28px">
        <h2 style="color:${{color}}">${{esc(phase)}}</h2>
        <span class="count-pill">${{DATA.jtc_counts[phase]||0}}</span>
      </div>
      <p style="font-size:11.5px;color:var(--text3);margin:-8px 0 14px">${{jtcDesc[phase]}}</p>
      ${{tbl(['Severity','Finding Type','Count','ATT&CK ID','Tactic'],rows||`<tr><td colspan="5" class="null-val">No mapped findings</td></tr>`)}}`;
  }});
}}
renderJTC();

/* ── Render MITRE ────────────────────────────────────────────────────────── */
function renderMitre(){{
  const tactics=Object.keys(DATA.tactic_counts).sort();
  const tPalette=['#4F8EF7','#7C6AF7','#059669','#D97706','#DC2626','#0891B2','#C061C2','#9CA3AF'];

  new Chart(document.getElementById('chartTactics'),{{
    type:'bar',
    data:{{
      labels:tactics,
      datasets:[{{
        label:'Findings',
        data:tactics.map(t=>DATA.tactic_counts[t]||0),
        backgroundColor:tPalette,
        borderColor:tPalette,borderWidth:1.5,
        borderRadius:6,borderSkipped:false
      }}]
    }},
    options:{{
      responsive:true,maintainAspectRatio:false,
      plugins:{{legend:{{display:false}},tooltip:{{callbacks:{{label:ctx=>`${{ctx.parsed.y}} findings`}}}}}},
      scales:{{
        x:{{ticks:{{color:'#8B9DB5',font:{{size:10}}}},grid:{{color:GRID_COLOR}}}},
        y:{{ticks:{{color:'#556070'}},grid:{{color:GRID_COLOR}}}}
      }},
      animation:{{duration:500}}
    }}
  }});

  const tbody=document.getElementById('mitre-tbody');
  DATA.findings.forEach(f=>{{
    const tr=document.createElement('tr');
    tr.dataset.search=(f.type+f.mitre_id+f.mitre_name+f.tactic).toLowerCase();
    tr.innerHTML=`
      <td>${{sev(f.severity)}}</td>
      <td><span class="mono-val">${{esc(f.type)}}</span></td>
      <td><strong>${{f.count}}</strong></td>
      <td>${{mitreBadge(f.mitre_id)}}</td>
      <td style="color:var(--text2);font-size:12px">${{esc(f.mitre_name)}}</td>
      <td><span class="tactic-tag">${{esc(f.tactic)}}</span></td>`;
    tbody.appendChild(tr);
  }});
}}
renderMitre();

function filterMitreTable(){{
  const q=document.getElementById('mitre-search').value.toLowerCase();
  document.querySelectorAll('#mitre-tbody tr').forEach(tr=>{{
    tr.style.display=tr.dataset.search.includes(q)?'':'none';
  }});
}}

/* ── Render Identity ─────────────────────────────────────────────────────── */
function renderIdentity(){{
  const el=document.getElementById('identity-content');
  const E=DATA.exposures;
  let html='';

  html+=`<div class="alert-banner alert-high">
    <div class="alert-icon">◎</div>
    <div class="alert-body"><strong>HIGH — Personnel Enumeration Confirmed</strong>
    <span>Identified names and usernames enable spear-phishing, credential stuffing, and social engineering.</span></div>
  </div>`;

  /* Names + Usernames grid */
  html+=`<div class="two-col">`;
  html+=`<div>
    <div class="sec-hdr"><h2>Human Names</h2><span class="count-pill">${{E.human_names.length}}</span></div>
    <div class="name-grid">${{E.human_names.map(n=>`<div class="name-chip">${{esc(n)}}</div>`).join('')}}</div>
  </div>`;
  html+=`<div>
    <div class="sec-hdr"><h2>Usernames</h2><span class="count-pill">${{E.usernames.length}}</span></div>
    <div class="name-grid">${{E.usernames.map(u=>`<div class="name-chip mono-chip">${{esc(u)}}</div>`).join('')}}</div>
  </div>`;
  html+=`</div>`;

  /* External accounts */
  if(E.accounts_external.length){{
    html+=`<div class="sec-hdr"><h2>External Platform Accounts</h2><span class="count-pill">${{E.accounts_external.length}}</span></div>`;
    let rows='';
    E.accounts_external.forEach(a=>{{
      const lines=String(a).split('\n');
      const platform=lines[0]||a;
      const url=lines[1]||'';
      rows+=`<tr>
        <td>${{esc(platform)}}</td>
        <td>${{url?`<span class="url-val">${{esc(url)}}</span>`:`<span class="null-val">—</span>`}}</td>
      </tr>`;
    }});
    html+=tbl(['Platform / Category','Profile URL'],rows);
  }}

  /* Emails */
  if(E.emails.length){{
    html+=`<div class="sec-hdr"><h2>Email Addresses</h2><span class="count-pill">${{E.emails.length}}</span></div>`;
    let rows=E.emails.map(e=>`<tr><td><span class="mono-val">${{esc(e)}}</span>${{copyBtn(e)}}</td></tr>`).join('');
    html+=tbl(['Email Address'],rows);
  }}

  /* Social media */
  if(E.social_media.length){{
    html+=`<div class="sec-hdr"><h2>Social Media Links</h2><span class="count-pill">${{E.social_media.length}}</span></div>`;
    let rows=E.social_media.map(s=>`<tr><td><span class="url-val">${{esc(s)}}</span>${{copyBtn(s)}}</td></tr>`).join('');
    html+=tbl(['URL'],rows);
  }}

  /* PGP Keys */
  if(E.pgp_keys.length){{
    html+=`<div class="sec-hdr"><h2>PGP Keys</h2><span class="count-pill">${{E.pgp_keys.length}}</span></div>`;
    E.pgp_keys.forEach(k=>{{
      html+=`<div class="pgp-block">
        <div class="pgp-hdr">
          <span class="pgp-dot"></span>
          <span class="pgp-label">PGP PUBLIC KEY — ${{esc(k[1]||'unknown')}}</span>
        </div>
        <pre class="pgp-body">-----BEGIN PGP PUBLIC KEY BLOCK-----
[key data available in raw SpiderFoot export]
-----END PGP PUBLIC KEY BLOCK-----</pre>
      </div>`;
    }});
  }}

  el.innerHTML=html;
}}
renderIdentity();

/* ── Render Infrastructure ───────────────────────────────────────────────── */
function renderInfra(){{
  const el=document.getElementById('infra-content');
  const E=DATA.exposures;
  let html='';

  /* Subdomains chip grid */
  html+=`<div class="sec-hdr"><h2>Subdomains / Internet Names</h2><span class="count-pill">${{E.subdomains.length}}</span></div>`;
  html+=`<div class="host-grid">${{E.subdomains.map(s=>`<div class="host-chip" title="${{esc(s)}}">${{esc(s)}}</div>`).join('')}}</div>`;

  /* IPs */
  html+=`<div class="sec-hdr"><h2>IP Addresses</h2><span class="count-pill">${{E.ip_addresses.length}}</span></div>`;
  let ipRows=E.ip_addresses.map(r=>`<tr>
    <td><span class="mono-val">${{safeVal(r.source)}}</span></td>
    <td><span class="mono-val" style="color:#7EB3FF;font-weight:600">${{safeVal(r.data)}}</span>${{copyBtn(r.data||'')}}</td>
  </tr>`).join('');
  html+=tbl(['Source Hostname','IP Address'],ipRows);

  /* Technologies */
  if(E.technologies.length){{
    html+=`<div class="sec-hdr"><h2>Technologies Detected</h2><span class="count-pill">${{E.technologies.length}}</span></div>`;
    let rows=E.technologies.map(t=>`<tr><td><span class="chip">${{esc(t)}}</span></td></tr>`).join('');
    html+=tbl(['Technology / Framework'],rows);
  }}

  /* Banners */
  if(E.banners.length){{
    html+=`<div class="sec-hdr"><h2>Server Banners</h2><span class="count-pill">${{E.banners.length}}</span></div>`;
    let rows=[...new Set(E.banners)].map(b=>`<tr><td><span class="mono-val" style="color:#8B9DB5">${{esc(b)}}</span></td></tr>`).join('');
    html+=tbl(['Banner String'],rows);
  }}

  /* Code repos */
  if(E.code_repos.length){{
    html+=`<div class="sec-hdr"><h2>Public Code Repositories</h2><span class="count-pill">${{E.code_repos.length}}</span></div>`;
    let rows=E.code_repos.map(r=>{{
      const raw=Array.isArray(r)?(r[1]||r[0]):r;
      // Parse SpiderFoot's "Name: ...\nURL: ...\nDescription: ..." structure
      const text=String(raw);
      const nameM=text.match(/Name:\s*(.*)/i);
      const urlM=text.match(/URL:\s*(\S+)/i);
      const descM=text.match(/Description:\s*([\s\S]*)/i);
      const name=nameM?nameM[1].trim():'';
      const url=urlM?urlM[1].trim():(text.startsWith('http')?text.trim():'');
      const desc=descM?descM[1].trim():'';
      const urlCell=url
        ? `<a class="url-val repo-url" href="${{esc(url)}}" target="_blank" rel="noopener">${{esc(url)}}</a>`
        : `<span class="url-val repo-url">${{esc(text)}}</span>`;
      return`<tr>
        <td>${{name?`<span class="mono-val">${{esc(name)}}</span>`:`<span class="null-val">—</span>`}}</td>
        <td class="repo-url-cell">${{urlCell}}</td>
        <td>${{desc?`<span style="color:var(--text2);font-size:12px">${{esc(desc)}}</span>`:`<span class="null-val">—</span>`}}</td>
        <td class="copy-cell">${{copyBtn(url||text)}}</td>
      </tr>`;
    }}).join('');
    html+=tbl(['Name','Repository URL','Description','&nbsp;'],rows);
  }}

  /* Physical addresses */
  if(E.physical_addresses.length){{
    html+=`<div class="sec-hdr"><h2>Physical Addresses</h2><span class="count-pill">${{E.physical_addresses.length}}</span></div>`;
    let rows=E.physical_addresses.map(a=>`<tr><td>${{esc(a)}}</td></tr>`).join('');
    html+=tbl(['Address'],rows);
  }}

  el.innerHTML=html;
}}
renderInfra();
</script>
</body>
</html>"""

def generate_report(csv_path, output_path):
    print(f"[*] Loading: {csv_path}")
    df = load_data(csv_path)
    print(f"[*] {len(df)} records, {df['Type'].nunique()} finding types")
    print("[*] Building data payload...")
    payload = build_json_payload(df)
    data_json = json.dumps(payload, default=str, ensure_ascii=False)
    print("[*] Rendering HTML (v2 premium UI)...")
    html = HTML_TEMPLATE.format(scan_name=payload["scan_name"], data_json=data_json)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"[+] Report written: {output_path}")
    print(f"    Scan:     {payload['scan_name']}")
    print(f"    Date:     {payload['scan_date']}")
    print(f"    Records:  {payload['total_findings']}")
    print(f"    CRITICAL: {payload['severity'].get('CRITICAL',0)}")
    print(f"    HIGH:     {payload['severity'].get('HIGH',0)}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 generate_spiderfoot_report_v2.py <input.csv> [output.html]")
        sys.exit(1)
    csv_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else Path(csv_path).stem + "_report_v2.html"
    generate_report(csv_path, output_path)
