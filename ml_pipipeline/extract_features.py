#!/usr/bin/env python3
"""
extract_features.py
Parse output from MobSF (report.json) and optional static scan files (strings grep, apktool dir)
and produce a CSV with feature columns matching the ML pipeline schema.

Usage:
  python extract_features.py --mobsf report.json --static_dir scans/app_apktool_dir --out ml_features.csv
"""
import argparse, json, os, csv, math, re
from collections import Counter
from pathlib import Path

FEATURE_COLUMNS = [
    "package_name","target_sdk","min_sdk","package_len","dangerous_permissions_count",
    "has_hardcoded_secret","exported_components_count","debuggable","api_getDeviceId_count",
    "api_sendSms_count","network_domains_count","domain_entropy","uses_http","label"
]

def entropy_of_list(items):
    if not items: return 0.0
    c = Counter(items)
    total = sum(c.values())
    import math
    e = -sum((v/total) * math.log2(v/total) for v in c.values())
    return round(e, 4)

def parse_mobsf_json(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        j = json.load(f)
    # Try to pull commonly-present fields; guard with fallbacks
    apk_info = j.get("apk_info", {}) if isinstance(j, dict) else {}
    package = apk_info.get("package_name") or j.get("package_name") or "unknown.package"
    target_sdk = int(apk_info.get("target_sdk", apk_info.get("targetSdkVersion", 0) or 0) or 0)
    min_sdk = int(apk_info.get("min_sdk", apk_info.get("minSdkVersion", 0) or 0) or 0)
    permissions = j.get("permissions", [])
    # permissions may be a dict or list
    if isinstance(permissions, dict):
        perms = list(permissions.keys())
    else:
        perms = permissions or []
    # exported components from manifest analysis
    exported = 0
    try:
        manifest = j.get("manifest_analysis", {}) or j.get("android_manifest", {}) or {}
        # manifest may contain components entries; fallback to scanning for 'exported' strings
        if isinstance(manifest, dict):
            for comp_type in ("activities","services","providers","receivers"):
                items = manifest.get(comp_type) or []
                for it in items:
                    if isinstance(it, dict) and it.get("exported") == "true":
                        exported += 1
        else:
            exported = 0
    except Exception:
        exported = 0
    # debuggable flag
    debuggable = 0
    try:
        debuggable = 1 if manifest.get("application",{}).get("debuggable") == "true" else 0
    except Exception:
        debuggable = 0
    return {
        "package_name": package,
        "target_sdk": target_sdk,
        "min_sdk": min_sdk,
        "permissions": perms,
        "exported_components_count": int(exported),
        "debuggable": int(debuggable)
    }

def scan_strings_for_secrets(strings_file):
    if not strings_file or not os.path.exists(strings_file):
        return 0, []
    suspects = []
    with open(strings_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            l = line.strip()
            # heuristics for secrets: long base64-like strings, keywords, or api keys
            if re.search(r'(api[_-]?key|secret|access[_-]?token|aws_secret|client[_-]?secret)', l, re.I):
                suspects.append(l)
            elif re.search(r'^[A-Za-z0-9+/=]{32,}$', l):
                suspects.append(l)
    return (1 if suspects else 0, suspects)

def count_api_usage_in_apktool(apktool_dir, apis=("getDeviceId","getDeviceSoftwareVersion","sendTextMessage")):
    counts = {a:0 for a in apis}
    if not apktool_dir:
        return counts
    # naive scan of smali/java looking for API names
    for root, dirs, files in os.walk(apktool_dir):
        for fn in files:
            if fn.endswith((".smali",".xml",".java",".kt",".txt")):
                try:
                    with open(os.path.join(root,fn),"r",encoding="utf-8",errors="ignore") as f:
                        data = f.read()
                    for a in apis:
                        counts[a] += data.count(a)
                except Exception:
                    continue
    return counts

def get_network_domains_from_mobsf(j):
    # MobSF often has 'network_traffic' or 'network' sections; fallback to scanning endpoints
    domains = []
    try:
        net = j.get("network",{}) or j.get("network_traffic",{})
        if isinstance(net, dict):
            endpoints = net.get("endpoints") or net.get("hosts") or []
            for e in endpoints:
                if isinstance(e, str):
                    domains.append(e)
                elif isinstance(e, dict):
                    if e.get("host"): domains.append(e.get("host"))
    except Exception:
        pass
    return domains

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mobsf", help="MobSF JSON report (report.json)", required=True)
    parser.add_argument("--strings", help="strings_found.txt (optional)")
    parser.add_argument("--apktool", help="apktool decompiled directory (optional)")
    parser.add_argument("--out", help="Output CSV path", default="ml_features.csv")
    parser.add_argument("--label", type=int, help="Optional label for supervised training (0 benign, 1 malicious)", default=None)
    args = parser.parse_args()

    mobsf = args.mobsf
    mobsf_json = {}
    try:
        with open(mobsf,"r",encoding="utf-8",errors="ignore") as f:
            mobsf_json = json.load(f)
    except Exception as e:
        print("Error reading MobSF JSON:", e); return

    meta = parse_mobsf_json(mobsf)
    has_secret, secret_lines = scan_strings_for_secrets(args.strings)
    api_counts = count_api_usage_in_apktool(args.apktool)
    domains = get_network_domains_from_mobsf(mobsf_json)

    row = {
        "package_name": meta["package_name"],
        "target_sdk": meta["target_sdk"],
        "min_sdk": meta["min_sdk"],
        "package_len": len(meta["package_name"]),
        "dangerous_permissions_count": sum(1 for p in meta["permissions"] if ("dangerous" in p.lower() or p.startswith("android.permission."))),
        "has_hardcoded_secret": has_secret,
        "exported_components_count": int(meta.get("exported_components_count",0)),
        "debuggable": int(meta.get("debuggable",0)),
        "api_getDeviceId_count": int(api_counts.get("getDeviceId",0)),
        "api_sendSms_count": int(api_counts.get("sendTextMessage",0)),
        "network_domains_count": len(domains),
        "domain_entropy": entropy_of_list(domains),
        "uses_http": 1 if any('http://' in (u or '').lower() for u in domains) else 0,
        "label": args.label if args.label is not None else ""
    }

    # Write CSV header if not exists; allow appending multiple apps
    outp = Path(args.out)
    write_header = not outp.exists()
    with open(outp,"a",newline="",encoding="utf-8") as csvf:
        writer = csv.DictWriter(csvf, fieldnames=FEATURE_COLUMNS)
        if write_header:
            writer.writeheader()
        writer.writerow(row)
    print("Wrote features to", str(outp))

if __name__ == "__main__":
    main()
