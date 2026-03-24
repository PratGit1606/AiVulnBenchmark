#!/usr/bin/env python3
import argparse, json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCANS_DIR = ROOT / "scans"
TRIAGE_DIR = ROOT / "triage"
TRIAGE_DIR.mkdir(exist_ok=True)

SEVERITY_MAP = {"ERROR":"high","WARNING":"medium","INFO":"low","HIGH":"high","MEDIUM":"medium","LOW":"low"}
CLASS_PATTERNS = [
    (re.compile(r"sql.inject|sqli",re.I),"sql_injection"),
    (re.compile(r"xss|cross.site.script",re.I),"xss"),
    (re.compile(r"path.trav|directory.trav",re.I),"path_traversal"),
    (re.compile(r"csrf|cross.site.request",re.I),"csrf"),
    (re.compile(r"command.inject|os\.system|subprocess",re.I),"command_injection"),
    (re.compile(r"hardcod.secret|hardcod.password|secret.key",re.I),"hardcoded_secret"),
    (re.compile(r"debug|debugger",re.I),"debug_enabled"),
    (re.compile(r"open.redirect",re.I),"open_redirect"),
    (re.compile(r"ssrf",re.I),"ssrf"),
    (re.compile(r"idor|broken.access|unauth",re.I),"idor"),
    (re.compile(r"rate.limit|brute.forc",re.I),"missing_rate_limit"),
    (re.compile(r"auth|session|password",re.I),"auth_weakness"),
    (re.compile(r"file.upload|upload",re.I),"insecure_file_upload"),
    (re.compile(r"race.condition|toctou",re.I),"race_condition"),
]

def classify(text):
    for pattern, cls in CLASS_PATTERNS:
        if pattern.search(text): return cls
    return "other"

def normalize_sev(raw):
    return SEVERITY_MAP.get(str(raw).upper().split()[0], "low")

def parse_bandit(path):
    findings = []
    try: data = json.loads(path.read_text())
    except: return findings
    for r in data.get("results", []):
        findings.append({
            "_tool": "bandit",
            "_class_hint": f"{r.get('test_id','')} {r.get('test_name','')} {r.get('issue_text','')}",
            "severity": normalize_sev(r.get("issue_severity","LOW")),
            "confidence": normalize_sev(r.get("issue_confidence","LOW")),
            "location": {"file": r.get("filename",""), "line": r.get("line_number",0)},
            "evidence": r.get("code", r.get("issue_text",""))[:300],
        })
    return findings

def parse_semgrep(path):
    findings = []
    try: data = json.loads(path.read_text())
    except: return findings
    for r in data.get("results", []):
        sev = r.get("extra",{}).get("severity","WARNING")
        findings.append({
            "_tool": "semgrep",
            "_class_hint": f"{r.get('check_id','')} {r.get('extra',{}).get('message','')}",
            "severity": normalize_sev(sev),
            "confidence": normalize_sev(sev),
            "location": {"file": r.get("path",""), "line": r.get("start",{}).get("line",0)},
            "evidence": r.get("extra",{}).get("lines", r.get("extra",{}).get("message",""))[:300],
        })
    return findings

PARSERS = {"bandit": parse_bandit, "semgrep": parse_semgrep}

def detect_tool(path):
    name = path.stem.lower()
    for tool in PARSERS:
        if tool in name: return tool
    return None

def merge_findings(raw):
    groups = {}
    for f in raw:
        cls = classify(f["_class_hint"])
        loc = f["location"]
        key = (cls, loc.get("file",""), (loc.get("line",0)//10)*10)
        if key not in groups:
            groups[key] = {"class":cls,"tool_hits":[],"locations":[],"severity":f["severity"],"confidence":f["confidence"],"evidence":f["evidence"]}
        g = groups[key]
        if f["_tool"] not in g["tool_hits"]: g["tool_hits"].append(f["_tool"])
        exact = {"file":loc.get("file",""),"line":loc.get("line",0)}
        if exact not in g["locations"]: g["locations"].append(exact)
        SEV = ["info","low","medium","high"]
        if SEV.index(f["severity"]) > SEV.index(g["severity"]): g["severity"] = f["severity"]
    return list(groups.values())

def process_app(app_id, out_path):
    print(f"\n[*] Aggregating scans for {app_id}...")
    raw = []
    for sf in sorted(SCANS_DIR.glob(f"{app_id}_*.json")):
        tool = detect_tool(sf)
        if not tool:
            print(f"  [skip] {sf.name}"); continue
        parsed = PARSERS[tool](sf)
        print(f"  [{tool}] {sf.name}: {len(parsed)} findings")
        raw.extend(parsed)
    merged = merge_findings(raw)
    SEV_ORDER = {"high":0,"medium":1,"low":2,"info":3}
    merged.sort(key=lambda x: SEV_ORDER.get(x["severity"],4))
    output = []
    for i,m in enumerate(merged,1):
        output.append({"vuln_id":f"{app_id}-{m['class'].upper()[:8]}-{i:03d}","class":m["class"],"tool_hits":sorted(m["tool_hits"]),"locations":m["locations"],"confidence":m["confidence"],"severity":m["severity"],"evidence":m["evidence"]})
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output, indent=2))
    print(f"[+] {len(output)} candidates → {out_path}")

def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--app")
    group.add_argument("--all", action="store_true")
    parser.add_argument("--out")
    args = parser.parse_args()
    if args.all:
        ids = sorted(set(re.match(r"(APP\d+)_",f.stem).group(1) for f in SCANS_DIR.glob("APP*_*.json") if re.match(r"(APP\d+)_",f.stem)))
        for app_id in ids:
            process_app(app_id, TRIAGE_DIR / f"{app_id}_candidates.json")
    else:
        process_app(args.app, Path(args.out) if args.out else TRIAGE_DIR / f"{args.app}_candidates.json")

if __name__ == "__main__":
    main()
