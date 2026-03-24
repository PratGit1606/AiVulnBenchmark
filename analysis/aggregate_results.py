#!/usr/bin/env python3
"""
analysis/aggregate_results.py
Consolidates triage CSVs + patch results into analysis/benchmark_results.csv
"""
import argparse, csv, json
from datetime import datetime, timezone
from pathlib import Path

ROOT          = Path(__file__).resolve().parents[1]
TRIAGE_DIR    = ROOT / "triage"
PATCH_DIR     = ROOT / "patch_results"
MANIFEST_FILE = ROOT / "generation" / "generation_manifest.json"
MATRIX_FILE   = ROOT / "prompts" / "experiment_matrix.csv"
OUT_FILE      = ROOT / "analysis" / "benchmark_results.csv"

OUTPUT_FIELDS = [
    "app_id","prompt_type","stack",
    "vulnerability_id","vulnerability_class","severity",
    "tool_detected","exploit_single","exploit_concurrent","CAF",
    "patch_type","patch_success","notes","timestamp",
]

def load_manifest():
    if not MANIFEST_FILE.exists(): return {}
    return {e["app_id"]: e for e in json.loads(MANIFEST_FILE.read_text())}

def load_matrix():
    result = {}
    if not MATRIX_FILE.exists(): return result
    with open(MATRIX_FILE, newline="") as f:
        for row in csv.DictReader(f):
            result[row["app_id"]] = row
    return result

def load_patches(app_id=None):
    index = {}
    if not PATCH_DIR.exists(): return index
    glob = f"{app_id}_*.json" if app_id else "*_*.json"
    for p in PATCH_DIR.glob(glob):
        try:
            data = json.loads(p.read_text())
            index[data.get("vuln_id", p.stem)] = data
        except: pass
    return index

def compute_caf(s, c):
    def parse(v):
        v = str(v).strip().lower()
        if v in ("true","yes","1"): return 1.0
        if v in ("false","no","0",""): return 0.0
        try: return float(v)
        except: return 0.0
    sv, cv = parse(s), parse(c)
    if sv == 0: return round(cv, 4) if cv else 1.0
    return round(cv / sv, 4)

def load_confirmed(app_id):
    p = TRIAGE_DIR / f"{app_id}_confirmed.csv"
    if not p.exists(): return []
    with open(p, newline="") as f:
        return list(csv.DictReader(f))

def load_candidates(app_id):
    p = TRIAGE_DIR / f"{app_id}_candidates.json"
    if not p.exists(): return []
    try: return json.loads(p.read_text())
    except: return []

def build_rows(app_id, manifest, matrix, patches):
    rows = []
    meta   = manifest.get(app_id, {})
    mrow   = matrix.get(app_id, {})
    ptype  = meta.get("prompt_type") or mrow.get("prompt_type","")
    stack  = meta.get("stack")       or mrow.get("stack","")
    ts     = datetime.now(timezone.utc).isoformat()

    confirmed = load_confirmed(app_id)
    if confirmed:
        for c in confirmed:
            vid    = c.get("vuln_id","")
            patch  = patches.get(vid, {})
            es, ec = c.get("exploit_single",""), c.get("exploit_concurrent","")
            rows.append({
                "app_id": app_id, "prompt_type": ptype, "stack": stack,
                "vulnerability_id": vid,
                "vulnerability_class": c.get("vuln_class",""),
                "severity": c.get("severity",""),
                "tool_detected": patch.get("tool_hits",""),
                "exploit_single": es, "exploit_concurrent": ec,
                "CAF": compute_caf(es, ec),
                "patch_type": patch.get("patch_type","none"),
                "patch_success": patch.get("patch_success",""),
                "notes": c.get("poc_notes",""),
                "timestamp": c.get("timestamp", ts),
            })
        return rows

    candidates = load_candidates(app_id)
    for cand in candidates:
        vid   = cand.get("vuln_id","")
        patch = patches.get(vid, {})
        rows.append({
            "app_id": app_id, "prompt_type": ptype, "stack": stack,
            "vulnerability_id": vid,
            "vulnerability_class": cand.get("class",""),
            "severity": cand.get("severity",""),
            "tool_detected": ", ".join(cand.get("tool_hits",[])),
            "exploit_single":"", "exploit_concurrent":"", "CAF":"",
            "patch_type": patch.get("patch_type","none"),
            "patch_success": patch.get("patch_success",""),
            "notes": cand.get("evidence","")[:120],
            "timestamp": ts,
        })

    if not rows:
        rows.append({
            "app_id": app_id, "prompt_type": ptype, "stack": stack,
            "vulnerability_id":"","vulnerability_class":"","severity":"",
            "tool_detected":"","exploit_single":"","exploit_concurrent":"",
            "CAF":"","patch_type":"","patch_success":"",
            "notes":"no_findings_yet","timestamp": ts,
        })
    return rows

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--app", default=None)
    parser.add_argument("--out", default=str(OUT_FILE))
    args = parser.parse_args()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    manifest = load_manifest()
    matrix   = load_matrix()
    patches  = load_patches(args.app)

    if args.app:
        app_ids = [args.app]
    else:
        ids = set(manifest.keys()) | set(matrix.keys())
        ids |= set(
            p.stem.replace("_confirmed","").replace("_candidates","")
            for p in TRIAGE_DIR.glob("APP*_*.csv")
        )
        app_ids = sorted(ids)

    if not app_ids:
        print("[warn] No apps found."); return

    all_rows = []
    for app_id in app_ids:
        rows = build_rows(app_id, manifest, matrix, patches)
        all_rows.extend(rows)
        print(f"  {app_id}: {len(rows)} row(s)")

    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=OUTPUT_FIELDS)
        writer.writeheader()
        writer.writerows(all_rows)

    print(f"\n[+] {len(all_rows)} total rows → {out_path}")

if __name__ == "__main__":
    main()
