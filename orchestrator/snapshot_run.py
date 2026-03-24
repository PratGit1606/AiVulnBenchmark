#!/usr/bin/env python3
"""
orchestrator/snapshot_run.py
Creates artifacts/{app}/snapshot.json for a completed benchmark run.
"""
import json, subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT           = Path(__file__).resolve().parents[1]
MANIFEST_FILE  = ROOT / "generation" / "generation_manifest.json"
SCANS_DIR      = ROOT / "scans"
TRIAGE_DIR     = ROOT / "triage"
ATTACK_DIR     = ROOT / "attacks" / "results"
PATCH_DIR      = ROOT / "patch_results"
LOGS_DIR       = ROOT / "logs"
ARTIFACTS_DIR  = ROOT / "artifacts"
import argparse, re

def load_manifest():
    if not MANIFEST_FILE.exists(): return {}
    return {e["app_id"]: e for e in json.loads(MANIFEST_FILE.read_text())}

def get_image_id(name):
    try:
        r = subprocess.run(["docker","inspect","--format","{{.Id}}",name],
                           capture_output=True, text=True, timeout=10)
        return r.stdout.strip() if r.returncode == 0 else None
    except: return None

def glob_rel(directory, pattern):
    if not directory.exists(): return []
    return sorted(str(p.relative_to(ROOT)) for p in directory.glob(pattern) if p.is_file())

def attack_summary(app_id):
    results = []
    if not ATTACK_DIR.exists(): return results
    for p in sorted(ATTACK_DIR.glob(f"{app_id}_*.json")):
        try:
            d = json.loads(p.read_text())
            results.append({
                "file": str(p.relative_to(ROOT)),
                "scenario": d.get("attack",""),
                "concurrency": d.get("concurrency"),
                "requests_total": d.get("requests_total"),
                "success_rate": d.get("success_rate"),
            })
        except: pass
    return results

def triage_summary(app_id):
    confirmed = TRIAGE_DIR / f"{app_id}_confirmed.csv"
    candidates = TRIAGE_DIR / f"{app_id}_candidates.json"
    s = {
        "confirmed_csv":   str(confirmed.relative_to(ROOT))  if confirmed.exists()  else None,
        "candidates_json": str(candidates.relative_to(ROOT)) if candidates.exists() else None,
        "confirmed_count": 0, "candidate_count": 0,
    }
    if confirmed.exists():
        import csv
        with open(confirmed, newline="") as f:
            s["confirmed_count"] = sum(1 for _ in csv.DictReader(f))
    if candidates.exists():
        try: s["candidate_count"] = len(json.loads(candidates.read_text()))
        except: pass
    return s

def infer_status(app_id):
    if list(PATCH_DIR.glob(f"{app_id}_*.json")): return "patched"
    if (TRIAGE_DIR / f"{app_id}_confirmed.csv").exists(): return "triaged"
    if list(ATTACK_DIR.glob(f"{app_id}_*.json")): return "attacked"
    if list(SCANS_DIR.glob(f"{app_id}_*.json")): return "scanned"
    return "generated"

def build_snapshot(app_id, entry):
    image = entry.get("docker_image", f"{app_id.lower()}_image:latest")
    return {
        "snapshot_version": "1.0",
        "app_id": app_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "generation": {
            "prompt_type":   entry.get("prompt_type",""),
            "stack":         entry.get("stack",""),
            "model_name":    entry.get("model_name",""),
            "commit_hash":   entry.get("commit_hash",""),
            "repo_path":     entry.get("repo_path",""),
            "timestamp":     entry.get("timestamp",""),
        },
        "deployment": {
            "docker_image_name": image,
            "docker_image_id":   get_image_id(image),
        },
        "scans":   {"files": glob_rel(SCANS_DIR, f"{app_id}_*.json")},
        "triage":  triage_summary(app_id),
        "attacks": attack_summary(app_id),
        "logs":    glob_rel(LOGS_DIR, f"*{app_id}*"),
        "analysis":{"benchmark_csv": str((ROOT/"analysis"/"benchmark_results.csv").relative_to(ROOT))
                    if (ROOT/"analysis"/"benchmark_results.csv").exists() else None},
        "status":  infer_status(app_id),
    }

def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--app-id")
    group.add_argument("--all", action="store_true")
    args = parser.parse_args()

    manifest = load_manifest()
    app_ids  = sorted(manifest.keys()) if args.all else [args.app_id]

    for app_id in app_ids:
        entry    = manifest.get(app_id, {"app_id": app_id})
        snapshot = build_snapshot(app_id, entry)
        out_dir  = ARTIFACTS_DIR / app_id
        out_dir.mkdir(parents=True, exist_ok=True)
        out      = out_dir / "snapshot.json"
        out.write_text(json.dumps(snapshot, indent=2))
        print(f"[+] {app_id}: {snapshot['status']} → {out}")

if __name__ == "__main__":
    main()
