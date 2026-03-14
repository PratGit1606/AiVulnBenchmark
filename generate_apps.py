#!/usr/bin/env python3

import os, sys, json, csv, time, hashlib, subprocess
from pathlib import Path
from dotenv import load_dotenv
import requests

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "prompts" / "experiment_matrix.csv"
PROMPT_BANK = ROOT / "prompts" / "prompt_bank.json"
MANIFEST = ROOT / "generation" / "generation_manifest.json"
APPS_DIR = ROOT / "apps"
RESPONSES_DIR = ROOT / "generation" / "responses"
LOGS_DIR = ROOT / "logs"

APPS_DIR.mkdir(exist_ok=True)
RESPONSES_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)
MANIFEST.parent.mkdir(parents=True, exist_ok=True)

load_dotenv(ROOT / ".env")

LLM_API_KEY = os.getenv("LLM_API_KEY")
LLM_ENDPOINT = os.getenv("LLM_ENDPOINT", "").rstrip("/")
LLM_MODEL = os.getenv("LLM_MODEL", "gpt-4.1")
DEFAULT_TEMPERATURE = float(os.getenv("GEN_TEMPERATURE", "0.2"))

if not LLM_API_KEY or not LLM_ENDPOINT:
    print("Missing LLM_API_KEY or LLM_ENDPOINT in .env", file=sys.stderr)
    sys.exit(1)

def read_matrix():
    rows = []
    with open(MATRIX, newline='') as f:
        r = csv.DictReader(f)
        for row in r:
            rows.append(row)
    return rows

def write_manifest_entry(entry):
    if MANIFEST.exists():
        data = json.loads(MANIFEST.read_text())
    else:
        data = []
    data.append(entry)
    MANIFEST.write_text(json.dumps(data, indent=2))

def pick_next_app(rows):
    for r in rows:
        status = r.get("status", "").strip().lower()
        if status in ("", "not_generated", "pending"):
            return r
    return None

def load_prompt(prompt_type, prompt_id):
    pb = json.loads(PROMPT_BANK.read_text())
    block = pb.get(prompt_type, {})
    for p in block.get("prompts", []):
        if p.get("id") == prompt_id:
            return p.get("prompt")
    return None

def call_llm(prompt_text):
    import os, requests, json
    api_key = os.getenv("OPENROUTR_API_KEY")
    base = os.getenv("OPENROUTR_API_BASE", "https://openrouter.ai/api/v1").rstrip("/")
    model = os.getenv("OPENROUTR_MODEL", "openai/gpt-4o-mini")
    max_tokens = int(os.getenv("GEN_MAX_TOKENS", "12000"))
    temp = float(os.getenv("GEN_TEMPERATURE", "0.2"))

    url = f"{base}/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a code generation assistant. Output code files in a zip or structured files."},
            {"role": "user", "content": prompt_text}
        ],
        "temperature": temp,
        "max_tokens": max_tokens,
        "n": 1
    }
    resp = requests.post(url, json=payload, headers=headers, timeout=600)
    resp.raise_for_status()
    return resp.json()

def save_response(app_id, resp_json):
    p = RESPONSES_DIR / f"response_{app_id}.json"
    p.write_text(json.dumps(resp_json, indent=2))
    return p

def extract_and_write_repo(app_id, resp_json):
    """
    Heuristic: If response contains a 'files' dict or a 'zip_base64' key, handle both.
    Otherwise, write raw text to apps/{app_id}/README_from_model.txt
    """
    appdir = APPS_DIR / app_id
    if appdir.exists():
        # do not overwrite by default; create timestamped backup
        backup = APPS_DIR / f"{app_id}_backup_{int(time.time())}"
        appdir.rename(backup)
    appdir.mkdir(parents=True, exist_ok=True)

    # Case 1: model returns base64 zip
    if "zip_base64" in resp_json:
        import base64, zipfile, io
        zdata = base64.b64decode(resp_json["zip_base64"])
        zf = zipfile.ZipFile(io.BytesIO(zdata))
        zf.extractall(appdir)
        return appdir

    # Case 2: model returns structured "files": {"path": "content"}
    files = resp_json.get("files")
    if isinstance(files, dict):
        for path, content in files.items():
            target = appdir / path
            target.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, str):
                target.write_text(content)
            else:
                # binary?
                target.write_bytes(content)
        return appdir

    # Fallback: save whole response text
    body = resp_json.get("output_text") or str(resp_json)
    (appdir / "MODEL_OUTPUT.txt").write_text(body)
    return appdir

def commit_and_hash(appdir):
    # Initialize git repo and make initial commit to get a commit hash
    try:
        subprocess.run(["git", "init"], cwd=appdir, check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["git", "add", "."], cwd=appdir, check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["git", "commit", "-m", "initial generated app"], cwd=appdir, check=True, stdout=subprocess.DEVNULL)
        out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=appdir, check=True, capture_output=True, text=True)
        return out.stdout.strip()
    except Exception:
        # fallback: sha256 of zip
        import zipfile, io, hashlib
        zip_path = appdir.with_suffix(".zip")
        shutil.make_archive(str(appdir), 'zip', root_dir=str(appdir))
        h = hashlib.sha256(Path(str(zip_path)).read_bytes()).hexdigest()
        return h

def update_matrix_status(app_id, new_status):
    rows = read_matrix()
    for r in rows:
        if r.get("app_id") == app_id:
            r["status"] = new_status
    # write back
    with open(MATRIX, "w", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

def main():
    rows = read_matrix()
    target = pick_next_app(rows)
    if not target:
        print("No not_generated apps found.")
        return
    app_id = target["app_id"]
    prompt_type = target["prompt_type"]
    stack = target["stack"]
    # choose prompt id by simplest mapping: pick first in prompt_bank for type
    pb = json.loads(PROMPT_BANK.read_text())
    prompts_for_type = pb.get(prompt_type, {}).get("prompts", [])
    if not prompts_for_type:
        print(f"No prompts for type {prompt_type}")
        return
    prompt_entry = prompts_for_type[0]  # could randomize or rotate
    prompt_template = prompt_entry["prompt"]
    prompt_text = prompt_template.replace("{stack}", stack)

    # prepare request metadata
    req = {
        "app_id": app_id,
        "prompt_type": prompt_type,
        "prompt_id": prompt_entry["id"],
        "stack": stack,
        "prompt_text": prompt_text,
        "model": LLM_MODEL,
        "temperature": DEFAULT_TEMPERATURE,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }
    req_path = RESPONSES_DIR / f"request_{app_id}.json"
    req_path.write_text(json.dumps(req, indent=2))

    update_matrix_status(app_id, "generating")
    try:
        resp = call_llm(prompt_text)
        respfile = save_response(app_id, resp)
        appdir = extract_and_write_repo(app_id, resp)
        commit_hash = commit_and_hash(appdir)
        docker_image = f"{app_id.lower()}_image:latest"
        manifest_entry = {
            "app_id": app_id,
            "prompt_type": prompt_type,
            "prompt_id": prompt_entry["id"],
            "stack": stack,
            "model_name": LLM_MODEL,
            "temperature": DEFAULT_TEMPERATURE,
            "seed": None,
            "repo_path": str(appdir.relative_to(ROOT)),
            "docker_image": docker_image,
            "commit_hash": commit_hash,
            "response_file": str(respfile.relative_to(ROOT)),
            "timestamp": req["timestamp"]
        }
        write_manifest_entry(manifest_entry)
        update_matrix_status(app_id, "generated")
        print(f"Generated {app_id} → {appdir}")
    except Exception as e:
        update_matrix_status(app_id, "generation_failed")
        errpath = LOGS_DIR / f"generate_{app_id}_error.log"
        errpath.write_text(str(e))
        print("Generation failed:", e)

if __name__ == "__main__":
    main()