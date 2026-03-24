#!/usr/bin/env python3

import os, sys, json, csv, time, re, subprocess, shutil, hashlib, base64, zipfile, io
from pathlib import Path
from dotenv import load_dotenv
import requests

ROOT          = Path(__file__).resolve().parent.parent
MATRIX        = ROOT / "HonorsThesis" / "prompts" / "experiment_matrix.csv"
PROMPT_BANK   = ROOT / "HonorsThesis" / "prompts" / "prompt_bank.json"
MANIFEST      = ROOT / "HonorsThesis" / "generation" / "generation_manifest.json"
APPS_DIR      = ROOT / "HonorsThesis" / "apps"
RESPONSES_DIR = ROOT / "HonorsThesis" / "generation" / "responses"
LOGS_DIR      = ROOT / "HonorsThesis" / "logs"

for d in (APPS_DIR, RESPONSES_DIR, LOGS_DIR, MANIFEST.parent):
    d.mkdir(parents=True, exist_ok=True)

load_dotenv(ROOT / "HonorsThesis" / ".env")

OPENROUTER_API_KEY  = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_API_BASE = os.getenv("OPENROUTER_API_BASE", "https://openrouter.ai/api/v1").rstrip("/")
LLM_MODEL           = os.getenv("OPENROUTER_MODEL", "openai/gpt-4o-mini")
DEFAULT_TEMPERATURE = float(os.getenv("GEN_TEMPERATURE", "0.2"))
MAX_TOKENS          = int(os.getenv("GEN_MAX_TOKENS", "12000"))

if not OPENROUTER_API_KEY:
    print("ERROR: OPENROUTER_API_KEY not set in .env", file=sys.stderr)
    sys.exit(1)

def read_matrix():
    with open(MATRIX, newline="") as f:
        return list(csv.DictReader(f))

def write_matrix(rows):
    with open(MATRIX, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)

def update_matrix_status(app_id, status):
    rows = read_matrix()
    for r in rows:
        if r["app_id"] == app_id:
            r["status"] = status
    write_matrix(rows)

def pick_next_app(rows):
    for r in rows:
        if r.get("status", "").strip().lower() in ("", "not_generated", "pending"):
            return r
    return None

def write_manifest_entry(entry):
    text = MANIFEST.read_text().strip() if MANIFEST.exists() else ""
    data = json.loads(text) if text else []
    data.append(entry)
    MANIFEST.write_text(json.dumps(data, indent=2))


SYSTEM_PROMPT = """\
You are a code generation assistant. Your job is to output a complete, working web application.

OUTPUT FORMAT — you MUST follow this exactly:
- Output every file using this delimiter on its own line:  === path/to/filename.ext ===
- Then immediately output the full file contents.
- Then the next === delimiter for the next file.
- No markdown fences (no ```). No explanation text between files.
- Always include: Dockerfile, requirements.txt (Python) or package.json (Node/React), and all source files.

Example:
=== requirements.txt ===
flask==2.3.0

=== app.py ===
from flask import Flask
app = Flask(__name__)

=== Dockerfile ===
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 8080
CMD ["python", "app.py"]

Output the COMPLETE application now. Every file. Full contents. No placeholders.\
"""

def call_llm(prompt_text):
    url     = f"{OPENROUTER_API_BASE}/chat/completions"
    headers = {"Authorization": f"Bearer {OPENROUTER_API_KEY}", "Content-Type": "application/json"}
    payload = {
        "model":       LLM_MODEL,
        "messages":    [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": prompt_text},
        ],
        "temperature": DEFAULT_TEMPERATURE,
        "max_tokens":  MAX_TOKENS,
    }
    resp = requests.post(url, json=payload, headers=headers, timeout=600)
    resp.raise_for_status()
    return resp.json()


def get_content(resp_json):
    try:
        return resp_json["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as e:
        raise ValueError(f"Cannot extract content from LLM response: {e}\nKeys: {list(resp_json.keys())}")


def parse_delimiter_blocks(content):
    pattern = re.compile(r'^===\s*(.+?)\s*===\s*$', re.MULTILINE)
    matches = list(pattern.finditer(content))
    if not matches:
        return None
    files = {}
    for i, m in enumerate(matches):
        filename = m.group(1).strip().lstrip('/')
        start    = m.end()
        end      = matches[i + 1].start() if i + 1 < len(matches) else len(content)
        body     = content[start:end].strip('\n')
        files[filename] = body
    return files or None


def parse_markdown_blocks(content):
    fence_re = re.compile(r'```(?:[a-zA-Z0-9_+-]*)?\n(.*?)```', re.DOTALL)
    blocks   = list(fence_re.finditer(content))
    if not blocks:
        return None

    lang_ext = {
        'python': 'py', 'py': 'py',
        'javascript': 'js', 'js': 'js', 'typescript': 'ts',
        'html': 'html', 'css': 'css',
        'dockerfile': 'Dockerfile', 'docker': 'Dockerfile',
        'yaml': 'yml', 'yml': 'yml', 'json': 'json',
        'txt': 'txt', 'sh': 'sh', 'php': 'php', 'plaintext': 'txt',
    }

    # Heading / filename hint pattern
    hint_re = re.compile(
        r'`([^`]+\.[a-z]{1,6})`'
        r'|###\s*\d+\.\s*[`\*]?([^\n`\*]+\.[a-z]{1,6})[`\*]?'
        r'|\*\*([^\*]+\.[a-z]{1,6})\*\*'
        r'|(?:^|\n)([a-zA-Z0-9_/.-]+\.[a-z]{1,6})\s*\n',
        re.IGNORECASE
    )

    files   = {}
    counter = {}

    for i, block in enumerate(blocks):
        code = block.group(1).rstrip('\n')
        if not code.strip():
            continue

        preceding = content[max(0, block.start() - 400): block.start()]
        hints     = hint_re.findall(preceding)
        filename  = None
        for groups in hints:
            candidate = next((g.strip() for g in groups if g.strip()), None)
            if candidate and '.' in candidate and len(candidate) < 80:
                filename = candidate.lstrip('/')
                break

        # Fallback: use lang tag from fence
        if not filename:
            lang_match = re.match(r'```([a-zA-Z0-9_+-]+)', content[block.start():block.start()+30])
            lang = lang_match.group(1).lower() if lang_match else 'txt'
            ext  = lang_ext.get(lang, lang)
            if ext == 'Dockerfile':
                filename = 'Dockerfile'
            else:
                counter[ext] = counter.get(ext, 0) + 1
                n = counter[ext]
                filename = f"file_{n:02d}.{ext}" if n > 1 else f"file.{ext}"

        if filename in files:
            base, _, ext2 = filename.rpartition('.')
            filename = f"{base}_{i}.{ext2}" if ext2 else f"{filename}_{i}"

        files[filename] = code

    return files or None

def write_files(appdir, files):
    for relpath, content in files.items():
        target = appdir / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding='utf-8')
    print(f"  Wrote {len(files)} file(s): {', '.join(sorted(files.keys()))}")


def commit_and_hash(appdir):
    try:
        subprocess.run(["git", "init"], cwd=appdir, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["git", "config", "user.email", "bench@thesis.local"], cwd=appdir,
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["git", "config", "user.name",  "Thesis Bench"], cwd=appdir,
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["git", "add", "."], cwd=appdir, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["git", "commit", "-m", "initial generated app"], cwd=appdir, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=appdir,
                             check=True, capture_output=True, text=True)
        return out.stdout.strip()
    except Exception as e:
        print(f"  [warn] git commit failed ({e}), using zip hash")
        zip_base = str(appdir) + "_hash_tmp"
        shutil.make_archive(zip_base, 'zip', root_dir=str(appdir))
        h = hashlib.sha256(Path(zip_base + ".zip").read_bytes()).hexdigest()
        Path(zip_base + ".zip").unlink(missing_ok=True)
        return h[:40]

def main():
    rows   = read_matrix()
    target = pick_next_app(rows)
    if not target:
        print("No apps left with status not_generated / pending.")
        return

    app_id      = target["app_id"]
    prompt_type = target["prompt_type"]
    stack       = target["stack"]

    pb      = json.loads(PROMPT_BANK.read_text())
    prompts = pb.get(prompt_type, {}).get("prompts", [])
    if not prompts:
        print(f"ERROR: no prompts for type '{prompt_type}'")
        return
    prompt_entry = prompts[0]
    prompt_text  = prompt_entry["prompt"].replace("{stack}", stack)

    req = {
        "app_id": app_id, "prompt_type": prompt_type,
        "prompt_id": prompt_entry["id"], "stack": stack,
        "prompt_text": prompt_text, "model": LLM_MODEL,
        "temperature": DEFAULT_TEMPERATURE,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    (RESPONSES_DIR / f"request_{app_id}.json").write_text(json.dumps(req, indent=2))

    update_matrix_status(app_id, "generating")
    print(f"[*] Generating {app_id} ({prompt_type}/{stack}) with {LLM_MODEL} ...")

    try:
        resp_json = call_llm(prompt_text)
        respfile  = RESPONSES_DIR / f"response_{app_id}.json"
        respfile.write_text(json.dumps(resp_json, indent=2))

        content = get_content(resp_json)
        print(f"  Response length: {len(content)} chars")

        files = parse_delimiter_blocks(content)
        if files:
            print(f"  Parser: delimiter format ({len(files)} files)")
        else:
            files = parse_markdown_blocks(content)
            if files:
                print(f"  Parser: markdown fences ({len(files)} files)")
            else:
                print("  [warn] No structured files found — saving raw output as MODEL_OUTPUT.txt")
                files = {"MODEL_OUTPUT.txt": content}

        appdir = APPS_DIR / app_id
        if appdir.exists():
            backup = APPS_DIR / f"{app_id}_backup_{int(time.time())}"
            appdir.rename(backup)
            print(f"  Backed up old dir → {backup.name}")
        appdir.mkdir(parents=True, exist_ok=True)
        write_files(appdir, files)

        commit_hash = commit_and_hash(appdir)
        print(f"  Commit hash: {commit_hash[:12]}...")

        entry = {
            "app_id":        app_id,
            "prompt_type":   prompt_type,
            "prompt_id":     prompt_entry["id"],
            "stack":         stack,
            "model_name":    LLM_MODEL,
            "temperature":   DEFAULT_TEMPERATURE,
            "seed":          None,
            "repo_path":     str(appdir.relative_to(ROOT)),
            "docker_image":  f"{app_id.lower()}_image:latest",
            "commit_hash":   commit_hash,
            "response_file": str(respfile.relative_to(ROOT)),
            "timestamp":     req["timestamp"],
        }
        write_manifest_entry(entry)
        update_matrix_status(app_id, "generated")
        print(f"[+] Done: {app_id} → {appdir}")

    except Exception as e:
        import traceback
        update_matrix_status(app_id, "generation_failed")
        errlog = LOGS_DIR / f"generate_{app_id}_error.log"
        errlog.write_text(traceback.format_exc())
        print(f"[!] Generation failed: {e}")
        print(f"    Traceback saved → {errlog}")

if __name__ == "__main__":
    main()