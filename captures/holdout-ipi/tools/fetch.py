#!/usr/bin/env python3
"""HELD-OUT set holdout-ipi: deterministic fetch + sample of public, permissively licensed INDIRECT
prompt-injection datasets that were NOT used to build or tune T3 and are not in captures/holdout-hf.

Defensive evaluation data only. Every sampled string is copied VERBATIM from the pinned upstream file;
nothing is authored here. Output: captures/holdout-ipi/upstream/<slug>.json (committed).

    python3 captures/holdout-ipi/tools/fetch.py            # re-fetch and rewrite upstream/*.json
    python3 captures/holdout-ipi/tools/fetch.py --check    # re-fetch and fail if anything differs

Same pattern as captures/holdout-hf/tools/fetch_hf.py:
  * each file is fetched at a pinned revision (HF dataset sha or GitHub commit) and its SHA-256 must match
    tools/pins.json (fail-loud on drift);
  * rows are deduplicated by exact text; rows whose text is already in captures/variants (main corpus) OR in
    captures/holdout-hf (the other held-out set) are dropped; then rows are ordered by
    sha256(SEED + ":" + text) and the first N per class are taken.
Bounds (fail-loud): SAMPLE_PER_CLASS rows per class per source; rows over MAX_ROW_CHARS are skipped AND
counted in `selection.skipped` (never silently). Category exclusions (BIPIA) are counted the same way.
Needs: Python 3.10+ only (all sources are JSON). Raw downloads are cached in .cache/ (gitignored).
"""
import hashlib, json, sys, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent  # captures/holdout-ipi
REPO = HERE.parent.parent
CACHE = HERE / ".cache"
OUT = HERE / "upstream"
SEED = "holdout-ipi-v1"
SAMPLE_PER_CLASS = 100
MAX_ROW_CHARS = 8000

LLMAIL = {"repo": "microsoft/llmail-inject-challenge", "revision": "1063bdf01ec8762b812d5e06ee768a06faa5a6f7", "host": "hf",
          "license": "MIT"}
BIPIA = {"repo": "microsoft/BIPIA", "revision": "a004b69ec0dd446e0afd461d98cb5e96e120a5d0", "host": "github", "license": "MIT"}

# BIPIA categories we deliberately do NOT sample (counted in skipped.excludedCategory):
#  - text: harmful-content goals (fraud / propaganda) rather than injection mechanics;
#  - code: destructive-malware goals (ransomware, DoS, OS corruption, keylogging, compromise).
# Kept: every text task-hijack category, and the code categories whose goal is data exfiltration / recon.
BIPIA_TEXT_EXCLUDE = {"Scams & Fraud", "Misinformation & Propaganda"}
BIPIA_CODE_KEEP = {"Data Eavesdropping", "Traffic Analysis", "Screen Scraping", "Introduce System Fingerprinting"}


def llmail_rows(data):
    d = json.loads(data)
    out = []
    for i, (text, meta) in enumerate(d.items()):
        a = str(meta.get("attack_attempt"))
        gt = {"True": "positive", "False": "negative"}.get(a)  # "Unclear" -> skipped (counted)
        out.append({"idx": i, "text": text, "gt": gt, "upstreamLabel": {"attack_attempt": meta.get("attack_attempt"), "reason": meta.get("reason")},
                    "skip": None if gt else "labelUnclear"})
    return out


def llmail_fp_rows(data):
    return [{"idx": i, "text": t, "gt": "negative", "upstreamLabel": "benign email (emails_for_fp_tests)", "skip": None}
            for i, t in enumerate(json.loads(data))]


def bipia_rows(keep):
    def f(data):
        out, i = [], 0
        for cat, items in json.loads(data).items():
            for j, t in enumerate(items):
                out.append({"idx": i, "text": t, "gt": "positive", "upstreamLabel": {"category": cat, "index": j},
                            "skip": None if keep(cat) else "excludedCategory"})
                i += 1
        return out
    return f


SOURCES = [
    {**LLMAIL, "slug": "llmail-inject", "file": "data/labelled_unique_submissions_phase2.json", "split": "Phase2 (labelled unique submissions)",
     "kind": "indirect_prompt_injection", "rows": llmail_rows,
     "rowIdxNote": "0-based position in the top-level JSON object (insertion order)"},
    {**LLMAIL, "slug": "llmail-fp", "file": "data/emails_for_fp_tests.json", "split": "emails_for_fp_tests (benign)",
     "kind": "benign_email", "rows": llmail_fp_rows, "rowIdxNote": "0-based index in the JSON array"},
    {**BIPIA, "slug": "bipia-text", "file": "benchmark/text_attack_test.json", "split": "test",
     "kind": "indirect_prompt_injection", "rows": bipia_rows(lambda c: c not in BIPIA_TEXT_EXCLUDE),
     "rowIdxNote": "0-based running index over categories in file order"},
    {**BIPIA, "slug": "bipia-code", "file": "benchmark/code_attack_test.json", "split": "test",
     "kind": "indirect_prompt_injection", "rows": bipia_rows(lambda c: c in BIPIA_CODE_KEEP),
     "rowIdxNote": "0-based running index over categories in file order"},
]

PINS_FILE = HERE / "tools" / "pins.json"


def sha(b):
    return hashlib.sha256(b).hexdigest()


def url_of(src):
    if src["host"] == "hf":
        return f"https://huggingface.co/datasets/{src['repo']}/resolve/{src['revision']}/{src['file']}"
    return f"https://raw.githubusercontent.com/{src['repo']}/{src['revision']}/{src['file']}"


def page_of(src):
    if src["host"] == "hf":
        return f"https://huggingface.co/datasets/{src['repo']}/blob/{src['revision']}/{src['file']}"
    return f"https://github.com/{src['repo']}/blob/{src['revision']}/{src['file']}"


def fetch(src):
    CACHE.mkdir(exist_ok=True)
    local = CACHE / f"{src['slug']}-{src['revision'][:12]}-{Path(src['file']).name}"
    if not local.exists():
        with urllib.request.urlopen(url_of(src), timeout=300) as r:
            local.write_bytes(r.read())
    return local.read_bytes()


def excluded_texts():
    """Strings already in the main corpus (captures/variants) or the other held-out set (captures/holdout-hf)."""
    seen = set()
    for p in (REPO / "captures" / "variants" / "fixtures").rglob("*.json"):
        fx = json.loads(p.read_text())
        for m in fx.get("request", {}).get("messages", []):
            if isinstance(m.get("content"), str):
                seen.add(m["content"].strip())
        t = (fx.get("source", {}).get("upstream") or {}).get("text")
        if isinstance(t, str):
            seen.add(t.strip())
    hf = {}
    for p in (REPO / "captures" / "holdout-hf" / "upstream").glob("*.json"):
        for k, rows in json.loads(p.read_text())["rows"].items():
            for r in rows:
                hf[r["text"].strip()] = 1
    return seen, set(hf)


def main():
    check = "--check" in sys.argv
    pins = json.loads(PINS_FILE.read_text()) if PINS_FILE.exists() else {}
    main_texts, hf_texts = excluded_texts()
    failed = False
    for src in SOURCES:
        data = fetch(src)
        digest = sha(data)
        pin = pins.get(src["slug"])
        if pin and pin != digest:
            raise SystemExit(f"ERROR {src['slug']}: file sha256 {digest} != pinned {pin} (upstream drift; refusing)")
        pins[src["slug"]] = digest
        rows = src["rows"](data)
        seen, by_class = set(), {"positive": [], "negative": []}
        skipped = {"duplicate": 0, "inMainCorpus": 0, "inHoldoutHf": 0, "empty": 0, "overMaxRowChars": 0, "labelUnclear": 0, "excludedCategory": 0}
        for r in rows:
            text = r["text"]
            if r["skip"]:
                skipped[r["skip"]] += 1
                continue
            if not isinstance(text, str) or not text.strip():
                skipped["empty"] += 1
                continue
            if text in seen:
                skipped["duplicate"] += 1
                continue
            seen.add(text)
            if text.strip() in main_texts:
                skipped["inMainCorpus"] += 1
                continue
            if text.strip() in hf_texts:
                skipped["inHoldoutHf"] += 1
                continue
            if len(text) > MAX_ROW_CHARS:
                skipped["overMaxRowChars"] += 1
                continue
            by_class[r["gt"]].append({"rowIdx": r["idx"], "text": text, "sha256": sha(text.encode("utf-8")), "upstreamLabel": r["upstreamLabel"]})
        order = lambda row: sha(f"{SEED}:{row['text']}".encode("utf-8"))
        sample = {k: sorted(v, key=order)[:SAMPLE_PER_CLASS] for k, v in by_class.items()}
        out = {
            "slug": src["slug"], "repo": src["repo"], "host": src["host"], "revision": src["revision"], "file": src["file"],
            "fileSha256": digest, "split": src["split"], "license": src["license"], "kind": src["kind"],
            "url": page_of(src), "rowIdx": src["rowIdxNote"],
            "selection": {"seed": SEED, "order": "sha256(seed + ':' + text) ascending", "perClass": SAMPLE_PER_CLASS,
                          "maxRowChars": MAX_ROW_CHARS, "eligible": {k: len(v) for k, v in by_class.items()},
                          "totalRows": len(rows), "skipped": skipped},
            "rows": {k: sorted(v, key=lambda x: x["rowIdx"]) for k, v in sample.items()},
        }
        text = json.dumps(out, indent=1, ensure_ascii=False) + "\n"
        dest = OUT / f"{src['slug']}.json"
        if check:
            same = dest.exists() and dest.read_text() == text
            print(("OK   " if same else "DIFF ") + str(dest.relative_to(REPO)))
            failed |= not same
        else:
            OUT.mkdir(exist_ok=True)
            dest.write_text(text)
            print(f"wrote {dest.relative_to(REPO)}: pos={len(sample['positive'])} neg={len(sample['negative'])} skipped={skipped}")
    if not check:
        PINS_FILE.write_text(json.dumps(pins, indent=1) + "\n")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
