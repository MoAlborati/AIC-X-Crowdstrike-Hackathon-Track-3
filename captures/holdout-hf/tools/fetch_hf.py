#!/usr/bin/env python3
"""T6c: deterministic fetch + sample of public Hugging Face prompt-injection / jailbreak datasets.

Defensive evaluation data only. Every sampled string is copied VERBATIM from the pinned upstream file;
nothing is authored here. Output: captures/holdout-hf/upstream/<slug>.json (committed).

    python3 captures/holdout-hf/tools/fetch_hf.py            # re-fetch and rewrite upstream/*.json
    python3 captures/holdout-hf/tools/fetch_hf.py --check    # re-fetch and fail if anything differs

Determinism:
  * each source file is fetched at a pinned dataset revision (git sha) and its SHA-256 must match the pin;
  * rows are deduplicated by exact text, rows whose text already appears in captures/variants (the main
    corpus) are dropped, then rows are ordered by sha256(SEED + ":" + text) and the first N are taken.
Bounds (fail-loud): up to SAMPLE_PER_CLASS rows per class per dataset; any single row over MAX_ROW_CHARS is
skipped AND counted in the output's `skipped` block (never silently); the downloaded file must match its pin.
Needs: Python 3.10+, and pyarrow for the one parquet source (Lakera). Raw downloads are cached in
captures/holdout-hf/.cache/ (gitignored).
"""
import csv, hashlib, io, json, os, sys, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent  # captures/holdout-hf
REPO = HERE.parent.parent
CACHE = HERE / ".cache"
OUT = HERE / "upstream"
SEED = "t6c-holdout-hf-v1"
SAMPLE_PER_CLASS = 100
MAX_ROW_CHARS = 8000  # keeps the committed set < 2 MB; overflow rows are itemized, not hidden

SOURCES = [
    {
        "slug": "jackhhao-jailbreak",
        "repo": "jackhhao/jailbreak-classification",
        "revision": "2f2ceeb39658696fd3f462403562b6eea5306287",
        "file": "balanced/jailbreak_dataset_test_balanced.csv",
        "split": "test",
        "license": "Apache-2.0",
        "format": "csv",
        "text": "prompt",
        "label": lambda r: {"jailbreak": "positive", "benign": "negative"}[r["type"]],
        "kind": "jailbreak",
    },
    {
        "slug": "lakera-gandalf",
        "repo": "Lakera/gandalf_ignore_instructions",
        "revision": "04737b65e90a6794ec227012e4a255a7def6344b",
        "file": "data/test-00000-of-00001-bc92128b9288a6d1.parquet",
        "split": "test",
        "license": "MIT",
        "format": "parquet",
        "text": "text",
        "label": lambda r: "positive",  # every row is a Gandalf 'ignore instructions' injection attempt
        "kind": "prompt_injection",
    },
    {
        "slug": "spml-chatbot-pi",
        "repo": "reshabhs/SPML_Chatbot_Prompt_Injection",
        "revision": "02ce8084e979bc7d4c24ee35d22ecb7f2db96ff5",
        "file": "spml_prompt_injection.csv",
        "split": "train (single file; dataset has no split)",
        "license": "MIT",
        "format": "csv",
        "text": "User Prompt",
        "label": lambda r: {"1": "positive", "0": "negative"}[r["Prompt injection"].strip()],
        "kind": "prompt_injection",
    },
]

PINS_FILE = HERE / "tools" / "pins.json"  # file sha256 pins, written on first fetch, enforced afterwards


def sha(b):
    return hashlib.sha256(b).hexdigest()


def fetch(src):
    CACHE.mkdir(exist_ok=True)
    local = CACHE / f"{src['slug']}-{src['revision'][:12]}-{Path(src['file']).name}"
    if not local.exists():
        url = f"https://huggingface.co/datasets/{src['repo']}/resolve/{src['revision']}/{src['file']}"
        with urllib.request.urlopen(url, timeout=120) as r:
            local.write_bytes(r.read())
    return local.read_bytes()


def rows_of(src, data):
    if src["format"] == "csv":
        return list(csv.DictReader(io.StringIO(data.decode("utf-8"))))
    import pyarrow.parquet as pq
    return pq.read_table(io.BytesIO(data)).to_pylist()


def main_corpus_texts():
    """Every upstream string already in the main corpus (captures/variants), so the held-out set is disjoint."""
    seen = set()
    for p in (REPO / "captures" / "variants" / "fixtures").rglob("*.json"):
        fx = json.loads(p.read_text())
        for m in fx.get("request", {}).get("messages", []):
            if isinstance(m.get("content"), str):
                seen.add(m["content"].strip())
        t = (fx.get("source", {}).get("upstream") or {}).get("text")
        if isinstance(t, str):
            seen.add(t.strip())
    return seen


def main():
    check = "--check" in sys.argv
    pins = json.loads(PINS_FILE.read_text()) if PINS_FILE.exists() else {}
    main_texts = main_corpus_texts()
    failed = False
    for src in SOURCES:
        data = fetch(src)
        digest = sha(data)
        pin = pins.get(src["slug"])
        if pin and pin != digest:
            raise SystemExit(f"ERROR {src['slug']}: file sha256 {digest} != pinned {pin} (upstream drift; refusing)")
        pins[src["slug"]] = digest
        rows = rows_of(src, data)
        seen, by_class = set(), {"positive": [], "negative": []}
        skipped = {"duplicate": 0, "inMainCorpus": 0, "empty": 0, "overMaxRowChars": 0}
        for idx, r in enumerate(rows):
            text = r[src["text"]]
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
            if len(text) > MAX_ROW_CHARS:
                skipped["overMaxRowChars"] += 1
                continue
            row = {"rowIdx": idx, "text": text, "sha256": sha(text.encode("utf-8")), "upstreamLabel": None}
            if src["slug"] == "jackhhao-jailbreak":
                row["upstreamLabel"] = r["type"]
            elif src["slug"] == "spml-chatbot-pi":
                row["upstreamLabel"] = r["Prompt injection"].strip()
                row["upstreamSource"] = r.get("Source")
                row["degree"] = r.get("Degree")
            else:
                row["upstreamLabel"] = "injection (all rows)"
            by_class[src["label"](r)].append(row)
        order = lambda row: sha(f"{SEED}:{row['text']}".encode("utf-8"))
        sample = {k: sorted(v, key=order)[:SAMPLE_PER_CLASS] for k, v in by_class.items()}
        out = {
            "slug": src["slug"], "repo": src["repo"], "revision": src["revision"], "file": src["file"],
            "fileSha256": digest, "split": src["split"], "license": src["license"], "kind": src["kind"],
            "url": f"https://huggingface.co/datasets/{src['repo']}/blob/{src['revision']}/{src['file']}",
            "selection": {"seed": SEED, "order": "sha256(seed + ':' + text) ascending", "perClass": SAMPLE_PER_CLASS,
                          "maxRowChars": MAX_ROW_CHARS, "eligible": {k: len(v) for k, v in by_class.items()},
                          "totalRows": len(rows), "skipped": skipped},
            "rows": {k: sorted(v, key=lambda x: x["rowIdx"]) for k, v in sample.items()},
        }
        text = json.dumps(out, indent=1, ensure_ascii=False) + "\n"
        dest = OUT / f"{src['slug']}.json"
        if check:
            if not dest.exists() or dest.read_text() != text:
                print(f"DIFF {dest.relative_to(REPO)}"); failed = True
            else:
                print(f"OK   {dest.relative_to(REPO)}")
        else:
            OUT.mkdir(exist_ok=True)
            dest.write_text(text)
            print(f"wrote {dest.relative_to(REPO)}: pos={len(sample['positive'])} neg={len(sample['negative'])} skipped={skipped}")
    if not check:
        PINS_FILE.write_text(json.dumps(pins, indent=1) + "\n")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
