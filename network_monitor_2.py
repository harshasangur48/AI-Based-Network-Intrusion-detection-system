#!/usr/bin/env python3
"""
network_monitor_2.py - dataset-driven monitor that posts every CSV row to NIDS API
and prints a console log similar to the screenshot (index/total + colored status + label/conf).

Usage example:
  python network_monitor_2.py \
    --api http://127.0.0.1:8000 \
    --csv test_data.csv \
    --class-map class_mapping.json \
    --delay 0.25 \
    --max 0 \
    --shuffle \
    --print-payload

Options:
  --max N            : max rows to send (0 = all)
  --shuffle          : shuffle rows
  --delay FLOAT      : seconds to sleep between posts
  --iface STR        : value for _meta.iface sent to backend (default "Wi-Fi")
  --print-payload    : print the JSON payload being sent (for debugging)
"""

import argparse
import json
import math
import sys
import time
from pathlib import Path
from random import shuffle

import pandas as pd
import requests


# ---------------------------
# Console helpers (ANSI)
# ---------------------------
CSI = "\x1b["
RESET = CSI + "0m"
BOLD = CSI + "1m"
GREEN = CSI + "32m"
RED = CSI + "31m"
YELLOW = CSI + "33m"
DIM = CSI + "2m"

def colored_dot(ok: bool) -> str:
    # return a green dot for benign, red for malicious
    dot = "●"
    return (GREEN + dot + RESET) if ok else (RED + dot + RESET)

def format_count(i: int, total: int) -> str:
    return f"[{i}/{total}]"

def short_label(lbl: str) -> str:
    # shorten long labels a bit for neat display
    return str(lbl)

# ---------------------------
# CLI
# ---------------------------
parser = argparse.ArgumentParser()
parser.add_argument("--api", required=True, help="NIDS API base URL (e.g. http://127.0.0.1:8000)")
parser.add_argument("--csv", required=True, help="CSV file with features (CICIDS style)")
parser.add_argument("--class-map", required=False, help="Optional class mapping JSON (not required if backend provides)")
parser.add_argument("--max", type=int, default=0, help="Max rows to send (0 = all)")
parser.add_argument("--delay", type=float, default=0.0, help="Delay seconds between POSTs")
parser.add_argument("--shuffle", action="store_true", help="Shuffle rows before sending")
parser.add_argument("--iface", default="Wi-Fi", help="_meta.iface tag to send")
parser.add_argument("--print-payload", action="store_true", help="Print each JSON payload before sending (debug)")
args = parser.parse_args()

API = args.api.rstrip("/")  # no trailing slash
HEALTHZ = API + "/healthz"
PREDICT = API + "/predict_flow/"

# ---------------------------
# Load CSV
# ---------------------------
csv_path = Path(args.csv)
if not csv_path.exists():
    print("CSV not found:", csv_path)
    sys.exit(1)

df = pd.read_csv(csv_path)
# drop unnamed index columns commonly present
df = df.loc[:, ~df.columns.str.contains("^Unnamed")]

# If label column present keep it separate (not sent to API)
label_col = None
for c in ("label", "Label", "class", "Class"):
    if c in df.columns:
        label_col = c
        break

# ---------------------------
# Ask backend for expected features and mapping
# ---------------------------
try:
    resp = requests.get(HEALTHZ, timeout=5)
    resp.raise_for_status()
    health = resp.json()
    expected_features = health.get("features", [])
    id2label_backend = health.get("id2label", {}) or {}
    benign_ids = health.get("benign_ids", []) or []
except Exception as e:
    print("WARNING: could not fetch /healthz from backend — falling back to CSV columns.")
    expected_features = [c.lower().strip() for c in df.columns if c != label_col]
    id2label_backend = {}
    benign_ids = []

# Normalize expected_features to snake-case like your backend shows it
expected_features = [str(f).strip() for f in expected_features]

# ---------------------------
# Build mapping heuristics
# ---------------------------
# We'll try to map CSV columns to backend feature keys using several heuristics:
# - lowercase and replace punctuation with underscores
# - remove percent signs and trailing / characters
def normalize_name(x: str) -> str:
    s = str(x).strip()
    s = s.replace("%", "pct")
    for ch in (" ", "-", "/", "\\", "(", ")"):
        s = s.replace(ch, "_")
    s = "".join(c for c in s if (c.isalnum() or c == "_"))
    while "__" in s:
        s = s.replace("__", "_")
    return s.lower()

csv_cols_norm = {normalize_name(c): c for c in df.columns}
expected_norm = [normalize_name(c) for c in expected_features]

# mapping from expected_feature -> csv_column (original name)
feature_to_csv = {}
for idx, en in enumerate(expected_features):
    norm = expected_norm[idx]
    if norm in csv_cols_norm:
        feature_to_csv[en] = csv_cols_norm[norm]
    else:
        # try some common renamed variants:
        # - remove trailing s or /s variants
        alt = norm.rstrip("s")
        if alt in csv_cols_norm:
            feature_to_csv[en] = csv_cols_norm[alt]
        else:
            # ultimately no mapping found -> will fill with zeros later
            feature_to_csv[en] = None

# ---------------------------
# Prepare rows to send
# ---------------------------
rows = df.to_dict(orient="records")
total = len(rows)
if args.shuffle:
    shuffle(rows)

if args.max and args.max > 0:
    rows = rows[: args.max]
    total = len(rows)

session = requests.Session()

print(f"Loaded {total} rows from CSV ({csv_path}). Sending to {PREDICT}")
print(f"Backend expected features: {len(expected_features)} keys")

# ---------------------------
# Main loop: send every row
# ---------------------------
for i, row in enumerate(rows, start=1):
    # Build features dict in exact expected_features order/keys
    features = {}
    for ef in expected_features:
        src_col = feature_to_csv.get(ef)
        if src_col:
            v = row.get(src_col, 0)
            # convert NaN -> 0.0
            try:
                if pd.isna(v):
                    v = 0.0
            except Exception:
                pass
            # ensure numeric when possible
            try:
                features[ef] = float(v)
            except Exception:
                # keep as-is (strings) if conversion fails
                features[ef] = v
        else:
            # no mapping found: zero-fill
            features[ef] = 0.0

    payload = {"features": features, "_meta": {"iface": args.iface, "demo": True}}

    if args.print_payload:
        print(DIM + "[PAYLOAD]" + RESET)
        print(json.dumps(payload, indent=2))
        print(DIM + "[/PAYLOAD]" + RESET)

    # send
    try:
        r = session.post(PREDICT, json=payload, timeout=8)
    except Exception as e:
        print(format_count(i, total), RED + "POST ERROR" + RESET, e)
        time.sleep(args.delay)
        continue

    # interpret response
    if r.status_code == 200:
        try:
            j = r.json()
        except Exception:
            j = {"predicted_class": str(r.text)[:120], "confidence": 0.0, "intrusion_detected": False}

        pred_label = j.get("predicted_class", str(j.get("pred", "")))
        conf = j.get("confidence", j.get("score", 0.0))
        intr = j.get("intrusion_detected", None)

        # determine benign vs malicious for dot color:
        ok = not bool(intr) if intr is not None else (str(pred_label).strip().lower() in ("benign", "normal"))
        dot = colored_dot(ok)

        # index/total display
        left = format_count(i, total)

        # pretty line: [i/total] ● LABEL (conf=0.99)
        # mimic your screenshot spacing and style
        label_text = short_label(pred_label)
        conf_text = f"(conf={float(conf):.2f})"
        print(f"{left} {dot} {BOLD}{label_text}{RESET} {DIM}{conf_text}{RESET}")

    else:
        # non-200 -> print error and server body (useful for 422)
        # keep body short
        body = r.text
        if len(body) > 300:
            body = body[:300] + "..."
        print(f"{format_count(i, total)} {YELLOW}POST ERROR {r.status_code}{RESET}: {body}")

    # small delay to not flood
    if args.delay:
        time.sleep(args.delay)

print("Replay complete.")
