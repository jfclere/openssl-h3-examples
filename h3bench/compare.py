#!/usr/bin/env python3
"""Compare benchmark results from two (or more) result files.

Usage:  python3 compare.py results.httpd results.tomcat
"""
import json
import re
import sys

def parse_results(path):
    """Extract the last merged summary per case from a results file."""
    cases = {}
    with open(path) as f:
        for line in f:
            m = re.match(r'^(\S+:\S+)\s+(\{.*\})\s*$', line)
            if m:
                cases[m.group(1)] = json.loads(m.group(2))
    return cases

def case_key(name):
    """Strip the tag prefix to get the case name (e.g. 'idle100' from 'httpd:idle100')."""
    return name.split(":", 1)[1] if ":" in name else name

def tag_name(name):
    return name.split(":", 1)[0] if ":" in name else name

if len(sys.argv) < 3:
    print(f"Usage: {sys.argv[0]} results.A results.B [results.C ...]")
    sys.exit(1)

files = sys.argv[1:]
all_data = {}
tags = []
for path in files:
    cases = parse_results(path)
    if not cases:
        print(f"WARNING: no results found in {path}")
        continue
    tag = tag_name(next(iter(cases)))
    tags.append(tag)
    for full_name, data in cases.items():
        ck = case_key(full_name)
        if tag not in all_data:
            all_data[tag] = {}
        all_data[tag][ck] = data

case_order = ["idle100", "idle1000", "idle2000", "idle4000", "idle8000",
              "1x1", "1x32", "1x64", "1x100", "1x150",
              "4x25", "8x25", "2x75", "16x16", "32x32"]
all_cases = []
for c in case_order:
    if any(c in all_data.get(t, {}) for t in tags):
        all_cases.append(c)
for tag in tags:
    for c in sorted(all_data.get(tag, {})):
        if c not in all_cases:
            all_cases.append(c)

metrics = [
    ("conns",       "conns",  "{:>6}",   "{:>6}"),
    ("rps",         "rps",    "{:>8}",   "{:>8.1f}"),
    ("p50ms",       "p50ms",  "{:>8}",   "{:>8.2f}"),
    ("p99ms",       "p99ms",  "{:>8}",   "{:>8.2f}"),
    ("errs",        "errs",   "{:>6}",   "{:>6}"),
    ("srv%",        "server_pct", "{:>6}", "{:>6.1f}"),
    ("us/req",      "us_per_req", "{:>8}", "{:>8.1f}"),
]

col_w = max(len(t) for t in tags) + 1
col_w = max(col_w, 8)

def sep_line(ncols):
    return "-" * (12 + ncols * (sum(int(m[2].split(">")[1].rstrip("}")) for m in metrics) + len(metrics) + 4))

print()
print(f"{'case':<12}", end="")
for tag in tags:
    header = "  |"
    for label, _, hfmt, _ in metrics:
        w = int(hfmt.split(">")[1].rstrip("}"))
        header += f" {label:>{w}}"
    print(f"  {tag:^{len(header)-2}}", end="")
print()

print(f"{'':<12}", end="")
for tag in tags:
    header = "  |"
    for label, _, hfmt, _ in metrics:
        w = int(hfmt.split(">")[1].rstrip("}"))
        header += f" {label:>{w}}"
    print(header, end="")
print()

print(f"{'':=<12}", end="")
for tag in tags:
    dashes = "==+"
    for _, _, hfmt, _ in metrics:
        w = int(hfmt.split(">")[1].rstrip("}"))
        dashes += "=" * (w + 1)
    print(dashes, end="")
print()

for case in all_cases:
    print(f"{case:<12}", end="")
    for tag in tags:
        data = all_data.get(tag, {}).get(case)
        print("  |", end="")
        if data is None:
            for _, _, hfmt, _ in metrics:
                w = int(hfmt.split(">")[1].rstrip("}"))
                print(f" {'--':>{w}}", end="")
        else:
            for _, key, _, vfmt in metrics:
                v = data.get(key, 0)
                print(" " + vfmt.format(v), end="")
    print()

print()

has_load = any(not c.startswith("idle") for c in all_cases)
has_idle = any(c.startswith("idle") for c in all_cases)
if len(tags) == 2 and has_load:
    a, b = tags
    print(f"  rps ratio ({a} / {b}):")
    for case in all_cases:
        if case.startswith("idle"):
            continue
        da = all_data.get(a, {}).get(case)
        db = all_data.get(b, {}).get(case)
        if da and db and db.get("rps", 0) > 0:
            ratio = da["rps"] / db["rps"]
            print(f"    {case:<12}  {ratio:.2f}x")
    print()

if len(tags) == 2 and has_idle:
    a, b = tags
    print(f"  server CPU ratio ({a} / {b}):")
    for case in all_cases:
        if not case.startswith("idle"):
            continue
        da = all_data.get(a, {}).get(case)
        db = all_data.get(b, {}).get(case)
        if da and db and db.get("server_pct", 0) > 0:
            ratio = da["server_pct"] / db["server_pct"]
            print(f"    {case:<12}  {ratio:.2f}x")
    print()
