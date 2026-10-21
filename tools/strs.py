#!/usr/bin/env python
"""Minimal `strings` replacement: python strs.py <file> <regex> [minlen]"""
import re, sys
data = open(sys.argv[1], "rb").read()
pat = re.compile(sys.argv[2], re.I)
minlen = int(sys.argv[3]) if len(sys.argv) > 3 else 5
seen = set()
for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, data):
    s = m.group().decode()
    if pat.search(s) and s not in seen:
        seen.add(s); print(f"{m.start():#010x} A {s}")
for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minlen, data):
    s = m.group().decode("utf-16-le")
    if pat.search(s) and s not in seen:
        seen.add(s); print(f"{m.start():#010x} W {s}")
