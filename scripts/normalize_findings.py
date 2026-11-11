#!/usr/bin/env python3
"""Create deterministic, timestamp-free keys for structured findings."""
from __future__ import annotations
import json, sys
from pathlib import Path

source=Path(sys.argv[1])
keys=[]
if source.exists():
    for line in source.read_text(encoding="utf-8",errors="replace").splitlines():
        try:
            item=json.loads(line)
        except json.JSONDecodeError:
            continue
        template=str(item.get("template-id") or item.get("templateID") or "unknown").lower()
        matched=str(item.get("matched-at") or item.get("matched") or item.get("host") or "unknown").lower()
        severity=str((item.get("info") or {}).get("severity") or item.get("severity") or "unknown").lower()
        keys.append(f"{template}|{matched}|{severity}")
print("\n".join(sorted(set(keys))))
