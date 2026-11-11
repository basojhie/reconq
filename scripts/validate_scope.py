#!/usr/bin/env python3
"""Normalize and enforce explicit root-domain scope for ReconQ Actions."""
from __future__ import annotations
import ipaddress
import re
import sys
from pathlib import Path

DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

def read(path: str) -> list[str]:
    p = Path(path)
    if not p.exists():
        return []
    values=[]
    for raw in p.read_text(encoding="utf-8").splitlines():
        item=raw.split("#",1)[0].strip().rstrip(".").lower()
        if not item:
            continue
        try:
            ipaddress.ip_address(item)
        except ValueError:
            pass
        else:
            raise ValueError(f"IP literals are not accepted in {path}: {item}")
        if not DOMAIN.fullmatch(item):
            raise ValueError(f"Invalid domain in {path}: {item}")
        values.append(item)
    return sorted(set(values))

def within(host: str, roots: list[str]) -> bool:
    return any(host == root or host.endswith("." + root) for root in roots)

def main() -> int:
    roots=read("scope/scope.txt")
    excluded=read("scope/out-of-scope.txt")
    if not roots:
        print("ERROR: scope/scope.txt is empty. Add authorized root domains before running.", file=sys.stderr)
        return 2
    assets=[]
    for raw in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
        host=raw.strip().rstrip(".").lower()
        if not host:
            continue
        if not DOMAIN.fullmatch(host):
            continue
        if within(host, roots) and not within(host, excluded):
            assets.append(host)
    Path(sys.argv[2]).write_text("\n".join(sorted(set(assets))) + ("\n" if assets else ""), encoding="utf-8")
    print(f"Scope roots: {len(roots)}; exclusions: {len(excluded)}; accepted assets: {len(set(assets))}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
