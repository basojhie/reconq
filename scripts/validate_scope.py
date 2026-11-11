#!/usr/bin/env python3
"""Validate explicit root-domain scope and filter discovered hostnames."""
from __future__ import annotations
import ipaddress
import re
import sys
from pathlib import Path

DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

def read_domains(path: str) -> list[str]:
    file = Path(path)
    if not file.exists():
        return []
    result = []
    for raw in file.read_text(encoding="utf-8").splitlines():
        value = raw.split("#", 1)[0].strip().rstrip(".").lower()
        if not value:
            continue
        try:
            ipaddress.ip_address(value)
        except ValueError:
            pass
        else:
            raise ValueError(f"IP literals are not allowed in {path}: {value}")
        if not DOMAIN.fullmatch(value):
            raise ValueError(f"Invalid domain in {path}: {value}")
        result.append(value)
    return sorted(set(result))

def within(host: str, roots: list[str]) -> bool:
    return any(host == root or host.endswith("." + root) for root in roots)

def in_authorized_scope(host: str, roots: list[str], exclusions: list[str]) -> bool:
    return within(host, roots) and not within(host, exclusions)

def filter_assets(candidates: list[str], roots: list[str], exclusions: list[str]) -> list[str]:
    return sorted({
        host.rstrip(".").lower()
        for host in candidates
        if DOMAIN.fullmatch(host.rstrip(".").lower())
        and in_authorized_scope(host.rstrip(".").lower(), roots, exclusions)
    })

def main() -> int:
    roots_path = sys.argv[3] if len(sys.argv) > 3 else "scope/scope.txt"
    roots = read_domains(roots_path)
    exclusions = read_domains("scope/out-of-scope.txt")
    if not roots:
        print("ERROR: scope/scope.txt is empty; add explicitly authorized root domains.", file=sys.stderr)
        return 2
    candidates = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace").splitlines()
    accepted = filter_assets(candidates, roots, exclusions)
    Path(sys.argv[2]).write_text("\n".join(accepted) + ("\n" if accepted else ""), encoding="utf-8")
    print(f"Scope roots={len(roots)} exclusions={len(exclusions)} accepted={len(accepted)}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
