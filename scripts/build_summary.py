#!/usr/bin/env python3
"""Build concise report and only surface new high/critical findings."""
from __future__ import annotations
import json
from pathlib import Path

out=Path("artifacts")
out.mkdir(exist_ok=True)
def lines(name):
 p=out/name
 return [x for x in p.read_text(encoding="utf-8",errors="replace").splitlines() if x.strip()] if p.exists() else []
subs=lines("subs.txt"); new_subs=lines("subs_new.txt"); alive=lines("alive.txt"); ports=lines("ports.txt"); findings=lines("nuclei.jsonl"); newkeys=set(lines("findings_new.txt"))
severity={"critical":0,"high":0,"medium":0,"low":0,"info":0}
new_high=[]
for raw in findings:
 try: item=json.loads(raw)
 except json.JSONDecodeError: continue
 info=item.get("info") or {}
 sev=str(info.get("severity") or "info").lower()
 severity[sev]=severity.get(sev,0)+1
 key=f"{str(item.get('template-id','unknown')).lower()}|{str(item.get('matched-at','unknown')).lower()}|{sev}"
 if key in newkeys and sev in {"critical","high"}:
  new_high.append((sev,item.get("template-id","unknown"),item.get("matched-at","unknown")))
summary={"subdomains_total":len(subs),"subdomains_new":len(new_subs),"alive_urls":len(alive),"ports_open":len(ports),"findings_total":severity,"new_high_critical":len(new_high)}
Path("artifacts/summary.json").write_text(json.dumps(summary,indent=2)+"\n",encoding="utf-8")
text=["ReconQ ASM report",f"Subdomains: {len(subs)} (new {len(new_subs)})",f"Alive URLs: {len(alive)}",f"Open ports: {len(ports)}", "Findings: "+", ".join(f"{k}={v}" for k,v in severity.items()),f"New High/Critical: {len(new_high)}"]
for sev,tid,matched in new_high[:10]: text.append(f"[{sev.upper()}] {tid} — {matched}")
Path("artifacts/telegram-summary.txt").write_text("\n".join(text)+"\n",encoding="utf-8")
