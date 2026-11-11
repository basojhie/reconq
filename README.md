# ReconQ — Roadmap-driven ASM

ReconQ integrates a Telegram command bot with a scope-gated GitHub Actions workflow.
The current workflow performs passive subdomain discovery, DNS resolution, HTTP
metadata probing, state diffing, artifact packaging and optional Telegram reporting.

## Roadmap alignment

| Roadmap phase | Implementation |
|---|---|
| Phase 1 — reconnaissance foundation | Pinned Subfinder, dnsx and HTTPx in the cloud runner; existing bot DNS/HTTPS metadata |
| Phase 2 — CI/CD automation | `.github/workflows/recon.yml`, scheduled + manual dispatch, artifact retention, scoped permissions, concurrency |
| Phase 3 — Termux command center | Root-level `reconq` script: baseline/recon dispatch and last-run inspection |
| Phase 4 — Telegram reporting | `/scan` triggers GitHub Actions after checking `scope/scope.txt`; `/last` reads recent workflow runs; Actions sends optional report |
| Phase 5 — expansion and diff tracking | State branch, baseline mode, asset delta, normalized findings helper; active port/vulnerability phases are intentionally gated/deferred |

## Required files and scope

- `scope/scope.txt`: one authorized root domain per line. It is empty by default so scans stop until the operator explicitly populates it.
- `scope/out-of-scope.txt`: exact domain/subdomain exclusions. Exclusions override roots.
- `state/`: asset state stored in a dedicated `state` branch when the state token is configured.

Never add a target unless you own it or have explicit written authorization to assess it.
Subfinder results are filtered back through the authorized root scope before processing.
A public DNS name alone does not establish authorization.

## GitHub Actions secrets

Configure repository Actions secrets:

- `TELEGRAM_BOT_TOKEN`: Telegram bot token used by the workflow report step.
- `TELEGRAM_CHAT_ID`: destination chat/channel ID.
- `RECONQ_STATE_TOKEN`: dedicated least-privilege token with Contents read/write on this repository, required to persist `state/subs_known.txt` to the `state` branch.
- `SUBFINDER_CONFIG_B64`: optional Base64-encoded Subfinder provider config. Avoid storing unnecessary provider credentials.

The workflow uses `GITHUB_TOKEN` with read-only contents permission for checkout/artifacts; the dedicated state token is used only for the state-branch push.

## Telegram bot environment

Set `TELEGRAM_BOT_TOKEN`. Optional:

- `TELEGRAM_ALLOWED_USER_IDS`: comma-separated numeric Telegram user IDs.
- `GITHUB_TOKEN`: token with permission to dispatch workflows and read workflow runs; used for `/scan` and `/last`.
- `GITHUB_OWNER`, `GITHUB_REPO`: default `basojhie/reconq`.

Run:

```bash
pip install -r requirements.txt
python bot.py
```

Commands: `/start`, `/help`, `/status`, `/recon example.com`, `/scan example.com`, `/last`.

## Termux

Install dependencies:

```bash
pkg update && pkg install curl jq
chmod +x reconq
export GITHUB_TOKEN='YOUR_GITHUB_TOKEN'
./reconq menu
```

To persist settings, place exports in a private shell profile or use a local ignored
configuration file. Do not commit tokens. Commands: `./reconq baseline`,
`./reconq recon`, `./reconq last`, `./reconq status RUN_ID`.

## Workflow behavior

1. Validate non-empty authorized scope.
2. Discover subdomains passively with Subfinder.
3. Filter discovered hosts to the authorized roots and exclusions.
4. Resolve A/AAAA using dnsx.
5. Diff against state; baseline mode suppresses deltas and notifications.
6. Probe in-scope resolved hosts with HTTPx JSON output.
7. Build compact reports and upload artifacts (14-day retention).
8. Send optional Telegram summary.
9. Persist known assets to `state` branch only when `RECONQ_STATE_TOKEN` exists.

GitHub Actions does not deploy or restart the long-running Telegram bot process.

## Deliberately gated roadmap items

Naabu/Nmap port scanning, Katana crawling, Dalfox XSS scanning and Nuclei vulnerability
templates are not automatically run by this first integration. These tools can generate
active traffic and must have separate approved scope, rate limits, exclusions and a
maintenance window. Add them only after the operator approves those operational controls.
Do not enable DoS, intrusive, exploit, brute-force or takeover tests in unattended runs.

## Tests

```bash
python -m unittest discover -s tests -v
python -m compileall -q bot.py scripts tests
pip check
```
