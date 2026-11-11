# ReconQ

Telegram bot for **authorized, passive-only domain reconnaissance**.

## Features

- Telegram commands: `/start`, `/help`, `/status`, `/recon <domain>`
- Passive DNS metadata: A, AAAA, MX, NS and TXT
- One HTTPS HEAD request for response metadata (no page body download)
- Skips HTTPS when DNS resolves to private, reserved, or otherwise non-public addresses
- Per-user cooldown and optional Telegram user-ID allowlist
- Input validation, bounded timeouts, logging and error handling

## Setup

Python 3.10+ is recommended.

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
cp .env.example .env
```

Set `TELEGRAM_BOT_TOKEN` in `.env` using a newly generated token from @BotFather.
Never commit `.env` or share the token. Optionally set
`TELEGRAM_ALLOWED_USER_IDS=123456789,987654321` to restrict bot users.
Set `RECON_COOLDOWN_SECONDS` to control the per-user cooldown (default: 30).

Run:

```bash
python bot.py
```

## Commands

- `/start` — welcome message
- `/help` — command help
- `/status` — process status
- `/recon example.com` — passive DNS and HTTPS metadata lookup

Only assess domains you own or are explicitly authorized to assess. Respect the
owner's scope and rate limits. The bot intentionally avoids port scanning,
service enumeration, crawling, brute force, exploitation, and bypass methods.

## Tests

```bash
python -m unittest discover -s tests -v
python -m compileall -q bot.py tests
pip check
```

## Security and deployment notes

- Rotate any bot token that has ever been committed or exposed. Removing a token
  from the current file does not remove it from Git history.
- Keep `.env` private and use environment secrets in hosted deployments.
- Configure the Telegram user-ID allowlist for private deployments.
- Run only one polling instance for a given bot token. When updating an existing
  host, pull the latest `main`, install requirements, and restart the existing
  process manager. GitHub Actions validates code; it does not deploy or restart
  the running Telegram process.
