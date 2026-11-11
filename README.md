# ReconQ

Telegram bot for **authorized, passive-only domain reconnaissance**.

## Features

- Telegram commands: `/start`, `/help`, `/status`, `/recon <domain>`
- Passive DNS metadata: A, AAAA, MX, NS and TXT
- One HTTPS metadata request (no crawling, exploitation, brute force, or port scanning)
- Optional Telegram user-ID allowlist
- Input validation, bounded timeouts, structured logging and error handling

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

Run:

```bash
python bot.py
```

## Commands

- `/start` — welcome message
- `/help` — command help
- `/status` — process status
- `/recon example.com` — passive DNS and HTTPS metadata lookup

Only scan domains you own or are explicitly authorized to assess. DNS and HTTP
metadata can still disclose information and generate network requests. Respect
the target owner's scope and rate limits.

## Security notes

- Rotate any bot token that has ever been committed or exposed.
- Keep `.env` private and use environment secrets in hosted deployments.
- Configure the Telegram user-ID allowlist for private deployments.
- This project intentionally does not implement active port scanning, service
  probing, vulnerability exploitation, or bypass techniques.

## Deployment

Keep the existing host/process manager and its current polling deployment. Update
the installed dependencies and environment variables, then restart the existing
bot process. Do not run two polling instances with the same bot token.
