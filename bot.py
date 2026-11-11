"""ReconQ Telegram bot.

Authorized, passive-only checks: DNS records and HTTPS response metadata.
No port scanning, brute force, exploitation, crawling, or evasion.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import time
from urllib.parse import urlparse

import dns.resolver
import httpx
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes

load_dotenv()

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    level=getattr(logging, LOG_LEVEL, logging.INFO),
)
logger = logging.getLogger("reconq")

TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
ALLOWED_USERS = {
    item.strip()
    for item in os.getenv("TELEGRAM_ALLOWED_USER_IDS", "").split(",")
    if item.strip()
}
RECON_COOLDOWN_SECONDS = max(5, int(os.getenv("RECON_COOLDOWN_SECONDS", "30")))
REQUEST_TIMEOUT = httpx.Timeout(8.0, connect=4.0)
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,63}$"
)


def normalize_domain(raw: str) -> str:
    """Accept a domain or HTTP(S) URL and return a normalized hostname."""
    value = raw.strip()
    if not value or len(value) > 2048:
        raise ValueError("Target kosong atau terlalu panjang.")

    parsed = urlparse(value if "://" in value else f"https://{value}")
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Hanya domain atau URL HTTP(S) yang diizinkan.")
    if parsed.username or parsed.password:
        raise ValueError("URL dengan username/password tidak diizinkan.")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("Port pada URL tidak valid.") from exc

    host = (parsed.hostname or "").rstrip(".")
    if not host:
        raise ValueError("Nama domain tidak ditemukan.")
    try:
        host = host.encode("idna").decode("ascii").lower()
        ipaddress.ip_address(host)
        raise ValueError("Gunakan nama domain, bukan alamat IP.")
    except ValueError as exc:
        if str(exc) == "Gunakan nama domain, bukan alamat IP.":
            raise
        # A normal domain is not an IP address; continue with DNS-name validation.

    if not DOMAIN_RE.fullmatch(host):
        raise ValueError("Target harus berupa nama domain publik yang valid.")
    if host == "localhost" or host.endswith(
        (".localhost", ".local", ".internal", ".test", ".invalid")
    ):
        raise ValueError("Domain lokal atau domain khusus tidak diizinkan.")
    return host


def authorized(update: Update) -> bool:
    """Optional allowlist; when configured, only listed Telegram user IDs can run commands."""
    if not ALLOWED_USERS:
        return True
    user = update.effective_user
    return bool(user and str(user.id) in ALLOWED_USERS)


async def guard(update: Update) -> bool:
    if not authorized(update):
        if update.effective_message:
            await update.effective_message.reply_text(
                "Akses ditolak. Akun Telegram Anda tidak diizinkan."
            )
        return False
    return True


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await guard(update):
        return
    await update.effective_message.reply_text(
        "Halo! Saya ReconQ.\\nGunakan /help untuk melihat perintah.\\n"
        "ReconQ hanya melakukan pemeriksaan pasif pada domain yang Anda miliki "
        "atau memiliki izin tertulis untuk diuji."
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await guard(update):
        return
    await update.effective_message.reply_text(
        "Perintah ReconQ:\\n"
        "/start - Mulai bot\\n"
        "/help - Bantuan\\n"
        "/status - Status bot\\n"
        "/recon <domain> - Pemeriksaan DNS dan metadata HTTPS pasif\\n\\n"
        "Contoh: /recon example.com\\n"
        "Gunakan hanya pada domain milik sendiri atau yang memiliki izin."
    )


async def status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await guard(update):
        return
    await update.effective_message.reply_text(
        "ReconQ aktif. Mode: passive-only."
    )


async def recon(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await guard(update):
        return
    message = update.effective_message
    if not context.args:
        await message.reply_text(
            "Format: /recon <domain>\\nContoh: /recon example.com"
        )
        return

    try:
        domain = normalize_domain(context.args[0])
    except (ValueError, UnicodeError) as exc:
        await message.reply_text(f"Target tidak valid: {exc}")
        return

    user = update.effective_user
    if user is None:
        await message.reply_text("Perintah ini harus dijalankan dari akun Telegram.")
        return

    # Per-user cooldown prevents accidental repeated requests and basic abuse.
    last_runs = context.application.bot_data.setdefault("recon_last_runs", {})
    now = time.monotonic()
    elapsed = now - last_runs.get(user.id, 0.0)
    if elapsed < RECON_COOLDOWN_SECONDS:
        remaining = int(RECON_COOLDOWN_SECONDS - elapsed) + 1
        await message.reply_text(
            f"Tunggu {remaining} detik sebelum menjalankan recon berikutnya."
        )
        return
    last_runs[user.id] = now

    await message.reply_text(
        f"Memeriksa metadata pasif untuk {domain}.\\n"
        "Pastikan Anda memiliki otorisasi atas domain ini..."
    )

    report = [f"ReconQ — {domain}", "Mode: passive-only", ""]
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3.0
    public_addresses: list[str] = []
    non_public_address_found = False

    for record in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            answers = await asyncio.to_thread(resolver.resolve, domain, record)
            values = [str(answer).strip() for answer in answers]
            if record in {"A", "AAAA"}:
                for value in values:
                    try:
                        address = ipaddress.ip_address(value)
                    except ValueError:
                        continue
                    if address.is_global:
                        public_addresses.append(value)
                    else:
                        non_public_address_found = True
                if non_public_address_found:
                    report.append(
                        f"{record}: resolusi non-publik terdeteksi; alamat disembunyikan"
                    )
                else:
                    report.append(f"{record}: " + (", ".join(values[:8]) or "tidak tersedia"))
            else:
                report.append(f"{record}: " + (", ".join(values[:8]) or "tidak tersedia"))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            report.append(f"{record}: tidak tersedia")
        except Exception as exc:
            logger.info("DNS %s lookup for %s failed: %s", record, domain, exc)
            report.append(f"{record}: gagal/timeout")

    # Only request HTTPS metadata when DNS returned public IPs exclusively.
    # HEAD avoids downloading a page body; redirects and environment proxies are disabled.
    if non_public_address_found:
        report.extend(["", "HTTPS: dilewati (alamat non-publik terdeteksi)"])
    elif not public_addresses:
        report.extend(["", "HTTPS: dilewati (alamat publik A/AAAA tidak ditemukan)"])
    else:
        try:
            async with httpx.AsyncClient(
                timeout=REQUEST_TIMEOUT,
                follow_redirects=False,
                trust_env=False,
                headers={"User-Agent": "ReconQ/1.1 (passive metadata check)"},
            ) as client:
                response = await client.head(f"https://{domain}/")
            report.extend(
                [
                    "",
                    f"HTTPS: HTTP {response.status_code}",
                    f"Server: {response.headers.get('server', 'tidak diungkap')}",
                    f"Content-Type: {response.headers.get('content-type', 'tidak diungkap')}",
                    f"Redirect: {response.headers.get('location', 'tidak ada')}",
                ]
            )
        except httpx.HTTPError as exc:
            logger.info("HTTPS metadata request for %s failed: %s", domain, exc)
            report.extend(["", "HTTPS: tidak dapat diakses/timeout"])

    await message.reply_text("\\n".join(report)[:3900])


async def error_handler(
    update: object, context: ContextTypes.DEFAULT_TYPE
) -> None:
    logger.error(
        "Unhandled Telegram update error",
        exc_info=(type(context.error), context.error, context.error.__traceback__)
        if context.error
        else None,
    )
    if isinstance(update, Update) and update.effective_message:
        await update.effective_message.reply_text(
            "Terjadi kesalahan internal. Periksa log bot."
        )


def main() -> None:
    if not TOKEN or TOKEN.lower() in {
        "change_me",
        "your_telegram_bot_token",
        "replace_with_new_bot_token",
    }:
        raise RuntimeError(
            "TELEGRAM_BOT_TOKEN belum diatur. Isi melalui environment atau file .env."
        )

    application = Application.builder().token(TOKEN).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("status", status))
    application.add_handler(CommandHandler("recon", recon))
    application.add_error_handler(error_handler)

    logger.info("ReconQ Telegram bot starting (passive-only mode)")
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
