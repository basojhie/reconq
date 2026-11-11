"""ReconQ Telegram bot.

Safe scope: passive DNS/HTTP metadata checks for domains the operator is
authorized to assess. No exploitation, brute force, port scanning, or evasion.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
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
REQUEST_TIMEOUT = httpx.Timeout(8.0, connect=4.0)
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")


def normalize_domain(raw: str) -> str:
    """Accept a domain or URL and return a normalized public DNS hostname."""
    value = raw.strip()
    if not value or len(value) > 2048:
        raise ValueError("Target kosong atau terlalu panjang.")

    parsed = urlparse(value if "://" in value else f"https://{value}")
    host = (parsed.hostname or "").rstrip(".").encode("idna").decode("ascii").lower()
    if not DOMAIN_RE.fullmatch(host):
        raise ValueError("Target harus berupa nama domain valid, bukan IP atau URL lokal.")

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip:
        raise ValueError("Gunakan nama domain, bukan alamat IP.")
    if host in {"localhost"} or host.endswith((".localhost", ".local", ".internal", ".test")):
        raise ValueError("Domain lokal tidak diizinkan.")
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
            await update.effective_message.reply_text("Akses ditolak. Akun Telegram Anda tidak diizinkan.")
        return False
    return True


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await guard(update):
        return
    await update.effective_message.reply_text(
        "Halo! Saya ReconQ.\nGunakan /help untuk melihat perintah.\n"
        "ReconQ hanya melakukan pemeriksaan pasif pada domain yang Anda miliki "
        "atau memiliki izin tertulis untuk diuji."
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await guard(update):
        return
    await update.effective_message.reply_text(
        "Perintah ReconQ:\n"
        "/start - Mulai bot\n"
        "/help - Bantuan\n"
        "/status - Status bot\n"
        "/recon <domain> - Pemeriksaan DNS dan metadata HTTP pasif\n\n"
        "Contoh: /recon example.com\n"
        "Gunakan hanya pada domain milik sendiri atau yang memiliki izin."
    )


async def status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await guard(update):
        return
    await update.effective_message.reply_text("ReconQ aktif. Mode: passive-only.")


async def recon(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await guard(update):
        return
    message = update.effective_message
    if not context.args:
        await message.reply_text("Format: /recon <domain>\nContoh: /recon example.com")
        return
    try:
        domain = normalize_domain(context.args[0])
    except (ValueError, UnicodeError) as exc:
        await message.reply_text(f"Target tidak valid: {exc}")
        return

    await message.reply_text(
        f"Memeriksa metadata pasif untuk {domain}.\n"
        "Pastikan Anda memiliki otorisasi atas domain ini..."
    )
    report = [f"ReconQ — {domain}", "Mode: passive-only", ""]

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4.0
    for record in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            answers = resolver.resolve(domain, record)
            values = [str(answer).strip() for answer in answers]
            report.append(f"{record}: " + ", ".join(values[:8]))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            report.append(f"{record}: tidak tersedia")
        except Exception as exc:
            logger.info("DNS %s lookup for %s failed: %s", record, domain, exc)
            report.append(f"{record}: gagal/timeout")

    try:
        async with httpx.AsyncClient(
            timeout=REQUEST_TIMEOUT,
            follow_redirects=False,
            headers={"User-Agent": "ReconQ/1.0 (+passive metadata check)"},
        ) as client:
            response = await client.get(f"https://{domain}/")
        report.extend([
            "",
            f"HTTPS: HTTP {response.status_code}",
            f"Server: {response.headers.get('server', 'tidak diungkap')}",
            f"Content-Type: {response.headers.get('content-type', 'tidak diungkap')}",
            f"Redirect: {response.headers.get('location', 'tidak ada')}",
        ])
    except httpx.HTTPError as exc:
        logger.info("HTTP metadata request for %s failed: %s", domain, exc)
        report.extend(["", "HTTPS: tidak dapat diakses/timeout"])

    text = "\n".join(report)
    # Telegram messages have a 4096-character limit.
    await message.reply_text(text[:3900])


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.exception("Unhandled Telegram update error", exc_info=context.error)
    if isinstance(update, Update) and update.effective_message:
        await update.effective_message.reply_text("Terjadi kesalahan internal. Periksa log bot.")


def main() -> None:
    if not TOKEN or TOKEN.lower() in {"change_me", "your_telegram_bot_token"}:
        raise RuntimeError("TELEGRAM_BOT_TOKEN belum diatur. Isi melalui environment atau file .env.")

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
