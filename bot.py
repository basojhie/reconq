"""ReconQ Telegram bot: authorized passive domain checks and cloud dispatch."""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import socket
import ssl
import time
from urllib.parse import urlparse

import dns.resolver
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes

load_dotenv()
logging.basicConfig(
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO),
)
logger = logging.getLogger("reconq")
TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
ALLOWED_USERS = {x.strip() for x in os.getenv("TELEGRAM_ALLOWED_USER_IDS", "").split(",") if x.strip()}
try:
    COOLDOWN = max(5, int(os.getenv("RECON_COOLDOWN_SECONDS", "30")))
except ValueError:
    COOLDOWN = 30
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def normalize_domain(raw: str) -> str:
    value = raw.strip()
    if not value or len(value) > 2048:
        raise ValueError("Target kosong atau terlalu panjang.")
    parsed = urlparse(value if "://" in value else f"https://{value}")
    if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
        raise ValueError("Masukkan domain atau URL HTTP(S) tanpa kredensial.")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("Port URL tidak valid.") from exc
    host = (parsed.hostname or "").rstrip(".")
    if not host:
        raise ValueError("Nama domain tidak ditemukan.")
    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Nama domain tidak valid.") from exc
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("Gunakan nama domain, bukan alamat IP.")
    if not DOMAIN_RE.fullmatch(host):
        raise ValueError("Target harus berupa nama domain publik yang valid.")
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal", ".test", ".invalid", ".example")):
        raise ValueError("Domain lokal tidak diizinkan.")
    return host


def authorized(update: Update) -> bool:
    return not ALLOWED_USERS or bool(update.effective_user and str(update.effective_user.id) in ALLOWED_USERS)


async def guard(update: Update) -> bool:
    if not authorized(update):
        if update.effective_message:
            await update.effective_message.reply_text("Akses ditolak.")
        return False
    return True


def fetch_https_head(domain: str) -> tuple[int, dict[str, str]]:
    endpoints = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
    checked = []
    for family, kind, proto, _, sockaddr in endpoints:
        if not ipaddress.ip_address(sockaddr[0]).is_global:
            raise ValueError("Resolved address is not public.")
        checked.append((family, kind, proto, sockaddr))
    if not checked:
        raise OSError("No public address found.")
    last_error = None
    for family, kind, proto, sockaddr in checked[:8]:
        try:
            with socket.socket(family, kind, proto) as raw:
                raw.settimeout(4)
                raw.connect(sockaddr)
                if not ipaddress.ip_address(raw.getpeername()[0]).is_global:
                    raise ValueError("Peer is not public.")
                with ssl.create_default_context().wrap_socket(raw, server_hostname=domain) as conn:
                    conn.settimeout(4)
                    conn.sendall(
                        f"HEAD / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: ReconQ/1.2\r\nConnection: close\r\n\r\n".encode("ascii")
                    )
                    with conn.makefile("rb") as response:
                        parts = response.readline(2048).split()
                        if len(parts) < 2 or not parts[1].isdigit():
                            raise OSError("Invalid HTTP response.")
                        status = int(parts[1])
                        headers = {}
                        size = 0
                        while True:
                            line = response.readline(4096)
                            if not line or line in (b"\r\n", b"\n"):
                                break
                            size += len(line)
                            if size > 16384:
                                raise OSError("HTTP headers exceed limit.")
                            key, sep, val = line.partition(b":")
                            key = key.decode("ascii", "ignore").strip().lower()
                            if sep and key in {"server", "content-type", "location"}:
                                headers[key] = val.decode("latin-1", "replace").strip()
                        return status, headers
        except ValueError:
            raise
        except (OSError, ssl.SSLError, TimeoutError) as exc:
            last_error = exc
    raise OSError(f"HTTPS request failed: {last_error}")


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if await guard(update):
        await update.effective_message.reply_text("Halo! Saya ReconQ. Gunakan /help untuk melihat perintah.")


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if await guard(update):
        await update.effective_message.reply_text(
            "Perintah ReconQ:\n/start — mulai\n/help — bantuan\n/status — status bot\n"
            "/recon <domain> — DNS dan metadata HTTPS pasif\n"
            "/scan <domain> — trigger workflow ASM (harus masuk scope/scope.txt)\n"
            "/last — daftar run GitHub terakhir\n\nGunakan hanya aset yang Anda miliki atau memiliki izin tertulis."
        )


async def status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if await guard(update):
        await update.effective_message.reply_text("ReconQ aktif. Passive-only; cloud workflow memakai scope allowlist.")


async def recon(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await guard(update):
        return
    message = update.effective_message
    if not context.args:
        await message.reply_text("Format: /recon <domain>")
        return
    try:
        domain = normalize_domain(context.args[0])
    except ValueError as exc:
        await message.reply_text(f"Target tidak valid: {exc}")
        return
    user = update.effective_user
    last = context.application.bot_data.setdefault("last_recon", {})
    now = time.monotonic()
    if user and now - last.get(user.id, 0) < COOLDOWN:
        await message.reply_text(f"Tunggu {int(COOLDOWN - (now-last[user.id]))+1} detik.")
        return
    if user:
        last[user.id] = now
    await message.reply_text(f"Recon pasif untuk {domain} dimulai...")
    report = [f"ReconQ — {domain}", "Mode: passive-only", ""]
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3
    public = []
    blocked = False
    for record in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            answers = await asyncio.to_thread(resolver.resolve, domain, record)
            values = [str(x) for x in answers]
            if record in ("A", "AAAA"):
                for value in values:
                    try:
                        address = ipaddress.ip_address(value)
                    except ValueError:
                        continue
                    if address.is_global:
                        public.append(value)
                    else:
                        blocked = True
                report.append(f"{record}: " + ("alamat non-publik disembunyikan" if blocked else ", ".join(values[:8])))
            else:
                report.append(f"{record}: " + ", ".join(values[:8]))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            report.append(f"{record}: tidak tersedia")
        except Exception as exc:
            logger.info("DNS lookup failed: %s", exc)
            report.append(f"{record}: gagal/timeout")
    if blocked or not public:
        report.append("\nHTTPS: dilewati (alamat publik tidak dapat diverifikasi)")
    else:
        try:
            code, headers = await asyncio.wait_for(asyncio.to_thread(fetch_https_head, domain), timeout=12)
            report.extend(["", f"HTTPS: HTTP {code}", f"Server: {headers.get('server','tidak diungkap')}", f"Content-Type: {headers.get('content-type','tidak diungkap')}", f"Redirect: {headers.get('location','tidak ada')}"])
        except (ValueError, OSError, ssl.SSLError, TimeoutError):
            report.append("\nHTTPS: dilewati/gagal (peer tidak publik atau timeout)")
    await message.reply_text("\n".join(report)[:3900])


def github_headers(token: str) -> dict[str, str]:
    return {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}", "X-GitHub-Api-Version": "2022-11-28"}


async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await guard(update):
        return
    message = update.effective_message
    if not ALLOWED_USERS:
        await message.reply_text("Remote scan dinonaktifkan. Atur TELEGRAM_ALLOWED_USER_IDS terlebih dahulu agar hanya operator yang diizinkan dapat memicu workflow.")
        return
    if not context.args:
        await message.reply_text("Format: /scan <domain>")
        return
    try:
        domain = normalize_domain(context.args[0])
    except ValueError as exc:
        await message.reply_text(f"Target tidak valid: {exc}")
        return
    owner = os.getenv("GITHUB_OWNER", "basojhie")
    repo = os.getenv("GITHUB_REPO", "reconq")
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if not token:
        await message.reply_text("GITHUB_TOKEN belum dikonfigurasi pada runtime bot.")
        return
    import base64
    import httpx
    base = f"https://api.github.com/repos/{owner}/{repo}"
    async with httpx.AsyncClient(timeout=12, headers=github_headers(token)) as client:
        scope_response = await client.get(f"{base}/contents/scope/scope.txt?ref=main")
        exclusion_response = await client.get(f"{base}/contents/scope/out-of-scope.txt?ref=main")
        if scope_response.status_code != 200:
            await message.reply_text("Tidak dapat membaca scope repository.")
            return
        roots = base64.b64decode(scope_response.json().get("content", "")).decode("utf-8", "replace").splitlines()
        exclusions = []
        if exclusion_response.status_code == 200:
            exclusions = base64.b64decode(exclusion_response.json().get("content", "")).decode("utf-8", "replace").splitlines()
        roots = [x.split("#", 1)[0].strip().lower().rstrip(".") for x in roots]
        exclusions = [x.split("#", 1)[0].strip().lower().rstrip(".") for x in exclusions]
        in_scope = any(domain == root or domain.endswith("." + root) for root in roots if root)
        excluded = any(domain == item or domain.endswith("." + item) for item in exclusions if item)
        if not in_scope or excluded:
            await message.reply_text("Target di luar scope/termasuk exclusions. Workflow tidak dipicu.")
            return
        response = await client.post(
            f"{base}/actions/workflows/recon.yml/dispatches",
            json={"ref": "main", "inputs": {"mode": "recon", "baseline": "false", "target": domain}},
        )
        if response.status_code not in (204, 200):
            await message.reply_text(f"GitHub dispatch gagal: HTTP {response.status_code}")
            return
    await message.reply_text(f"Permintaan passive ASM untuk {domain} dikirim. Gunakan /last untuk status.")


async def last_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await guard(update):
        return
    import httpx
    token = os.getenv("GITHUB_TOKEN", "").strip()
    owner = os.getenv("GITHUB_OWNER", "basojhie")
    repo = os.getenv("GITHUB_REPO", "reconq")
    if not token:
        await update.effective_message.reply_text("GITHUB_TOKEN belum dikonfigurasi.")
        return
    async with httpx.AsyncClient(timeout=12, headers=github_headers(token)) as client:
        response = await client.get(f"https://api.github.com/repos/{owner}/{repo}/actions/workflows/recon.yml/runs?per_page=5")
    if response.status_code != 200:
        await update.effective_message.reply_text(f"Gagal mengambil run: HTTP {response.status_code}")
        return
    runs = response.json().get("workflow_runs", [])
    if not runs:
        await update.effective_message.reply_text("Belum ada workflow run.")
        return
    lines = [f"#{item['id']} {item['status']} / {item.get('conclusion') or 'pending'}\n{item['html_url']}" for item in runs]
    await update.effective_message.reply_text("\n\n".join(lines)[:3900])


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.error("Unhandled Telegram update error", exc_info=(type(context.error), context.error, context.error.__traceback__) if context.error else None)
    if isinstance(update, Update) and update.effective_message:
        await update.effective_message.reply_text("Terjadi kesalahan internal. Periksa log bot.")


def main() -> None:
    if not TOKEN or TOKEN.lower() in {"change_me", "replace_with_new_bot_token", "your_telegram_bot_token"}:
        raise RuntimeError("TELEGRAM_BOT_TOKEN belum diatur.")
    app = Application.builder().token(TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("status", status))
    app.add_handler(CommandHandler("recon", recon))
    app.add_handler(CommandHandler("scan", scan_command))
    app.add_handler(CommandHandler("last", last_command))
    app.add_error_handler(error_handler)
    logger.info("ReconQ Telegram bot starting.")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
