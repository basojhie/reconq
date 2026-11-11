import os
import logging
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes

# Memuat token dari file .env
load_dotenv()

# Konfigurasi logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)

# Fungsi untuk perintah /start
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    await update.message.reply_html(
        f"Halo {user.mention_html()}!\nSaya adalah bot reconq. Ketik /help untuk melihat perintah."
    )

# Fungsi untuk perintah /help
async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "Perintah yang tersedia:\n"
        "/start - Mulai bot\n"
        "/help - Menampilkan bantuan\n"
        "/recon <target> - Memulai pemindaian (contoh: /recon example.com)"
    )

# Fungsi untuk perintah /recon
async def recon(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await update.message.reply_text("Gunakan format: /recon <target>\nContoh: /recon target.com")
        return

    target = context.args[0]
    await update.message.reply_text(f"Memulai proses recon untuk target: {target}...\n(Fitur scanning akan ditambahkan di sini)")
    
    # Di sini nanti Anda bisa menambahkan skrip recon (seperti nmap, subfinder, dll)

def main() -> None:
    # Mengambil token dari environment variable
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not token or token == "masukkan_token_botfather_disini":
        print("ERROR: Token bot belum diatur di file .env")
        return

    # Inisialisasi Application
    application = Application.builder().token(token).build()

    # Mendaftarkan handler perintah
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("recon", recon))

    # Menjalankan bot
    print("Bot @devopsq_bot sedang berjalan...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()