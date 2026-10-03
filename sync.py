import hashlib
import os
import sys
import urllib.request

INPUT_URL = os.getenv("INPUT_SUB_URL")
OUTPUT_FILE = "sub.txt"

if not INPUT_URL:
    print("خطا: لینک سابسکریپشن ورودی یافت نشد.")
    sys.exit(1)

try:
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    req = urllib.request.Request(INPUT_URL, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as response:
        new_bytes = response.read()
except Exception as e:
    print(f"خطا در دریافت اطلاعات از لینک ورودی: {e}")
    sys.exit(1)

current_bytes = b""
if os.path.exists(OUTPUT_FILE):
    with open(OUTPUT_FILE, "rb") as f:
        current_bytes = f.read()

new_hash = hashlib.sha256(new_bytes).hexdigest()
current_hash = hashlib.sha256(current_bytes).hexdigest()

if new_hash != current_hash:
    with open(OUTPUT_FILE, "wb") as f:
        f.write(new_bytes)
    print("محتوای جدید دریافت شد و فایل با موفقیت به روز گردید.")
else:
    print("هیچ تغییری در لینک ورودی رخ نداده است.")
