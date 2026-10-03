import base64
import hashlib
import json
import os
import sys
import urllib.request

INPUT_URL = os.getenv("INPUT_SUB_URL")
OUTPUT_FILE = "sub.txt"

if not INPUT_URL:
    print("خطا: لینک سابسکریپشن ورودی یافت نشد.")
    sys.exit(1)


def process_line(line, index_num):
    line = line.strip()
    if not line or line.startswith("//"):
        return ""

    # تبدیل شماره ترتیبی به رشته متنی
    name_str = str(index_num)

    # پردازش لینک‌های VMess (تنظیم مقدار ps به شماره عدد)
    if line.startswith("vmess://"):
        try:
            b64_part = line[8:]
            padding = len(b64_part) % 4
            if padding:
                b64_part += "=" * (4 - padding)
            decoded_bytes = base64.b64decode(b64_part)
            data = json.loads(decoded_bytes.decode("utf-8", errors="ignore"))

            # جایگزینی نام کانفیگ با شماره عدد
            data["ps"] = name_str

            new_json = json.dumps(data, ensure_ascii=False)
            new_b64 = base64.b64encode(new_json.encode("utf-8")).decode("utf-8")
            return f"vmess://{new_b64}"
        except Exception:
            base_url = line.split("#")[0]
            return f"{base_url}#{name_str}"

    # پردازش VLESS, Trojan, SS, Hysteria2, TUIC (جایگزینی بخش بعد از # با شماره)
    base_url = line.split("#")[0]
    return f"{base_url}#{name_str}"


# دانلود محتوای سابسکریپشن ورودی
try:
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    req = urllib.request.Request(INPUT_URL, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as response:
        raw_bytes = response.read()
except Exception as e:
    print(f"خطا در دریافت اطلاعات از لینک ورودی: {e}")
    sys.exit(1)

# بررسی و رمزگشایی اولیه در صورت Base64 بودن کل سابسکریپشن
text = raw_bytes.decode("utf-8", errors="ignore").strip()
lines = []

if not any(
    text.startswith(p)
    for p in ["vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "tuic://"]
):
    try:
        b64_text = text
        padding = len(b64_text) % 4
        if padding:
            b64_text += "=" * (4 - padding)
        decoded = base64.b64decode(b64_text).decode("utf-8", errors="ignore")
        if "://" in decoded:
            lines = decoded.splitlines()
    except Exception:
        pass

if not lines:
    lines = text.splitlines()

# تغییر نام تمام خطوط به شماره‌های ترتیبی
cleaned_lines = []
counter = 1

for line in lines:
    line_str = line.strip()
    if not line_str or line_str.startswith("//"):
        continue

    processed_config = process_line(line_str, counter)
    if processed_config:
        cleaned_lines.append(processed_config)
        counter += 1

final_content = "\n".join(cleaned_lines) + "\n"
final_bytes = final_content.encode("utf-8")

# بررسی تغییرات با فایل قبلی جهت جلوگیری از Commit بی‌مورد
current_bytes = b""
if os.path.exists(OUTPUT_FILE):
    with open(OUTPUT_FILE, "rb") as f:
        current_bytes = f.read()

new_hash = hashlib.sha256(final_bytes).hexdigest()
current_hash = hashlib.sha256(current_bytes).hexdigest()

if new_hash != current_hash:
    with open(OUTPUT_FILE, "wb") as f:
        f.write(final_bytes)
    print("محتوای کانفیگ‌ها دریافت و نام تمامی آن‌ها به شماره ترتیبی عددی تغییر یافت.")
else:
    print("هیچ تغییری در سابسکریپشن ورودی رخ نداده است.")
