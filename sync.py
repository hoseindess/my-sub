import base64
import glob
import hashlib
import json
import os
import sys

# لیست فایل‌های متنی سیستمی که نباید دستکاری شوند
EXCLUDED_FILES = ["requirements.txt", "license.txt", "readme.txt"]

# یافتن تمامی فایل‌های .txt موجود در ریشه مخزن
txt_files = [
    f
    for f in glob.glob("*.txt")
    if os.path.basename(f).lower() not in EXCLUDED_FILES
]

if not txt_files:
    print(
        "خطا: هیچ فایل .txt معتبری در مخزن یافت نشد. لطفاً حداقل یک فایل .txt ایجاد کنید."
    )
    sys.exit(1)

print(f"تعداد {len(txt_files)} فایل متنی برای پردازش یافت شد: {txt_files}")


def process_line(line, index_num):
    """جایگزینی برچسب/نام کانفیگ با فرمت 🔑عدد"""
    line = line.strip()
    if not line or line.startswith("//"):
        return ""

    name_str = f"🔑{index_num}"

    # پردازش پروتکل VMess (نیاز به باز کردن Base64 داخلی و تغییر کلید ps دارد)
    if line.startswith("vmess://"):
        try:
            b64_part = line[8:]
            padding = len(b64_part) % 4
            if padding:
                b64_part += "=" * (4 - padding)
            decoded_bytes = base64.b64decode(b64_part)
            data = json.loads(decoded_bytes.decode("utf-8", errors="ignore"))

            data["ps"] = name_str

            new_json = json.dumps(data, ensure_ascii=False)
            new_b64 = base64.b64encode(new_json.encode("utf-8")).decode("utf-8")
            return f"vmess://{new_b64}"
        except Exception:
            base_url = line.split("#")[0]
            return f"{base_url}#{name_str}"

    # پردازش سایر پروتکل‌ها (VLESS, Trojan, SS, Hysteria2, TUIC)
    base_url = line.split("#")[0]
    return f"{base_url}#{name_str}"


# پیمایش و پردازش تک‌تک فایل‌های متنی
for file_path in txt_files:
    print(f"\n--- در حال پردازش فایل: {file_path} ---")

    try:
        with open(file_path, "rb") as f:
            raw_bytes = f.read()
    except Exception as e:
        print(f"خطا در خواندن فایل {file_path}: {e}")
        continue

    text = raw_bytes.decode("utf-8", errors="ignore").strip()
    lines = []

    # بررسی اینکه آیا کل فایل به‌صورت Base64 رمزنگاری شده است یا خیر
    if not any(
        text.startswith(p)
        for p in [
            "vless://",
            "vmess://",
            "trojan://",
            "ss://",
            "hysteria2://",
            "tuic://",
        ]
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

    # مقایسه هش جهت اطمینان از انجام تغییرات واقعی
    new_hash = hashlib.sha256(final_bytes).hexdigest()
    current_hash = hashlib.sha256(raw_bytes).hexdigest()

    if new_hash != current_hash:
        with open(file_path, "wb") as f:
            f.write(final_bytes)
        print(
            f"موفقیت: فایل {file_path} بروزرسانی شد ({len(cleaned_lines)} کانفیگ مرتب‌سازی شدند)."
        )
    else:
        print(f"اطلاع: فایل {file_path} تغییر جدیدی نداشت.")
