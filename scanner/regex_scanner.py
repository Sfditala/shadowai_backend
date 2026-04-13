# ================================================================
# ShadowAI Detector — كاشف الأنماط بالـ Regex (v2)
# ================================================================

import re

CODE_INDICATORS = [
    r"\b(const|let|var)\s+\w+\s*=",
    r"\bfunction\s+\w+\s*\(",
    r"\bclass\s+\w+",
    r"=>\s*{",
    r"\bif\s*\(",
    r"\bfor\s*\(",
    r"\.addEventListener\(",
    r"document\.",
    r"\bdef\s+\w+\s*\(",
    r"\bclass\s+\w+.*:",
    r"\bimport\s+\w+",
    r"\bfrom\s+\w+\s+import",
    r"print\s*\(",
    r"#\s*(TODO|FIXME|NOTE|Example|example)",
    r"type\s*=\s*['\"]password['\"]",
    r"<input\b",
    r"<form\b",
    r"<!--",
    r"[{};]\s*$",
    r"^\s*//.*",
    r"^\s*#\s+\w",
    r"\$\{[^}]+\}",
    r"'YOUR_[A-Z_]+_HERE'",
    r"<your-[a-z-]+>",
    r"os\.getenv\(",
    r"os\.environ",
    r"process\.env\.",
    r"bcrypt\.",
    r"jwt\.(encode|decode)\(",
    r"models\.\w+Field\(",
    r"SELECT\s+.*\s+FROM\s+",
    r"ALTER\s+TABLE\s+",
    r"CREATE\s+(INDEX|TABLE)\s+",
    r"filter_var\s*\(",
    r"router\.(get|post|put|delete)\(",
]


def is_code(text: str) -> bool:
    for pattern in CODE_INDICATORS:
        if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
            return True
    return False


KNOWN_TEST_CARDS = {
    "4111111111111111",
    "4242424242424242",
    "4012888888881881",
    "5500005555555559",
    "5425233430109903",
    "378282246310005",
    "371449635398431",
    "6011111111111117",
    "3530111333300000",
    "4532015112830366",
    "4916338506082832",
    "5105105105105100",
    "4539578763621486",
    "4929420209979305",
    "4485275742308327",
    "4716184360702308",
    "4000056655665556",
    "4000002500003155",
    "4000000000009995",
    "4000000000000002",
    "5200828282828210",
    "2223003122003222",
    "4032030801082005",
    "4263982640269299",
    "4899335540849766",
    "4005519200000004",
    "4009348888881881",
    "4012000033330026",
    "4012000077777777",
    "4217651111111119",
    "4500600000000061",
    "378734493671000",
    "370000000000002",
    "6011000990139424",
    "3566002020360505",
}


def luhn_check(card_number: str) -> bool:
    digits = [int(d) for d in card_number if d.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def has_high_repetition(card_number: str) -> bool:
    digits = card_number.replace(" ", "").replace("-", "")
    for digit in "0123456789":
        if digits.count(digit) >= 8:
            return True
    for i in range(len(digits) - 1):
        pattern = digits[i : i + 2]
        count = sum(
            1 for j in range(0, len(digits) - 1, 2) if digits[j : j + 2] == pattern
        )
        if count >= 4:
            return True
    return False


def classify_card(card_number: str, context_text: str = "") -> dict:
    """
    يصنّف البطاقة مع الأخذ بعين الاعتبار السياق المحيط.

    ✨ v2: رقم فاشل Luhn + سياق "card/بطاقة" → suspicious=True → high
    """
    clean = card_number.replace(" ", "").replace("-", "")

    if clean.startswith("4"):
        card_type = "Visa"
    elif clean[:2] in ["51", "52", "53", "54", "55"] or (
        len(clean) >= 4 and 2221 <= int(clean[:4]) <= 2720
    ):
        card_type = "Mastercard"
    elif clean[:2] in ["34", "37"]:
        card_type = "American Express"
    elif clean[:4] in ["6011", "6441", "6445", "6450", "6456"]:
        card_type = "Discover"
    elif clean[:2] in ["35"]:
        card_type = "JCB"
    else:
        card_type = "Unknown"

    is_valid = luhn_check(clean)
    is_test = (clean in KNOWN_TEST_CARDS) or has_high_repetition(clean)

    has_card_context = bool(
        re.search(
            r"(?i)(card|بطاقة|كارت|visa|mastercard|amex|credit|debit|رقم\s*البطاقة|card\s*number|رقم\s*الكارت)",
            context_text,
        )
    )

    suspicious = False

    if not is_valid:
        if has_card_context:
            label = f"رقم {card_type} مشبوه ⚠️ — فشل Luhn لكن سياق بطاقة!"
            suspicious = True
        else:
            label = f"رقم {card_type} غير صالح (فشل Luhn)"
        risk_upgrade = False
    elif is_test:
        label = f"بطاقة {card_type} تيست/اختبار 🧪"
        risk_upgrade = False
    else:
        label = f"بطاقة {card_type} حقيقية ⚠️ خطر مرتفع!"
        risk_upgrade = True

    return {
        "is_valid": is_valid,
        "is_test": is_test,
        "card_type": card_type,
        "label": label,
        "risk_upgrade": risk_upgrade,
        "suspicious": suspicious,
    }


COUNTRY_CODES = {
    "+970": "فلسطين",
    "+972": "إسرائيل",
    "+962": "الأردن",
    "+961": "لبنان",
    "+963": "سوريا",
    "+966": "السعودية",
    "+971": "الإمارات",
    "+965": "الكويت",
    "+974": "قطر",
    "+973": "البحرين",
    "+968": "عُمان",
    "+967": "اليمن",
    "+964": "العراق",
    "+20": "مصر",
    "+212": "المغرب",
    "+213": "الجزائر",
    "+216": "تونس",
    "+249": "السودان",
    "+90": "تركيا",
    "+1": "أمريكا/كندا",
    "+44": "بريطانيا",
    "+49": "ألمانيا",
    "+33": "فرنسا",
    "+39": "إيطاليا",
    "+34": "إسبانيا",
    "+7": "روسيا",
    "+86": "الصين",
    "+91": "الهند",
    "+81": "اليابان",
    "+82": "كوريا الجنوبية",
    "+55": "البرازيل",
    "+52": "المكسيك",
    "+61": "أستراليا",
}


def detect_phone_country(phone: str) -> str | None:
    clean = phone.strip()
    if clean.startswith("00"):
        clean = "+" + clean[2:]
    for code in sorted(COUNTRY_CODES.keys(), key=len, reverse=True):
        if clean.startswith(code):
            return COUNTRY_CODES[code]
    return None


LOCATION_NAMES = (
    r"غزة|رام\s*الله|نابلس|الخليل|جنين|طولكرم|أريحا|القدس|بيت\s*لحم|"
    r"طوباس|قلقيلية|سلفيت|البيرة|رفح|خانيونس|دير\s*البلح|بيت\s*حانون|"
    r"فلسطين|الضفة\s*الغربية|قطاع\s*غزة|"
    r"الأردن|عمّان|إربد|الزرقاء|"
    r"مصر|القاهرة|الإسكندرية|الجيزة|"
    r"لبنان|بيروت|طرابلس|صيدا|"
    r"سوريا|دمشق|حلب|حمص|اللاذقية|"
    r"السعودية|الرياض|جدة|مكة|المدينة|"
    r"الإمارات|دبي|أبوظبي|الشارقة|"
    r"الكويت|قطر|الدوحة|البحرين|المنامة|"
    r"عُمان|مسقط|اليمن|صنعاء|عدن|"
    r"العراق|بغداد|البصرة|الموصل|أربيل|"
    r"تركيا|إسطنبول|أنقرة|"
    r"المغرب|الرباط|الدار\s*البيضاء|"
    r"تونس|الجزائر|ليبيا|السودان|الخرطوم|"
    r"London|Paris|New\s*York|Berlin|Tokyo|"
    r"Dubai|Riyadh|Cairo|Amman|Beirut|"
    r"Gaza|Ramallah|Nablus|Jerusalem|Hebron|Jenin|"
    r"Sydney|Toronto|Madrid|Rome|Moscow|"
    r"Beijing|Shanghai|Mumbai|Delhi|Seoul"
)

RESIDENCE_WORDS = (
    r"أسكن\s*في|عنواني|عنوان\s*سكني|أقطن\s*في|أقيم\s*في|أعيش\s*في|"
    r"منزلي\s*في|بيتي\s*في|شقتي\s*في|"
    r"I\s*live\s*in|my\s*address|home\s*address|living\s*at|"
    r"located\s*in|based\s*in|residing\s*in|resident\s*of|"
    r"شارع|حي|مخيم|بناء|شقة|طابق|بلوك|"
    r"street|avenue|road|apt|apartment|flat|building|district|neighborhood"
)


PATTERNS = [
    # ── CRITICAL ──
    {
        "pattern": r"\b(?:\d[ -]?){15,16}\b",
        "level": "critical",
        "message": "رقم بطاقة ائتمان — يُرجى التحقق",
        "card_check": True,
    },
    {
        "pattern": r"(?i)(password|passwd|pwd|pass|كلمة[\s_\-]?المرور|كلمة[\s_\-]?السر|الباسورد|الرمز[\s_\-]?السري)\s*[=:]\s*\S+",
        "level": "critical",
        "message": "كلمة مرور مكشوفة",
        "skip_if_code": True,
    },
    {
        "pattern": r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|app[_-]?secret|client[_-]?secret)\s*[=:]\s*\S+",
        "level": "critical",
        "message": "مفتاح API أو توكن مكشوف",
        "skip_if_code": True,
    },
    {
        "pattern": r"AKIA[0-9A-Z]{16}",
        "level": "critical",
        "message": "مفتاح AWS مكشوف",
    },
    {
        "pattern": r"-----BEGIN\s+(RSA\s+|EC\s+|OPENSSH\s+|PGP\s+)?PRIVATE KEY-----",
        "level": "critical",
        "message": "مفتاح تشفير خاص مكشوف",
    },
    {
        "pattern": r"gh[pso]_[A-Za-z0-9]{36,}",
        "level": "critical",
        "message": "توكن GitHub مكشوف",
    },
    {
        "pattern": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        "level": "critical",
        "message": "JWT Token مكشوف",
        "skip_if_code": True,
    },
    {
        # ✨ sk_live فقط = critical (حقيقي)
        "pattern": r"sk_live_[A-Za-z0-9]{20,}",
        "level": "critical",
        "message": "مفتاح Stripe الحقيقي مكشوف ⚠️",
    },
    {
        # ✨ sk_test = medium (ليس حقيقياً)
        "pattern": r"sk_test_[A-Za-z0-9]{10,}",
        "level": "medium",
        "message": "مفتاح Stripe تيست 🧪 — غير حقيقي",
    },
    {
        "pattern": r"(?i)(app_secret|jwt_secret|session_secret|encryption_key|hash_key|signing_key|webhook_secret|nextauth_secret)\s*[=:]\s*\S+",
        "level": "critical",
        "message": "مفتاح سري في متغيرات البيئة",
        "skip_if_code": True,
    },
    # ── HIGH ──
    {
        "pattern": r"(?i)(bank[\s_]?account|حساب[\s_]?بنكي|رقم[\s_]?الحساب[\s_]?البنكي|account[\s_]?number)\s*[:\-]?\s*\d{6,20}",
        "level": "high",
        "message": "رقم حساب بنكي",
    },
    {
        "pattern": r"\b(192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b",
        "level": "high",
        "message": "عنوان IP داخلي للشبكة",
    },
    {
        "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
        "level": "high",
        "message": "رقم ضمان اجتماعي (SSN)",
    },
    {
        "pattern": r"\b[A-Z]{1,2}\d{6,9}\b",
        "level": "high",
        "message": "رقم جواز سفر محتمل",
    },
    {
        "pattern": r"(?i)(national[\s_]?id|رقم[\s_]?الهوية|هويتي|id[\s_]?number|رقم[\s_]?هوية)\s*[:\-]?\s*\d{8,12}",
        "level": "high",
        "message": "رقم هوية وطنية",
    },
    {
        "pattern": r"(?i)(date[\s_]?of[\s_]?birth|dob|تاريخ[\s_]?الميلاد|مواليد|born[\s_]?on)\s*[:\-]?\s*[\d/\-\.]{6,10}",
        "level": "high",
        "message": "تاريخ ميلاد",
    },
    # ── MEDIUM ──
    {
        "pattern": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        "level": "medium",
        "message": "عنوان بريد إلكتروني",
        "skip_if_code": True,
    },
    {
        "pattern": r"(?:(?:\+|00)\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}",
        "level": "medium",
        "message": "رقم هاتف",
        "phone_check": True,
    },
    {
        "pattern": r"(?i)(?:"
        + RESIDENCE_WORDS
        + r").{0,30}(?:"
        + LOCATION_NAMES
        + r")",
        "level": "medium",
        "message": "عنوان سكن محتمل 📍",
    },
    {
        "pattern": r"(?i)(?:"
        + LOCATION_NAMES
        + r").{0,30}(?:"
        + RESIDENCE_WORDS
        + r")",
        "level": "medium",
        "message": "عنوان سكن محتمل 📍",
    },
    {
        "pattern": r"(?i)(mongodb|mysql|postgresql|postgres|redis|sqlite|mssql|cassandra|couchdb)\:\/\/[^\s]+",
        "level": "medium",
        "message": "رابط قاعدة بيانات",
    },
    {
        "pattern": r"(?i)(database_url|db_url|db_connection|db_host|database_host)\s*[=:]\s*\S+",
        "level": "medium",
        "message": "رابط اتصال قاعدة بيانات",
    },
    {
        "pattern": r"\b(localhost|127\.0\.0\.1)\s*:\s*\d{2,5}\b",
        "level": "medium",
        "message": "عنوان خادم محلي مع بورت",
    },
    {
        "pattern": r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7,19}\b",
        "level": "medium",
        "message": "رقم IBAN بنكي",
    },
    {
        "pattern": r"(?i)(port|بورت|منفذ)\s*[:\-]?\s*\d{2,5}",
        "level": "medium",
        "message": "رقم بورت سيرفر",
    },
    {
        "pattern": r"pk_(live|test)_[A-Za-z0-9]{20,}",
        "level": "medium",
        "message": "مفتاح Stripe العام",
    },
    {
        "pattern": r"(?i)(diagnosis|تشخيص|medical[\s_]?condition|الحالة[\s_]?الصحية)\s*[:\-]?\s*\S+",
        "level": "medium",
        "message": "معلومة طبية حساسة",
    },
]


def scan_text(text: str) -> dict:
    text_is_code = is_code(text)
    detected = []
    has_critical = has_high = has_medium = False

    for rule in PATTERNS:
        if text_is_code and rule.get("skip_if_code", False):
            continue

        matches = re.findall(rule["pattern"], text)
        if not matches:
            continue

        level = rule["level"]
        message = rule["message"]
        extra_info = {}

        if rule.get("card_check"):
            first_raw = matches[0] if isinstance(matches[0], str) else matches[0][0]
            card_digits = first_raw.replace(" ", "").replace("-", "")
            card_info = classify_card(card_digits, context_text=text)
            extra_info["card_analysis"] = card_info
            message = f"رقم بطاقة ائتمان — {card_info['label']}"

            if card_info["is_test"]:
                level = "medium"
                message = (
                    f"رقم بطاقة تيست/اختبار ({card_info['card_type']}) 🧪 — غير حقيقية"
                )
            elif card_info.get("suspicious"):
                level = "high"
                message = (
                    f"رقم {card_info['card_type']} مشبوه ⚠️ — فشل Luhn لكن سياق بطاقة!"
                )
            elif not card_info["is_valid"]:
                level = "medium"
                message = f"رقم بطاقة غير صالح ({card_info['card_type']}) — فشل Luhn"

        if rule.get("phone_check"):
            first_raw = (
                matches[0]
                if isinstance(matches[0], str)
                else "".join(m for m in matches[0] if m)
            )
            country = detect_phone_country(first_raw.strip())
            message = f"رقم هاتف دولي ({country}) 🌍" if country else "رقم هاتف"
            if country:
                extra_info["country"] = country

        detected.append(
            {"level": level, "message_ar": message, "count": len(matches), **extra_info}
        )

        if level == "critical":
            has_critical = True
        elif level == "high":
            has_high = True
        elif level == "medium":
            has_medium = True

    highest_level = (
        "critical"
        if has_critical
        else "high" if has_high else "medium" if has_medium else None
    )

    return {
        "detected": detected,
        "highest_level": highest_level,
        "found": len(detected) > 0,
    }


# اختبار
if __name__ == "__main__":
    cases = [
        ("My Visa card number is 4916123456789012 expiry 12/27", "high"),
        ("card: 4916123456789010 exp 12/26", "critical"),
        ("بطاقة التيست هي 4242424242424242 cvv 123", "medium"),
        ("password=Admin123", "critical"),
        ("sk_live_abcdefghijklmnopqrstu", "critical"),
        ("sk_test_4eC39HqLyjWDarjtT1zdp7dc", "medium"),
        ("mongodb://admin:pass@localhost", "medium"),
        ("SSN: 123-45-6789", "high"),
        ("+970591234567 تواصل معي", "medium"),
        ("أسكن في رام الله شارع 5", "medium"),
        ("كيف أكتب for loop؟", None),
        ("const password = '***';", None),
    ]
    ok = 0
    for txt, exp in cases:
        r = scan_text(txt)["highest_level"]
        chk = "✅" if r == exp else "❌"
        ok += r == exp
        print(f"{chk} [{str(r):8}] {txt[:60]}")
    print(f"\n📊 {ok}/{len(cases)} ({ok/len(cases)*100:.0f}%)")
