# ================================================================
# ShadowAI Detector — كاشف الأنماط بالـ Regex
# ================================================================
# الهدف: يكشف البيانات الحساسة بأنماط محددة بدقة 100%
#
# ليش Regex وليس ML فقط؟
# - الـ ML يخمن بناءً على تجربة سابقة — ممكن يغلط
# - الـ Regex يتأكد بناءً على شكل ثابت — دقة 100% للأنماط المعروفة
#
# المبدأ: الـ Regex يتكفل بالواضح، والـ ML يتكفل بالغامض
#
# ══════════════════════════════════════════════════════
# القاعدة الذهبية: الكود البرمجي = آمن دائماً
# "password=Admin123"          → critical ✅
# "const password = '***';"    → safe ✅
# "input type='password'"      → safe ✅
# "function login(u, password)" → safe ✅
# ══════════════════════════════════════════════════════
#
# ══════════════════════════════════════════════════════
# التحسينات الجديدة (Black Hat 2026):
# 1. كشف بطاقات الائتمان الحقيقية مقابل بطاقات الاختبار (Luhn)
# 2. كشف أرقام الهواتف الدولية بمقدمات الدول
# 3. كشف عناوين السكن (اسم مدينة + كلمة سكن)
# ══════════════════════════════════════════════════════
# ================================================================

import re


# ================================================================
# كاشف الكود البرمجي
# ================================================================

CODE_INDICATORS = [
    # JavaScript / TypeScript
    r"\b(const|let|var)\s+\w+\s*=",
    r"\bfunction\s+\w+\s*\(",
    r"\bclass\s+\w+",
    r"=>\s*{",
    r"\bif\s*\(",
    r"\bfor\s*\(",
    r"\.addEventListener\(",
    r"document\.",
    # Python
    r"\bdef\s+\w+\s*\(",
    r"\bclass\s+\w+.*:",
    r"\bimport\s+\w+",
    r"\bfrom\s+\w+\s+import",
    r"print\s*\(",
    r"#\s*(TODO|FIXME|NOTE|Example|example)",
    # HTML / Template
    r"type\s*=\s*['\"]password['\"]",
    r"<input\b",
    r"<form\b",
    r"<!--",
    # General code patterns
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
    """
    يكشف إذا النص كود برمجي
    """
    for pattern in CODE_INDICATORS:
        if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
            return True
    return False


# ================================================================
# ✨ جديد: خوارزمية Luhn لكشف بطاقات الائتمان الحقيقية
# ================================================================
# خوارزمية Luhn هي المعيار العالمي للتحقق من صحة أرقام البطاقات
# كل بطاقة Visa/Mastercard/Amex حقيقية تجتاز هذا الاختبار
# بطاقات التيست (مثل 4111111111111111) تجتاز الخوارزمية أيضاً
# لكن نكشف التيست من خلال التكرار العالي في الأرقام
# ================================================================

# بطاقات التيست المعروفة — موثّقة في Stripe, PayPal, Braintree
KNOWN_TEST_CARDS = {
    "4111111111111111",  # Visa Test
    "4242424242424242",  # Stripe Visa Test
    "4012888888881881",  # Visa Test 2
    "5500005555555559",  # Mastercard Test
    "5425233430109903",  # Mastercard Test 2
    "378282246310005",  # Amex Test
    "371449635398431",  # Amex Test 2
    "6011111111111117",  # Discover Test
    "3530111333300000",  # JCB Test
    "4532015112830366",  # Visa Test Common
    "4916338506082832",  # Visa Test 3
    "5105105105105100",  # Mastercard Test 3
    "4539578763621486",  # Visa Test 4
    "4929420209979305",  # Visa Test 5
    "4485275742308327",  # Visa Test 6
    "4716184360702308",  # Visa Test 7
    # ── ✨ إضافة جديدة: Stripe ──
    "4000056655665556",  # Visa Debit Test
    "4000002500003155",  # Visa 3D Secure Test
    "4000000000009995",  # Visa Decline Test
    "4000000000000002",  # Visa Decline Test 2
    "5200828282828210",  # Mastercard Debit Test
    "5105105105105100",  # Mastercard Test
    "2223003122003222",  # Mastercard 2-series Test
    # ── ✨ إضافة جديدة: PayPal ──
    "4032030801082005",  # PayPal Visa Test
    "4263982640269299",  # PayPal Visa Test 2
    "4899335540849766",  # PayPal Visa Test 3
    # ── ✨ إضافة جديدة: Braintree ──
    "4005519200000004",  # Braintree Visa Test
    "4009348888881881",  # Braintree Visa Test 2
    "4012000033330026",  # Braintree Visa Test 3
    "4012000077777777",  # Braintree Visa Test 4
    "4217651111111119",  # Braintree Visa Test 5
    "4500600000000061",  # Braintree Visa Test 6
    # ── ✨ إضافة جديدة: Amex Test ──
    "378734493671000",  # Amex Corporate Test
    "370000000000002",  # Amex Test 3
    # ── ✨ إضافة جديدة: Discover Test ──
    "6011000990139424",  # Discover Test 2
    "6011111111111117",  # Discover Test 3
    # ── ✨ إضافة جديدة: JCB Test ──
    "3566002020360505",  # JCB Test 2
    "3530111333300000",  # JCB Test 3
}


def luhn_check(card_number: str) -> bool:
    """
    خوارزمية Luhn — تتحقق من صحة رقم البطاقة رياضياً
    كل بطاقة حقيقية (وبطاقات التيست المعروفة) تجتاز هذا الاختبار

    الخوارزمية:
    1. نعكس الأرقام
    2. نضاعف كل رقم في الموضع الزوجي
    3. لو الناتج > 9 نطرح 9
    4. نجمع الكل — لو قابل القسمة على 10 = صالح
    """
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
    """
    يكشف إذا الرقم فيه تكرار عالي — علامة بطاقة تيست
    مثال: 4242424242424242 → نمط "42" يتكرر 8 مرات
    مثال: 4111111111111111 → الرقم 1 يتكرر 12 مرة
    """
    digits = card_number.replace(" ", "").replace("-", "")

    # كشف تكرار رقم واحد
    for digit in "0123456789":
        if digits.count(digit) >= 8:
            return True

    # كشف تكرار نمط ثنائي (مثل "42" أو "55")
    for i in range(len(digits) - 1):
        pattern = digits[i : i + 2]
        count = sum(
            1 for j in range(0, len(digits) - 1, 2) if digits[j : j + 2] == pattern
        )
        if count >= 4:
            return True

    return False


def classify_card(card_number: str) -> dict:
    """
    يصنّف البطاقة: حقيقية / تيست / غير صالحة

    المخرج:
    {
        "is_valid": bool,        # تجتاز Luhn؟
        "is_test": bool,         # بطاقة تيست؟
        "card_type": str,        # Visa / Mastercard / Amex / Unknown
        "label": str,            # وصف للمستخدم
        "risk_upgrade": bool,    # ترفع الخطورة لو حقيقية
    }
    """
    clean = card_number.replace(" ", "").replace("-", "")

    # نوع البطاقة من أول رقم
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
    is_known_test = clean in KNOWN_TEST_CARDS
    is_repetitive = has_high_repetition(clean)
    is_test = is_known_test or is_repetitive

    if not is_valid:
        label = f"رقم {card_type} غير صالح (فشل Luhn)"
        risk_upgrade = False
    elif is_test:
        label = f"بطاقة {card_type} تيست/اختبار 🧪"
        risk_upgrade = False  # بطاقة تيست أقل خطورة
    else:
        label = f"بطاقة {card_type} حقيقية ⚠️ خطر مرتفع!"
        risk_upgrade = True  # بطاقة حقيقية = خطر أعلى

    return {
        "is_valid": is_valid,
        "is_test": is_test,
        "card_type": card_type,
        "label": label,
        "risk_upgrade": risk_upgrade,
    }


# ================================================================
# ✨ جديد: كشف أرقام الهواتف الدولية بمقدمات الدول
# ================================================================

# مقدمات الدول العربية + الشائعة
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
    """
    يكشف مقدمة الدولة من رقم الهاتف
    يدعم الصيغ: +970, 00970
    يرجع اسم الدولة أو None
    """
    clean = phone.strip()

    # تحويل 00XXX إلى +XXX
    if clean.startswith("00"):
        clean = "+" + clean[2:]

    # نبحث عن أطول مقدمة تطابق (لتجنب الخلط بين +1 و+964)
    for code in sorted(COUNTRY_CODES.keys(), key=len, reverse=True):
        if clean.startswith(code):
            return COUNTRY_CODES[code]

    return None


# ================================================================
# ✨ جديد: قائمة المدن والدول للكشف عن العناوين
# ================================================================

LOCATION_NAMES = (
    # فلسطين
    r"غزة|رام\s*الله|نابلس|الخليل|جنين|طولكرم|أريحا|القدس|بيت\s*لحم|"
    r"طوباس|قلقيلية|سلفيت|البيرة|رفح|خانيونس|دير\s*البلح|بيت\s*حانون|"
    r"فلسطين|الضفة\s*الغربية|قطاع\s*غزة|"
    # دول عربية
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
    r"تونس|الجزائر|ليبيا|طرابلس|"
    r"السودان|الخرطوم|"
    # دولي
    r"London|Paris|New\s*York|Berlin|Tokyo|"
    r"Dubai|Riyadh|Cairo|Amman|Beirut|"
    r"Gaza|Ramallah|Nablus|Jerusalem|Hebron|Jenin|"
    r"Sydney|Toronto|Madrid|Rome|Moscow|"
    r"Beijing|Shanghai|Mumbai|Delhi|Seoul"
)

# كلمات تدل على السكن/الإقامة
RESIDENCE_WORDS = (
    r"أسكن\s*في|عنواني|عنوان\s*سكني|أقطن\s*في|أقيم\s*في|أعيش\s*في|"
    r"منزلي\s*في|بيتي\s*في|شقتي\s*في|"
    r"I\s*live\s*in|my\s*address|home\s*address|living\s*at|"
    r"located\s*in|based\s*in|residing\s*in|resident\s*of|"
    r"شارع|حي|مخيم|بناء|شقة|طابق|بلوك|"
    r"street|avenue|road|apt|apartment|flat|building|district|neighborhood"
)


# ================================================================
# قاموس الأنماط
# ================================================================

PATTERNS = [
    # ================================================================
    # 🔴 CRITICAL — أخطر الأنماط، تسريبها يسبب ضرر فوري
    # ================================================================
    {
        # ✨ محدّث: أرقام بطاقات الائتمان — مع كشف التيست عبر Luhn
        # الكشف الأولي هنا، والتصنيف الدقيق يتم في get_detected_with_snippets
        "pattern": r"\b(?:\d[ -]?){15,16}\b",
        "level": "critical",
        "message": "رقم بطاقة ائتمان — يُرجى التحقق",
        "card_check": True,  # ← علامة: طبّق classify_card() على هذا التطابق
    },
    {
        # كلمات المرور الحقيقية
        "pattern": r"(?i)(password|passwd|pwd|pass|كلمة[\s_\-]?المرور|كلمة[\s_\-]?السر|الباسورد|الرمز[\s_\-]?السري)\s*[=:]\s*\S+",
        "level": "critical",
        "message": "كلمة مرور مكشوفة",
        "skip_if_code": True,
    },
    {
        # مفاتيح API والتوكنات
        "pattern": r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|app[_-]?secret|client[_-]?secret)\s*[=:]\s*\S+",
        "level": "critical",
        "message": "مفتاح API أو توكن مكشوف",
        "skip_if_code": True,
    },
    {
        # مفاتيح AWS
        "pattern": r"AKIA[0-9A-Z]{16}",
        "level": "critical",
        "message": "مفتاح AWS مكشوف",
    },
    {
        # مفاتيح التشفير الخاصة
        "pattern": r"-----BEGIN\s+(RSA\s+|EC\s+|OPENSSH\s+|PGP\s+)?PRIVATE KEY-----",
        "level": "critical",
        "message": "مفتاح تشفير خاص مكشوف",
    },
    {
        # توكنات GitHub
        "pattern": r"gh[pso]_[A-Za-z0-9]{36,}",
        "level": "critical",
        "message": "توكن GitHub مكشوف",
    },
    {
        # JWT Tokens
        "pattern": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        "level": "critical",
        "message": "JWT Token مكشوف",
        "skip_if_code": True,
    },
    {
        # Stripe Secret Keys
        "pattern": r"sk_(live|test)_[A-Za-z0-9]{20,}",
        "level": "critical",
        "message": "مفتاح Stripe السري مكشوف",
    },
    {
        # متغيرات البيئة السرية
        "pattern": r"(?i)(app_secret|jwt_secret|session_secret|encryption_key|hash_key|signing_key|webhook_secret|nextauth_secret)\s*[=:]\s*\S+",
        "level": "critical",
        "message": "مفتاح سري في متغيرات البيئة",
        "skip_if_code": True,
    },
    # ================================================================
    # 🔴 HIGH — بيانات شخصية خطيرة (PII)
    # ================================================================
    {
        # البريد الإلكتروني
        "pattern": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        "level": "medium",
        "message": "عنوان بريد إلكتروني",
        "skip_if_code": True,
    },
    {
        # ✨ محدّث: أرقام الهواتف الدولية بمقدمات الدول (00XXX أو +XXX)
        "pattern": r"(?:(?:\+|00)\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}",
        "level": "medium",
        "message": "رقم هاتف",
        "phone_check": True,  # ← علامة: طبّق detect_phone_country() لتحسين الرسالة
    },
    {
        # أرقام الحسابات البنكية
        "pattern": r"(?i)(bank[\s_]?account|حساب[\s_]?بنكي|رقم[\s_]?الحساب[\s_]?البنكي|account[\s_]?number)\s*[:\-]?\s*\d{6,20}",
        "level": "high",
        "message": "رقم حساب بنكي",
    },
    {
        # عناوين IP الداخلية
        "pattern": r"\b(192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b",
        "level": "high",
        "message": "عنوان IP داخلي للشبكة",
    },
    {
        # أرقام الضمان الاجتماعي (SSN)
        "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
        "level": "high",
        "message": "رقم ضمان اجتماعي (SSN)",
    },
    {
        # أرقام جوازات السفر
        "pattern": r"\b[A-Z]{1,2}\d{6,9}\b",
        "level": "high",
        "message": "رقم جواز سفر محتمل",
    },
    {
        # أرقام الهوية الوطنية
        "pattern": r"(?i)(national[\s_]?id|رقم[\s_]?الهوية|هويتي|id[\s_]?number|رقم[\s_]?هوية)\s*[:\-]?\s*\d{8,12}",
        "level": "high",
        "message": "رقم هوية وطنية",
    },
    {
        # تاريخ الميلاد
        "pattern": r"(?i)(date[\s_]?of[\s_]?birth|dob|تاريخ[\s_]?الميلاد|مواليد|born[\s_]?on)\s*[:\-]?\s*[\d/\-\.]{6,10}",
        "level": "high",
        "message": "تاريخ ميلاد",
    },
    # ================================================================
    # ✨ جديد: كشف عناوين السكن
    # ================================================================
    {
        # عنوان سكن = كلمة سكن + اسم مدينة/دولة
        "pattern": (
            r"(?i)(?:" + RESIDENCE_WORDS + r")" + r".{0,30}(?:" + LOCATION_NAMES + r")"
        ),
        "level": "medium",
        "message": "عنوان سكن محتمل 📍",
    },
    {
        # اسم مدينة/دولة + كلمة سكن (الترتيب المعكوس)
        "pattern": (
            r"(?i)(?:" + LOCATION_NAMES + r")" + r".{0,30}(?:" + RESIDENCE_WORDS + r")"
        ),
        "level": "medium",
        "message": "عنوان سكن محتمل 📍",
    },
    # ================================================================
    # 🟠 MEDIUM — معلومات حساسة لكن لا تسبب ضرراً فورياً
    # ================================================================
    {
        # روابط قواعد البيانات
        "pattern": r"(?i)(mongodb|mysql|postgresql|postgres|redis|sqlite|mssql|cassandra|couchdb)\:\/\/[^\s]+",
        "level": "medium",
        "message": "رابط قاعدة بيانات",
    },
    {
        # متغيرات بيئة قواعد البيانات
        "pattern": r"(?i)(database_url|db_url|db_connection|db_host|database_host)\s*[=:]\s*\S+",
        "level": "medium",
        "message": "رابط اتصال قاعدة بيانات",
    },
    {
        # Localhost مع بورت
        "pattern": r"\b(localhost|127\.0\.0\.1)\s*:\s*\d{2,5}\b",
        "level": "medium",
        "message": "عنوان خادم محلي مع بورت",
    },
    {
        # IBAN
        "pattern": r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7,19}\b",
        "level": "medium",
        "message": "رقم IBAN بنكي",
    },
    {
        # رقم البورت
        "pattern": r"(?i)(port|بورت|منفذ)\s*[:\-]?\s*\d{2,5}",
        "level": "medium",
        "message": "رقم بورت سيرفر",
    },
    {
        # Stripe Publishable Keys
        "pattern": r"pk_(live|test)_[A-Za-z0-9]{20,}",
        "level": "medium",
        "message": "مفتاح Stripe العام",
    },
    {
        # معلومات طبية
        "pattern": r"(?i)(diagnosis|تشخيص|medical[\s_]?condition|الحالة[\s_]?الصحية)\s*[:\-]?\s*\S+",
        "level": "medium",
        "message": "معلومة طبية حساسة",
    },
    # قبل — يعامل test و live بنفس الطريقة
    {
        "pattern": r"sk_(live|test)_[A-Za-z0-9]{20,}",
        "level": "critical",
        "message": "مفتاح Stripe السري مكشوف",
    },
    # بعد — يفرق بين test و live
    {
        "pattern": r"sk_live_[A-Za-z0-9]{20,}",
        "level": "critical",
        "message": "مفتاح Stripe الحقيقي مكشوف ⚠️",
    },
    {
        "pattern": r"sk_test_[A-Za-z0-9]{10,}",
        "level": "medium",
        "message": "مفتاح Stripe تيست 🧪 — غير حقيقي",
    },
]


# ================================================================
# الدالة الرئيسية — محدّثة
# ================================================================


def scan_text(text: str) -> dict:
    """
    يفحص النص ويرجع قائمة بكل المشاكل المكتشفة

    الخطوات:
    1. يتحقق إذا النص كود برمجي
    2. لو كود، يتجاهل الأنماط اللي عندها skip_if_code=True
    3. ✨ للبطاقات: يطبق Luhn لتمييز الحقيقية من التيست
    4. ✨ للهواتف: يكشف مقدمة الدولة
    5. يرجع أعلى مستوى خطورة وجده
    """
    text_is_code = is_code(text)

    detected = []
    has_critical = False
    has_high = False
    has_medium = False

    for rule in PATTERNS:
        if text_is_code and rule.get("skip_if_code", False):
            continue

        matches = re.findall(rule["pattern"], text)
        if not matches:
            continue

        level = rule["level"]
        message = rule["message"]
        extra_info = {}

        # ✨ كشف البطاقات الذكي
        if rule.get("card_check"):
            # نأخذ أول تطابق ونحلله
            first_raw = matches[0] if isinstance(matches[0], str) else matches[0][0]
            card_digits = first_raw.replace(" ", "").replace("-", "")
            card_info = classify_card(card_digits)

            extra_info["card_analysis"] = card_info
            message = f"رقم بطاقة ائتمان — {card_info['label']}"

            # لو البطاقة تيست → نخفض الخطورة لـ medium
            if card_info["is_test"] and not card_info["risk_upgrade"]:
                level = "medium"
                message = (
                    f"رقم بطاقة تيست/اختبار ({card_info['card_type']}) 🧪 — غير حقيقية"
                )
            elif not card_info["is_valid"]:
                level = "medium"
                message = f"رقم بطاقة غير صالح ({card_info['card_type']}) — فشل Luhn"
            # لو حقيقية → critical تبقى

        # ✨ كشف الهاتف الذكي
        if rule.get("phone_check"):
            first_raw = (
                matches[0]
                if isinstance(matches[0], str)
                else "".join(m for m in matches[0] if m)
            )
            country = detect_phone_country(first_raw.strip())
            if country:
                message = f"رقم هاتف دولي ({country}) 🌍"
                extra_info["country"] = country
            else:
                message = "رقم هاتف"

        detected.append(
            {
                "level": level,
                "message_ar": message,
                "count": len(matches),
                **extra_info,
            }
        )

        if level == "critical":
            has_critical = True
        elif level == "high":
            has_high = True
        elif level == "medium":
            has_medium = True

    if has_critical:
        highest_level = "critical"
    elif has_high:
        highest_level = "high"
    elif has_medium:
        highest_level = "medium"
    else:
        highest_level = None

    return {
        "detected": detected,
        "highest_level": highest_level,
        "found": len(detected) > 0,
    }


# ================================================================
# اختبار — شغل: python regex_scanner.py
# ================================================================
if __name__ == "__main__":
    print("🧪 اختبار regex_scanner المحدّث:\n")

    test_cases = [
        # ✨ بطاقات: حقيقية vs تيست
        ("رقم بطاقتي 4532015112830366", "critical"),  # تيست معروفة → medium
        ("رقم بطاقتي 4916123456789012", "critical"),  # Visa بصيغة قد تكون حقيقية
        ("بطاقة 4242424242424242", "critical"),  # Stripe test → medium
        # critical أخرى
        ("password=Admin123", "critical"),
        ("كلمة المرور : Admin2024", "critical"),
        ("api_key=sk-abc123def456ghi789jkl", "critical"),
        ("AKIAIOSFODNN7EXAMPLE", "critical"),
        ("-----BEGIN RSA PRIVATE KEY-----", "critical"),
        ("ghp_1234567890abcdefghijklmnopqrstuvwx", "critical"),
        ("sk_live_abcdefghijklmnopqrstu", "critical"),
        # safe — كود برمجي
        ("const password = '***';", None),
        ("input type='password'", None),
        ("function login(u, password) { }", None),
        ("api_key = os.getenv('API_KEY')", None),
        ("SECRET_KEY = os.environ.get('SECRET_KEY')", None),
        # high
        ("السيرفر على 192.168.1.100", "high"),
        ("bank account: 1234567890", "high"),
        ("SSN: 123-45-6789", "high"),
        # ✨ هواتف دولية
        ("+970591234567 تواصل معي", "medium"),
        ("00966501234567", "medium"),
        ("+1-555-123-4567", "medium"),
        # ✨ عناوين سكن
        ("أسكن في رام الله", "medium"),
        ("my address is in Gaza", "medium"),
        ("أقطن في شارع النزهة نابلس", "medium"),
        # medium عادية
        ("my email is john@example.com", "medium"),
        ("mongodb://root:pass@localhost:27017/db", "medium"),
        ("running on port 3000", "medium"),
        # safe
        ("كيف أكتب حلقة for؟", None),
        ("what is machine learning?", None),
        ("اسمي تالا", None),
        ("صباح الخير", None),
    ]

    correct = 0
    for text, expected in test_cases:
        result = scan_text(text)
        found = result["highest_level"]

        # بطاقات التيست تُصنَّف medium وليس critical
        # نقبل medium كنتيجة صحيحة للبطاقات المعروفة كتيست
        check = (
            "✅"
            if found == expected
            or (
                expected == "critical"
                and found == "medium"
                and any(
                    d.get("card_analysis", {}).get("is_test")
                    for d in result["detected"]
                )
            )
            else "❌"
        )
        correct += 1 if check == "✅" else 0

        icon = (
            "🔴"
            if found in ["critical", "high"]
            else "🟠" if found == "medium" else "🟢"
        )

        # اظهر معلومات البطاقة لو موجودة
        card_note = ""
        for d in result["detected"]:
            if "card_analysis" in d:
                ca = d["card_analysis"]
                card_note = f" [{ca['card_type']} | {'تيست' if ca['is_test'] else 'حقيقية' if ca['is_valid'] else 'غير صالحة'}]"
            if "country" in d:
                card_note = f" [دولة: {d['country']}]"

        print(f"   {check} {icon} [{str(found):8}] {text[:50]}{card_note}")

    print(
        f"\n📊 دقة الـ Regex: {correct}/{len(test_cases)} ({correct/len(test_cases)*100:.0f}%)"
    )

    # ── اختبار Luhn منفصل ──
    print("\n🔬 اختبار خوارزمية Luhn:")
    luhn_tests = [
        ("4532015112830366", True, True),  # test card
        ("4242424242424242", True, True),  # stripe test
        ("4916123456789012", True, False),  # potentially real
        ("1234567890123456", False, False),  # invalid
        ("4111111111111111", True, True),  # test card
    ]
    for num, expected_valid, expected_test in luhn_tests:
        info = classify_card(num)
        v = "✅" if info["is_valid"] == expected_valid else "❌"
        t = "🧪" if info["is_test"] else "💳"
        print(f"   {v} {t} {num} → {info['label']}")
