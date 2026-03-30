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
# ================================================================

import re


# ================================================================
# كاشف الكود البرمجي
# ================================================================
# قبل ما نفحص النص، نتأكد إنه مش كود
# لأن الكود ممكن فيه كلمة password أو api_key لكنها للتطوير مش للتسريب
# ================================================================

# أنماط تدل على إن النص كود برمجي
CODE_INDICATORS = [
    # JavaScript / TypeScript
    r"\b(const|let|var)\s+\w+\s*=",  # const x =
    r"\bfunction\s+\w+\s*\(",  # function login(
    r"\bclass\s+\w+",  # class PasswordValidator
    r"=>\s*{",  # arrow function
    r"\bif\s*\(",  # if (condition)
    r"\bfor\s*\(",  # for (let i...
    r"\.addEventListener\(",  # addEventListener
    r"document\.",  # document.getElementById
    # Python
    r"\bdef\s+\w+\s*\(",  # def check_password(
    r"\bclass\s+\w+.*:",  # class MyClass:
    r"\bimport\s+\w+",  # import os
    r"\bfrom\s+\w+\s+import",  # from flask import
    r"print\s*\(",  # print(
    r"#\s*(TODO|FIXME|NOTE|Example|example)",  # # TODO: ...
    # HTML / Template
    r"type\s*=\s*['\"]password['\"]",  # type='password'
    r"<input\b",  # <input
    r"<form\b",  # <form
    r"<!--",  # HTML comment
    # General code patterns
    r"[{};]\s*$",  # line ends with { } ;
    r"^\s*//.*",  # // comment
    r"^\s*#\s+\w",  # # comment
    r"\$\{[^}]+\}",  # ${VARIABLE}
    r"'YOUR_[A-Z_]+_HERE'",  # 'YOUR_API_KEY_HERE'
    r"<your-[a-z-]+>",  # <your-api-key>
    r"os\.getenv\(",  # os.getenv(
    r"os\.environ",  # os.environ
    r"process\.env\.",  # process.env.
    r"bcrypt\.",  # bcrypt.hash(
    r"jwt\.(encode|decode)\(",  # jwt.encode(
    r"models\.\w+Field\(",  # models.EmailField(
    r"SELECT\s+.*\s+FROM\s+",  # SQL query
    r"ALTER\s+TABLE\s+",  # SQL ALTER
    r"CREATE\s+(INDEX|TABLE)\s+",  # SQL CREATE
    r"filter_var\s*\(",  # PHP filter_var
    r"router\.(get|post|put|delete)\(",  # Express route
]


def is_code(text: str) -> bool:
    """
    يكشف إذا النص كود برمجي

    المدخل: text (str)
    المخرج: True لو كود، False لو مش كود

    كيف يعمل؟
    يبحث عن أنماط مميزة للكود زي:
    - const/let/var/def/function/class
    - تعليقات // أو #
    - HTML tags
    - متغيرات بيئة os.getenv أو process.env
    """
    for pattern in CODE_INDICATORS:
        if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
            return True
    return False


# ================================================================
# قاموس الأنماط
# ================================================================

PATTERNS = [
    # ================================================================
    # 🔴 CRITICAL — أخطر الأنماط، تسريبها يسبب ضرر فوري
    # ================================================================
    {
        # أرقام بطاقات الائتمان
        "pattern": r"\b(?:\d[ -]?){15,16}\b",
        "level": "critical",
        "message": "رقم بطاقة ائتمان محتمل",
    },
    {
        # كلمات المرور الحقيقية
        # يلتقط: password=Admin123 أو كلمة المرور : 123
        # لكن لو الكود برمجي → is_code() تمنعه
        "pattern": r"(?i)(password|passwd|pwd|pass|كلمة[\s_\-]?المرور|كلمة[\s_\-]?السر|الباسورد|الرمز[\s_\-]?السري)\s*[=:]\s*\S+",
        "level": "critical",
        "message": "كلمة مرور مكشوفة",
        "skip_if_code": True,  # ← مش يطبق على الكود
    },
    {
        # مفاتيح API والتوكنات
        # skip_if_code لأن api_key = os.getenv('API_KEY') كود آمن
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
        "skip_if_code": True,  # jwt.encode(payload, secret) كود آمن
    },
    {
        # Stripe Secret Keys
        "pattern": r"sk_(live|test)_[A-Za-z0-9]{20,}",
        "level": "critical",
        "message": "مفتاح Stripe السري مكشوف",
    },
    {
        # متغيرات البيئة السرية
        # skip_if_code لأن SECRET_KEY = os.environ.get('SECRET_KEY') كود آمن
        "pattern": r"(?i)(app_secret|jwt_secret|session_secret|encryption_key|hash_key|signing_key|webhook_secret|nextauth_secret)\s*[=:]\s*\S+",
        "level": "critical",
        "message": "مفتاح سري في متغيرات البيئة",
        "skip_if_code": True,
    },
    # ================================================================
    # 🔴 HIGH — بيانات شخصية خطيرة (PII)
    # ================================================================
    {
        # البريد الإلكتروني — medium (مش high) لأن الإيميل المجرد أقل خطورة
        "pattern": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        "level": "medium",
        "message": "عنوان بريد إلكتروني",
        "skip_if_code": True,  # email = models.EmailField() كود آمن
    },
    {
        # أرقام الهواتف — medium لأن الهاتف المجرد أقل خطورة
        "pattern": r"(\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
        "level": "medium",
        "message": "رقم هاتف",
    },
    {
        # أرقام الحسابات البنكية — high لأن رقم الحساب خطير
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
]


# ================================================================
# الدالة الرئيسية
# ================================================================


def scan_text(text: str) -> dict:
    """
    يفحص النص ويرجع قائمة بكل المشاكل المكتشفة

    الخطوات:
    1. يتحقق إذا النص كود برمجي
    2. لو كود، يتجاهل الأنماط اللي عندها skip_if_code=True
    3. يرجع أعلى مستوى خطورة وجده
    """

    # ── هل النص كود؟ ──
    text_is_code = is_code(text)

    detected = []
    has_critical = False
    has_high = False
    has_medium = False

    for rule in PATTERNS:
        # لو الكود برمجي والـ rule يستثني الكود → تجاهل
        if text_is_code and rule.get("skip_if_code", False):
            continue

        matches = re.findall(rule["pattern"], text)

        if matches:
            detected.append(
                {
                    "level": rule["level"],
                    "message_ar": rule["message"],
                    "count": len(matches),
                }
            )

            if rule["level"] == "critical":
                has_critical = True
            elif rule["level"] == "high":
                has_high = True
            elif rule["level"] == "medium":
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
# اختبار — شغل: python scanner/regex_scanner.py
# ================================================================
if __name__ == "__main__":
    print("🧪 اختبار regex_scanner:\n")

    test_cases = [
        # critical
        ("رقم بطاقتي 4532015112830366", "critical"),
        ("password=Admin123", "critical"),
        ("كلمة المرور : Admin2024", "critical"),
        ("api_key=sk-abc123def456ghi789jkl", "critical"),
        ("AKIAIOSFODNN7EXAMPLE", "critical"),
        ("-----BEGIN RSA PRIVATE KEY-----", "critical"),
        ("ghp_1234567890abcdefghijklmnopqrstuvwx", "critical"),
        ("eyJhbGciOiJIUzI1NiJ9.abc.xyz", "critical"),
        ("sk_live_abcdefghijklmnopqrstu", "critical"),
        # safe — كود برمجي (الأهم!)
        ("const password = '***';", None),
        ("input type='password'", None),
        ("function login(u, password) { }", None),
        ("# Example: password=your_password", None),
        ("api_key = os.getenv('API_KEY')", None),
        ("SECRET_KEY = os.environ.get('SECRET_KEY')", None),
        ("token = jwt.encode(payload, secret)", None),
        ("email = models.EmailField()", None),
        # high
        ("السيرفر على 192.168.1.100", "high"),
        ("bank account: 1234567890", "high"),
        ("رقم الحساب البنكي: 9876543210", "high"),
        ("SSN: 123-45-6789", "high"),
        # medium
        ("my email is john@example.com", "medium"),
        ("رقم هاتفي 0591234567", "medium"),
        ("mongodb://root:pass@localhost:27017/db", "medium"),
        ("localhost:8080", "medium"),
        ("IBAN: PS92PALS000000000400123456702", "medium"),
        ("running on port 3000", "medium"),
        # safe
        ("كيف أكتب حلقة for؟", None),
        ("what is machine learning?", None),
        ("اسمي تالا", None),
    ]

    correct = 0
    for text, expected in test_cases:
        result = scan_text(text)
        found = result["highest_level"]
        check = "✅" if found == expected else "❌"
        correct += 1 if found == expected else 0
        icon = (
            "🔴"
            if found in ["critical", "high"]
            else "🟠" if found == "medium" else "🟢"
        )
        print(f"   {check} {icon} [{str(found):8}] ← {text[:55]}")

    print(
        f"\n📊 دقة الـ Regex: {correct}/{len(test_cases)} ({correct/len(test_cases)*100:.0f}%)"
    )
