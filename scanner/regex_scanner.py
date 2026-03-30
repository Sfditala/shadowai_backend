# ================================================================
# ShadowAI Detector — كاشف الأنماط بالـ Regex
# ================================================================
# الهدف: يكشف البيانات الحساسة بأنماط محددة بدقة 100%
#
# ليش Regex وليس ML فقط؟
# - الـ ML يخمن بناءً على تجربة سابقة — ممكن يغلط
# - الـ Regex يتأكد بناءً على شكل ثابت — دقة 100% للأنماط المعروفة
# - مثال: رقم البطاقة دايماً 16 رقم، الإيميل دايماً فيه @
#
# المبدأ: الـ Regex يتكفل بالواضح، والـ ML يتكفل بالغامض
# ================================================================

import re

PATTERNS = [
    # ================================================================
    # 🔴 CRITICAL — أخطر الأنماط، تسريبها يسبب ضرر فوري
    # ================================================================
    {
        # ── أرقام بطاقات الائتمان ──
        # الشكل: 16 رقم ممكن متلاصقة أو بمسافات أو بشرطات
        # أمثلة: 4532015112830366 أو 4532-0151-1283-0366
        # \b = حد الكلمة (عشان ما يلتقط أرقام أطول من 16)
        # (?:\d[ -]?) = رقم ممكن بعده مسافة أو شرطة اختيارية
        # {15,16} = يتكرر 15 أو 16 مرة
        "pattern": r"\b(?:\d[ -]?){15,16}\b",
        "level": "critical",
        "message": "رقم بطاقة ائتمان محتمل",
    },
    {
        # ── كلمات المرور ──
        # يلتقط: password= أو passwd: أو كلمة المرور : (مع مسافات)
        # (?i) = تجاهل الحروف الكبيرة والصغيرة
        # [\s_\-]? = مسافة أو underscore أو شرطة اختيارية بين الكلمتين
        # \s*[=:]\s* = يساوي أو نقطتين مع مسافات اختيارية من الجانبين
        # التعديل: أضفنا \s* قبل وبعد [=:] لالتقاط "كلمة المرور : 123"
        "pattern": r"(?i)(password|passwd|pwd|pass|كلمة[\s_\-]?المرور|كلمة[\s_\-]?السر|الباسورد|الرمز[\s_\-]?السري)\s*[=:]\s*\S+",
        "level": "critical",
        "message": "كلمة مرور مكشوفة",
    },
    {
        # ── مفاتيح API والتوكنات ──
        # يلتقط: api_key= أو secret_key: أو access_token= وغيرها
        # [_-]? = شرطة أو underscore اختيارية بين الكلمتين
        "pattern": r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|app[_-]?secret|client[_-]?secret)\s*[=:]\s*\S+",
        "level": "critical",
        "message": "مفتاح API أو توكن مكشوف",
    },
    {
        # ── مفاتيح AWS ──
        # كل مفاتيح AWS Access Key تبدأ بـ AKIA ثم 16 حرف/رقم كبير
        # مثال: AKIAIOSFODNN7EXAMPLE
        "pattern": r"AKIA[0-9A-Z]{16}",
        "level": "critical",
        "message": "مفتاح AWS مكشوف",
    },
    {
        # ── مفاتيح التشفير الخاصة ──
        # الشكل الثابت لكل أنواع المفاتيح الخاصة (RSA, EC, OpenSSH, PGP)
        # (RSA\s+|EC\s+|OPENSSH\s+|PGP\s+)? = نوع المفتاح اختياري
        "pattern": r"-----BEGIN\s+(RSA\s+|EC\s+|OPENSSH\s+|PGP\s+)?PRIVATE KEY-----",
        "level": "critical",
        "message": "مفتاح تشفير خاص مكشوف",
    },
    {
        # ── توكنات GitHub ──
        # ghp_ = Personal Access Token
        # ghs_ = Service Token
        # gho_ = OAuth Token
        # بعدها 36+ حرف/رقم
        "pattern": r"gh[pso]_[A-Za-z0-9]{36,}",
        "level": "critical",
        "message": "توكن GitHub مكشوف",
    },
    {
        # ── JWT Tokens ──
        # دايماً يبدأ بـ eyJ لأن { بالـ base64 = eyJ
        # ثلاثة أجزاء مفصولة بنقطة: header.payload.signature
        # مثال: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123
        "pattern": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        "level": "critical",
        "message": "JWT Token مكشوف",
    },
    {
        # ── Stripe Secret Keys ──
        # sk_live_ = مفتاح إنتاج خطير جداً (يتيح سحب أموال)
        # sk_test_ = مفتاح تجريبي
        "pattern": r"sk_(live|test)_[A-Za-z0-9]{20,}",
        "level": "critical",
        "message": "مفتاح Stripe السري مكشوف",
    },
    {
        # ── متغيرات البيئة السرية ──
        # مثال: APP_SECRET=abc123 أو JWT_SECRET=mysecret
        "pattern": r"(?i)(app_secret|jwt_secret|session_secret|encryption_key|hash_key|signing_key|webhook_secret|nextauth_secret)\s*[=:]\s*\S+",
        "level": "critical",
        "message": "مفتاح سري في متغيرات البيئة",
    },
    # ================================================================
    # 🔴 HIGH — بيانات شخصية خطيرة (PII)
    # ================================================================
    {
        # ── البريد الإلكتروني ──
        # ليش HIGH؟ لأنه مفتاح الهوية الرقمية ويُستخدم لـ password reset
        # الشكل: أحرف/أرقام/رموز @ دومين . امتداد
        "pattern": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        "level": "high",
        "message": "عنوان بريد إلكتروني",
    },
    {
        # ── أرقام الهواتف ──
        # يلتقط: +970599123456 أو 0599123456 أو +1-555-123-4567
        # (\+\d{1,3}[-.\s]?)? = كود الدولة اختياري
        # \(?\d{3}\)? = 3 أرقام ممكن بأقواس
        "pattern": r"(\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
        "level": "high",
        "message": "رقم هاتف",
    },
    {
        # ── أرقام الحسابات البنكية ──
        # ⬆️ رُفع من MEDIUM لـ HIGH
        # ليش؟ لأن رقم الحساب + اسمك يكفي للاحتيال المصرفي
        # \d{6,20} = أرقام الحسابات من 6 لـ 20 خانة
        "pattern": r"(?i)(bank[\s_]?account|حساب[\s_]?بنكي|رقم[\s_]?الحساب[\s_]?البنكي|account[\s_]?number)\s*[:\-]?\s*\d{6,20}",
        "level": "high",
        "message": "رقم حساب بنكي",
    },
    {
        # ── عناوين IP الداخلية ──
        # ليش HIGH؟ لأنها تكشف بنية الشبكة الداخلية
        # 192.168.x.x = المنازل والمكاتب الصغيرة
        # 10.x.x.x = شبكات الشركات الكبيرة
        # 172.16-31.x.x = نطاق وسيط
        "pattern": r"\b(192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b",
        "level": "high",
        "message": "عنوان IP داخلي للشبكة",
    },
    {
        # ── أرقام الضمان الاجتماعي (SSN) ──
        # الشكل الأمريكي الثابت: 3-2-4
        # مثال: 123-45-6789
        "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
        "level": "high",
        "message": "رقم ضمان اجتماعي (SSN)",
    },
    {
        # ── أرقام جوازات السفر ──
        # الشكل: 1-2 حرف كبير + 6-9 أرقام
        # مثال: AB1234567 أو A12345678
        "pattern": r"\b[A-Z]{1,2}\d{6,9}\b",
        "level": "high",
        "message": "رقم جواز سفر محتمل",
    },
    {
        # ── أرقام الهوية الوطنية ──
        # يلتقط: رقم هويتي: 123456789 أو national id: 987654321
        "pattern": r"(?i)(national[\s_]?id|رقم[\s_]?الهوية|هويتي|id[\s_]?number|رقم[\s_]?هوية)\s*[:\-]?\s*\d{8,12}",
        "level": "high",
        "message": "رقم هوية وطنية",
    },
    {
        # ── تاريخ الميلاد ──
        # ليش HIGH؟ مع الاسم والإيميل يكمل هوية كاملة
        "pattern": r"(?i)(date[\s_]?of[\s_]?birth|dob|تاريخ[\s_]?الميلاد|مواليد|born[\s_]?on)\s*[:\-]?\s*[\d/\-\.]{6,10}",
        "level": "high",
        "message": "تاريخ ميلاد",
    },
    # ================================================================
    # 🟠 MEDIUM — معلومات حساسة لكن لا تسبب ضرراً فورياً
    # ================================================================
    {
        # ── روابط قواعد البيانات ──
        # الشكل: protocol://user:password@host:port/database
        # [^\s]+ = أي شيء مش مسافة (الرابط الكامل)
        "pattern": r"(?i)(mongodb|mysql|postgresql|postgres|redis|sqlite|mssql|cassandra|couchdb)\:\/\/[^\s]+",
        "level": "medium",
        "message": "رابط قاعدة بيانات",
    },
    {
        # ── متغيرات بيئة قواعد البيانات ──
        # مثال: DATABASE_URL=postgres://...
        "pattern": r"(?i)(database_url|db_url|db_connection|db_host|database_host)\s*[=:]\s*\S+",
        "level": "medium",
        "message": "رابط اتصال قاعدة بيانات",
    },
    {
        # ── Localhost مع بورت ──
        # يلتقط: localhost:8080 أو 127.0.0.1:3000
        "pattern": r"\b(localhost|127\.0\.0\.1)\s*:\s*\d{2,5}\b",
        "level": "medium",
        "message": "عنوان خادم محلي مع بورت",
    },
    {
        # ── IBAN ──
        # رقم الحساب الدولي — وحده ما يكفي للسرقة
        # لذلك MEDIUM وليس HIGH
        # الشكل: 2 حرف دولة + 2 رقم تحقق + 4 أحرف + 7-19 رقم
        "pattern": r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7,19}\b",
        "level": "medium",
        "message": "رقم IBAN بنكي",
    },
    {
        # ── رقم البورت ──
        # يلتقط: running on port 8080 أو السيرفر على البورت 3000
        "pattern": r"(?i)(port|بورت|منفذ)\s*[:\-]?\s*\d{2,5}",
        "level": "medium",
        "message": "رقم بورت سيرفر",
    },
    {
        # ── Stripe Publishable Keys ──
        # pk_live_ = مفتاح عام للإنتاج، أقل خطورة من sk_
        "pattern": r"pk_(live|test)_[A-Za-z0-9]{20,}",
        "level": "medium",
        "message": "مفتاح Stripe العام",
    },
    {
        # ── معلومات طبية ──
        # يلتقط: diagnosis: أو تشخيصي: أو my condition:
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

    المدخل:  text (str)
    المخرج:  dict فيه detected + highest_level + found
    """

    detected = []
    has_critical = False
    has_high = False
    has_medium = False

    for rule in PATTERNS:
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
        ("رقم بطاقتي 4532015112830366", "critical"),
        ("password=Admin123", "critical"),
        ("كلمة المرور : Admin2024", "critical"),
        ("api_key=sk-abc123def456ghi789jkl", "critical"),
        ("AKIAIOSFODNN7EXAMPLE", "critical"),
        ("-----BEGIN RSA PRIVATE KEY-----", "critical"),
        ("ghp_1234567890abcdefghijklmnopqrstuvwx", "critical"),
        ("eyJhbGciOiJIUzI1NiJ9.abc.xyz", "critical"),
        ("sk_live_abcdefghijklmnopqrstu", "critical"),
        ("my email is john@example.com", "high"),
        ("رقم هاتفي 0591234567", "high"),
        ("السيرفر على 192.168.1.100", "high"),
        ("bank account: 1234567890", "high"),
        ("رقم الحساب البنكي: 9876543210", "high"),
        ("SSN: 123-45-6789", "high"),
        ("mongodb://root:pass@localhost:27017/db", "medium"),
        ("localhost:8080", "medium"),
        ("IBAN: PS92PALS000000000400123456702", "medium"),
        ("running on port 3000", "medium"),
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
