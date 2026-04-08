from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import os
import sys
import re
import time

sys.path.append(os.path.join(os.path.dirname(__file__), "scanner"))
from regex_scanner import scan_text, PATTERNS, classify_card, detect_phone_country

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
model = joblib.load("models/classifier.pkl")
vectorizer = joblib.load("models/vectorizer.pkl")

LABELS_AR = {
    "critical": "خطر حرج 🔴",
    "high": "خطر عالي 🔴",
    "medium": "خطر متوسط 🟠",
    "safe": "آمن 🟢",
}

RISK_SCORES = {
    "critical": 0.95,
    "high": 0.80,
    "medium": 0.55,
    "safe": 0.10,
}


def get_final_level(regex_level, ml_level):
    priority = {"critical": 4, "high": 3, "medium": 2, "safe": 1}

    # ✨ لو Regex قال medium والـ ML قال critical → نثق بالـ Regex
    if regex_level == "medium" and ml_level == "critical":
        return "medium"

    return (
        regex_level
        if priority.get(regex_level, 0) >= priority.get(ml_level, 0)
        else ml_level
    )


def get_detected_with_snippets(text):
    """
    يفحص النص ويرجع المشاكل مع الجزء المكتشف
    snippet = الجزء الحساس من النص
    ✨ محدّث: يدعم كشف البطاقات الذكي (Luhn) وكشف مقدمة الدولة للهاتف
    """
    from regex_scanner import is_code

    text_is_code = is_code(text)
    detected = []
    has_critical = False
    has_high = False
    has_medium = False

    for rule in PATTERNS:
        if text_is_code and rule.get("skip_if_code", False):
            continue

        matches = list(re.finditer(rule["pattern"], text))
        if not matches:
            continue

        first_match = matches[0]
        matched_text = first_match.group()
        snippet = matched_text[:37] + "..." if len(matched_text) > 40 else matched_text

        level = rule["level"]
        message = rule["message"]
        extra = {}

        # ✨ كشف البطاقات الذكي باستخدام Luhn
        if rule.get("card_check"):
            card_digits = matched_text.replace(" ", "").replace("-", "")
            card_info = classify_card(card_digits)
            extra["card_analysis"] = card_info

            if card_info["is_test"]:
                level = "medium"
                message = f"بطاقة {card_info['card_type']} تيست 🧪 — غير حقيقية"
            elif not card_info["is_valid"]:
                level = "medium"
                message = f"رقم {card_info['card_type']} غير صالح — فشل Luhn"
            else:
                level = "critical"
                message = f"بطاقة {card_info['card_type']} حقيقية ⚠️ — خطر فوري!"

        # ✨ كشف مقدمة الدولة للهاتف
        if rule.get("phone_check"):
            country = detect_phone_country(matched_text.strip())
            if country:
                message = f"رقم هاتف دولي ({country}) 🌍"
                extra["country"] = country

        detected.append(
            {
                "level": level,
                "message_ar": message,
                "count": len(matches),
                "snippet": snippet,
                **extra,
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


@app.route("/scan", methods=["POST"])
def scan():
    start_time = time.time()

    data = request.get_json()
    text = data.get("text", "")

    if not text.strip():
        return jsonify({"error": "النص فاضي"}), 400

    # ================================================================
    # ✨ Override فوري: مفاتيح التيست دائماً medium بغض النظر عن ML
    # السبب: ML لا يستطيع التمييز بين sk_test_ و sk_live_ بدقة كافية
    # الـ Regex أدق لهاي الحالات المحددة
    # ================================================================
    TEST_PATTERNS = [
        r"sk_test_[A-Za-z0-9]{10,}",
        r"pk_test_[A-Za-z0-9]{10,}",
        r"rk_test_[A-Za-z0-9]{10,}",
    ]
    LIVE_PATTERNS = [
        r"sk_live_",
        r"pk_live_",
        r"rk_live_",
    ]

    has_test_key = any(re.search(p, text) for p in TEST_PATTERNS)
    has_live_key = any(re.search(p, text) for p in LIVE_PATTERNS)

    if has_test_key and not has_live_key:
        regex_result = get_detected_with_snippets(text)
        scan_duration_ms = round((time.time() - start_time) * 1000)
        return jsonify(
            {
                "result": {
                    "risk_level": "medium",
                    "risk_label_ar": LABELS_AR["medium"],
                    "risk_score": round(RISK_SCORES["medium"], 2),
                    "should_block": False,
                    "message_ar": "النص آمن للإرسال",
                    "detected": regex_result["detected"],
                    "ml_prediction": None,
                    "detection_method": "regex",
                    "scan_duration_ms": scan_duration_ms,
                    "text_length": len(text),
                }
            }
        )

    # ================================================================
    # ── المرحلة 1: فحص Regex دائماً ──
    # ================================================================
    regex_result = get_detected_with_snippets(text)
    regex_level = regex_result["highest_level"]

    # ================================================================
    # ── المرحلة 2: Smart Pre-filter ──
    # لو الـ Regex وجد critical أو high → لا نحتاج ML أصلاً
    # الـ Regex أسرع بكثير ودقيق 100% للأنماط المعروفة
    # ================================================================
    ml_pred = None
    ml_prob = None
    used_ml = False

    if regex_level in ["critical", "high"]:
        # Regex كفيل — تخطّ ML
        final_level = regex_level
        final_score = RISK_SCORES[regex_level]
    else:
        # نشغّل ML للنصوص الغامضة أو الآمنة
        used_ml = True
        X = vectorizer.transform([text])
        ml_pred = model.predict(X)[0]
        ml_prob = max(model.predict_proba(X)[0])

        if regex_level:
            final_level = get_final_level(regex_level, ml_pred)
            final_score = max(RISK_SCORES[final_level], ml_prob)
        else:
            final_level = ml_pred
            final_score = ml_prob

    should_block = final_level in ["critical", "high"]
    scan_duration_ms = round((time.time() - start_time) * 1000)

    # ✨ detection_method: نخبر الـ UI كيف تم الكشف
    if used_ml and regex_level:
        detection_method = "regex + ml"
    elif used_ml:
        detection_method = "ml"
    else:
        detection_method = "regex"

    return jsonify(
        {
            "result": {
                "risk_level": final_level,
                "risk_label_ar": LABELS_AR[final_level],
                "risk_score": round(final_score, 2),
                "should_block": should_block,
                "message_ar": (
                    "يحتوي على بيانات حساسة!" if should_block else "النص آمن للإرسال"
                ),
                "detected": regex_result["detected"],
                "ml_prediction": ml_pred,
                "detection_method": detection_method,
                "scan_duration_ms": scan_duration_ms,
                "text_length": len(text),
            }
        }
    )


if __name__ == "__main__":
    print("🛡️  ShadowAI Detector API")
    print("📡 Running on http://localhost:5000")
    app.run(debug=True, port=5000)
