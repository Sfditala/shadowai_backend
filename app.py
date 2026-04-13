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

# ✨ رُفعت نسبة high من 0.80 → 0.85
RISK_SCORES = {
    "critical": 0.95,
    "high": 0.85,
    "medium": 0.55,
    "safe": 0.10,
}


def get_final_level(regex_level, ml_level):
    priority = {"critical": 4, "high": 3, "medium": 2, "safe": 1}
    return (
        regex_level
        if priority.get(regex_level, 0) >= priority.get(ml_level, 0)
        else ml_level
    )


def get_detected_with_snippets(text):
    """
    يفحص النص ويرجع المشاكل مع snippet لكل مشكلة.

    ✨ v2:
    - تمرير النص كسياق لـ classify_card
    - دعم suspicious: فاشل Luhn + سياق بطاقة → high
    - تفريق sk_live (critical) عن sk_test (medium)
    """
    from regex_scanner import is_code

    text_is_code = is_code(text)
    detected = []
    has_critical = has_high = has_medium = False

    for rule in PATTERNS:
        if text_is_code and rule.get("skip_if_code", False):
            continue

        matches = list(re.finditer(rule["pattern"], text))
        if not matches:
            continue

        matched_text = matches[0].group()
        snippet = matched_text[:37] + "..." if len(matched_text) > 40 else matched_text
        level = rule["level"]
        message = rule["message"]
        extra = {}

        # ✨ كشف البطاقات الذكي
        if rule.get("card_check"):
            card_digits = matched_text.replace(" ", "").replace("-", "")
            card_info = classify_card(card_digits, context_text=text)
            extra["card_analysis"] = card_info

            if card_info["is_test"]:
                level = "medium"
                message = f"بطاقة {card_info['card_type']} تيست 🧪 — غير حقيقية"
            elif card_info.get("suspicious"):
                level = "high"
                message = (
                    f"رقم {card_info['card_type']} مشبوه ⚠️ — فشل Luhn لكن سياق بطاقة!"
                )
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


@app.route("/scan", methods=["POST"])
def scan():
    start_time = time.time()
    data = request.get_json()
    text = data.get("text", "")

    if not text.strip():
        return jsonify({"error": "النص فاضي"}), 400

    # المرحلة 1: Regex دائماً
    regex_result = get_detected_with_snippets(text)
    regex_level = regex_result["highest_level"]

    # Smart Pre-filter: لو critical/high من Regex → تخطّ ML
    ml_pred = ml_prob = None
    used_ml = False

    if regex_level in ["critical", "high"]:
        final_level = regex_level
        final_score = RISK_SCORES[regex_level]
    else:
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
    print("🛡️  ShadowAI Detector API v2")
    print("📡 Running on http://localhost:5000")
    app.run(debug=True, port=5000)
