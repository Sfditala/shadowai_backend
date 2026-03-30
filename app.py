from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import os
import sys
import re

sys.path.append(os.path.join(os.path.dirname(__file__), "scanner"))
from regex_scanner import scan_text, PATTERNS

app = Flask(__name__)
CORS(app)

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
    return (
        regex_level
        if priority.get(regex_level, 0) >= priority.get(ml_level, 0)
        else ml_level
    )


def get_detected_with_snippets(text):
    """
    يفحص النص ويرجع المشاكل مع الجزء المكتشف
    snippet = الجزء الحساس من النص عشان يعرف المستخدم وين المشكلة
    """
    detected = []
    has_critical = False
    has_high = False
    has_medium = False

    for rule in PATTERNS:
        # finditer بدل findall — يرجع objects فيها مكان التطابق
        matches = list(re.finditer(rule["pattern"], text))

        if matches:
            first_match = matches[0]
            matched_text = first_match.group()

            # نقطع لو طويل
            snippet = (
                matched_text[:37] + "..." if len(matched_text) > 40 else matched_text
            )

            detected.append(
                {
                    "level": rule["level"],
                    "message_ar": rule["message"],
                    "count": len(matches),
                    "snippet": snippet,
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


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    text = data.get("text", "")

    if not text.strip():
        return jsonify({"error": "النص فاضي"}), 400

    regex_result = get_detected_with_snippets(text)
    regex_level = regex_result["highest_level"]

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
            }
        }
    )


if __name__ == "__main__":
    print("🛡️  ShadowAI Detector API")
    print("📡 Running on http://localhost:5000")
    app.run(debug=True, port=5000)
