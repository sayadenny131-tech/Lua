import os
import base64
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

BOT_TOKEN = os.getenv("BOT_TOKEN", "")
CHAT_ID = os.getenv("CHAT_ID", "")

@app.get("/")
def index():
    return jsonify({
        "ok": True,
        "service": "autofbskuy",
        "message": "Auto Feedback server is running"
    })

@app.post("/send-feedback")
def send_feedback():
    if not BOT_TOKEN or not CHAT_ID:
        return jsonify({
            "ok": False,
            "error": "Server environment variables are not configured"
        }), 500

    image_base64 = request.form.get("base64_image", "")
    caption = request.form.get("caption", "")

    if not image_base64:
        return jsonify({
            "ok": False,
            "error": "Missing base64_image"
        }), 400

    if image_base64.startswith("data:image/") and "," in image_base64:
        image_base64 = image_base64.split(",", 1)[1]

    try:
        image_data = base64.b64decode(image_base64, validate=True)
    except Exception:
        return jsonify({
            "ok": False,
            "error": "Invalid base64 image"
        }), 400

    if len(image_data) > 10 * 1024 * 1024:
        return jsonify({
            "ok": False,
            "error": "Image too large"
        }), 413

    caption = caption[:1024]

    telegram_url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendPhoto"

    try:
        response = requests.post(
            telegram_url,
            data={
                "chat_id": CHAT_ID,
                "caption": caption
            },
            files={
                "photo": ("feedback.jpg", image_data, "image/jpeg")
            },
            timeout=30
        )
    except requests.RequestException as e:
        return jsonify({
            "ok": False,
            "error": "Telegram connection failed",
            "detail": str(e)
        }), 502

    try:
        telegram_data = response.json()
    except ValueError:
        telegram_data = {"raw": response.text}

    if response.ok and telegram_data.get("ok") is True:
        return jsonify({
            "ok": True,
            "message": "Feedback sent to Telegram"
        })

    return jsonify({
        "ok": False,
        "error": "Telegram rejected the request",
        "telegram": telegram_data
    }), 502


if __name__ == "__main__":
    port = int(os.getenv("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)
