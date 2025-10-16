from flask import Flask, request, jsonify, redirect
from flask_cors import CORS
from dotenv import load_dotenv
import os
import requests
from datetime import datetime

load_dotenv()

# === CONFIGURATION ===
app = Flask(__name__)
CORS(app)

BEARER_TOKEN = os.getenv("BEARER_TOKEN")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI")
FLASK_SECRET = os.getenv("FLASK_SECRET")
GOOGLE_SCRIPT_URL = os.getenv("GOOGLE_SCRIPT_URL")
GOOGLE_SCRIPT_SECRET = os.getenv("GOOGLE_SCRIPT_SECRET")

# === ROUTE RACINE ===
@app.route('/')
def home():
    return {
        "status": "OK",
        "message": "Kibble Backend is running successfully 🦴"
    }, 200


# === AUTH TWITTER (CONNEXION) ===
@app.route('/auth/twitter')
def twitter_auth():
    try:
        url = (
            "https://twitter.com/i/oauth2/authorize"
            f"?response_type=code"
            f"&client_id={CLIENT_ID}"
            f"&redirect_uri={REDIRECT_URI}"
            "&scope=tweet.read%20users.read%20follows.read%20like.read"
            "&state=xyz123"
            "&code_challenge=challenge"
            "&code_challenge_method=plain"
        )
        return redirect(url)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# === CALLBACK TWITTER ===
@app.route('/twitter/callback')
def twitter_callback():
    code = request.args.get("code")
    if not code:
        return jsonify({"error": "Missing code"}), 400

    token_url = "https://api.twitter.com/2/oauth2/token"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    data = {
        "code": code,
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": "challenge",
        "client_secret": CLIENT_SECRET
    }

    try:
        r = requests.post(token_url, headers=headers, data=data)
        if r.status_code != 200:
            return f"Token exchange failed: {r.text}", 400
        token_data = r.json()
        access_token = token_data["access_token"]

        user_resp = requests.get(
            "https://api.twitter.com/2/users/me",
            headers={"Authorization": f"Bearer {access_token}"}
        )

        user_data = user_resp.json().get("data", {})
        username = user_data.get("username", "UnknownUser")

        return f"""
        <script>
            window.opener.postMessage({{
                type: 'TWITTER_AUTH',
                username: '{username}'
            }}, '*');
            window.close();
        </script>
        """

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# === VERIFICATION / GOOGLE SHEET ===
@app.route('/verify', methods=['POST'])
def verify_tasks():
    try:
        data = request.get_json()
        username = data.get("username")
        wallet = data.get("wallet")
        follow = data.get("follow", False)
        retweet = data.get("retweet", False)

        if not username or not wallet:
            return jsonify({"error": "Missing data"}), 400

        # Envoi à Google Sheet via Apps Script
        payload = {
            "secret": GOOGLE_SCRIPT_SECRET,
            "timestamp": datetime.utcnow().isoformat(),
            "username": username,
            "wallet": wallet,
            "follow": follow,
            "retweet": retweet
        }

        res = requests.post(GOOGLE_SCRIPT_URL, json=payload)
        print("[DEBUG] Google Sheet response:", res.status_code, res.text)

        if res.status_code != 200:
            return jsonify({"error": "Google Script error"}), 500

        return jsonify({"status": "success"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# === RUN FLASK (Render-friendly port) ===
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
