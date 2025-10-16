from flask import Flask, request, jsonify, redirect, session
from flask_cors import CORS
from dotenv import load_dotenv
import os
import requests
import base64
import secrets
import hashlib
from datetime import datetime

load_dotenv()

app = Flask(__name__)
CORS(app)
app.secret_key = os.getenv("FLASK_SECRET", "random_secret")

CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI")
GOOGLE_SCRIPT_URL = os.getenv("GOOGLE_SCRIPT_URL")
GOOGLE_SCRIPT_SECRET = os.getenv("GOOGLE_SCRIPT_SECRET")

# ===============  HOME  ===============
@app.route('/')
def home():
    return jsonify({"status": "OK", "message": "Backend live ✅"}), 200


# ===============  AUTH TWITTER  ===============
@app.route('/auth/twitter')
def twitter_auth():
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = (
        base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode().rstrip("=")
    )

    session["code_verifier"] = code_verifier

    auth_url = (
        "https://twitter.com/i/oauth2/authorize"
        "?response_type=code"
        f"&client_id={CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        "&scope=tweet.read%20users.read%20follows.read%20like.read%20offline.access"
        "&state=xyz123"
        f"&code_challenge={code_challenge}"
        "&code_challenge_method=S256"
    )
    return redirect(auth_url)


# ===============  CALLBACK TWITTER  (corrigé) ===============
@app.route('/twitter/callback')
def twitter_callback():
    code = request.args.get("code")
    if not code:
        return jsonify({"error": "Missing code"}), 400

    code_verifier = session.get("code_verifier")
    token_url = "https://api.twitter.com/2/oauth2/token"

    # ✅ Encodage correct du payload
    payload = (
        f"code={code}"
        f"&grant_type=authorization_code"
        f"&client_id={CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&code_verifier={code_verifier}"
    )

    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    response = requests.post(token_url, headers=headers, data=payload)

    if response.status_code != 200:
        return f"Token exchange failed: {response.text}", 400

    token_data = response.json()
    access_token = token_data.get("access_token")

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


# ===============  VERIFY TASKS  ===============
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


# ===============  RUN  ===============
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
