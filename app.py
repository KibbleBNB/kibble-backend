from flask import Flask, request, jsonify, session, redirect, render_template_string
import os, requests, base64
from flask_cors import CORS
from dotenv import load_dotenv
from datetime import datetime
from oauth_helpers import generate_code_verifier, code_challenge_from_verifier

# -------------------- CONFIG --------------------

load_dotenv()

app = Flask(__name__)
CORS(app)
app.secret_key = os.getenv("FLASK_SECRET")

# Variables d'environnement
BEARER_TOKEN = os.getenv("BEARER_TOKEN")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI")
GOOGLE_SCRIPT_URL = os.getenv("GOOGLE_SCRIPT_URL")
GOOGLE_SCRIPT_SECRET = os.getenv("GOOGLE_SCRIPT_SECRET")

FOLLOW_ACCOUNT_ID = "1879010851592269824"  # @PlayKibbleBNB
TWEET_ID = "1978508218100822026"

HEADERS = {"Authorization": f"Bearer {BEARER_TOKEN}"}

TWITTER_AUTH_URL = "https://twitter.com/i/oauth2/authorize"
TWITTER_TOKEN_URL = "https://api.twitter.com/2/oauth2/token"
SCOPES = "tweet.read users.read follows.read offline.access"

# Mode dev (bypass)
DEV_BYPASS = False

# -------------------- AUTH TWITTER --------------------

@app.route("/auth/twitter")
def auth_twitter():
    verifier = generate_code_verifier()
    challenge = code_challenge_from_verifier(verifier)
    session["verifier"] = verifier

    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPES,
        "state": "xyz123",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    url = TWITTER_AUTH_URL + "?" + "&".join([f"{k}={requests.utils.requote_uri(v)}" for k, v in params.items()])
    return redirect(url)


@app.route("/twitter/callback")
def twitter_callback():
    code = request.args.get("code")
    if not code:
        return "No code returned", 400

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "code_verifier": session.get("verifier"),
    }

    basic_token = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
    headers = {
        "Authorization": f"Basic {basic_token}",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    r = requests.post(TWITTER_TOKEN_URL, data=data, headers=headers)
    if r.status_code != 200:
        return f"Token exchange failed: {r.text}", 400

    token = r.json().get("access_token")
    user_resp = requests.get(
        "https://api.twitter.com/2/users/me",
        headers={"Authorization": f"Bearer {token}"}
    )

    if user_resp.status_code != 200:
        return f"Failed to get user info: {user_resp.text}", 400

    user = user_resp.json().get("data", {})
    username = user.get("username")
    user_id = user.get("id")

    html = f"""
    <html>
      <body>
        <script>
          window.opener.postMessage({{'username': '{username}', 'id': '{user_id}'}}, "*");
          window.close();
        </script>
      </body>
    </html>
    """
    return render_template_string(html)

# -------------------- TASK CHECKS --------------------

def send_to_google(username, wallet, follow, retweet):
    data = {
        "username": username,
        "wallet": wallet,
        "follow": str(follow),
        "retweet": str(retweet),
        "timestamp": datetime.now().isoformat(),
        "_secret": GOOGLE_SCRIPT_SECRET
    }
    try:
        r = requests.post(GOOGLE_SCRIPT_URL, json=data)
        print("[DEBUG] Google Sheet response:", r.status_code, r.text)
    except Exception as e:
        print("[ERROR] Erreur Google Sheet:", e)

def check_follow(user_id):
    url = f"https://api.twitter.com/2/users/{user_id}/following"
    r = requests.get(url, headers=HEADERS)
    print("[DEBUG] check_follow:", r.status_code)
    return False if r.status_code != 200 else any(u["id"] == FOLLOW_ACCOUNT_ID for u in r.json().get("data", []))

def check_retweet(user_id):
    url = f"https://api.twitter.com/2/tweets/{TWEET_ID}/retweeted_by"
    r = requests.get(url, headers=HEADERS)
    print("[DEBUG] check_retweet:", r.status_code)
    return False if r.status_code != 200 else any(u["id"] == user_id for u in r.json().get("data", []))

# -------------------- VERIFY ROUTE --------------------

@app.route("/verify", methods=["POST"])
def verify_user():
    content = request.json
    username = content.get("username")
    wallet = content.get("wallet")
    user_id = content.get("user_id")

    if not username or not wallet or not user_id:
        return jsonify({"error": "missing fields"}), 400

    # Mode dev : succès forcé
    if DEV_BYPASS:
        print(f"[DEV_MODE] Simulation pour @{username}")
        send_to_google(username, wallet, True, True)
        return jsonify({"success": True})

    # Mode réel
    follow = check_follow(user_id)
    retweet = check_retweet(user_id)
    send_to_google(username, wallet, follow, retweet)
    print(f"[VERIFY] @{username} - Follow: {follow}, Retweet: {retweet}")

    return jsonify({"success": follow and retweet})

# -------------------- RUN SERVER --------------------

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
