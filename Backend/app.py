from flask import Flask, request, jsonify, redirect, send_from_directory, session
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from authlib.integrations.base_client.errors import OAuthError
from users import add_user, find_user
from oauth_config import oauth, init_oauth
import os
import secrets

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Replace with a secure key in production
CORS(app)
bcrypt = Bcrypt(app)
init_oauth(app)

# Define base directories using relative paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.abspath(os.path.join(BASE_DIR, "../Frontend"))
ASSETS_DIR = os.path.abspath(os.path.join(BASE_DIR, "../assets"))

# Serve login page
@app.route("/")
def serve_login():
    return send_from_directory(FRONTEND_DIR, "MenuMate_login_page.html")

# Serve registration page
@app.route("/register")
def serve_register():
    return send_from_directory(FRONTEND_DIR, "MenuMate_registeration_Page.html")

@app.route("/MenuMate_registeration_Page.html")
def serve_register_alias():
    return send_from_directory(FRONTEND_DIR, "MenuMate_registeration_Page.html")

@app.route("/MenuMate_login_page.html")
def serve_login_alias():
    return send_from_directory(FRONTEND_DIR, "MenuMate_login_page.html")

# Serve static assets
@app.route("/assets/<path:filename>")
def serve_assets(filename):
    return send_from_directory(ASSETS_DIR, filename)

# -------------------------------
# 🔐 API: Register
@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"message": "Email and password are required"}), 400

    if find_user(email):
        return jsonify({"message": "User already exists"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
    add_user(email, hashed_password)
    return jsonify({"message": "User registered successfully"}), 201

# 🔐 API: Login
@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    user = find_user(email)
    if not user or not bcrypt.check_password_hash(user["password"], password):
        return jsonify({"message": "Invalid credentials"}), 401

    return jsonify({"message": "Login successful", "email": user["email"]}), 200

# -------------------------------
# 🔐 OAuth: Google Login
@app.route("/auth/google")
def google_login():
    nonce = secrets.token_urlsafe(16)
    session["oauth_nonce"] = nonce
    redirect_uri = "http://localhost:5000/auth/google/callback"
    return oauth.google.authorize_redirect(redirect_uri, nonce=nonce)

@app.route("/auth/google/callback")
def google_callback():
    try:
        if "error" in request.args:
            return redirect("/")

        token = oauth.google.authorize_access_token()
        nonce = session.pop("oauth_nonce", None)

        if not nonce:
            return "Missing nonce", 400

        user_info = oauth.google.parse_id_token(token, nonce=nonce)
        email = user_info["email"]

        # Add user if they don't exist
        if not find_user(email):
            add_user(email, password=None, source="google")

        session["user_email"] = email
        print(f"✅ Google login for: {email}")

        return redirect("/")

    except OAuthError as e:
        print("OAuthError:", e)
        return redirect("/")
    except Exception as e:
        print("Unexpected error:", e)
        return redirect("/")

# -------------------------------------
# ✅ Check Session Login State
@app.route("/api/user")
def get_user():
    email = session.get("user_email")
    if email:
        return jsonify({"logged_in": True, "email": email})
    return jsonify({"logged_in": False}), 200

# -------------------------------------
# 🔓 Logout
@app.route("/logout")
def logout():
    session.pop("user_email", None)
    return redirect("/")
    
# -------------------------------------
if __name__ == "__main__":
    app.run(debug=True)



