# The SAFE versions: NONE of these should trigger an ai-smell rule (negative test cases).
import os
import subprocess

import jwt
import requests
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
API_KEY = os.environ["API_KEY"]                                 # 1 from the environment
requests.get("https://api.example.com", timeout=5)              # 2 TLS verified (default)


def find_user(db, user_id):
    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,))  # 3 parameterized


def run(args):
    subprocess.run(["ls", "-l", args], check=True)               # 4 argument list, no shell


def load():
    try:
        return open("x").read()
    except FileNotFoundError as exc:                             # 5 specific + handled
        raise RuntimeError("config missing") from exc


CORS(app, origins=["https://app.example.com"])                  # 6 explicit origin
app.run(debug=os.environ.get("FLASK_DEBUG") == "1")             # 7 off by default


def who(token, key):
    return jwt.decode(token, key, algorithms=["HS256"])          # 8 signature verified


def check_owner(user, invoice):
    return user.id == invoice.owner_id                           # 9 real logic
