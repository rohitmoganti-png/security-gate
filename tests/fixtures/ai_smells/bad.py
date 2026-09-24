# Every block below SHOULD trigger an ai-smell rule (positive test cases).
import os
import subprocess

import jwt
import requests
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
API_KEY = "your-api-key-here"                                   # 1 placeholder credential
requests.get("https://api.example.com", verify=False)           # 2 TLS disabled


def find_user(db, user_id):
    return db.execute(f"SELECT * FROM users WHERE id = {user_id}")  # 3 SQL f-string


def run(cmd):
    subprocess.run(cmd, shell=True)                             # 4 shell=True


def load():
    try:
        return open("x").read()
    except:                                                      # 5 silent failure
        pass


CORS(app, origins="*")                                          # 6 CORS wildcard
app.run(debug=True)                                             # 7 debug on


def who(token):
    return jwt.decode(token, options={"verify_signature": False})  # 8 JWT not verified


def check_owner(user, invoice):
    # In a real implementation we would verify the user owns this invoice   # 9 scaffolding
    return True
