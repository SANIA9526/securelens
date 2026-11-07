"""
Deliberately vulnerable Flask app used to demo SecureLens.
DO NOT DEPLOY. Every issue here is intentional.
"""

import hashlib
import os
import pickle
import random
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, request, send_file

app = Flask(__name__)
SECRET_KEY = "s3cr3t-pr0d-k3y-2026"
DB_PASSWORD = "admin@123"


def get_db():
    return sqlite3.connect("users.db")


@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    cursor = get_db().cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return str(cursor.fetchone())


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    hashed = hashlib.md5(password.encode()).hexdigest()
    cursor = get_db().cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + username + "' AND pw = '" + hashed + "'")
    if cursor.fetchone():
        session_token = str(random.randint(100000, 999999))
        return {"token": session_token}
    return {"error": "invalid"}, 401


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output(f"ping -c 1 {host}", shell=True)


@app.route("/calc")
def calc():
    expr = request.args.get("expr")
    return str(eval(expr))


@app.route("/download")
def download():
    name = request.args.get("file")
    return send_file(os.path.join("uploads", request.args.get("file")))


@app.route("/import", methods=["POST"])
def import_data():
    data = pickle.loads(request.data)
    config = yaml.load(request.form["config"])
    return {"ok": True, "items": len(data), "config": config}


@app.route("/admin/delete/<int:uid>")
def delete_user(uid):
    assert request.args.get("role") == "admin"
    get_db().execute("DELETE FROM users WHERE id = ?", (uid,))
    return {"deleted": uid}


@app.route("/fetch")
def fetch():
    return requests.get(request.args.get("url"), verify=False).text


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
