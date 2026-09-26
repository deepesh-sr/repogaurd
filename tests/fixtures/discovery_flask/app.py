"""T2 Flask fixture: open GET, login-required GET, POST-only."""
from flask import Flask
from flask_login import login_required

app = Flask(__name__)


@app.route("/open")
def open_view():
    return "open"


@app.route("/private")
@login_required
def private_view():
    return "private"


@app.route("/submit", methods=["POST"])
def submit_view():
    return "ok"
