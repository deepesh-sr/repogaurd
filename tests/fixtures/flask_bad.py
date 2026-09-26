"""Intentionally bad Flask app: fires CFG-08 (T1b fixture)."""
from flask import Flask

app = Flask(__name__)


@app.route("/")
def index():
    return "hi"


if __name__ == "__main__":
    app.run(debug=True)  # CFG-08
