"""Known-good Flask app: zero CFG findings (T1b fixture)."""
import os

from flask import Flask

app = Flask(__name__)


@app.route("/")
def index():
    return "hi"


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
