"""Throwaway M3 demo app: 1 open + 1 token-protected + 1 POST-only endpoint."""
from flask import Flask, jsonify, request

app = Flask(__name__)
TOKEN = "demo-token-123"


@app.route("/api/public")
def public():
    return jsonify([{"id": 1, "note": "public data here"}])


@app.route("/api/private")
def private():
    if request.headers.get("Authorization") != f"Bearer {TOKEN}":
        return jsonify({"detail": "Unauthorized"}), 401
    return jsonify([{"id": 2, "note": "private data here"}])


@app.route("/api/submit", methods=["POST"])
def submit():
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(port=8123)
