import os
from flask import Flask, jsonify

def create_app() -> Flask:
    app = Flask(__name__)

    @app.get("/healthz")
    def healthz():
        return jsonify({"message": "Tatou API is up and running."}), 200

    return app


# WSGI entrypoint for Gunicorn
app = create_app()

if __name__ == "__main__":
    # Useful for local debugging; in containers we use Gunicorn (see Dockerfile)
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

