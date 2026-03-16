"""
DorkMaster - Flask Web Application
====================================

Unified tool combining DorkForge (generator) and DorkHunter (search).
Supports multi-engine dork generation and URL extraction via web UI.
"""

from flask import Flask

from web.routes import views_bp, api_bp


def create_app() -> Flask:
    """Application factory: creates and configures the Flask app."""
    app = Flask(
        __name__,
        template_folder="web/templates",
        static_folder="web/static",
    )

    app.register_blueprint(views_bp)
    app.register_blueprint(api_bp)

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
