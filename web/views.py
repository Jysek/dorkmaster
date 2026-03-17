"""
DorkMaster Web - Page Rendering Routes
"""

from flask import Blueprint, render_template

from core.engine import DorkConfig

views_bp = Blueprint("views", __name__)


@views_bp.route("/")
def index():
    """Render the main application page."""
    config = DorkConfig.get_instance()

    engines = {}
    for eid in config.get_all_engine_ids():
        eng = config.get_engine(eid)
        if eng is None:
            continue
        engines[eid] = {
            "name": eng["name"],
            "operators": {
                k: v["description"] for k, v in eng["operators"].items()
            },
            "filetypes": eng.get("filetype_list", []),
        }

    return render_template(
        "index.html",
        engines=engines,
        default_keywords=config.default_keywords,
        vuln_params=config.vuln_params,
    )
