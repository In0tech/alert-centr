

from flask_login import login_required

from flask import Blueprint, render_template
from flask import Flask, render_template, request, url_for, redirect

import services.data_fetcher as data_fetcher


bp = Blueprint("pages", __name__)


def _safe_count(fn):
    """Call a count helper and return its int, or None on any error
    (DB down, table missing, etc.) so the template can render a dash."""
    try:
        return fn()
    except Exception:
        return None


@bp.route("/")
@bp.route("/home")
@bp.route("/index")
@login_required
def home():
    counts = {
        'open_alerts': _safe_count(data_fetcher.count_open_alerts),
        'active_mitigations': _safe_count(data_fetcher.count_active_mitigations),
        'genie_events_24h': _safe_count(data_fetcher.count_genie_events_24h),
        'kuma_probes': _safe_count(data_fetcher.count_kuma_probes),
    }
    return render_template("pages/welcome.html", **counts)


@bp.route("/alerts")
@login_required
def alerts():
    return render_template("pages/home.html")

@bp.route("/genie")
@login_required
def genie():
    return render_template("pages/genie.html")

@bp.route("/reports")
@login_required
def reports():    
    return render_template("pages/reports.html")

@bp.route("/metrics")
@login_required
def metrics():
    return render_template("pages/metrics.html")

@bp.route("/search")
@login_required
def search():
    return render_template("pages/search.html")

@bp.route("/db-assist")
@login_required
def db_assist():
    return render_template("pages/db_assist.html")

@bp.route("/alert/<int:alert_id>")
@login_required
def alert(alert_id):
    return render_template("pages/alert.html", alert_id=alert_id)

