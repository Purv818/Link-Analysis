"""
app.py  --  AI Link Threat Analyzer Flask application
"""

import os, re, csv, io, json, logging, urllib.parse
from datetime import datetime
from flask import (Flask, render_template, request, jsonify,
                   redirect, url_for, abort, make_response)

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from config import get_config
app = Flask(__name__)
cfg = get_config()
app.config.from_object(cfg)
logging.basicConfig(level=getattr(logging, cfg.LOG_LEVEL, logging.INFO))
app.logger.setLevel(getattr(logging, cfg.LOG_LEVEL, logging.INFO))

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    limiter = Limiter(key_func=get_remote_address, app=app,
                      default_limits=["300 per day","60 per hour"],
                      storage_uri="memory://")
    RATE_LIMITING = True
except Exception:
    RATE_LIMITING = False
    class _FL:
        def limit(self, *a, **kw): return lambda f: f
    limiter = _FL()

@app.before_request
def enforce_https():
    if app.config.get("FORCE_HTTPS") and not request.is_secure:
        return redirect(request.url.replace("http://","https://",1), code=301)

from database.db_init import (init_db, save_scan, get_scan_history,
                                get_scan_by_id, get_stats, get_scan_count)
from src.predict import predict, model_is_ready
init_db()

_URL_RE = re.compile(r"^https?://\S+$", re.IGNORECASE)

def _validate_url(url):
    if not url or not url.strip():
        return False, "URL cannot be empty."
    url = url.strip()
    if len(url) > 2048:
        return False, "URL exceeds maximum length (2048 characters)."
    if not url.startswith(("http://","https://")):
        url = "https://" + url
    if not _URL_RE.match(url):
        return False, "URL format is invalid. Please enter a valid URL."
    try:
        p = urllib.parse.urlparse(url)
        if not p.netloc:
            return False, "URL must contain a valid domain."
    except Exception:
        return False, "Could not parse the URL."
    return True, ""

def _sanitise_url(url):
    url = url.strip()
    if not url.startswith(("http://","https://")):
        url = "https://" + url
    return url

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"error":"Endpoint not found."}), 404
    return render_template("error.html", code=404, title="Page Not Found",
                           message="The page you requested does not exist."), 404

@app.errorhandler(429)
def rate_limited(e):
    if request.path.startswith("/api/"):
        return jsonify({"error":"Too many requests. Please slow down."}), 429
    return render_template("error.html", code=429, title="Too Many Requests",
                           message="Too many requests. Please wait and try again."), 429

@app.errorhandler(500)
def server_error(e):
    app.logger.exception("Unhandled server error")
    if request.path.startswith("/api/"):
        return jsonify({"error":"Internal server error."}), 500
    return render_template("error.html", code=500, title="Server Error",
                           message="An unexpected error occurred. Please try again shortly."), 500

# ── Page routes ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html", model_ready=model_is_ready())

@app.route("/dashboard")
def dashboard():
    stats = get_stats()
    return render_template("dashboard.html", stats=stats,
                           stats_json=json.dumps(stats),
                           model_ready=model_is_ready())

@app.route("/history")
def history():
    page = max(1, request.args.get("page", 1, type=int))
    pf   = (request.args.get("filter","").upper() or None)
    sq   = (request.args.get("q","").strip() or None)
    if pf not in ("SAFE","SUSPICIOUS","PHISHING","MALICIOUS"):
        pf = None
    per_pg = 20
    offset = (page-1)*per_pg
    scans  = get_scan_history(limit=per_pg, offset=offset,
                               prediction_filter=pf, search_query=sq)
    total  = get_scan_count(pf, sq)
    pages  = max(1, (total+per_pg-1)//per_pg)
    return render_template("history.html", scans=scans, page=page, pages=pages,
                           total=total, prediction_filter=pf or "",
                           search_query=sq or "")

@app.route("/details/<int:scan_id>")
def details(scan_id):
    scan = get_scan_by_id(scan_id)
    if scan is None:
        abort(404)
    raw_url = scan.get("url","")
    try:
        p = urllib.parse.urlparse(raw_url if "://" in raw_url else "http://"+raw_url)
        url_parts = {"scheme":p.scheme,"domain":p.netloc,"path":p.path,
                     "query":urllib.parse.parse_qs(p.query),"fragment":p.fragment}
    except Exception:
        url_parts = {}
    # Prev / next scan IDs for navigation
    from database.db_init import get_adjacent_scans
    prev_id, next_id = get_adjacent_scans(scan_id)
    return render_template("details.html", scan=scan, url_parts=url_parts,
                           features=scan.get("features_json",{}),
                           explanation=scan.get("explanation_json",[]),
                           probabilities=scan.get("probabilities_json",{}),
                           prev_id=prev_id, next_id=next_id)

@app.route("/model-report")
def model_report():
    import joblib
    comparison, selected_model, feature_names, metrics = [], "Unknown", [], {}
    cp = os.path.join(os.path.dirname(__file__),"models","feature_config.pkl")
    if os.path.exists(cp):
        try:
            fc = joblib.load(cp)
            selected_model = fc.get("selected_model","Unknown")
            feature_names  = fc.get("feature_names",[])
            metrics        = fc.get("metrics",{})
        except Exception:
            pass
    for name, m in metrics.items():
        comparison.append({
            "name":name,
            "accuracy": round(float(m.get("accuracy",0) or 0)*100,2),
            "precision":round(float(m.get("precision",0) or 0)*100,2),
            "recall":   round(float(m.get("recall",0) or 0)*100,2),
            "f1":       round(float(m.get("f1",0) or 0)*100,2),
            "roc_auc":  (round(float(m.get("roc_auc",0) or 0)*100,2)
                         if m.get("roc_auc") is not None else None),
            "selected": name==selected_model,
        })
    reports_dir = os.path.join(app.static_folder,"reports")
    chart_meta = {
        "model_comparison.png":      "Model Comparison",
        "label_distribution.png":    "Label Distribution",
        "feature_distributions.png": "Feature Distributions",
        "feature_importance.png":    "Feature Importance (Best Model)",
        "cm_random_forest.png":      "Confusion Matrix - Random Forest",
        "cm_gradient_boosting.png":  "Confusion Matrix - Gradient Boosting",
        "cm_xgboost.png":            "Confusion Matrix - XGBoost",
        "cm_logistic_regression.png":"Confusion Matrix - Logistic Regression",
        "cm_decision_tree.png":      "Confusion Matrix - Decision Tree",
    }
    report_charts = [
        {"filename":fn,"label":lbl,"url":url_for("static",filename="reports/"+fn)}
        for fn,lbl in chart_meta.items()
        if os.path.exists(os.path.join(reports_dir,fn))
    ]
    return render_template("model_report.html", comparison=comparison,
                           selected_model=selected_model,
                           feature_names=feature_names,
                           report_charts=report_charts,
                           model_ready=model_is_ready())

@app.route("/scan", methods=["GET","POST"])
def scan_form():
    """Non-JS fallback: form POST redirects to details page."""
    url = (request.form.get("url") if request.method=="POST"
           else request.args.get("url","")) or ""
    url = url.strip()
    if not url:
        if request.method == "GET":
            return redirect(url_for("index"))
        return render_template("index.html", model_ready=model_is_ready(),
                               form_error="URL cannot be empty."), 400
    valid, err = _validate_url(url)
    if not valid:
        return render_template("index.html", model_ready=model_is_ready(),
                               form_error=err), 400
    if not model_is_ready():
        return render_template("index.html", model_ready=False,
                               form_error="ML model not trained yet."), 503
    url = _sanitise_url(url)
    try:
        result  = predict(url)
        scan_id = save_scan(result)
        return redirect(url_for("details", scan_id=scan_id))
    except Exception:
        app.logger.exception("Scan form error")
        return render_template("error.html", code=500, title="Scan Failed",
                               message="Prediction failed. Please try again."), 500

# ── API routes ───────────────────────────────────────────────────────────────

@app.route("/api/health")
def api_health():
    """GET /api/health -- liveness + model readiness check."""
    ready = model_is_ready()
    return jsonify({
        "status":        "ok" if ready else "degraded",
        "model_ready":   ready,
        "rate_limiting": RATE_LIMITING,
        "timestamp":     datetime.utcnow().isoformat() + "Z",
    }), 200 if ready else 503

@app.route("/api/analyze", methods=["POST"])
@limiter.limit("30 per minute")
def api_analyze():
    """POST /api/analyze  Body: { "url": "https://example.com" }"""
    data = ((request.get_json(silent=True) or {}) if request.is_json
            else request.form.to_dict())
    url = data.get("url","").strip()
    valid, err = _validate_url(url)
    if not valid:
        return jsonify({"error":err}), 400
    if not model_is_ready():
        return jsonify({"error":"ML model not trained. Run: python -m src.train_model"}), 503
    url = _sanitise_url(url)
    try:
        result = predict(url)
    except FileNotFoundError as e:
        return jsonify({"error":str(e)}), 503
    except Exception:
        app.logger.exception("Prediction error")
        return jsonify({"error":"Prediction failed."}), 500
    try:
        result["scan_id"] = save_scan(result)
    except Exception:
        app.logger.exception("DB write error")
        result["scan_id"] = None
    return jsonify({
        "scan_id":        result.get("scan_id"),
        "url":            result["url"],
        "prediction":     result["prediction"],
        "risk_score":     result["risk_score"],
        "risk_level":     result["risk_level"],
        "confidence":     result["confidence"],
        "probabilities":  result["probabilities"],
        "features":       result["features"],
        "explanation":    result["explanation"],
        "contributions":  result.get("contributions", []),
        "explain_method": result.get("explain_method", "rule_based"),
        "model_name":     result["model_name"],
        "disclaimer":     ("Automated ML prediction based on static URL analysis. "
                           "Not a guarantee of safety or maliciousness."),
    }), 200

@app.route("/api/analyze/batch", methods=["POST"])
@limiter.limit("5 per minute")
def api_analyze_batch():
    """
    POST /api/analyze/batch
    Body: { "urls": ["https://a.com", "http://b.xyz"] }
    Returns up to 20 results.
    """
    data = ((request.get_json(silent=True) or {}) if request.is_json
            else request.form.to_dict())
    urls = data.get("urls",[])
    if not isinstance(urls, list):
        return jsonify({"error":"'urls' must be a JSON array."}), 400
    if len(urls) == 0:
        return jsonify({"error":"'urls' array is empty."}), 400
    if len(urls) > 20:
        return jsonify({"error":"Maximum 20 URLs per batch request."}), 400
    if not model_is_ready():
        return jsonify({"error":"ML model not trained."}), 503

    results = []
    for raw in urls:
        if not isinstance(raw, str):
            results.append({"url":str(raw),"error":"Invalid URL type."}); continue
        valid, err = _validate_url(raw)
        if not valid:
            results.append({"url":raw,"error":err}); continue
        url = _sanitise_url(raw)
        try:
            res = predict(url)
            try: res["scan_id"] = save_scan(res)
            except Exception: res["scan_id"] = None
            results.append({"scan_id":res.get("scan_id"),"url":res["url"],
                             "prediction":res["prediction"],"risk_score":res["risk_score"],
                             "risk_level":res["risk_level"],"confidence":res["confidence"],
                             "explanation":res["explanation"],
                             "contributions":res.get("contributions",[]),
                             "explain_method":res.get("explain_method","rule_based")})
        except Exception:
            results.append({"url":url,"error":"Prediction failed."})

    return jsonify({"count":len(results),"results":results,
                    "disclaimer":"Automated ML predictions. Not a security guarantee."}), 200

@app.route("/api/history")
def api_history():
    """GET /api/history?limit=50&offset=0&filter=PHISHING&q=search"""
    limit  = min(200, max(1, request.args.get("limit", 50, type=int)))
    offset = max(0,           request.args.get("offset", 0, type=int))
    pf     = (request.args.get("filter","").upper() or None)
    sq     = (request.args.get("q","").strip() or None)
    if pf not in ("SAFE","SUSPICIOUS","PHISHING","MALICIOUS",None): pf=None
    scans = get_scan_history(limit=limit,offset=offset,
                              prediction_filter=pf,search_query=sq)
    total = get_scan_count(pf,sq)
    return jsonify({"total":total,"limit":limit,"offset":offset,"scans":scans})

@app.route("/api/stats")
def api_stats():
    return jsonify(get_stats())

@app.route("/api/scan/<int:scan_id>")
def api_scan_detail(scan_id):
    scan = get_scan_by_id(scan_id)
    if scan is None:
        return jsonify({"error":"Scan not found."}), 404
    return jsonify(scan)

@app.route("/api/export/csv")
@limiter.limit("10 per hour")
def api_export_csv():
    """GET /api/export/csv?filter=PHISHING&q=search  -- download history as CSV."""
    pf = (request.args.get("filter","").upper() or None)
    sq = (request.args.get("q","").strip() or None)
    if pf not in ("SAFE","SUSPICIOUS","PHISHING","MALICIOUS",None): pf=None
    scans = get_scan_history(limit=5000,offset=0,
                              prediction_filter=pf,search_query=sq)
    buf = io.StringIO()
    w   = csv.writer(buf)
    w.writerow(["id","url","domain","protocol","prediction","risk_score",
                "risk_level","confidence_pct","model_name","scanned_at"])
    for s in scans:
        w.writerow([s.get("id",""),s.get("url",""),s.get("domain",""),
                    s.get("protocol",""),s.get("prediction",""),
                    s.get("risk_score",""),s.get("risk_level",""),
                    round(s.get("confidence",0)*100,1),
                    s.get("model_name",""),s.get("scanned_at","")])
    ts      = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    suffix  = ("_" + pf.lower()) if pf else ""
    suffix += ("_search") if sq else ""
    fname   = f"scan_history{suffix}_{ts}.csv"
    resp = make_response(buf.getvalue())
    resp.headers["Content-Type"]        = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = f"attachment; filename={fname}"
    return resp


@app.route("/api/features")
def api_features():
    """
    GET /api/features
    Returns documentation for all 34 URL features used by the model.
    Useful for understanding what the ML model analyses and for API consumers.
    """
    import joblib
    config_path = os.path.join(os.path.dirname(__file__), "models", "feature_config.pkl")
    if not os.path.exists(config_path):
        return jsonify({"error": "Model not trained yet."}), 503

    try:
        cfg = joblib.load(config_path)
    except Exception:
        return jsonify({"error": "Could not load feature config."}), 500

    # Full feature metadata
    feature_docs = {
        "url_length":            {"group": "Structural",    "type": "integer", "description": "Total character length of the URL"},
        "domain_length":         {"group": "Structural",    "type": "integer", "description": "Length of the hostname"},
        "path_length":           {"group": "Structural",    "type": "integer", "description": "Length of the URL path"},
        "query_length":          {"group": "Structural",    "type": "integer", "description": "Length of the query string"},
        "num_dots":              {"group": "Structural",    "type": "integer", "description": "Count of dot characters in the URL"},
        "num_slashes":           {"group": "Structural",    "type": "integer", "description": "Count of slash characters"},
        "num_hyphens":           {"group": "Structural",    "type": "integer", "description": "Count of hyphen characters"},
        "num_underscores":       {"group": "Structural",    "type": "integer", "description": "Count of underscore characters"},
        "num_digits":            {"group": "Structural",    "type": "integer", "description": "Count of digit characters in the full URL"},
        "num_special_chars":     {"group": "Structural",    "type": "integer", "description": "Count of non-standard characters"},
        "num_query_params":      {"group": "Structural",    "type": "integer", "description": "Number of key=value query parameters"},
        "num_subdomains":        {"group": "Structural",    "type": "integer", "description": "Number of subdomain levels in the hostname"},
        "uses_https":            {"group": "Protocol",      "type": "binary",  "description": "1 if scheme is https, 0 otherwise"},
        "uses_http":             {"group": "Protocol",      "type": "binary",  "description": "1 if scheme is http, 0 otherwise"},
        "has_ip_address":        {"group": "Suspicious",    "type": "binary",  "description": "1 if host is an IPv4 address instead of a domain name"},
        "has_at_symbol":         {"group": "Suspicious",    "type": "binary",  "description": "1 if @ present in netloc (can redirect to different host)"},
        "has_hex_chars":         {"group": "Suspicious",    "type": "binary",  "description": "1 if more than 3 percent-encoded or hex sequences detected"},
        "suspicious_kw_count":   {"group": "Suspicious",    "type": "integer", "description": "Count of suspicious keywords (login, verify, billing, etc.)"},
        "has_suspicious_tld":    {"group": "Suspicious",    "type": "binary",  "description": "1 if TLD is on the high-confidence abuse list (.xyz, .ml, .tk, etc.)"},
        "is_url_shortener":      {"group": "Suspicious",    "type": "binary",  "description": "1 if host is a known URL-shortening service"},
        "excessive_subdomains":  {"group": "Suspicious",    "type": "binary",  "description": "1 if subdomain count is 4 or more"},
        "has_login_keyword":     {"group": "Suspicious",    "type": "binary",  "description": "1 if URL contains login/signin/logon keywords"},
        "has_verify_keyword":    {"group": "Suspicious",    "type": "binary",  "description": "1 if URL contains verify/validation/confirm keywords"},
        "has_account_keyword":   {"group": "Suspicious",    "type": "binary",  "description": "1 if URL contains account/billing/payment keywords"},
        "has_password_keyword":  {"group": "Suspicious",    "type": "binary",  "description": "1 if URL contains password/credential keywords"},
        "has_double_slash_path": {"group": "Suspicious",    "type": "binary",  "description": "1 if path contains // (possible injection attempt)"},
        "has_multiple_at":       {"group": "Suspicious",    "type": "binary",  "description": "1 if more than one @ character in the URL"},
        "domain_entropy":        {"group": "Domain Quality","type": "float",   "description": "Shannon entropy of the domain name characters (high = random-looking)"},
        "digit_ratio_domain":    {"group": "Domain Quality","type": "float",   "description": "Fraction of digits in the domain name"},
        "path_depth":            {"group": "Structural",    "type": "integer", "description": "Number of path segments (depth of directory tree)"},
        "has_fragment":          {"group": "Navigation",    "type": "binary",  "description": "1 if URL contains a # fragment identifier"},
        "has_non_standard_port": {"group": "Protocol",      "type": "binary",  "description": "1 if port is not 80, 443, 8080, or 8443"},
        "has_redirect_param":    {"group": "Navigation",    "type": "binary",  "description": "1 if query string contains a redirect parameter (url, next, goto, etc.)"},
        "has_malware_keyword":   {"group": "Malware/C2",    "type": "binary",  "description": "1 if URL contains malware/C2 keyword (ransomware, botnet, beacon, exploit, etc.)"},
    }

    feature_names = cfg.get("feature_names", [])
    features_out  = []
    for i, name in enumerate(feature_names, 1):
        meta = feature_docs.get(name, {"group": "Other", "type": "numeric", "description": ""})
        features_out.append({
            "index":       i,
            "name":        name,
            "group":       meta["group"],
            "type":        meta["type"],
            "description": meta["description"],
        })

    return jsonify({
        "count":       len(features_out),
        "model":       cfg.get("selected_model", "Unknown"),
        "features":    features_out,
        "note": ("All features are extracted statically from the URL string. "
                 "No network requests are made to the target URL."),
    })


@app.route('/robots.txt')
def robots():
    return app.send_static_file('robots.txt')


@app.route("/api/explain/<int:scan_id>")
def api_explain(scan_id: int):
    """
    GET /api/explain/<id>
    Returns the full explainability breakdown for a stored scan:
      - method used (tree_importance / shap / linear / rule_based)
      - top feature contributions with importance scores and direction
      - human-readable flag strings
    """
    scan = get_scan_by_id(scan_id)
    if scan is None:
        return jsonify({"error": "Scan not found."}), 404

    contributions = scan.get("contributions_json", [])
    if isinstance(contributions, str):
        import json as _json
        try: contributions = _json.loads(contributions)
        except: contributions = []

    return jsonify({
        "scan_id":       scan_id,
        "url":           scan.get("url", ""),
        "prediction":    scan.get("prediction", ""),
        "risk_score":    scan.get("risk_score", 0),
        "explain_method": scan.get("explain_method", "rule_based"),
        "contributions": contributions,
        "flags":         scan.get("explanation_json", []),
        "note": ("Contributions show which features most influenced the prediction. "
                 "Importance is the model's feature importance score."),
    })

@app.context_processor
def inject_globals():
    return {"app_name":"AI Link Threat Analyzer",
            "current_year":datetime.utcnow().year}

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
