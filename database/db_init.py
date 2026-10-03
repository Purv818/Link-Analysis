"""
db_init.py
----------
SQLite database initialisation and all data-access functions.
Uses parameterised queries throughout to prevent SQL injection.
"""

import os
import sqlite3
import json
from datetime import datetime

# ---------------------------------------------------------------------------
# Path configuration
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_PATH = os.path.join(PROJECT_ROOT, "database", "scans.db")


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    url             TEXT    NOT NULL,
    domain          TEXT,
    protocol        TEXT,
    prediction      TEXT    NOT NULL,
    risk_score      INTEGER NOT NULL,
    risk_level      TEXT    NOT NULL,
    confidence      REAL    NOT NULL,
    features_json   TEXT,
    explanation_json TEXT,
    probabilities_json TEXT,
    model_name      TEXT,
    contributions_json TEXT,
    explain_method TEXT,
    scanned_at      TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scans_prediction  ON scans(prediction);
CREATE INDEX IF NOT EXISTS idx_scans_scanned_at  ON scans(scanned_at);
CREATE INDEX IF NOT EXISTS idx_scans_risk_score  ON scans(risk_score);
"""


# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------
def _get_connection() -> sqlite3.Connection:
    """Return a new SQLite connection with row_factory set."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # better concurrent read support
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------
def init_db() -> None:
    """Create tables and indexes if they do not already exist."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with _get_connection() as conn:
        conn.executescript(SCHEMA)
    print(f"[db] Database ready at: {DB_PATH}")


# ---------------------------------------------------------------------------
# Write
# ---------------------------------------------------------------------------
def save_scan(result: dict) -> int:
    """
    Persist a prediction result returned by predict.predict().

    Parameters
    ----------
    result : dict
        The full result dict from predict().

    Returns
    -------
    int : the row id of the newly inserted record.
    """
    import urllib.parse
    raw_url = result.get("url", "")
    try:
        parsed   = urllib.parse.urlparse(raw_url if "://" in raw_url
                                         else "http://" + raw_url)
        domain   = parsed.hostname or ""
        protocol = parsed.scheme   or ""
    except Exception:
        domain, protocol = "", ""

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    sql = """
        INSERT INTO scans
            (url, domain, protocol, prediction, risk_score, risk_level,
             confidence, features_json, explanation_json,
             probabilities_json, contributions_json, explain_method,
             model_name, scanned_at)
        VALUES
            (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    params = (
        raw_url,
        domain,
        protocol,
        result.get("prediction", "UNKNOWN"),
        result.get("risk_score",  0),
        result.get("risk_level",  "Unknown"),
        result.get("confidence",  0.0),
        json.dumps(result.get("features",       {})),
        json.dumps(result.get("explanation",    [])),
        json.dumps(result.get("probabilities",  {})),
        json.dumps(result.get("contributions",  [])),
        result.get("explain_method", "rule_based"),
        result.get("model_name", ""),
        now,
    )

    with _get_connection() as conn:
        cursor = conn.execute(sql, params)
        return cursor.lastrowid


# ---------------------------------------------------------------------------
# Read — history list
# ---------------------------------------------------------------------------
def get_scan_history(limit: int = 200,
                     offset: int = 0,
                     prediction_filter: str = None,
                     search_query: str = None) -> list:
    """
    Retrieve scan history with optional filtering.

    Parameters
    ----------
    limit            : max rows to return
    offset           : pagination offset
    prediction_filter: one of SAFE / SUSPICIOUS / PHISHING / MALICIOUS
    search_query     : substring to match against the url column

    Returns
    -------
    list of dicts
    """
    conditions = []
    params     = []

    if prediction_filter and prediction_filter.upper() in (
            "SAFE", "SUSPICIOUS", "PHISHING", "MALICIOUS"):
        conditions.append("UPPER(prediction) = ?")
        params.append(prediction_filter.upper())

    if search_query:
        conditions.append("url LIKE ?")
        params.append(f"%{search_query}%")

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    sql = f"""
        SELECT id, url, domain, protocol, prediction, risk_score,
               risk_level, confidence, model_name, scanned_at
        FROM   scans
        {where}
        ORDER  BY scanned_at DESC
        LIMIT  ? OFFSET ?
    """
    params += [limit, offset]

    with _get_connection() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def get_scan_count(prediction_filter: str = None,
                   search_query: str = None) -> int:
    """Return the total count matching the same filters as get_scan_history."""
    conditions = []
    params     = []

    if prediction_filter and prediction_filter.upper() in (
            "SAFE", "SUSPICIOUS", "PHISHING", "MALICIOUS"):
        conditions.append("UPPER(prediction) = ?")
        params.append(prediction_filter.upper())

    if search_query:
        conditions.append("url LIKE ?")
        params.append(f"%{search_query}%")

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    sql   = f"SELECT COUNT(*) FROM scans {where}"

    with _get_connection() as conn:
        row = conn.execute(sql, params).fetchone()
    return row[0] if row else 0


# ---------------------------------------------------------------------------
# Read — single scan
# ---------------------------------------------------------------------------
def get_scan_by_id(scan_id: int) -> dict | None:
    """Return the full scan record for a given id, or None."""
    sql = "SELECT * FROM scans WHERE id = ?"
    with _get_connection() as conn:
        row = conn.execute(sql, (scan_id,)).fetchone()
    if row is None:
        return None
    record = dict(row)
    # Deserialise JSON fields
    for field in ("features_json", "explanation_json", "probabilities_json", "contributions_json"):
        try:
            record[field] = json.loads(record[field] or "{}")
        except (json.JSONDecodeError, TypeError):
            record[field] = {}
    return record




# ---------------------------------------------------------------------------
# Read — adjacent scans (for prev/next navigation on the details page)
# ---------------------------------------------------------------------------
def get_adjacent_scans(scan_id: int):
    """
    Return (prev_id, next_id) for the given scan.
    Scans are ordered by scanned_at DESC, so:
      prev = the scan recorded just AFTER this one (higher row / older default order)
      next = the scan recorded just BEFORE this one (newer)
    Returns None for each direction when no neighbour exists.
    """
    with _get_connection() as conn:
        # next (newer) — smaller id than current when ordered by time desc means larger scanned_at
        row_prev = conn.execute(
            "SELECT id FROM scans WHERE id < ? ORDER BY id DESC LIMIT 1", (scan_id,)
        ).fetchone()
        row_next = conn.execute(
            "SELECT id FROM scans WHERE id > ? ORDER BY id ASC  LIMIT 1", (scan_id,)
        ).fetchone()
    return (row_prev[0] if row_prev else None,
            row_next[0] if row_next else None)


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------
def delete_scan(scan_id: int) -> bool:
    """Delete a scan record by id. Returns True if a row was deleted."""
    with _get_connection() as conn:
        cursor = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        return cursor.rowcount > 0

# ---------------------------------------------------------------------------
# Read — dashboard statistics
# ---------------------------------------------------------------------------
def get_stats() -> dict:
    """Aggregate statistics for the dashboard."""
    sql_totals = """
        SELECT
            COUNT(*)                                        AS total,
            SUM(CASE WHEN UPPER(prediction)='SAFE'       THEN 1 ELSE 0 END) AS safe,
            SUM(CASE WHEN UPPER(prediction)='SUSPICIOUS' THEN 1 ELSE 0 END) AS suspicious,
            SUM(CASE WHEN UPPER(prediction)='PHISHING'   THEN 1 ELSE 0 END) AS phishing,
            SUM(CASE WHEN UPPER(prediction)='MALICIOUS'  THEN 1 ELSE 0 END) AS malicious,
            ROUND(AVG(risk_score), 1)                      AS avg_risk_score,
            ROUND(AVG(confidence) * 100, 1)                AS avg_confidence
        FROM scans
    """

    sql_by_day = """
        SELECT DATE(scanned_at) AS day, COUNT(*) AS count
        FROM   scans
        GROUP  BY day
        ORDER  BY day DESC
        LIMIT  30
    """

    sql_risk_buckets = """
        SELECT
            SUM(CASE WHEN risk_score BETWEEN 0  AND 30  THEN 1 ELSE 0 END) AS low,
            SUM(CASE WHEN risk_score BETWEEN 31 AND 60  THEN 1 ELSE 0 END) AS medium,
            SUM(CASE WHEN risk_score BETWEEN 61 AND 80  THEN 1 ELSE 0 END) AS high,
            SUM(CASE WHEN risk_score BETWEEN 81 AND 100 THEN 1 ELSE 0 END) AS critical
        FROM scans
    """

    with _get_connection() as conn:
        totals      = dict(conn.execute(sql_totals).fetchone()      or {})
        by_day_rows = conn.execute(sql_by_day).fetchall()
        risk_bkts   = dict(conn.execute(sql_risk_buckets).fetchone() or {})

    by_day = [dict(r) for r in by_day_rows]

    return {
        "total":           totals.get("total",          0) or 0,
        "safe":            totals.get("safe",            0) or 0,
        "suspicious":      totals.get("suspicious",      0) or 0,
        "phishing":        totals.get("phishing",        0) or 0,
        "malicious":       totals.get("malicious",       0) or 0,
        "avg_risk_score":  totals.get("avg_risk_score",  0) or 0,
        "avg_confidence":  totals.get("avg_confidence",  0) or 0,
        "scans_by_day":    by_day,
        "risk_buckets": {
            "low":      risk_bkts.get("low",      0) or 0,
            "medium":   risk_bkts.get("medium",   0) or 0,
            "high":     risk_bkts.get("high",     0) or 0,
            "critical": risk_bkts.get("critical", 0) or 0,
        },
    }
