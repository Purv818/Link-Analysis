/**
 * app.js — AI Link Threat Analyzer
 * Single consolidated DOMContentLoaded entry point.
 * All utilities are global so inline scripts in templates can use them.
 */
"use strict";

/* ==========================================================================
   Global utilities (available to all pages and inline scripts)
   ========================================================================== */

/** Escape HTML to prevent XSS. */
function escHtml(str) {
  if (str == null) return "";
  return String(str)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

/** Map 0-100 risk score to CSS class. */
function riskClass(score) {
  if (score <= 30) return "low";
  if (score <= 60) return "medium";
  if (score <= 80) return "high";
  return "critical";
}

/** Bootstrap-Icons class for a prediction label. */
function predictionIcon(pred) {
  const map = { SAFE: "bi-shield-check-fill", SUSPICIOUS: "bi-exclamation-triangle-fill",
                PHISHING: "bi-fish-fill", MALICIOUS: "bi-bug-fill" };
  return map[pred] || "bi-question-circle-fill";
}

/** CSS colour variable for a prediction label. */
function predictionColor(pred) {
  const map = { SAFE: "var(--safe)", SUSPICIOUS: "var(--suspicious)",
                PHISHING: "var(--phishing)", MALICIOUS: "var(--malicious)" };
  return map[pred] || "var(--text-secondary)";
}

/**
 * Animate a numeric counter from 0 to target.
 * @param {Element} el   - DOM element whose textContent will be updated
 * @param {number}  target
 * @param {number}  duration - ms (default 900)
 */
function animateCount(el, target, duration) {
  duration = duration || 900;
  const start   = performance.now();
  const isFloat = String(target).includes(".");
  function step(now) {
    const p = Math.min((now - start) / duration, 1);
    const e = 1 - Math.pow(1 - p, 3); // ease-out cubic
    const v = target * e;
    el.textContent = isFloat ? v.toFixed(1) : Math.round(v);
    if (p < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

/* ==========================================================================
   Main DOMContentLoaded
   ========================================================================== */
document.addEventListener("DOMContentLoaded", function () {

  /* ── Scanner (index page only) ─────────────────────────────────────────── */
  var scanForm    = document.getElementById("scanForm");
  var urlInput    = document.getElementById("urlInput");
  var analyzeBtn  = document.getElementById("analyzeBtn");
  var clearBtn    = document.getElementById("clearBtn");
  var urlError    = document.getElementById("urlError");
  var loadingSect = document.getElementById("loadingSection");
  var resultSect  = document.getElementById("resultSection");
  var errorSect   = document.getElementById("errorSection");
  var errorMsg    = document.getElementById("errorMessage");

  if (scanForm) {

    /* Example URL buttons */
    document.querySelectorAll(".btn-example").forEach(function (btn) {
      btn.addEventListener("click", function () {
        if (urlInput) { urlInput.value = btn.dataset.url || ""; urlInput.focus(); }
        clearValidationUI();
      });
    });

    /* Clear button */
    if (clearBtn) {
      clearBtn.addEventListener("click", function () {
        if (urlInput) urlInput.value = "";
        clearValidationUI();
        hideAll();
      });
    }

    /* Form submit */
    scanForm.addEventListener("submit", function (e) {
      e.preventDefault();
      var url = urlInput ? urlInput.value.trim() : "";
      var err = validateURL(url);
      if (err) { showURLError(err); return; }
      clearValidationUI();
      analyzeURL(url);
    });

    /* MutationObserver — refresh recent widget when result becomes visible */
    if (resultSect) {
      new MutationObserver(function (muts) {
        muts.forEach(function (m) {
          if (m.attributeName === "class" && !resultSect.classList.contains("d-none")) {
            setTimeout(loadRecentWidget, 800);
          }
        });
      }).observe(resultSect, { attributes: true });
    }
  }

  /* ── Recent scans widget (index page) ────────────────────────────────────── */
  loadRecentWidget();

  function loadRecentWidget() {
    var widget = document.getElementById("recentWidget");
    var body   = document.getElementById("recentWidgetBody");
    if (!widget || !body) return;
    fetch("/api/history?limit=5")
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (!data.scans || data.scans.length === 0) return;
        body.innerHTML = data.scans.map(function (s) {
          var rc = riskClass(s.risk_score);
          return '<a href="/details/' + s.id + '" class="recent-scan-row">' +
            '<span class="badge-pred badge-pred-' + s.prediction.toLowerCase() + ' flex-shrink-0">' + escHtml(s.prediction) + '</span>' +
            '<span class="recent-scan-url" title="' + escHtml(s.url) + '">' + escHtml(s.url) + '</span>' +
            '<span class="risk-pill risk-' + rc + ' flex-shrink-0">' + s.risk_score + '/100</span>' +
            '<span class="recent-scan-time flex-shrink-0">' + escHtml(s.scanned_at.slice(0, 16)) + '</span>' +
            '</a>';
        }).join("");
        widget.style.display = "block";
      })
      .catch(function () {});
  }

  /* ── Batch scanner toggle ─────────────────────────────────────────────────── */
  var batchToggle = document.getElementById("batchToggleBtn");
  var batchSect   = document.getElementById("batchSection");
  var batchIcon   = document.getElementById("batchToggleIcon");

  if (batchToggle && batchSect) {
    batchToggle.addEventListener("click", function () {
      var open = batchSect.style.display !== "none";
      batchSect.style.display = open ? "none" : "block";
      if (batchIcon) {
        batchIcon.className = batchIcon.className
          .replace(/bi-chevron-(down|up)/, open ? "bi-chevron-down" : "bi-chevron-up");
      }
      if (!open) {
        batchSect.scrollIntoView({ behavior: "smooth", block: "start" });
        var ta = document.getElementById("batchInput");
        if (ta) setTimeout(function () { ta.focus(); }, 350);
      }
    });
  }

  /* ── Batch scanner logic ──────────────────────────────────────────────────── */
  var batchBtn     = document.getElementById("batchBtn");
  var batchClear   = document.getElementById("batchClearBtn");
  var batchInput   = document.getElementById("batchInput");
  var batchProg    = document.getElementById("batchProgress");
  var batchResults = document.getElementById("batchResults");

  if (batchBtn) {
    if (batchClear) {
      batchClear.addEventListener("click", function () {
        if (batchInput)   batchInput.value   = "";
        if (batchResults) batchResults.innerHTML = "";
        if (batchProg)    batchProg.classList.add("d-none");
      });
    }

    batchBtn.addEventListener("click", function () {
      var raw  = batchInput ? batchInput.value.trim() : "";
      if (!raw) return;
      var urls = raw.split(/\r?\n/).map(function (u) { return u.trim(); }).filter(Boolean);
      if (!urls.length) return;
      if (urls.length > 20) {
        batchResults.innerHTML = '<div class="alert alert-warning"><i class="bi bi-exclamation-triangle me-2"></i>Maximum 20 URLs per batch.</div>';
        return;
      }
      if (batchProg)  batchProg.classList.remove("d-none");
      batchResults.innerHTML = "";
      batchBtn.disabled = true;

      fetch("/api/analyze/batch", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ urls: urls })
      })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
      .then(function (res) {
        if (!res.ok) {
          batchResults.innerHTML = '<div class="alert alert-danger">' + escHtml(res.d.error || "Batch scan failed.") + '</div>';
          return;
        }
        var rows = (res.d.results || []).map(function (r) {
          if (r.error) return '<tr><td class="ps-3 font-mono small" title="' + escHtml(r.url) + '">' + escHtml(r.url.slice(0, 55)) + '</td><td colspan="4"><span class="text-danger small">' + escHtml(r.error) + '</span></td></tr>';
          var rc = riskClass(r.risk_score);
          var link = r.scan_id ? "/details/" + r.scan_id : "#";
          return '<tr>' +
            '<td class="ps-3"><a href="' + link + '" class="url-cell text-truncate d-inline-block" style="max-width:260px" title="' + escHtml(r.url) + '">' + escHtml(r.url) + '</a></td>' +
            '<td><span class="badge-pred badge-pred-' + r.prediction.toLowerCase() + '">' + escHtml(r.prediction) + '</span></td>' +
            '<td><span class="risk-pill risk-' + rc + '">' + r.risk_score + '/100</span></td>' +
            '<td>' + (r.confidence * 100).toFixed(1) + '%</td>' +
            '<td class="pe-3 text-end">' + (r.scan_id ? '<a href="' + link + '" class="btn btn-sm btn-outline-primary"><i class="bi bi-eye me-1"></i>View</a>' : '') + '</td>' +
            '</tr>';
        }).join("");
        batchResults.innerHTML =
          '<div class="chart-card mt-3">' +
          '<div class="chart-card-header"><i class="bi bi-collection me-2 text-info"></i>Batch Results — ' + res.d.count + ' URL' + (res.d.count !== 1 ? "s" : "") + ' scanned</div>' +
          '<div class="chart-card-body p-0"><div class="table-responsive">' +
          '<table class="table table-dark table-hover mb-0 align-middle">' +
          '<thead><tr><th class="ps-3">URL</th><th>Prediction</th><th>Risk</th><th>Confidence</th><th class="pe-3 text-end">Details</th></tr></thead>' +
          '<tbody>' + rows + '</tbody></table></div></div>' +
          '<div class="chart-card-header border-top-0 pt-0 pb-2 px-4"><small class="text-muted"><i class="bi bi-info-circle me-1"></i>' + escHtml(res.d.disclaimer || "") + '</small></div>' +
          '</div>';
        loadRecentWidget(); // refresh recent widget after batch
      })
      .catch(function () {
        batchResults.innerHTML = '<div class="alert alert-danger"><i class="bi bi-wifi-off me-2"></i>Could not connect to the server.</div>';
      })
      .finally(function () {
        if (batchProg) batchProg.classList.add("d-none");
        batchBtn.disabled = false;
      });
    });
  }

  /* ── Scanner core ─────────────────────────────────────────────────────────── */
  function analyzeURL(url) {
    showLoading();
    fetch("/api/analyze", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url })
    })
    .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
    .then(function (res) {
      if (!res.ok) { showError(res.d.error || "Server error."); return; }
      renderResult(res.d);
    })
    .catch(function () { showError("Could not connect to the server. Please try again."); });
  }

  function renderResult(data) {
    hideAll();
    var pred     = (data.prediction || "UNKNOWN").toUpperCase();
    var predL    = pred.toLowerCase();

    var header = document.getElementById("resultHeader");
    var icon   = document.getElementById("resultIcon");
    var predEl = document.getElementById("resultPrediction");
    var urlEl  = document.getElementById("resultUrl");
    if (header) header.className = "result-header header-" + predL;
    if (icon)   { icon.className = "result-icon icon-" + predL; icon.innerHTML = '<i class="bi ' + predictionIcon(pred) + '"></i>'; }
    if (predEl) { predEl.textContent = pred; predEl.style.color = predictionColor(pred); }
    if (urlEl)  { urlEl.textContent = data.url || ""; urlEl.title = data.url || ""; }

    var riskEl  = document.getElementById("riskScore");
    var levelEl = document.getElementById("riskLevel");
    var riskBar = document.getElementById("riskBar");
    if (riskEl)  riskEl.textContent  = (data.risk_score) + "/100";
    if (levelEl) levelEl.textContent = data.risk_level || "";
    if (riskBar) {
      riskBar.style.width = data.risk_score + "%";
      var cm = { low: "var(--safe)", medium: "var(--suspicious)", high: "var(--phishing)", critical: "var(--malicious)" };
      riskBar.style.background = cm[riskClass(data.risk_score)] || "var(--text-muted)";
    }

    var confEl  = document.getElementById("confidenceVal");
    var modelEl = document.getElementById("modelName");
    if (confEl)  confEl.textContent  = (data.confidence * 100).toFixed(1) + "%";
    if (modelEl) modelEl.textContent = data.model_name || "Unknown";

    /* Probability bars */
    var probEl = document.getElementById("probBars");
    if (probEl && data.probabilities) {
      probEl.innerHTML = ["safe","suspicious","phishing","malicious"].map(function (lbl) {
        var pct = ((data.probabilities[lbl] || 0) * 100).toFixed(1);
        var hl  = lbl === predL ? "fw-bold text-light" : "text-muted";
        return '<div class="prob-row mb-3">' +
          '<div class="prob-label-row"><span class="badge-pred badge-pred-' + lbl + '">' + lbl.toUpperCase() + '</span>' +
          '<span class="small ' + hl + '">' + pct + '%</span></div>' +
          '<div class="prob-track"><div class="prob-fill prob-fill-' + lbl + '" style="width:' + pct + '%;"></div></div>' +
          '</div>';
      }).join("");
    }

    /* Explanation flags */
    var flagEl = document.getElementById("flagList");
    if (flagEl) {
      var flags = data.explanation || [];
      if (!flags.length) {
        flagEl.innerHTML = '<li class="flag-item text-muted">No specific flags detected.</li>';
      } else {
        flagEl.innerHTML = flags.map(function (flag) {
          var pos  = /HTTPS protocol|proper domain|URL length is normal|No suspicious|standard TLD|Normal subdomain/i.test(flag);
          var ico  = pos ? "bi-check-circle-fill text-success" : "bi-exclamation-circle-fill text-warning";
          return '<li class="flag-item"><i class="bi ' + ico + '"></i>' + escHtml(flag) + '</li>';
        }).join("");
      }
    }


    /* Feature contributions (from model internals) */
    var contribEl = document.getElementById("contribSection");
    if (contribEl && data.contributions && data.contributions.length > 0) {
      var topN = data.contributions.slice(0, 6);
      var rows = topN.map(function(c) {
        var pct   = Math.min(Math.round(c.importance * 500), 100);
        var isRisk = c.direction === "increases";
        var valStr = c.value === 1 ? "Yes" : c.value === 0 ? "No" : c.value.toFixed ? c.value.toFixed(2) : c.value;
        var valCls = c.value === 1 ? "text-warning" : c.value === 0 ? "text-success" : "text-info";
        return '<div class="contrib-row mb-3">' +
          '<div class="d-flex justify-content-between align-items-center mb-1">' +
          '<span class="contrib-name font-mono small">' + escHtml(c.feature) + '</span>' +
          '<div class="d-flex align-items-center gap-2">' +
          '<span class="contrib-value ' + valCls + '">' + valStr + '</span>' +
          '<span class="contrib-importance text-muted small">' + (c.importance*100).toFixed(1) + '%</span>' +
          '<span class="contrib-dir small ' + (isRisk ? "text-danger" : "text-success") + '">' +
          (isRisk ? '<i class="bi bi-arrow-up-short"></i>risk' : '<i class="bi bi-arrow-down-short"></i>risk') +
          '</span></div></div>' +
          '<div class="contrib-bar-track">' +
          '<div class="contrib-bar-fill ' + (isRisk ? "contrib-bar-risk" : "contrib-bar-safe") + '" style="width:' + pct + '%;"></div>' +
          '</div></div>';
      }).join("");

      var methodLabel = (data.explain_method || "rule_based").replace(/_/g," ");
      contribEl.innerHTML =
        '<div class="mb-4">' +
        '<h6 class="section-label"><i class="bi bi-diagram-3-fill me-2"></i>Feature Contributions ' +
        '<span class="badge bg-secondary ms-1 fw-normal" style="font-size:0.65rem;text-transform:none;">' + methodLabel + '</span></h6>' +
        rows +
        '<p class="text-muted small mb-0 mt-2"><i class="bi bi-info-circle me-1"></i>Which features most influenced this prediction, by model importance.</p>' +
        '</div>';
      contribEl.style.display = "block";
    } else if (contribEl) {
      contribEl.style.display = "none";
    }

    /* Details link */
    var detLink = document.getElementById("detailsLink");
    if (detLink && data.scan_id) detLink.href = "/details/" + data.scan_id;

    /* Feature chips — includes has_malware_keyword */
    var fgrid = document.getElementById("featureGrid");
    if (fgrid && data.features) {
      var f = data.features;
      var chips = [
        { label: "HTTPS",          ok: !!f.uses_https },
        { label: "IP Address",     ok: !f.has_ip_address },
        { label: "Malware KW",     ok: !f.has_malware_keyword },
        { label: "Suspicious TLD", ok: !f.has_suspicious_tld },
        { label: "URL Shortener",  ok: !f.is_url_shortener },
        { label: "@ Symbol",       ok: !f.has_at_symbol },
        { label: "Hex Obfusc.",    ok: !f.has_hex_chars },
        { label: "Suspicious KW",  ok: (f.suspicious_kw_count || 0) < 2 },
        { label: "Redirect Param", ok: !f.has_redirect_param },
        { label: "URL Length",     ok: (f.url_length || 0) <= 100 },
      ];
      fgrid.innerHTML = chips.map(function (chip) {
        var cls = chip.ok ? "feature-chip-ok"
          : (chip.label === "URL Length" ? "feature-chip-warn" : "feature-chip-bad");
        var ico = chip.ok ? "check-circle-fill" : "x-circle-fill";
        return '<div class="feature-chip ' + cls + '"><i class="bi bi-' + ico + '"></i><span>' + escHtml(chip.label) + '</span></div>';
      }).join("");
    }

    if (resultSect) {
      resultSect.classList.remove("d-none");
      resultSect.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  function showLoading() {
    hideAll();
    if (loadingSect) loadingSect.classList.remove("d-none");
    if (analyzeBtn)  analyzeBtn.disabled = true;
  }

  function hideAll() {
    [loadingSect, resultSect, errorSect].forEach(function (el) {
      if (el) el.classList.add("d-none");
    });
    if (analyzeBtn) analyzeBtn.disabled = false;
  }

  function showError(msg) {
    hideAll();
    if (errorMsg)  errorMsg.textContent = msg;
    if (errorSect) errorSect.classList.remove("d-none");
  }

  function showURLError(msg) {
    if (urlInput) urlInput.classList.add("is-invalid");
    if (urlError) {
      urlError.innerHTML = '<i class="bi bi-exclamation-circle me-1"></i>' + escHtml(msg);
      urlError.classList.remove("d-none");
    }
  }

  function clearValidationUI() {
    if (urlInput) urlInput.classList.remove("is-invalid");
    if (urlError) urlError.classList.add("d-none");
  }

  function validateURL(url) {
    if (!url || !url.length) return "Please enter a URL before analyzing.";
    if (url.length > 2048)   return "URL is too long (max 2048 characters).";
    var withScheme = /^https?:\/\//i.test(url) ? url : "https://" + url;
    try {
      var p = new URL(withScheme);
      if (!p.hostname || p.hostname.length < 2) return "URL must contain a valid domain name.";
    } catch (e) {
      return "URL format is invalid. Please enter a valid URL (e.g. https://example.com).";
    }
    return null;
  }

  /* ── Dashboard stat card animated counters ───────────────────────────────── */
  var obs = new IntersectionObserver(function (entries) {
    entries.forEach(function (en) {
      if (!en.isIntersecting) return;
      var el  = en.target;
      var val = parseFloat(el.dataset.count) || 0;
      animateCount(el, val, 900);
      obs.unobserve(el);
    });
  }, { threshold: 0.3 });
  document.querySelectorAll(".stat-value[data-count]").forEach(function (el) { obs.observe(el); });

  /* ── Dashboard last-refreshed timestamp ──────────────────────────────────── */
  var lr = document.getElementById("lastRefreshed");
  if (lr) lr.textContent = "Updated: " + new Date().toLocaleTimeString();

}); /* end DOMContentLoaded */
