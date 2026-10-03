"""
feature_extraction.py
---------------------
Extracts URL-based features for ML classification.
All analysis is purely static — no HTTP requests are made to the target URL.
"""

import re
import math
import urllib.parse
from collections import Counter

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "logon", "log-in",
    "verify", "verification", "validate", "validation",
    "secure", "security", "alert", "warning", "urgent",
    "account", "accounts", "billing", "payment", "invoice",
    "password", "passwd", "credential", "credentials",
    "update", "confirm", "confirmation", "restore", "recover",
    "suspend", "suspended", "limited", "locked", "blocked",
    "bank", "banking", "paypal", "credit", "debit", "card",
    "ssn", "social", "identity", "id-verify", "id-check",
    "click-here", "click-now", "act-now", "action-required",
    "free", "winner", "prize", "gift", "reward", "bonus",
    "lucky", "congratulations", "selected", "offer",
    "download", "install", "setup", "crack", "keygen", "patch",
    "exploit", "malware", "virus", "trojan", "ransomware",
    "phishing", "scam", "fraud", "hack", "hacked",
]

# URL shorteners known to obscure destinations
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co",
    "short.link", "is.gd", "buff.ly", "adf.ly", "bit.do",
    "bc.vc", "rebrand.ly", "cutt.ly", "s.id", "shorturl.at",
]

# TLDs very commonly abused in phishing/malware campaigns (high confidence)
SUSPICIOUS_TLDS = [
    ".xyz", ".ml", ".tk", ".top", ".click", ".link",
    ".download", ".zip", ".review", ".country", ".kim",
    ".science", ".work", ".party", ".gq", ".cf",
    ".pw", ".cc", ".su", ".icu", ".cyou", ".bond",
    ".cfd", ".hair", ".beauty", ".monster", ".quest",
]

# Medium-confidence TLDs — common in spam but also used legitimately
MEDIUM_SUSPICIOUS_TLDS = [
    ".info", ".biz", ".name", ".mobi", ".tel",
]

# Keywords strongly associated with malware/C2/exploits (not just suspicious)
MALWARE_KEYWORDS = [
    "ransomware", "malware", "trojan", "botnet", "c2", "c&c",
    "beacon", "payload", "exploit", "shellcode", "dropper",
    "keylogger", "spyware", "rootkit", "worm", "backdoor",
    "meterpreter", "cobalt-strike", "cobaltstrike", "mimikatz",
    "metasploit", "rat", "remote-access", "cryptominer", "cryptojack",
    "exfil", "exfiltrate", "harvest", "stealer", "credential-dump",
    "zero-day", "zeroday", "powershell-dropper", "fileless",
    "drive-by", "watering-hole", "command-and-control",
]

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _entropy(text: str) -> float:
    """Shannon entropy of a string — high entropy indicates randomness."""
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _count_digits(text: str) -> int:
    return sum(1 for c in text if c.isdigit())


def _count_special_chars(text: str) -> int:
    """Count characters that are not alphanumeric, dot, slash, colon, or hyphen."""
    return sum(1 for c in text if c not in
               "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-/:_?=&#@%+")


def _has_ip_address(url: str) -> int:
    """Return 1 if the URL host looks like an IPv4 address."""
    ipv4_pattern = re.compile(
        r"(https?://)?(\d{1,3}\.){3}\d{1,3}"
    )
    return int(bool(ipv4_pattern.search(url)))


def _count_subdomains(hostname: str) -> int:
    """Number of subdomains (parts minus the registered domain + TLD)."""
    parts = hostname.split(".")
    # Anything beyond the last two parts is a subdomain
    return max(0, len(parts) - 2)


def _is_url_shortener(hostname: str) -> int:
    return int(any(shortener in hostname for shortener in URL_SHORTENERS))


def _has_suspicious_tld(url: str) -> int:
    """Return 1 if the URL host uses a high-confidence abuse TLD."""
    try:
        parsed   = urllib.parse.urlparse(url if "://" in url else "http://" + url)
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return 0
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld) or ("." + hostname.split(".")[-1]) == tld:
                return 1
    except Exception:
        pass
    return 0


def _has_malware_keyword(url: str) -> int:
    """Return 1 if the URL contains a keyword strongly associated with malware/C2."""
    url_lower = url.lower()
    return int(any(kw in url_lower for kw in MALWARE_KEYWORDS))


def _suspicious_keyword_count(url: str) -> int:
    url_lower = url.lower()
    return sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)


def _has_hex_chars(url: str) -> int:
    """Detect percent-encoded or 0x-style hex sequences beyond normal URL encoding."""
    hex_pattern = re.compile(r"(%[0-9a-fA-F]{2}|0x[0-9a-fA-F]+)")
    matches = hex_pattern.findall(url)
    # More than 3 encoded chars is suspicious
    return int(len(matches) > 3)


def _has_at_symbol(url: str) -> int:
    """@ in URL can redirect the browser to a different host."""
    parsed = urllib.parse.urlparse(url)
    return int("@" in parsed.netloc)


def _count_query_params(query_string: str) -> int:
    if not query_string:
        return 0
    return len(urllib.parse.parse_qs(query_string))


def _domain_entropy(hostname: str) -> float:
    return _entropy(hostname.replace(".", ""))


# ---------------------------------------------------------------------------
# Main feature extraction function
# ---------------------------------------------------------------------------

def extract_features(url: str) -> dict:
    """
    Extract a comprehensive set of static features from a URL string.

    Parameters
    ----------
    url : str
        The raw URL to analyse.

    Returns
    -------
    dict
        A flat dictionary mapping feature name → numeric value.
    """
    # Ensure the URL has a scheme so urllib.parse works correctly
    raw_url = url.strip()
    if not raw_url.startswith(("http://", "https://", "ftp://")):
        raw_url = "http://" + raw_url

    try:
        parsed = urllib.parse.urlparse(raw_url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
        fragment = parsed.fragment or ""
    except Exception:
        hostname, path, query, fragment = "", "", "", ""

    # ---- Basic structural features ----------------------------------------
    url_length        = len(url)
    domain_length     = len(hostname)
    path_length       = len(path)
    query_length      = len(query)

    num_dots          = url.count(".")
    num_slashes       = url.count("/")
    num_hyphens       = url.count("-")
    num_underscores   = url.count("_")
    num_digits        = _count_digits(url)
    num_special_chars = _count_special_chars(url)
    num_query_params  = _count_query_params(query)
    num_subdomains    = _count_subdomains(hostname)

    # ---- Protocol features ------------------------------------------------
    uses_https        = int(parsed.scheme == "https")
    uses_http         = int(parsed.scheme == "http")

    # ---- Suspicious-pattern features -------------------------------------
    has_ip_address    = _has_ip_address(raw_url)
    has_at_symbol     = _has_at_symbol(raw_url)
    has_hex_chars     = _has_hex_chars(raw_url)
    suspicious_kw_count = _suspicious_keyword_count(raw_url)
    has_suspicious_tld  = _has_suspicious_tld(raw_url)
    is_url_shortener    = _is_url_shortener(hostname)
    excessive_subdomains = int(num_subdomains >= 4)

    # Specific keyword category flags
    login_keywords = ["login", "signin", "sign-in", "logon", "log-in"]
    verify_keywords = ["verify", "verification", "validate", "confirm"]
    account_keywords = ["account", "accounts", "billing", "payment"]
    password_keywords = ["password", "passwd", "credential"]

    url_lower = raw_url.lower()
    has_login_keyword    = int(any(kw in url_lower for kw in login_keywords))
    has_verify_keyword   = int(any(kw in url_lower for kw in verify_keywords))
    has_account_keyword  = int(any(kw in url_lower for kw in account_keywords))
    has_password_keyword = int(any(kw in url_lower for kw in password_keywords))

    # Unusual character combos
    has_double_slash_in_path = int("//" in path)
    has_multiple_at          = int(url.count("@") > 1)

    # Domain entropy (randomised domains score high)
    domain_entropy_score = round(_domain_entropy(hostname), 4)

    # Path depth
    path_depth = len([p for p in path.split("/") if p])

    # Digit ratio in domain (e.g., "a1b2c3xyz.com")
    digit_ratio_domain = (
        round(_count_digits(hostname) / len(hostname), 4) if hostname else 0.0
    )

    # Fragment present (unusual in phishing — can hide destination)
    has_fragment = int(bool(fragment))

    # Port present (non-standard port is suspicious)
    has_non_standard_port = int(
        parsed.port is not None and parsed.port not in (80, 443, 8080, 8443)
    )

    # Redirect-like query params
    redirect_params = ["redirect", "url", "next", "goto", "return", "dest", "redir"]
    has_redirect_param = int(
        any(p in query.lower() for p in redirect_params)
    )

    # Malware/C2-specific keyword indicator (stronger signal than general suspicious_kw)
    has_malware_keyword  = _has_malware_keyword(raw_url)

    return {
        # Basic
        "url_length":             url_length,
        "domain_length":          domain_length,
        "path_length":            path_length,
        "query_length":           query_length,
        "num_dots":               num_dots,
        "num_slashes":            num_slashes,
        "num_hyphens":            num_hyphens,
        "num_underscores":        num_underscores,
        "num_digits":             num_digits,
        "num_special_chars":      num_special_chars,
        "num_query_params":       num_query_params,
        "num_subdomains":         num_subdomains,
        # Protocol
        "uses_https":             uses_https,
        "uses_http":              uses_http,
        # Suspicious patterns
        "has_ip_address":         has_ip_address,
        "has_at_symbol":          has_at_symbol,
        "has_hex_chars":          has_hex_chars,
        "suspicious_kw_count":    suspicious_kw_count,
        "has_suspicious_tld":     has_suspicious_tld,
        "is_url_shortener":       is_url_shortener,
        "excessive_subdomains":   excessive_subdomains,
        "has_login_keyword":      has_login_keyword,
        "has_verify_keyword":     has_verify_keyword,
        "has_account_keyword":    has_account_keyword,
        "has_password_keyword":   has_password_keyword,
        "has_double_slash_path":  has_double_slash_in_path,
        "has_multiple_at":        has_multiple_at,
        # Domain quality
        "domain_entropy":         domain_entropy_score,
        "digit_ratio_domain":     digit_ratio_domain,
        # Structure
        "path_depth":             path_depth,
        "has_fragment":           has_fragment,
        "has_non_standard_port":  has_non_standard_port,
        "has_redirect_param":     has_redirect_param,
        "has_malware_keyword":    has_malware_keyword,
    }


def get_feature_names() -> list:
    """Return the ordered list of feature names used by the model."""
    sample = extract_features("https://example.com")
    return list(sample.keys())


def get_human_readable_flags(features: dict) -> list:
    """
    Convert a feature dictionary into human-readable explanation strings.
    Returns only the flags that are actually triggered / noteworthy.
    """
    flags = []

    if features.get("has_malware_keyword"):
        flags.append("URL contains a malware/C2-associated keyword")
    if features.get("has_malware_keyword"):
        flags.append("URL contains a malware/C2-associated keyword")
    if features.get("has_ip_address"):
        flags.append("URL uses an IP address instead of a domain name")
    if features.get("has_at_symbol"):
        flags.append("URL contains '@' symbol — may redirect to a different host")
    if features.get("has_hex_chars"):
        flags.append("URL contains obfuscated hex-encoded characters")
    if features.get("suspicious_kw_count", 0) >= 2:
        flags.append(f"URL contains {features['suspicious_kw_count']} suspicious keywords")
    elif features.get("suspicious_kw_count", 0) == 1:
        flags.append("URL contains a suspicious keyword")
    if features.get("has_suspicious_tld"):
        flags.append("URL uses a TLD commonly associated with abuse")
    if features.get("is_url_shortener"):
        flags.append("URL is a known URL-shortening service (destination unknown)")
    if features.get("excessive_subdomains"):
        flags.append(f"Excessive subdomains detected ({features.get('num_subdomains')})")
    if features.get("has_login_keyword"):
        flags.append("URL contains login-related keywords")
    if features.get("has_verify_keyword"):
        flags.append("URL contains verification-related keywords")
    if features.get("has_account_keyword"):
        flags.append("URL contains account/billing-related keywords")
    if features.get("has_password_keyword"):
        flags.append("URL contains password/credential-related keywords")
    if features.get("url_length", 0) > 100:
        flags.append(f"URL is unusually long ({features['url_length']} characters)")
    if features.get("num_hyphens", 0) >= 4:
        flags.append(f"URL contains many hyphens ({features['num_hyphens']})")
    if features.get("num_dots", 0) >= 5:
        flags.append(f"URL contains many dots ({features['num_dots']})")
    if features.get("domain_entropy", 0) > 3.8:
        flags.append("Domain name has high entropy (may be randomly generated)")
    if features.get("digit_ratio_domain", 0) > 0.35:
        flags.append("Domain name contains an unusually high proportion of digits")
    if not features.get("uses_https"):
        flags.append("URL does not use HTTPS (no encryption)")
    if features.get("has_redirect_param"):
        flags.append("URL contains a redirect parameter (may forward to another site)")
    if features.get("has_non_standard_port"):
        flags.append("URL uses a non-standard port")
    if features.get("has_double_slash_path"):
        flags.append("URL path contains double slashes (possible injection attempt)")
    if features.get("num_special_chars", 0) >= 5:
        flags.append(f"URL contains many special characters ({features['num_special_chars']})")
    if features.get("has_fragment"):
        flags.append("URL contains a fragment identifier")
    if features.get("num_query_params", 0) >= 5:
        flags.append(f"URL has many query parameters ({features['num_query_params']})")

    # Positive flags — only when no risk indicators at all
    if not flags:
        pos = []
        if features.get("uses_https"):
            pos.append("HTTPS protocol in use")
        if not features.get("has_ip_address"):
            pos.append("Uses a proper domain name")
        if features.get("url_length", 0) <= 75:
            pos.append("URL length is normal")
        if features.get("suspicious_kw_count", 0) == 0:
            pos.append("No suspicious keywords detected")
        if features.get("num_subdomains", 0) <= 1:
            pos.append("Normal subdomain structure")
        if not features.get("has_suspicious_tld"):
            pos.append("Domain uses a standard TLD")
        flags = pos if pos else ["No significant risk indicators detected"]

    return flags
