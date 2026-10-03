"""
config.py
---------
Application configuration for different environments.

Usage:
    The Flask app reads FLASK_ENV (or APP_ENV) from the environment.
    Set it before starting:

        Windows PowerShell:
            $env:FLASK_ENV = "production"
            python app.py

        Bash / macOS / Linux:
            FLASK_ENV=production python app.py

    For secrets, create a .env file in the project root (never commit it):

        SECRET_KEY=your-random-secret-here
        FLASK_ENV=development

    Then load it with:
        pip install python-dotenv
        # app.py already calls load_dotenv() when python-dotenv is available.
"""

import os
import secrets


def _bool(val: str, default: bool = False) -> bool:
    """Parse a string environment variable as a boolean."""
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


class BaseConfig:
    """Settings shared across all environments."""

    # Flask core
    SECRET_KEY: str = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
    JSON_SORT_KEYS: bool = False
    MAX_CONTENT_LENGTH: int = 1 * 1024 * 1024   # 1 MB max request body

    # Application paths (resolved relative to this file)
    BASE_DIR: str   = os.path.dirname(os.path.abspath(__file__))
    DATA_DIR: str   = os.path.join(BASE_DIR, "data")
    MODELS_DIR: str = os.path.join(BASE_DIR, "models")
    DB_DIR: str     = os.path.join(BASE_DIR, "database")

    # Model paths
    MODEL_PATH: str  = os.path.join(MODELS_DIR, "link_detection_model.pkl")
    CONFIG_PATH: str = os.path.join(MODELS_DIR, "feature_config.pkl")

    # Database
    DB_PATH: str = os.path.join(DB_DIR, "scans.db")

    # Rate limiting
    RATELIMIT_DEFAULT:      str = "200 per day, 60 per hour"
    RATELIMIT_ANALYZE:      str = "30 per minute"
    RATELIMIT_STORAGE_URI:  str = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")

    # Security
    FORCE_HTTPS:     bool = _bool(os.environ.get("FORCE_HTTPS"), default=False)
    SESSION_COOKIE_SECURE:   bool = False
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str  = "Lax"

    # Logging
    LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "INFO")


class DevelopmentConfig(BaseConfig):
    """Local development — verbose errors, no HTTPS enforcement."""
    DEBUG:       bool = True
    TESTING:     bool = False
    FORCE_HTTPS: bool = False
    LOG_LEVEL:   str  = "DEBUG"


class TestingConfig(BaseConfig):
    """Unit / integration testing — in-memory DB, no rate limits."""
    DEBUG:       bool = True
    TESTING:     bool = True
    # Use an in-memory DB so tests don't touch the real database
    DB_PATH:     str  = ":memory:"
    RATELIMIT_ENABLED: bool = False
    WTF_CSRF_ENABLED:  bool = False


class ProductionConfig(BaseConfig):
    """Production deployment — strict security, HTTPS enforced."""
    DEBUG:       bool = False
    TESTING:     bool = False
    FORCE_HTTPS: bool = _bool(os.environ.get("FORCE_HTTPS"), default=True)

    # In production SECRET_KEY MUST come from an environment variable
    SECRET_KEY: str = os.environ.get("SECRET_KEY") or BaseConfig.SECRET_KEY

    SESSION_COOKIE_SECURE:   bool = True
    SESSION_COOKIE_SAMESITE: str  = "Strict"
    LOG_LEVEL: str = "WARNING"


# ---------------------------------------------------------------------------
# Config selector
# ---------------------------------------------------------------------------
_CONFIG_MAP = {
    "development": DevelopmentConfig,
    "testing":     TestingConfig,
    "production":  ProductionConfig,
    # Aliases
    "dev":  DevelopmentConfig,
    "test": TestingConfig,
    "prod": ProductionConfig,
}

def get_config(env: str | None = None) -> type:
    """
    Return the configuration class for the given environment name.

    If *env* is None the function reads FLASK_ENV (then APP_ENV) from the
    OS environment and falls back to 'development'.
    """
    if env is None:
        env = os.environ.get("FLASK_ENV") or os.environ.get("APP_ENV", "development")
    return _CONFIG_MAP.get(env.lower(), DevelopmentConfig)
