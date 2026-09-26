"""Known-good Django settings: zero CFG findings (T1b fixture)."""
import os

DEBUG = False

ALLOWED_HOSTS = ["example.com"]

SECRET_KEY = os.environ["SECRET_KEY"]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "mydb",
        "USER": "admin",
        "PASSWORD": os.environ.get("DB_PASSWORD", ""),
        "HOST": "localhost",
    }
}

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
]

SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True

CORS_ALLOWED_ORIGINS = ["https://example.com"]
