"""Intentionally bad Django settings: fires CFG-01..07 (T1b fixture)."""
import os

DEBUG = True  # CFG-01

ALLOWED_HOSTS = ["*"]  # CFG-02

SECRET_KEY = "django-insecure-hardcoded-key-for-tests-only"  # CFG-03

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "mydb",
        "USER": "admin",
        "PASSWORD": "s3cr3t-db-password",  # CFG-04
        "HOST": "localhost",
    }
}

MIDDLEWARE = [  # CFG-05 x2 (no CsrfViewMiddleware, no SecurityMiddleware)
    "django.middleware.common.CommonMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
]

SESSION_COOKIE_SECURE = False  # CFG-06
# CSRF_COOKIE_SECURE missing -> CFG-06 Low

CORS_ALLOW_ALL_ORIGINS = True  # CFG-07

GOOD_ENV_KEY = os.environ.get("SOME_KEY")  # must NOT fire CFG-03
