"""
Django settings for parent_control project.

Generated by 'django-admin startproject' using Django 3.2.11.

For more information on this file, see
https://docs.djangoproject.com/en/3.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/3.2/ref/settings/
"""

import os
import sys
from pathlib import Path

from django.conf.global_settings import STATICFILES_FINDERS

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# We put it in a subdir so that we can map it in docker with -v param.
_local_settings_file = BASE_DIR / "local_settings" / "local_settings.py"

if os.environ.get("PARENT_CONTROL_LOCAL_TEST_SETTINGS", None):  # pragma: no cover
    # This is to make sure settings_for_tests.py is not used for unit tests.
    assert _local_settings_file != os.environ["PARENT_CONTROL_LOCAL_TEST_SETTINGS"]
    _local_settings_file = os.environ["PARENT_CONTROL_LOCAL_TEST_SETTINGS"]

local_settings = None
if os.path.isfile(_local_settings_file):  # pragma: no cover
    local_settings_module = None

    local_settings_package, local_settings_file_name = (
        os.path.split(_local_settings_file))

    local_settings_package = os.path.split(local_settings_package)[-1]

    local_settings_module_name, ext = (
        os.path.splitext(local_settings_file_name))
    assert ext == ".py"
    exec(f"from {local_settings_package} import {local_settings_module_name}"
         f" as local_settings_module")

    local_settings = local_settings_module.__dict__  # type: ignore  # noqa

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/3.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get(
    "PARENT_CONTROL_SERVER_SECRET_KEY",
    'django-insecure-cn2=(%5qhtaqn_x0or!u=v2)vk7@7)$)8ply7uey8hxy+3wz#9')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.environ.get('PARENT_CONTROL_SERVER_DEBUG', 'off') == 'on'

ALLOWED_HOSTS = ("127.0.0.1",)

# You can set extra allowed host items by setting the item name
# startswith PARENT_CONTROL_ALLOWED_HOST_ (with no ending 'S')
# e.g., PARENT_CONTROL_ALLOWED_HOST_CAT = "http://example.com"
custom_allowed_hosts = [
    value for item, value in list(dict(os.environ).items())
    if item.startswith("PARENT_CONTROL_ALLOWED_HOST")]

if custom_allowed_hosts:  # pragma: no cover
    ALLOWED_HOSTS = ALLOWED_HOSTS + tuple(custom_allowed_hosts)

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    "crispy_forms",
    "django_celery_beat",
    # 'django_celery_results',
    'corsheaders',
    'rest_framework.authtoken',
    'rest_framework',
    'my_router',
]

CRISPY_TEMPLATE_PACK = "bootstrap3"

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'parent_control.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': ["parent_control/templates"],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'my_router.views.routers_context_processor',
            ],
            "builtins": ["my_router.templatetags.my_router_tags"],
        },
    },
]

WSGI_APPLICATION = 'parent_control.wsgi.application'

# Database
# https://docs.djangoproject.com/en/3.2/ref/settings/#databases

PARENT_CONTROL_SERVER_DB_HOST = os.getenv("PARENT_CONTROL_SERVER_DB_HOST",
                                          "localhost")
PARENT_CONTROL_SERVER_DB_PORT = os.getenv("PARENT_CONTROL_SERVER_DB_PORT", "5432")
PARENT_CONTROL_SERVER_DB_USER = os.getenv("PARENT_CONTROL_SERVER_DB_USER",
                                          "parent_control")
PARENT_CONTROL_SERVER_DB_PASSWORD = os.getenv("PARENT_CONTROL_SERVER_DB_PASSWORD",
                                              "parent_control_pass")
PARENT_CONTROL_SERVER_DB = os.getenv("PARENT_CONTROL_SERVER_DB", "parent_control")

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': PARENT_CONTROL_SERVER_DB,
        'USER': PARENT_CONTROL_SERVER_DB_USER,
        'PASSWORD': PARENT_CONTROL_SERVER_DB_PASSWORD,
        'HOST': PARENT_CONTROL_SERVER_DB_HOST,
        'PORT': PARENT_CONTROL_SERVER_DB_PORT,
    },
}

# Password validation
# https://docs.djangoproject.com/en/3.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',  # noqa
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
# https://docs.djangoproject.com/en/3.2/topics/i18n/

LANGUAGE_CODE = 'zh-Hans'

TIME_ZONE = 'Hongkong'

USE_I18N = True

USE_L10N = True

USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.2/howto/static-files/

STATIC_URL = '/static/'

STATIC_ROOT = "/srv/www/static"

STATICFILES_FINDERS += ("npm.finders.NpmFinder",)

STATICFILES_DIRS = (
    os.path.join(BASE_DIR, "parent_control", "static"),
)

# Default primary key field type
# https://docs.djangoproject.com/en/3.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# {{{ CORS settings
# CORS_ORIGIN_ALLOW_ALL: If True, all origins will be accepted
# (not use the whitelist below). Defaults to False. CORS_ORIGIN_WHITELIST:
# List of origins that are authorized to make cross-site HTTP requests.
# Defaults to []
CORS_ORIGIN_ALLOW_ALL = os.environ.get(
    "PARENT_CONTROL_CORS_ORIGIN_ALLOW_ALL") is None
CORS_ORIGIN_WHITELIST = (
    'http://localhost:8030',
    'http://localhost:8080',
    'http://host.docker.internal:8030',
)

CORS_URLS_REGEX = r'^/api/.*$'

# You can set extra whitelist items by setting the item name
# startswith PARENT_CONTROL_CORS_ORIGIN_WHITELIST
# e.g., PARENT_CONTROL_CORS_ORIGIN_WHITELIST_LOCAL = "http://192.168.50.1"
custom_whitelist_items = [
    value for item, value in list(dict(os.environ).items())
    if item.startswith("PARENT_CONTROL_CORS_ORIGIN_WHITELIST")]

if custom_whitelist_items:  # pragma: no cover
    CORS_ORIGIN_WHITELIST = CORS_ORIGIN_WHITELIST + tuple(custom_whitelist_items)

LOCALE_PATHS = (
    BASE_DIR / 'locale',
)

# {{{ rest auth

# https://stackoverflow.com/a/52347668/3437454
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.TokenAuthentication',
    ],
    "TIME_INPUT_FORMATS": ["%H:%M"],
    "TIME_FORMAT": "%H:%M"
}

# }}}

redis_location = os.getenv('PARENT_CONTROL_SERVER_REDIS_LOCATION', None)
redis_cache_location = (
    f"{redis_location}/0" if redis_location else "redis://127.0.0.1:6379/0")
redis_backend_location = (
    f"{redis_location}/1" if redis_location else "redis://127.0.0.1:6379/1")

CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": [
            redis_cache_location,
        ],
        "TIMEOUT": None,
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
            "IGNORE_EXCEPTIONS": True,
        }
    }
}

# Celery settings
CELERY_BROKER_URL = redis_backend_location
CELERY_RESULT_BACKEND = redis_backend_location
CELERY_TIMEZONE = TIME_ZONE
CELERY_BEAT_SCHEDULER = 'django_celery_beat.schedulers:DatabaseScheduler'

LANGUAGE_CODE = os.environ.get("PARENT_CONTROL_SERVER_LANGUAGE_CODE", 'zh-hans')

TIME_ZONE = os.environ.get("PARENT_CONTROL_SERVER_TZ", 'Asia/Shanghai')

USE_I18N = True

USE_L10N = True

USE_TZ = True

LOGIN_URL = "/login/"
LOGIN_REDIRECT_URL = 'profile'

if sys.platform.lower().startswith("win"):  # pragma: no cover
    STATIC_ROOT = BASE_DIR / "static"
else:  # pragma: no cover
    NPM_ROOT_PATH = "/srv"

# The interval which the app fetches remote info, in seconds
try:
    PARENT_CONTROL_FETCH_INFO_INTERVAL = int(
        os.environ.get("PARENT_CONTROL_FETCH_INFO_INTERVAL"))
except Exception:
    PARENT_CONTROL_FETCH_INFO_INTERVAL = 10

if local_settings is not None:  # pragma: no cover
    for name, val in local_settings.items():
        if not name.startswith("_"):
            globals()[name] = val

    # enable auto-reload when developing
    try:
        import local_settings
    except ImportError:  # pragma: no cover
        pass
