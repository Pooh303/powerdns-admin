import os
import urllib.parse

basedir = os.path.abspath(os.path.dirname(__file__))

BIND_ADDRESS = '0.0.0.0'
CAPTCHA_ENABLE = True
CAPTCHA_HEIGHT = 60
CAPTCHA_LENGTH = 6
CAPTCHA_SESSION_KEY = 'captcha_image'
CAPTCHA_WIDTH = 160
CSRF_COOKIE_HTTPONLY = True
HSTS_ENABLED = False
PORT = 9191
SALT = '$2b$12$yLUMTIfl21FKJQpTkRQXCu'
SAML_ASSERTION_ENCRYPTED = True
SAML_ENABLED = False
SECRET_KEY = os.getenv('SECRET_KEY', 'replace_me_with_something_random')
SERVER_EXTERNAL_SSL = os.getenv('SERVER_EXTERNAL_SSL', True)
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_TYPE = os.getenv('SESSION_TYPE', 'filesystem')
SESSION_FILE_DIR = os.getenv('SESSION_FILE_DIR', '/tmp/flask_session')
SESSION_FILE_THRESHOLD = int(os.getenv('SESSION_FILE_THRESHOLD', '500'))
SESSION_PERMANENT = os.getenv('SESSION_PERMANENT', 'False').lower() == 'true'
PERMANENT_SESSION_LIFETIME = int(os.getenv('PERMANENT_SESSION_LIFETIME', '1800'))
SESSION_COOKIE_SECURE = os.getenv('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
SESSION_COOKIE_HTTPONLY = os.getenv('SESSION_COOKIE_HTTPONLY', 'True').lower() == 'true'

# Database configuration PostgreSQL
SQLA_DB_USER = os.getenv('SQLA_DB_USER', 'pda')
SQLA_DB_PASSWORD = os.getenv('SQLA_DB_PASSWORD', 'changeme')
SQLA_DB_HOST = os.getenv('SQLA_DB_HOST', '127.0.0.1')
SQLA_DB_NAME = os.getenv('SQLA_DB_NAME', 'pda')
SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI', 'postgresql://{}:{}@{}/{}'.format(
    urllib.parse.quote_plus(SQLA_DB_USER),
    urllib.parse.quote_plus(SQLA_DB_PASSWORD),
    SQLA_DB_HOST,
    SQLA_DB_NAME
))
SQLALCHEMY_TRACK_MODIFICATIONS = True

# Ensure JSON responses
JSON_AS_ASCII = False
JSON_SORT_KEYS = True
JSONIFY_PRETTYPRINT_REGULAR = False
JSONIFY_MIMETYPE = 'application/json'

# SMTP Configuration
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SMTP_USERNAME = 'dreamminigame333@gmail.com'
SMTP_PASSWORD = 'raez vdiz zbfd qpuq'
# SMTP_FROM_ADDRESS = os.getenv('SMTP_FROM_ADDRESS', 'noreply@localhost')
SMTP_FROM_ADDRESS = os.getenv('SMTP_FROM_ADDRESS', 'PowerDNS Admin <dreamminingame333@gmail.com>')
SMTP_USE_TLS = True
SMTP_USE_SSL = os.getenv('SMTP_USE_SSL', 'False').lower() == 'true'
SMTP_DEFAULT_SENDER = 'dreamminigame333@gmail.com'

# Admin Configuration
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', 'dreamminigame333@gmail.com')


# Email recipient(s) for LUA backend status alerts
NOTIFICATION_EMAILS = os.getenv('NOTIFICATION_EMAILS', 'samchaischool96@gmail.com,rouimmit1987@gmail.com')
# Notify when a LUA backend port comes back UP
NOTIFY_PORT_UP = os.getenv('NOTIFY_PORT_UP', 'False').lower() == 'true'
# Notify when a LUA backend port goes DOWN
NOTIFY_PORT_DOWN = os.getenv('NOTIFY_PORT_DOWN', 'True').lower() == 'true'
# Interval for checking LUA backend statuses (in seconds)
LUA_BACKEND_MONITOR_INTERVAL = int(os.getenv('LUA_BACKEND_MONITOR_INTERVAL', '60'))
# Enable or disable the LUA backend monitoring service
ENABLE_LUA_BACKEND_MONITOR = os.getenv('ENABLE_LUA_BACKEND_MONITOR', 'False').lower() == 'true'