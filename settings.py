CAS_SERVER_URL = 'localhost:8000'
CAS_LOGOUT_COMPLETELY = True
CAS_SINGLE_SIGN_OUT = True
CAS_REDIRECT_URL = '/'


DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}

SECRET_KEY = 'cas-secret-key'

INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',

    'django_coverage',
    'django_nose',
)

TEST_RUNNER = 'django_nose.NoseTestSuiteRunner'
NOSE_PLUGINS = []

# Tell nose to measure coverage on the 'foo' and 'bar' apps
NOSE_ARGS = [
    '--with-coverage',
    '--cover-html',
    '--cover-package=django_cas',
    '--cover-tests',
    '--cover-erase',
    ]

# EMAIL_BACKEND = 'django.core.mail.backends.filebased.EmailBackend'
# EMAIL_FILE_PATH = '/tmp/invest-messages'  # change this to a proper location
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# To avoid warnings
MIDDLEWARE_CLASSES = (
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django_cas.middleware.CASMiddleware',
)

AUTHENTICATION_BACKENDS = (
    'django.contrib.auth.backends.ModelBackend',
    'django_cas.backends.CASBackend',
)


ROOT_URLCONF = 'urls'