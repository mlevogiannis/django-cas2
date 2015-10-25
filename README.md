django-cas2
===========

CAS 2.0 authentication module for Django with support for proxy authentication
and single sign out. This project is a fork and rewrite of the original django-cas
module which is found at https://bitbucket.org/cpcc/django-cas/ as of this writing.
It is a drop-in replacement for most cases, but support for very old versions of CAS,
Python and Django is removed and in the case you need this (you really shouldn't)
you have to look for the django-cas version mentioned above.

[CAS](http://www.jasig.org/cas), Central Authentication Server, is an open source,
single sign on solution for web applications. [Django](http://www.djangoproject.com/)
is a Python web application framework.

More useful detailed information about CAS is the [protocol specification](http://www.jasig.org/cas/protocol)
and the [CAS Proxy Walkthrough](https://wiki.jasig.org/display/CAS/Proxy+CAS+Walkthrough)

## Major release 2.0

The release 2.0 marks a more definite departure from previous versions of Django
and focuses on support for Django versions 1.4 and later. See [RELEASE_NOTES](RELEASE_NOTES.md)
for more information about the relase.

## Comparing to original django_cas module

This fork was prompted by missing functionality in the original django_cas module.
The original django_cas module works ok for basic CAS authentication, but does not
support any more advanced features of CAS. This project add features and removes
support for old framework versions, e.g:

* Support for CAS proxy authentication making it possible to authenticate to backend
  web services using CAS.
* Support for the CAS gateway feature prohibiting user interaction. This is typically
  used by backend services not directly exposed to the user.
* Support for CAS single sign out making it possible to sign out users from your
  Django application when they sign out of the CAS single sign on server.
* Use logging and raise 400:s rather than raise 500:s for most error cases.
* Removed Django messaging. The original module registers a welcome message for
  all users. This has to be taken care of somewhere else if you want this feature.
  It's easy enough using the `user_logged_in` signal issued by Django for example.
* Removed creation of user accounts on successful authentication by default. This
  is often not wanted in managed environments. If you want the original behaviuor,
  use the CAS_AUTO_CREATE_USERS setting mentioned below.
* Removed support for old versions of Django and Python. This module is currently
  focused on Django 1.4 and later versions as well as Python 2.6 and later. If you
  need support for previous versions, look at the 1.2 release of this project or
  the original django_cas module.

## Installation

Run `python setup.py install` as per usual or mess with your PYTHONPATH appropriately,
using the master branch for the latest stable version or the pre built source tar-balls
in the downloads section.

Or you can use pip to install directly from the master branch.

```
pip install -e git+git://github.com/fjollberg/django-cas2#egg=django_cas
```

### Django configuration

Add the **django_cas**, **CASMiddleware** and **CASBackends** to the Django configuration. Note
that you need the Django AuthenticationMiddleware as well.

```
INSTALLED_APPS = (
  ...
  'django_cas',
  ...
)
```

```
MIDDLEWARE_CLASSES = (
  ...
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django_cas.middleware.CASMiddleware',
    ...
)
```

```
AUTHENTICATION_BACKENDS = (
	...
    'django.contrib.auth.backends.ModelBackend',
    'django_cas.backends.CASBackend',
    ...
)
```

The login and logout URLs must be handled in the urls.py file, and to use proxy authentication
support also the proxy call back URL, see optional settings below.

```
...
(r'^accounts/login/$', 'django_cas.views.login'),
(r'^accounts/logout/$', 'django_cas.views.logout'),
...
```

Create necessary database tables with the Django management command `python manage.py syncdb`.

### Configuration options for django-cas2

#### Mandatory setting

`CAS_SERVER_URL: None`

Mandatory. The URL for the CAS server.  This should be a HTTPS URI, otherwise the authentication
is vulnerable to man-in-the-middle attacks.

#### Optional settings

`CAS_SERVER_SSL_VERIFY: True`

If `True`, HTTPS connections to the CAS server have their SSL certificates validated.  If set
to `False`, SSL certificates will not be validated and the configuration will be insecure.

The certificate is validated against a bundle included with [requests](http://www.python-requests.org),
which comes from Mozilla.  However, it is recommended to pin your server's certificate by specifying a
path to a public key, for example: `CAS_SERVER_SSL_VERIFY = '/usr/local/share/certificates/mycert.pem'`.

Note that if a HTTP server is passed as the `CAS_SERVER_URL`, this option is *ignored*, and the module
will proceed with *insecure* communication with the CAS server.

`CAS_SERVER_SSL_CERT: None`

This will pass a client certificate for use when connecting to the CAS server over HTTPS.

`CAS_LOGOUT_COMPLETELY: True`

If `True`, redirect and do a CAS logout when user logs out of the Django application.
It is in most cases pointless to turn this off unless CAS_RENEW is set.

`CAS_SINGLE_SIGN_OUT: True`

If `True`, support single sign out reqeusts form the CAS server and sign out of the
Django application when a user signs out of CAS.

NOTE: If your sessions are not database mapped, either with the database backend or
the cached database backend, the table keeping track of the session ticket - session
mappings may not always be cleared when sessions are expired and deleted. In that
case you have to run the django-admin command purge_session_service_tickets
periodically.

`CAS_RENEW: False`

If `True`, enables the renew feature of CAS, sending renew parameter on login
and verification of tickets to enforce that the login is made with a fresh
username and password verification in the CAS server.

`CAS_GATEWAY: False`

If `True`, enables the gateway feature of CAS, enforcing a non-interactive authorization
by CAS. In other words, a user will not be presented with a login screen if not signed
into CAS, but redirected to the service URL with not ticket. This is useful for backend
web services that are not directly accessed by users. This option in CAS is fundmentally
incompatible with the renew feature mentioned above, hence CAS_GATEWAY will be silently
ignored and no gateway option sent to the CAS server if CAS_RENEW is set.

NOTE: setting CAS_GATEWAY will add a parameter, 'casgw', to the service URL to identify
failed gateway requests as such. It is a part of the inner workings of django_cas and
not apublic property, but it may interfere with any existing parameter with the same
name used by your Django application. The name is configurable by setting `CAS_GATEWAY_PARAM`.

`CAS_REDIRECT_URL: '/'`

Default URL to redirect to after login and logout when there is no referrer or next
page provided by Django.

`CAS_IGNORE_REFERER: False`

If `True`, logging out of the application will always send the user to the URL specified by `CAS_REDIRECT_URL`.

`CAS_RETRY_LOGIN: False`

If `True`, redirect back to CAS server if CAS authentication fails.

`CAS_AUTO_CREATE_USERS : False`

If `True`, automatically create accounts for authenticated users which don't have one. This
is a change in behavior from the original django-cas module which hade no such option and
auto created users. Admittedly, it was probably a mistake to change the default, but there
you go. It won't hurt your data at least.

`CAS_PROXY_CALLBACK: None`

The callback URL the CAS server should use to inject proxy tickets. Setting this enables
proxy granting ticket support. The URL must also be registered in urls.py and handled
by the django_cas.views.proxy_callback, e.g:
`(r'^accounts/login/casProxyCallback$', 'django_cas.views.proxy_callback')`
See [Proxy CAS Authentication](./PROXY_AUTHENTICATION.md)
for more information and trouble shooting hints.

`CAS_ALLOWED_PROXIES : []`

A list of URLs of proxies that are allowed to proxy authenticate to the Django application.
If set, the proxy chain provided by the CAS server in the validation response must not contain
services that are not included in this list. There is currently no wild carding or other magic.

`CAS_ATTRIBUTES : {}`

A dict which describes mappings between phpCAS-style (CAS 2.0 draft) attributes
and attributes of the User model.  If populated, this will cause `django-cas2`
to overwrite the User model with attributes provided by CAS, if they are
provided by the CAS server.

In order to use this with Jasig CAS, it is required to [patch the CAS server](https://wiki.jasig.org/display/CASUM/Attributes#Attributes-AccessingattributesusingphpCAS)
such that these attributes are propegated.

The mapping uses the dictionary's value to refer to an attribute of the
`django.contrib.auth.models.User` class, and the key is a unicode referring to the
tag name that CAS provides.

For example: `{u'cas:GivenName': 'first_name', u'cas:Surname': 'last_name', u'cas:Mail': 'email'}`.

In the absence of any attribute listed, it will not be populated.  The behaviour
of providing multiple tags for the same attribute in the User model is undefined.

**Note**: This allows changing of the `is_admin` and `is_staff` attributes
which can be a potential security issue.


`CAS_EXTRA_LOGIN_PARAMS: None`

> Not quite sure what the purpose for this is, anyone using it? How? I'm tempted to
> remove it since it is outside of the protocol specification, but I can think of some
> possible use cases, the question is if someone is using it?
> /Fredrik Jönsson Oct 15 2012

A dictionary of extra URL parameters to add to the login URL when redirecting the user.

## Security considerations

### Use SSL/TLS

Even if the authentication with CAS is made using a mechanism which makes
it difficult to interfere with, all authorized communication will subsequentely use
a cookie identifing the session which can be used to hijack the connection.
So you need to encrypt the communication. There is just no way around that if you
want to enforce some sort of security.

### Single sign out

There was in the applied single-sign-out patch, and in the 1.0 release of this project
a setting with which you could list hosts which where allowed to do the single sign out
call to the application, CAS_LOGOUT_REQUEST_ALLOWED. This is removed in 1.1. As it was
implemented it did not work in a number of situations, and my belief is that it suggested
security that it didn't really provide.

The recommendation instead is that if you have conserns with the possibility of denial
of service attacks caused by faked logout requests with compromised CAS session tickets,
you should turn single sign out support of completely, using CAS_SINGLE_SIGN_OUT = False.

The issue at hand is that if someone intercepts your service ticket, it can be used to
logout the user from the application at a later point. In this sense, the CAS service ticket
has a long life, wheras it otherwise has a very short life span for authentication. The
service ticket is sent as an URL parameter and thus generally more exposed (for example
in access logging) than most other authentication data.

The only likely place the service ticket is more exposed than other relevant data, say
the django session, is in the access log files. The possibly increased risk is thus if
the log files are more easily accessible than other harmful data, such as the database,
or provides another vector of attack. The possible effect of this risk is that users
could be logged out, causing a kind of denial of service.

The CAS_LOGOUT_REQUEST_ALLOWED amended this effect to some extent by given the remote
address in the request, only allow hosts with the correct address as reported by the
address resolving routines of the server host. This is in itself fraught with a number
of issues, and does not work well for proxied applications. Some of these deficits could
be worked around by additional code.

## Development

This project uses git and git flow style branching. Hence, the master branch is the
stable release branch, and development is done on the development branch. For more
information about the branch model see http://nvie.com/posts/a-successful-git-branching-model/.
For the `git flow` command line tool, see https://github.com/nvie/gitflow.

Version numbering follows the [Semantic versioning](http://semver.org) approach.
A 'KTH-' prefix is currently applied to the version number to distinguish this project
from the original django_cas project derivatives for the time being, see further below.

## Copyrights

The source has been and is licensed by a MIT [license](./LICENCE.md).
In other words, do as you please with it, but don't think you can hold us liable for any damage caused
to or by you if you use it.

## Rationale for forking

The django-cas project has been rather poorly maintained for some time. The most obvious changes
include moving the repo around. Patches supplied by myself in order to support proxy authentication
and by others for single sign out (http://code.google.com/r/arnaudgrausem-django-cas/) have
not been integrated but are in fact lost in the repo changes.

Also the django_cas project suffers from dead code, some wierdness and support for really,
really old versions of CAS, Python and Django, bogging it down.

The module is still called django_cas for the time being, the rationale being that it is
a drop-in replacement and I don't want to handle migrations issues in the database as yet.
