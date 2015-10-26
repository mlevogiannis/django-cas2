""" Django CAS 2.0 authentication backend """

import logging
import time
import uuid
from xml.dom import minidom, Node
try:
    from xml.etree import ElementTree
    _hush_pyflakes = [ElementTree]
except ImportError:
    from elementtree import ElementTree

import requests

from django.conf import settings
from django.contrib.auth.backends import ModelBackend
try:
    # Django >= 1.5
    from django.contrib.auth import get_user_model
    User = get_user_model()
except ImportError:
    from django.contrib.auth.models import User

from django.utils.six.moves import urllib
from django.utils.six.moves.urllib.parse import urljoin, urlencode


from django_cas.exceptions import CasTicketException
from django_cas.models import Tgt, PgtIOU


__all__ = ['CASBackend', 'CASBackend_SAML']

logger = logging.getLogger(__name__)


class CASBackend(ModelBackend):
    """ CAS authentication backend """

    def authenticate(self, ticket, service):
        """ Verifies CAS ticket and gets or creates User object """

        (username, proxies, attributes) = self._verify(ticket, service)
        if not username:
            return None

        if settings.CAS_ALLOWED_PROXIES:
            for proxy in proxies:
                if not proxy in settings.CAS_ALLOWED_PROXIES:
                    return None

        logger.debug("User '%s' passed authentication by CAS backend", username)

        user = None

        try:
            return User.objects.get(username=username)
        except User.DoesNotExist:
            if settings.CAS_AUTO_CREATE_USERS:
                logger.info("User '%s' auto created by CAS backend", username)
                return User.objects.create_user(username)
            else:
                logger.error("Failed authentication, user '%s' does not exist", username)

        if user != None:
            # user was found, set attributes
            provided_attributes = False

            for k, v in settings.CAS_ATTRIBUTES.iteritems():
                if k in attributes:
                    # the attribute exists in the attributes data, set it
                    setattr(user, v, attributes[k])
                    provided_attributes = True

            if provided_attributes:
                # we have changed the user object, save it.
                user.save()

        # returns None if invalid user
        return user

    def _verify(self, ticket, service):
        """ Verifies CAS 2.0+ XML-based authentication ticket.

            Returns tuple (username, [proxy URLs], {attributes}) on success or None on failure.
        """
        params = {'ticket': ticket, 'service': service}
        if settings.CAS_PROXY_CALLBACK:
            params.update({'pgtUrl': settings.CAS_PROXY_CALLBACK})
        if settings.CAS_RENEW:
            params.update({'renew': 'true'})

        page = requests.get(urljoin(settings.CAS_SERVER_URL, 'proxyValidate'), params=params,
            verify=settings.CAS_SERVER_SSL_VERIFY, cert=settings.CAS_SERVER_SSL_CERT)

        try:
            response = minidom.parseString(page.content)
            if response.getElementsByTagName('cas:authenticationFailure'):
                logger.warn("Authentication failed from CAS server: %s",
                            response.getElementsByTagName('cas:authenticationFailure')[0].firstChild.nodeValue)
                return (None, None, None)

            username = response.getElementsByTagName('cas:user')[0].firstChild.nodeValue
            proxies = []
            attributes = {}
            if response.getElementsByTagName('cas:proxyGrantingTicket'):
                proxies = [p.firstChild.nodeValue for p in response.getElementsByTagName('cas:proxies')]
                pgt = response.getElementsByTagName('cas:proxyGrantingTicket')[0].firstChild.nodeValue
                try:
                    pgtIou = self._get_pgtiou(pgt)
                    tgt = Tgt.objects.get(username=username)
                    tgt.tgt = pgtIou.tgt
                    tgt.save()
                    pgtIou.delete()
                except Tgt.DoesNotExist:
                    Tgt.objects.create(username=username, tgt=pgtIou.tgt)
                    pgtIou.delete()
                except Exception:
                    logger.error("Failed to do proxy authentication.", exc_info=True)

            attrib_tag = response.getElementsByTagName('cas:attributes')
            if attrib_tag:
                for child in attrib_tag[0].childNodes:
                    if child.nodeType != Node.ELEMENT_NODE:
                        # only parse tags
                        continue

                    attributes[child.tagName] = child.firstChild.nodeValue

            logger.debug("Cas proxy authentication succeeded for %s with proxies %s", username, proxies)
            return (username, proxies, attributes)
        except Exception as e:
            logger.error("Failed to verify CAS authentication", e)
            return (None, None, None)
        finally:
            page.close()

    def _get_pgtiou(self, pgt):
        """ Returns a PgtIOU object given a pgt.

            The PgtIOU (tgt) is set by the CAS server in a different request that has
            completed before this call, however, it may not be found in the database
            by this calling thread, hence the attempt to get the ticket is retried
            for up to 5 seconds. This should be handled some better way.
        """
        pgtIou = None
        retries_left = 5
        while not pgtIou and retries_left:
            try:
                return PgtIOU.objects.get(pgtIou=pgt)
            except PgtIOU.DoesNotExist:
                time.sleep(1)
                retries_left -= 1
        raise CasTicketException("Could not find pgtIou for pgt %s" % pgt)


class CASBackend_SAML(CASBackend):
    SAML_1_0_NS = 'urn:oasis:names:tc:SAML:1.0:'
    SAML_1_0_PROTOCOL_NS = '{' + SAML_1_0_NS + 'protocol' + '}'
    SAML_1_0_ASSERTION_NS = '{' + SAML_1_0_NS + 'assertion' + '}'

    SAML_REQUEST = """<?xml version="1.0" encoding="UTF-8"?>
    <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
    <SOAP-ENV:Header/>
    <SOAP-ENV:Body>
        <samlp:Request xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol"
                MajorVersion="1" MinorVersion="1"
                RequestID="%(request_id)s" IssueInstant="%(issue_instant)s">
        <samlp:AssertionArtifact>%(ticket)s</samlp:AssertionArtifact>
        </samlp:Request>
    </SOAP-ENV:Body>
    </SOAP-ENV:Envelope>
    """
    HTTP_HEADERS = {'soapaction': 'http://www.oasis-open.org/committees/security',
            'cache-control': 'no-cache',
            'pragma': 'no-cache',
            'accept': 'text/xml',
            'connection': 'keep-alive',
            'content-type': 'text/xml'}

    def _prepare_request(self, ticket):
        """Prepare a few variables for the SAML_REQUEST
        """
        return { 'request_id': uuid.uuid4(),
                'issue_instant': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'ticket': ticket }

    def _get_response(self, rdict, params):
        """ send request and fetch response from CAS through HTTP
        """
        url = urllib.request.Request(urljoin(settings.CAS_SERVER_URL, 'samlValidate') \
                                + '?' + urlencode(params), '', self.HTTP_HEADERS)

        url.add_data(self.SAML_REQUEST % rdict)
        try:
            page = None
            logger.debug("Verifying ticket through: %s", url.get_full_url())
            page = urllib.request.urlopen(url)
            return ElementTree.parse(page)
        finally:
            if page:
                page.close()

    def _verify(self, ticket, service):
        """Verifies CAS 3.0+ XML-based authentication ticket and returns extended attributes.

        @date: 2011-11-30
        @author: Carlos Gonzalez Vila <carlewis@gmail.com>

        Returns username and attributes on success and None,None on failure.
        """


        # We do the SAML validation
        params = {'TARGET': service}
        rdict = self._prepare_request(ticket)

        try:
            tree = self._get_response(rdict, params)
            # logger.debug("The tree: %s", ElementTree.dump(tree))
        except Exception:
            logger.exception("Cannot get ticket validation response:")
            return (None, None, None)

        _status_code = './/' + self.SAML_1_0_PROTOCOL_NS + 'StatusCode'
        _attribute = './/%sAttributeStatement/%sAttribute' % (self.SAML_1_0_ASSERTION_NS, self.SAML_1_0_ASSERTION_NS)
        _attribute_value = self.SAML_1_0_ASSERTION_NS + 'AttributeValue'
        try:
            user = None
            attributes = {}
            # TODO: proxies?

            # Find the authentication status
            elem = tree.getroot()
            assert elem.tag == '{http://schemas.xmlsoap.org/soap/envelope/}Envelope' , elem.tag
            elem = elem[0]
            assert elem.tag == '{http://schemas.xmlsoap.org/soap/envelope/}Body' , elem.tag

            response = elem[0]
            if response.tag !=  self.SAML_1_0_PROTOCOL_NS + 'Response':
                logger.warning("SAML response is not valid: %s", response.tag)
                raise ValueError("Invalid SAML response")
            if response.get('MajorVersion', None) != '1' or response.get('MinorVersion', None) != '1':
                raise ValueError("Invalid SAML version in response: %s.%s", response.get('MajorVersion', '?'), response.get('MinorVersion', '?'))
            if response.get('Recipient', '') != service:
                logger.warning("Recipient mismatch: %s != %s", response.get('Recipient', ''), service)
            else:
                logger.debug("Rest of attributes are: %s", list(response.items()))

            res_status = response.find(_status_code)

            if res_status is not None and ':' in res_status.get('Value',''):
                res_status_val = res_status.get('Value','').rsplit(':',1)[1]
            else:
                res_status_val = '?'

            if res_status_val == 'Success':
                # User is validated
                for at in response.iterfind(_attribute):
                    att_name = at.get('AttributeName', None)
                    if not att_name:
                        logger.warning("Malformed attribute in SAML:\n %s", ElementTree.tostring(at))
                        continue
                    # att_ns = at.get('AttributeNamespace') eventually check that?
                    vals = []
                    for ve in at.iter(_attribute_value):
                        # Here, we ignore so far
                        # the "{http://www.w3.org/2001/XMLSchema-instance}type"
                        # attribute that could indicate a non-string variable
                        vals.append(ve.text)

                    if att_name == 'uid':
                        if len(vals) != 1:
                            # that would be ambiguous, it's a problem
                            raise ValueError('Attribute "uid" has %d values!' % len(vals))
                        user = vals[0]

                    if len(vals) == 1:
                        attributes[att_name] = vals[0]
                    else:
                        attributes[att_name] = vals
            else:
                # response.find("Status/StatusMessage") and ("Status/StatusDetail")
                logger.info('Ticket validation of "%s" failed: %s', ticket, res_status.get('Value', ''))
                return None, None, None
            logger.debug("User: %s, attributes: %d", user, len(attributes))
            for a, v in list(attributes.items()):
                logger.debug("                     %s: %s", a, v)
            return user, [], attributes
        except Exception:
            logger.warning("Cannot parse ticket validation response:", exc_info=True)
            return None, None, None
