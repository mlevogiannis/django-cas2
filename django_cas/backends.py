""" Django CAS 2.0 authentication backend """

from django.conf import settings
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import User
from django_cas.exceptions import CasTicketException
from django_cas.models import Tgt, PgtIOU
from urllib import urlencode, urlopen
from urlparse import urljoin
from xml.dom import minidom
import logging
import time

__all__ = ['CASBackend']

logger = logging.getLogger(__name__)

class CASBackend(ModelBackend):
    """ CAS authentication backend """

    def authenticate(self, ticket, service):
        """ Verifies CAS ticket and gets or creates User object """

        (username, proxies) = self._verify(ticket, service)
        if not username:
            return None
        
        if settings.CAS_ALLOWED_PROXIES:
            for proxy in proxies:
                if not proxy in settings.CAS_ALLOWED_PROXIES:
                    return None

        logger.debug("User '%s' passed authentication by CAS backend", username)

        try:
            return User.objects.get(username=username)
        except User.DoesNotExist:
            if settings.CAS_AUTO_CREATE_USERS:
                logger.debug("User '%s' auto created by CAS backend", username)
                return User.objects.create_user(username)
            else:
                logger.error("Failed authentication, user '%s' does not exist", username)

        return None

    
    def _verify(self, ticket, service):
        """ Verifies CAS 2.0+ XML-based authentication ticket.
    
            Returns tuple (username, [proxy URLs]) on success or None on failure.
        """
        params = {'ticket': ticket, 'service': service}
        if settings.CAS_PROXY_CALLBACK:
            params.update({'pgtUrl': settings.CAS_PROXY_CALLBACK})
        if settings.CAS_RENEW:
            params.update({'renew': 'true'})
    
        page = urlopen(urljoin(settings.CAS_SERVER_URL, 'proxyValidate') + '?' + urlencode(params))
    
        try:
            response = minidom.parseString(page.read())
            if response.getElementsByTagName('cas:authenticationFailure'):
                logger.warn("Authentication failed from CAS server: %s", 
                            response.getElementsByTagName('cas:authenticationFailure')[0].firstChild.nodeValue)
                return (None, None)
    
            username = response.getElementsByTagName('cas:user')[0].firstChild.nodeValue
            proxies = []
            if response.getElementsByTagName('cas:proxyGrantingTicket'):
                proxies = [p.firstChild.nodeValue for p in response.getElementsByTagName('cas:proxies')]
                pgt = response.getElementsByTagName('cas:proxyGrantingTicket')[0].firstChild.nodeValue
                try:
                    pgtIou = self._get_pgtiou(pgt)
                    tgt = Tgt.objects.get(username = username)
                    tgt.tgt = pgtIou.tgt
                    tgt.save()
                    pgtIou.delete()
                except Tgt.DoesNotExist:
                    Tgt.objects.create(username = username, tgt = pgtIou.tgt)
                    pgtIou.delete()
                except:
                    logger.error("Failed to do proxy authentication.", exc_info=True)
    
            logger.debug("Cas proxy authentication succeeded for %s with proxies %s", username, proxies)
            return (username, proxies)
        except Exception as e:
            logger.error("Failed to verify CAS authentication", e)
            return (None, None)
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

def get_saml_assertion(ticket):
   return """<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Header/><SOAP-ENV:Body><samlp:Request xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol"  MajorVersion="1" MinorVersion="1" RequestID="_192.168.16.51.1024506224022" IssueInstant="2002-06-19T17:03:44.022Z"><samlp:AssertionArtifact>""" + ticket + """</samlp:AssertionArtifact></samlp:Request></SOAP-ENV:Body></SOAP-ENV:Envelope>"""

SAML_1_0_NS = 'urn:oasis:names:tc:SAML:1.0:'
SAML_1_0_PROTOCOL_NS = '{' + SAML_1_0_NS + 'protocol' + '}'
SAML_1_0_ASSERTION_NS = '{' + SAML_1_0_NS + 'assertion' + '}'

def _verify_cas2_saml(ticket, service):
    """Verifies CAS 3.0+ XML-based authentication ticket and returns extended attributes.

    @date: 2011-11-30
    @author: Carlos Gonzalez Vila <carlewis@gmail.com>

    Returns username and attributes on success and None,None on failure.
    """

    try:
        from xml.etree import ElementTree
    except ImportError:
        from elementtree import ElementTree

    # We do the SAML validation
    headers = {'soapaction': 'http://www.oasis-open.org/committees/security',
        'cache-control': 'no-cache',
        'pragma': 'no-cache',
        'accept': 'text/xml',
        'connection': 'keep-alive',
        'content-type': 'text/xml'}
    params = {'TARGET': service}
    url = urllib2.Request(urljoin(settings.CAS_SERVER_URL, 'samlValidate') + '?' + urlencode(params), '', headers)
    data = get_saml_assertion(ticket)
    url.add_data(get_saml_assertion(ticket))

    page = urllib2.urlopen(url)

    try:
        user = None
        attributes = {}
        response = page.read()
        print response
        tree = ElementTree.fromstring(response)
        # Find the authentication status
        success = tree.find('.//' + SAML_1_0_PROTOCOL_NS + 'StatusCode')
        if success is not None and success.attrib['Value'] == 'samlp:Success':
            # User is validated
            attrs = tree.findall('.//' + SAML_1_0_ASSERTION_NS + 'Attribute')
            for at in attrs:
                if 'uid' in at.attrib.values():
                    user = at.find(SAML_1_0_ASSERTION_NS + 'AttributeValue').text
                    attributes['uid'] = user
                values = at.findall(SAML_1_0_ASSERTION_NS + 'AttributeValue')
                if len(values) > 1:
                    values_array = []
                    for v in values:
                        values_array.append(v.text)
                    attributes[at.attrib['AttributeName']] = values_array
                else:
                   attributes[at.attrib['AttributeName']] = values[0].text
        return user, attributes
    finally:
        page.close()
