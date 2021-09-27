import sys
from base64 import urlsafe_b64encode
from hashlib import md5
from time import time
if (sys.version_info > (2, 7)):
    PYTHON_VER = 3 if (sys.version_info >= (3, 0)) else 2
    from urllib.parse import urlparse, urlunparse, ParseResult
else:
    PYTHON_VER = 2
    from urlparse import urlparse, urlunparse, ParseResult

DEFAULT = object()


def generate_key(s):
    if PYTHON_VER == 2:
        return urlsafe_b64encode(md5(s).digest()).rstrip('=')
    else:
        return urlsafe_b64encode(md5(s.encode('utf-8')).digest()).rstrip('='.encode('utf-8')).decode('utf-8')


class Signer(object):
    def __init__(self, key, timeout=DEFAULT, address = None, format='{key}{value}{expiration}'):
        self.key = key
        self.timeout = 60*60*24 if timeout is DEFAULT else timeout
        self.address = address
        self.format = '{key}{address}{value}{expiration}' if address else format

    def sign(self, *args, **kwargs):
        raise NotImplementedError


class Nginx(Signer):
    def get_expiration(self):
        if self.timeout is not None:
            return str(int(self.timeout+time()))
        return ''

    def signature(self, url):
        expiration = self.get_expiration()
        if not self.address:
            string = self.format.format(key=self.key, value=url, expiration=expiration)
        else:
            # string = self.format.format(key=self.key, value=s, expiration=expiration, address=self.address)
            string = f"{expiration}{url}{self.address} {self.key}"
        return generate_key(string), expiration


class UriSigner(Nginx):
    def sign(self, uri):
        sig, exp = self.signature(uri)

        parsed = urlparse(uri)

        query = parsed.query
        if query:
            query += '&'
        query += 'md5=%s&expires=%s' % (sig, exp)

        return urlunparse(ParseResult(
            parsed.scheme, parsed.netloc,
            parsed.path, parsed.params, query, parsed.fragment))


class UriQuerySigner(Nginx):
    def sign(self, key, value):
        sig, exp = self.signature(value)
        return '%s=%s&md5=%s&expires=%s' % (key, value, sig, exp)
