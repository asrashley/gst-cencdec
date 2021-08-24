import base64
import binascii
import json
import ssl
import sys

import certifi
import urllib3

from keystore import KeyStore

class W3CClearkey(KeyStore):
    def __init__(self, la_url, tls_check=True):
        super(W3CClearkey, self).__init__()
        self.la_url = la_url
        self.http_pool = urllib3.PoolManager(
            cert_reqs=ssl.CERT_REQUIRED if tls_check else ssl.CERT_NONE,
            strict=True,
            ca_certs=certifi.where()
        )

    def base64url_encode(self, b):
        b = base64.b64encode(b)
        b = b.replace('+', '-')
        b = b.replace('/', '_')
        return b.replace('=', '')

    def base64url_decode(self, b):
        b = b.replace('-', '+')
        b = b.replace('_', '/')
        padding = len(b) % 4
        if padding == 2:
            b += '=='
        elif padding == 3:
            b += '='
        return base64.b64decode(b)

    def request_keys(self):
        todo = []
        for kid, key in self.keys.iteritems():
            if key is not None:
                continue
            todo.append(kid)
        if not todo:
            return True
        todo = map(lambda i: self.base64url_encode(i), todo)
        request = {
            "kids": todo,
            "type": "temporary"
        }
        post = json.dumps(request).encode('utf-8')
        print(post)
        result = self.http_pool.urlopen('POST', self.la_url, body=post,
                                        headers={
                                            'Content-Type': 'application/json'
                                        })
        print('HTTP status {}'.format(result.status))
        print(result.headers)
        print(result.data)
        if result.status != 200:
            return False
        jwk = json.loads(result.data)
        for item in jwk["keys"]:
            key = self.base64url_decode(item["k"]).encode('hex')
            kid = self.base64url_decode(item["kid"]).encode('hex')
            print(kid, key)
            self.add_key(kid, key)
        return True
        
if __name__ == "__main__":
    if len(sys.argv)<3:
        print('Usage: %s <la_url> <kid> [<kid> .. ]'%(sys.argv[0]))
        sys.exit(1)
    wck = W3CClearkey(sys.argv[1])
    for kid in sys.argv[2:]:
        wck.add_key(kid)
    if wck.request_keys():
        wck.save()

