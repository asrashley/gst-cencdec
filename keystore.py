#!/usr/bin/env python

import base64
import binascii
import hashlib
import os
import re
import sys

class KeyStore(object):
    def __init__(self):
        self.keys = {}

    def add_key(self, kid, key=None):
        """Adds a key to the store.
        Both kid and key can be either hex or base64 encoded
        """
        kid = kid.strip()
        if re.match(r'^[0-9a-f-]+$', kid, re.IGNORECASE):
            bin_kid= binascii.unhexlify(kid.replace('-',''))
        else:
            bin_kid = base64.b64decode(kid)
        if len(bin_kid)!=16:
            raise ValueError('ERROR: KID is not 16 bytes long')
        if key is not None:
            key = key.strip()
            if re.match(r'^[0-9a-f]+$', key, re.IGNORECASE):
                key = binascii.unhexlify(key.replace('-',''))
            else:
                key = base64.b64decode(key)
            if len(key)!=16:
                raise ValueError('ERROR: Key is not 16 bytes long')
        self.keys[bin_kid] = key

    def save(self):
        for kid, key in self.keys.iteritems():
            # Marlin naming
            id_str = ':'.join(['urn','marlin','kid',binascii.hexlify(kid)])
            filename = os.path.join('/tmp', hashlib.sha1(id_str).hexdigest()) + '.key'
            self.store_key(filename, key)

            # Clearkey naming
            filename = os.path.join('/tmp', binascii.hexlify(kid)) + '.key'
            self.store_key(filename, key)

    def store_key(self, filename, key):
        with open(filename,'wb') as kfile:
            kfile.write(key)
        print('Key stored: {0}'.format(filename))

if __name__ == "__main__":
    if len(sys.argv)<3:
        print('Usage: %s <KID> <key> [<KID> <key> .. ]'%(sys.argv[0]))
        sys.exit(1)
    ks = KeyStore()
    for i in range(1, len(sys.argv), 2):
        ks.add_key(sys.argv[i], sys.argv[i+1])
    ks.save()

