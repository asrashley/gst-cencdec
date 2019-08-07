#!/usr/bin/env python

import base64
import binascii
import hashlib
import os
import re
import sys

def store_key(filename, key):
    kfile = open(filename,'wb')
    kfile.write(key)
    kfile.close()
    print('Key stored: {0}'.format(filename))

if len(sys.argv)<3:
    print('Usage: %s <KID> <key>'%(sys.argv[0]))
    sys.exit(1)

kid_str = sys.argv[1].strip().replace('-','')
bin_kid= binascii.unhexlify(kid_str)
if len(bin_kid)!=16:
    print('ERROR: KID is not 16 bytes long')
    sys.exit(2)

key_str = sys.argv[2].strip()
if re.match(r'^[0-9a-f]+$', key_str, re.IGNORECASE):
    bin_key = binascii.unhexlify(key_str)
else:
    bin_key = base64.b64decode(key_str)
if len(bin_key)!=16:
    print('ERROR: Key is not 16 bytes long')
    sys.exit(2)

# Marlin naming
id_str = ':'.join(['urn','marlin','kid',binascii.hexlify(bin_kid)])
filename = os.path.join('/tmp', hashlib.sha1(id_str).hexdigest()) + '.key'
store_key(filename, bin_key)

# Clearkey naming
filename = os.path.join('/tmp', binascii.hexlify(bin_kid)) + '.key'
store_key(filename, bin_key)
