#!/usr/bin/env python

import hashlib, binascii, os, sys

if len(sys.argv)<3:
    print('Usage: %s <KID> <key>'%(sys.argv[0]))
    sys.exit(1)

bin_kid= binascii.unhexlify(sys.argv[1])
if len(bin_kid)!=16:
    print('ERROR: KID is not 16 bytes long')
    sys.exit(2)

id_str = ':'.join(['urn','marlin','kid',binascii.hexlify(bin_kid)])
print(id_str)
filename = os.path.join('/tmp',hashlib.sha1(id_str).hexdigest()) + '.key'
print(filename)
key= binascii.unhexlify(sys.argv[2])
if len(key)!=16:
    print('ERROR: Key is not 16 bytes long')
    sys.exit(2)

kfile = open(filename,'wb')
kfile.write(key)
kfile.close()
print('Key stored')
