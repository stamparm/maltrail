#!/usr/bin/env python

"""
Copyright (c) 2014-2015 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission

Derivative work from 'python-pbkdf2' by Armin Ronacher (@mitsuhiko)
"""

import hmac
import hashlib
import itertools
import operator
import os
import struct

DEFAULT_ITERATIONS = 10000

# Reference: https://github.com/mitsuhiko/python-pbkdf2
def pbkdf2(password, salt, iterations=10000, keylen=24, hashfunc=None):
    hashfunc = hashfunc or hashlib.sha1
    mac = hmac.new(password, None, hashfunc)

    def _pseudorandom(x, mac=mac):
        h = mac.copy()
        h.update(x)
        return map(ord, h.digest())

    buf = []
    for block in xrange(1, -(-keylen // mac.digest_size) + 1):        
        rv = u = _pseudorandom(salt + struct.pack(">I", block))

        for i in xrange(iterations - 1):
            u = _pseudorandom(''.join(map(chr, u)))
            rv = itertools.starmap(operator.xor, itertools.izip(rv, u))

        buf.extend(rv)

    return ''.join(map(chr, buf))[:keylen]

def main():
    password = raw_input("Password: ").strip()

    try:
        iterations = int(raw_input("Iterations (e.g. %d): " % DEFAULT_ITERATIONS).strip())
    except:
        iterations = DEFAULT_ITERATIONS
    finally:
        salt = os.urandom(8)

    print "PBKDF2: $%s$%d$%s" % (salt.encode("hex"), iterations, pbkdf2(password, salt).encode("hex"))

if __name__ == '__main__':
    main()
