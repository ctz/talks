#.  Copyright (C) 2005-2010   Gregory P. Smith (greg@krypto.org)
#  Licensed to PSF under a Contributor Agreement.
#

import hashlib
new = hashlib.new

_trans_5C = bytes((x ^ 0x5C) for x in range(256))
_trans_36 = bytes((x ^ 0x36) for x in range(256))

def pbkdf2_hmac(hash_name, password, salt, iterations, dklen=None):
    """Password based key derivation function 2 (PKCS #5 v2.0)

    This Python implementations based on the hmac module about as fast
    as OpenSSL's PKCS5_PBKDF2_HMAC for short passwords and much faster
    for long passwords.
    """
    if not isinstance(hash_name, str):
        raise TypeError(hash_name)

    if not isinstance(password, (bytes, bytearray)):
        password = bytes(memoryview(password))
    if not isinstance(salt, (bytes, bytearray)):
        salt = bytes(memoryview(salt))

    # Fast inline HMAC implementation
    inner = new(hash_name)
    outer = new(hash_name)
    blocksize = getattr(inner, 'block_size', 64)
    if len(password) > blocksize:
        password = new(hash_name, password).digest()
    password = password + b'\x00' * (blocksize - len(password))
    inner.update(password.translate(_trans_36))
    outer.update(password.translate(_trans_5C))

    def prf(msg, inner=inner, outer=outer):
        # PBKDF2_HMAC uses the password as key. We can re-use the same
        # digest objects and just update copies to skip initialization.
        icpy = inner.copy()
        ocpy = outer.copy()
        icpy.update(msg)
        ocpy.update(icpy.digest())
        return ocpy.digest()

    if iterations < 1:
        raise ValueError(iterations)
    if dklen is None:
        dklen = outer.digest_size
    if dklen < 1:
        raise ValueError(dklen)

    dkey = b''
    loop = 1
    from_bytes = int.from_bytes
    while len(dkey) < dklen:
        prev = prf(salt + loop.to_bytes(4, 'big'))
        # endianess doesn't matter here as long to / from use the same
        rkey = int.from_bytes(prev, 'big')
        for i in range(iterations - 1):
            prev = prf(prev)
            # rkey = rkey ^ prev
            rkey ^= from_bytes(prev, 'big')
        loop += 1
        dkey += rkey.to_bytes(inner.digest_size, 'big')

    return dkey[:dklen]

