import hashlib, binascii

iterations = 1 << 22
k = hashlib.pbkdf2_hmac('sha1', b'password', b'saltsalt', iterations)
print('SHA1,%d,%s' % (iterations, binascii.hexlify(k).decode('utf8')))
