import localhashlib, binascii

iterations = 1 << 22
k = localhashlib.pbkdf2_hmac('sha1', b'password', b'saltsalt', iterations)
print('SHA1,%d,%s' % (iterations, binascii.hexlify(k).decode('utf8')))
