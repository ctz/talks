import pbkdf2
import binascii

iterations = 1 << 22
k = pbkdf2.PBKDF2(b'password', b'saltsalt', iterations).read(20)
print('SHA1,%d,%s' % (iterations, binascii.hexlify(k).decode('utf8')))
