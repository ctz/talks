import pbkdf2

iterations = 1 << 22
k = pbkdf2.pbkdf2('password', 'saltsalt', iterations, 20, pbkdf2.sha)
print 'SHA1,%d,%s' % (iterations, k.encode('hex'))
