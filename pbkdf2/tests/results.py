import sys, re
from os import path

export = dict(
        openssl = 'openssl',
        python = 'python-34',
        nodejs = 'nodejs',
        mono = 'mono',
        fastpbkdf = 'fastpbkdf2',
        javaopenjdk = 'java-jdk',
        golang = 'golang',
        php = 'php5',
        phppatch = 'php5-new'
)

if __name__ == '__main__':
    tests = sys.argv[1:]
    timings = {}

    for dir in tests:
        name = dir.replace('/', '')
        tf = open(path.join(dir, 'timing')).read()
        time = re.search(r'([0-9\.]+)user', tf).group(1)
        timings[name] = time

    print timings

    with open('../measurements.tex', 'w') as f:
        for name, test in export.items():
            print >>f, '\def \%stime {%s}' % (name, timings[test])

