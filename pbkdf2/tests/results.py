import sys, re
from os import path

export = dict(
        openssl = 'openssl',
        python = 'python-34',
        nodejs = 'nodejs',
        fastpbkdf = 'fastpbkdf2',
        javaopenjdk = 'java-jdk',
        golang = 'golang',
        php = 'php5',
        phppatch = 'php5-new'
)

def read_res(fn):
    tf = open(fn).read()
    time = re.search(r'([0-9\.]+)user', tf).group(1)
    return float(time)

if __name__ == '__main__':
    tests = sys.argv[1:]
    timings = {}

    for dir in tests:
        name = dir.replace('/', '')

        if path.exists(path.join(dir, 'timing')):
            best_time = read_res(path.join(dir, 'timing'))
        else:
            best_time = min([read_res(path.join(dir, 'timing.%s' % x)) for x in '12345'])

        timings[name] = best_time

    print timings

    if 'openssl' in timings:
        with open('../measurements.tex', 'w') as f:
            for name, test in export.items():
                print >>f, '\def \%stime {%s}' % (name, timings[test])

