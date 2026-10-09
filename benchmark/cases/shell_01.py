# expect: CWE-78
# INTENTIONALLY INSECURE. Benchmark case, never use in production.
import subprocess


def ping(host):
    subprocess.run("ping -c 1 " + host, shell=True)
