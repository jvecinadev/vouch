from vouch.models import Finding
from vouch.trace import trace_finding

CODE = '''import sqlite3
DB_PASSWORD = "x"

def login(email):
    q = f"SELECT * FROM users WHERE email = '{email}'"
    return q

def count():
    table = "users"
    q = f"SELECT COUNT(*) FROM {table}"
    return q
'''


def F(rule, line):
    return Finding(id="1", tool="bandit", rule_id=rule, title="t", cwe=None,
                   severity="medium", file="a.py", line=line, message="m")


def test_parameter_is_real():
    assert trace_finding(F("B608", 5), CODE)["lean"] == "real"


def test_fixed_word_is_false_alarm():
    assert trace_finding(F("B608", 10), CODE)["lean"] == "false_alarm"


def test_fixed_password_is_real():
    r = trace_finding(F("B105", 2), CODE)
    assert r["lean"] == "real" and "environment variable" in r["note"]