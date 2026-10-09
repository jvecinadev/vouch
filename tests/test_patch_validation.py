import pytest

from vouch.patch import PatchGenerationError, _validate_fixed_code


def test_rejects_empty_code():
    with pytest.raises(PatchGenerationError, match="empty code"):
        _validate_fixed_code({"fixed_code": "\n  \n"}, "print(1)\n")


def test_rejects_missing_or_wrong_field():
    with pytest.raises(PatchGenerationError, match="string named"):
        _validate_fixed_code({"fixed_code": None}, "print(1)\n")


def test_rejects_suspiciously_short_rewrite():
    original = "\n".join([f"line_{i} = {i}" for i in range(12)])
    with pytest.raises(PatchGenerationError, match="removes most"):
        _validate_fixed_code({"fixed_code": "pass"}, original)


def test_accepts_small_security_fix():
    original = "query = f\"SELECT * FROM users WHERE email = '{email}'\"\ncursor.execute(query)"
    fixed = "query = \"SELECT * FROM users WHERE email = ?\"\ncursor.execute(query, (email,))"
    assert _validate_fixed_code({"fixed_code": fixed}, original) == fixed