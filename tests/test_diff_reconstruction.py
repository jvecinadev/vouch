
from vouch.diff import parse_diff

def test_diff_does_not_recover_missing_lines():
    diff = """diff --git a/example.py b/example.py
index 1234567..abcdef0 100644
--- a/example.py
+++ b/example.py
@@ -1,2 +1,2 @@
 def greet():
-    print("old")
+    print("new")
@@ -10,2 +10,2 @@
 def finish():
-    return False
+    return True
"""

    files = parse_diff(diff)
    source = files[0].new_text

    assert "def greet():" in source
    assert "def finish():" in source
    assert "def middle_function():" not in source
    assert "\n\n\n" in source