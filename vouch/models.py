"""THE CONTRACT. Every module passes these objects around. Change with team agreement only."""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Badge(str, Enum):
    VERIFIED = "verified"        # patch applies, code parses, finding gone
    UNVERIFIED = "unverified"    # patch applies but a later check failed
    NEEDS_HUMAN = "needs_human"  # no valid patch after retries
    SKIPPED = "skipped"          # no fix attempted (false positive, or model unavailable)
    AI_CHECKED = "ai_checked"    # AI-found issue: patch applies and parses, but no scanner rule can re-check it



@dataclass
class ChangedFile:
    path: str
<<<<<<< HEAD
    new_text: str
    added_lines: set = field(default_factory=set)
    complete: bool = True
=======
    new_text: str                                  # reconstructed new version of the file
    added_lines: set = field(default_factory=set)  # line numbers added by the diff
    hunks: list = field(default_factory=list)      # per hunk: [(tag "+"/"-"/" ", new line no, text)]
>>>>>>> a98c7ea925a8e1ad69e4fd586e02361270606e9f


@dataclass
class Finding:
    id: str
    tool: str                
    rule_id: str
    title: str
    cwe: Optional[str]        # e.g. "CWE-89"
    severity: str             
    file: str
    line: int
    message: str
    code: str = ""
    # filled by triage.py
    verdict: str = ""         # "true_positive" | "likely_false_positive"
    explanation: str = ""
    trace: str = ""          # short note on where the flagged value came from
    # filled by patch.py / verify.py
    patch: str = ""
    badge: Badge = Badge.SKIPPED
    attempts: int = 0
    first_try_applies: bool = False
    verify_log: list = field(default_factory=list)