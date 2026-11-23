"""Database error signatures, used only to recognize that a response shows a DB error —
never to decide anything else. Matching one of these is direct, observable evidence."""
from __future__ import annotations

import re

_PATTERNS = (
    ("MySQL/MariaDB", re.compile(r"you have an error in your sql syntax|warning:\s*mysqli?_|"
                                 r"check the manual that corresponds to your (mysql|mariadb)", re.I)),
    ("PostgreSQL", re.compile(r"pg_query\(\)|pg_exec\(\)|unterminated quoted string|syntax error at or near", re.I)),
    ("Microsoft SQL Server", re.compile(r"unclosed quotation mark after the character string|"
                                        r"microsoft ole db provider for sql server|incorrect syntax near", re.I)),
    ("Oracle", re.compile(r"ora-\d{5}|quoted string not properly terminated", re.I)),
    ("SQLite", re.compile(r"sqlite3\.(operationalerror|programmingerror)|sqlite_error|near \".*\": syntax error", re.I)),
    ("Generic SQL", re.compile(r"sql syntax.*error|unclosed quotation mark", re.I)),
)


def find_db_error(text: str) -> tuple[str | None, str | None]:
    for engine, pattern in _PATTERNS:
        match = pattern.search(text)
        if match:
            return engine, match.group(0)[:200]
    return None, None
