"""
detector.py
Checks responses for in-band marker reflection and known parser error text.
"""

import re

ERROR_PATTERNS = [
    r"XMLSyntaxError",
    r"org\.xml\.sax",
    r"ExpatError",
    r"libxml2",
    r"DOCTYPE is not allowed",
    r"startEntity\(\)",
    r"external entity",
    r"EntityRef",
    r"DTDForbidden",
    r"xml\.parsers\.expat",
    r"SAXParseException",
    r"undefined entity",
]

_compiled = [re.compile(p, re.IGNORECASE) for p in ERROR_PATTERNS]


def marker_reflected(response_text: str, marker: str) -> bool:
    """True if the marker value we planted appears in the response body."""
    return bool(marker) and marker in response_text


def find_error_signatures(response_text: str):
    """Return the list of known parser-error patterns found in the text."""
    found = []
    for pattern in _compiled:
        if pattern.search(response_text):
            found.append(pattern.pattern)
    return found
