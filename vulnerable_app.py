"""
vulnerable_app.py
A deliberately VULNERABLE lab target for XXEProbe to test against.

This simulates the realistic cause of most real-world XXE bugs: a developer
adds a custom EntityResolver (often to support external includes/schemas)
that blindly fetches whatever SYSTEM identifier is given - file:// or
http(s)://. Modern XML libraries (e.g. recent libxml2) have hardened
default behaviour and block network entity fetches, which is why this lab
uses Python's xml.sax with an explicit (vulnerable) resolver: it reliably
reproduces BOTH the local-file-read and the out-of-band (SSRF-style) XXE
behaviour for teaching/demo purposes.

Run this ONLY on your own machine, for your own lab testing.
"""

import urllib.request
from io import StringIO

import xml.sax
from xml.sax.handler import ContentHandler
from flask import Flask, request

app = Flask(__name__)


class VulnerableResolver(xml.sax.handler.EntityResolver):
    """VULNERABLE: fetches ANY systemId it is given, no allow-list at all."""

    def resolveEntity(self, publicId, systemId):
        try:
            if systemId.startswith("file://"):
                return open(systemId[len("file://"):], "r")
            return urllib.request.urlopen(systemId, timeout=3)
        except Exception:
            return None


class TextHandler(ContentHandler):
    def __init__(self):
        self.text = []

    def characters(self, content):
        self.text.append(content)


@app.route("/upload", methods=["POST"])
def upload():
    xml_bytes = request.get_data()
    handler = TextHandler()
    parser = xml.sax.make_parser()
    parser.setContentHandler(handler)
    parser.setEntityResolver(VulnerableResolver())
    # VULNERABLE: explicitly turns external general-entity processing ON.
    parser.setFeature(xml.sax.handler.feature_external_ges, True)
    try:
        parser.parse(StringIO(xml_bytes.decode("utf-8", errors="replace")))
        text = "".join(handler.text)
        return f"Parsed OK. Content: {text}", 200
    except Exception as e:
        # Deliberately leaks parser error detail (used by error-based step).
        return f"SAXParseException: {type(e).__name__}: {e}", 500


if __name__ == "__main__":
    print("Starting VULNERABLE lab app on http://127.0.0.1:5000 (lab use only)")
    app.run(host="127.0.0.1", port=5000)
