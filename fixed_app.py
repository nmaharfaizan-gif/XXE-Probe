"""
fixed_app.py
The SAME endpoint as vulnerable_app.py, but with the defensive fix applied:
no custom EntityResolver, and external general-entity processing turned
OFF. Run XXEProbe against this one too - it should come back NOT VULNERABLE.
"""

from io import StringIO

import xml.sax
from xml.sax.handler import ContentHandler
from flask import Flask, request

app = Flask(__name__)


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
    # FIXED: no EntityResolver set, and external entities explicitly OFF.
    parser.setFeature(xml.sax.handler.feature_external_ges, False)
    parser.setFeature(xml.sax.handler.feature_external_pes, False)
    try:
        parser.parse(StringIO(xml_bytes.decode("utf-8", errors="replace")))
        text = "".join(handler.text)
        return f"Parsed OK. Content: {text}", 200
    except Exception:
        # Same generic error path, but nothing sensitive is ever fetched.
        return "Could not parse XML document.", 400


if __name__ == "__main__":
    print("Starting FIXED lab app on http://127.0.0.1:5001 (lab use only)")
    app.run(host="127.0.0.1", port=5001)
