# XXEProbe

A lab-only command-line tool that tests whether an XML-parsing endpoint is
vulnerable to **XXE (XML External Entity)** injection, and proves it safely
using your own listener and your own marker files — never real system data.

**Student:** Faizan — Web Security track, PNY Trainings Cyber Security Department
**Instructor:** Abdul Mannan

---

## ⚠️ Lab-only / Legal Notice

- Only run this against **your own machine or an isolated lab you own**.
- Never test a system you do not have written permission to test.
- Unauthorized access to computer systems is a criminal offence under the
  **Prevention of Electronic Crimes Act, 2016 (Pakistan)**.
- The tool includes a built-in safety guard: by default it **refuses any
  target that is not local/private**. Bypassing it requires an explicit
  `--allow-remote --confirm "I OWN THIS TARGET OR HAVE WRITTEN PERMISSION"`
  flag combination — use it only on a lab target you actually own.

---

## What is XXE, in simple words?

Some applications accept XML and let their parser process a `DOCTYPE`
with **entities** — basically variables that can be defined to point at an
external file or URL. If external entity resolution is switched on, the
parser will go fetch whatever the entity points to and may include it in
its response. An attacker can abuse this to read files or make the server
contact internal addresses. XXEProbe finds and *proves* this behaviour —
it never touches real files; it only uses markers and listeners you create
yourself in a lab.

## How XXEProbe works

1. **Baseline** — sends a normal XML document, records the normal response.
2. **Out-of-band (OOB) proof** — sends a payload whose entity points at a
   local listener you run; if the parser is vulnerable, the listener
   receives a request.
3. **In-band proof** — sends a payload whose entity points at a marker
   file you created yourself; if vulnerable, the marker text comes back
   in the HTTP response.
4. **Parameter-entity variant** — for parsers that block plain external
   entities but still process parameter entities.
5. **Error-based detection** — sends an intentionally broken entity
   reference and checks the response for known parser-error signatures.
6. **Report** — all evidence (hits, reflected markers, error signatures)
   is printed and saved to a text file, with a remediation note.

## Project layout

```
XXEProbe/
├── xxeprobe/
│   ├── probe.py       # main CLI (argparse)
│   ├── payloads.py    # XML payload builder
│   ├── listener.py    # local OOB listener
│   ├── detector.py    # marker / error-signature detection
│   └── safety.py       # lab-only safety guard
├── lab/
│   ├── vulnerable_app.py   # deliberately vulnerable Flask+lxml target
│   └── fixed_app.py        # same endpoint, entities disabled
├── lab_marker/marker.txt   # marker file for in-band proof (lab-only)
├── reports/                # saved sample reports
└── README.md
```

## Requirements

- Python 3.9+ (standard library only for the tool itself)
- For the lab target apps only: `pip install --break-system-packages flask lxml`
- Tested on Kali Linux

## How to run

**1. Start the vulnerable lab app** (terminal 1):
```bash
python3 lab/vulnerable_app.py
# Serving on http://127.0.0.1:5000
```

**2. Create your own marker file** (never a real system file):
```bash
mkdir -p lab_marker
echo -n "XXEPROBE_LAB_MARKER_42" > lab_marker/marker.txt
```

**3. Run XXEProbe** (terminal 2):
```bash
python3 -m xxeprobe.probe \
  --url http://127.0.0.1:5000/upload \
  --marker XXEPROBE_LAB_MARKER_42 \
  --marker-file "$(pwd)/lab_marker/marker.txt" \
  --output reports/vulnerable_app_report.txt
```

**4. Compare against the fixed app:**
```bash
python3 lab/fixed_app.py          # terminal 1, port 5001
python3 -m xxeprobe.probe --url http://127.0.0.1:5001/upload \
  --marker XXEPROBE_LAB_MARKER_42 \
  --marker-file "$(pwd)/lab_marker/marker.txt" \
  --output reports/fixed_app_report.txt
```

Expected result: vulnerable app → `VERDICT: VULNERABLE`; fixed app →
`VERDICT: NOT VULNERABLE (as tested)`.

## Defensive lesson: disabling external entities

The lab's vulnerable app uses Python's `xml.sax` with a custom
`EntityResolver` that blindly fetches any `SYSTEM` identifier — this
mirrors a very common real cause of XXE: a developer adds custom entity
resolution (often to support external includes/schemas) without
restricting what it is allowed to fetch.

```python
# Vulnerable (lab/vulnerable_app.py):
parser.setEntityResolver(VulnerableResolver())   # fetches ANY systemId
parser.setFeature(xml.sax.handler.feature_external_ges, True)

# Fixed (lab/fixed_app.py):
# no EntityResolver registered at all
parser.setFeature(xml.sax.handler.feature_external_ges, False)
parser.setFeature(xml.sax.handler.feature_external_pes, False)
```

The fix: never register an entity resolver that fetches arbitrary
`SYSTEM` URIs, and explicitly turn external general/parameter entity
processing OFF. The same idea applies in any XML library — with `lxml`
it is `resolve_entities=False, load_dtd=False` (or use the `defusedxml`
package); in Java it is
`setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)`. The safest
general rule is: reject any XML document that contains a `DOCTYPE`
declaration at all, since legitimate API payloads almost never need one.

**Note on modern libraries:** recent `libxml2`/`lxml` versions already
block network-based (`http://`) external entity fetches by default as a
security hardening measure, even when `resolve_entities=True` — this is
why the lab app uses `xml.sax` with an explicit resolver instead, so the
out-of-band (SSRF-style) behaviour can be reliably demonstrated for
learning purposes. This hardening is itself worth knowing: it shows that
library defaults matter, but a careless custom resolver can still
reintroduce the exact same vulnerability.

## Credits / AI assistance disclosure

This project was built with research and AI assistance (Claude) for code
structure and explanations. All code was tested by me against my own lab
apps, and I understand how each part works (see the viva-prep notes in
`docs/viva_questions.md`). I confirmed with my instructor that AI
assistance is permitted for this assignment.
