#!/usr/bin/env python3
"""
XXEProbe - a lab-only XML External Entity (XXE) tester.

Built by Faizan (PNY Trainings, Web Security track) with research and AI
assistance; tested and understood by me. See README.md for full details.

USAGE (examples):
    python3 probe.py --url http://127.0.0.1:5000/upload \
                      --marker-file /home/kali/lab/marker.txt \
                      --output reports/sample_report.txt

Safety: this tool refuses non-local targets by default. See xxeprobe/safety.py.
"""

import argparse
import sys
import time
import urllib.request
import urllib.error
import uuid
from pathlib import Path

from xxeprobe import payloads, detector
from xxeprobe.listener import XXEListener
from xxeprobe.safety import enforce_lab_only, UnsafeTargetError


def send_xml(url: str, xml_body: str, timeout: int = 5):
    """POST an XML body to the target and return (status, text, error)."""
    data = xml_body.encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST", headers={"Content-Type": "application/xml"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace"), None
    except urllib.error.HTTPError as e:
        # Error responses still carry a body we want to inspect
        body = e.read().decode("utf-8", errors="replace")
        return e.code, body, None
    except urllib.error.URLError as e:
        return None, "", str(e.reason)


def build_marker_file_uri(path_str: str) -> str:
    p = Path(path_str).resolve()
    return p.as_uri()


def run(args):
    report = {"target": args.url, "started": time.strftime("%Y-%m-%d %H:%M:%S"), "steps": []}

    # --- Safety guard ---------------------------------------------------
    try:
        enforce_lab_only(args.url, args.allow_remote, args.confirm or "")
    except UnsafeTargetError as e:
        print(f"[REFUSED] {e}")
        sys.exit(2)

    marker = args.marker or f"XXEPROBE_{uuid.uuid4().hex[:12]}"

    # --- Step: baseline ---------------------------------------------------
    print("[*] Step 1/5: sending baseline request...")
    status, body, err = send_xml(args.url, payloads.baseline_payload())
    report["steps"].append({"step": "baseline", "status": status, "error": err})
    print(f"    status={status} error={err}")

    # --- Step: start listener + OOB payload -------------------------------
    print("[*] Step 2/5: starting local listener and sending OOB payload...")
    listener = XXEListener(host=args.listener_host, port=args.listener_port)
    listener.start()
    time.sleep(0.3)
    oob_xml = payloads.oob_payload(listener.url)
    status, body, err = send_xml(args.url, oob_xml)
    time.sleep(0.5)  # give the server a moment to actually fetch the entity
    oob_hit = listener.had_hit()
    report["steps"].append(
        {
            "step": "out_of_band",
            "status": status,
            "error": err,
            "listener_hit": oob_hit,
            "hits": [h.as_dict() for h in listener.hits],
        }
    )
    print(f"    status={status} listener_hit={oob_hit}")
    listener.stop()

    # --- Step: in-band payload ---------------------------------------------
    inband_hit = False
    if args.marker_file:
        print("[*] Step 3/5: sending in-band payload (marker file)...")
        marker_uri = build_marker_file_uri(args.marker_file)
        inband_xml = payloads.inband_payload(marker_uri)
        status, body, err = send_xml(args.url, inband_xml)
        inband_hit = detector.marker_reflected(body, marker)
        # Also accept: marker file content reflected even if literal marker
        # string differs - caller should put `marker` text inside that file.
        report["steps"].append(
            {
                "step": "in_band",
                "status": status,
                "error": err,
                "marker_reflected": inband_hit,
                "response_snippet": body[:300],
            }
        )
        print(f"    status={status} marker_reflected={inband_hit}")
    else:
        print("[*] Step 3/5: skipped (no --marker-file given)")
        report["steps"].append({"step": "in_band", "skipped": True})

    # --- Step: parameter-entity variant --------------------------------
    print("[*] Step 4/5: trying parameter-entity variant...")
    listener2 = XXEListener(host=args.listener_host, port=args.listener_port)
    listener2.start()
    time.sleep(0.3)
    param_xml = payloads.param_entity_payload(listener2.url)
    status, body, err = send_xml(args.url, param_xml)
    time.sleep(0.5)
    param_hit = listener2.had_hit()
    report["steps"].append(
        {"step": "param_entity", "status": status, "error": err, "listener_hit": param_hit}
    )
    print(f"    status={status} listener_hit={param_hit}")
    listener2.stop()

    # --- Step: error-based detection ------------------------------------
    print("[*] Step 5/5: trying error-based payload...")
    err_xml = payloads.error_based_payload()
    status, body, err = send_xml(args.url, err_xml)
    signatures = detector.find_error_signatures(body)
    report["steps"].append(
        {
            "step": "error_based",
            "status": status,
            "error": err,
            "signatures_found": signatures,
            "response_snippet": body[:300],
        }
    )
    print(f"    status={status} signatures_found={signatures}")

    # --- Verdict -----------------------------------------------------------
    vulnerable = oob_hit or inband_hit or param_hit or bool(signatures)
    report["vulnerable"] = vulnerable
    report["evidence_summary"] = {
        "out_of_band_hit": oob_hit,
        "in_band_marker_reflected": inband_hit,
        "param_entity_hit": param_hit,
        "error_signatures": signatures,
    }
    report["remediation"] = (
        "Disable DTD / external-entity processing in the XML parser. "
        "In Python xml.sax: parser.setFeature(feature_external_ges, False) and "
        "feature_external_pes, False), and do not register a custom EntityResolver "
        "that fetches arbitrary SYSTEM identifiers. In lxml: resolve_entities=False "
        "and load_dtd=False (or use the defusedxml library). In Java: setFeature "
        "XMLConstants.FEATURE_SECURE_PROCESSING. General rule: reject any XML "
        "document that contains a DOCTYPE declaration."
    )
    report["finished"] = time.strftime("%Y-%m-%d %H:%M:%S")

    print()
    print("=" * 60)
    print(f"VERDICT: {'VULNERABLE' if vulnerable else 'NOT VULNERABLE (as tested)'}")
    print("=" * 60)

    if args.output:
        save_report(report, args.output)
        print(f"[*] Full report saved to {args.output}")

    return report


def save_report(report: dict, path: str):
    lines = []
    lines.append("XXEProbe Report")
    lines.append("=" * 60)
    lines.append(f"Target:   {report['target']}")
    lines.append(f"Started:  {report['started']}")
    lines.append(f"Finished: {report['finished']}")
    lines.append(f"Verdict:  {'VULNERABLE' if report['vulnerable'] else 'NOT VULNERABLE'}")
    lines.append("")
    lines.append("Evidence:")
    for k, v in report["evidence_summary"].items():
        lines.append(f"  - {k}: {v}")
    lines.append("")
    lines.append("Remediation:")
    lines.append(f"  {report['remediation']}")
    lines.append("")
    lines.append("Step details:")
    for step in report["steps"]:
        lines.append(f"  - {step}")
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text("\n".join(lines), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="XXEProbe - lab-only XXE tester")
    parser.add_argument("--url", required=True, help="Target lab endpoint that accepts XML")
    parser.add_argument("--listener-host", default="127.0.0.1")
    parser.add_argument("--listener-port", type=int, default=8000)
    parser.add_argument("--marker", default=None, help="Marker string to look for in-band")
    parser.add_argument(
        "--marker-file",
        default=None,
        help="Path to a marker file YOU created in the lab (never a real system file)",
    )
    parser.add_argument("--output", default=None, help="Path to save the text report")
    parser.add_argument(
        "--allow-remote",
        action="store_true",
        help="Required (with --confirm) to test a non-local target",
    )
    parser.add_argument(
        "--confirm",
        default=None,
        help='Exact phrase: "I OWN THIS TARGET OR HAVE WRITTEN PERMISSION"',
    )
    args = parser.parse_args()
    run(args)


if __name__ == "__main__":
    main()
