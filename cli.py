from __future__ import annotations

import argparse
import json
import sys

from .job_scam import analyze_job_text
from .qr_check import analyze_qr_payload, decode_qr_image
from .scoring import render_text
from .url_analysis import analyze_url_report


def main(argv=None) -> int:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="machine-readable output")

    ap = argparse.ArgumentParser(prog="scamshield", description="Detect job scams and fake QR codes.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    j = sub.add_parser("job", parents=[common], help="analyze a job offer / recruiter message")
    j.add_argument("--text")
    j.add_argument("--file")

    q = sub.add_parser("qr", parents=[common], help="analyze a QR code image or payload")
    q.add_argument("image", nargs="?")
    q.add_argument("--payload", help="already-decoded QR contents")

    u = sub.add_parser("url", parents=[common], help="analyze a link")
    u.add_argument("url")

    a = ap.parse_args(argv)
    reports = []

    if a.cmd == "job":
        if a.text:
            text = a.text
        elif a.file:
            with open(a.file, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        else:
            text = sys.stdin.read()
        reports.append(analyze_job_text(text))
    elif a.cmd == "url":
        reports.append(analyze_url_report(a.url))
    else:
        if a.payload:
            payloads = [a.payload]
        elif a.image:
            with open(a.image, "rb") as fh:
                payloads = decode_qr_image(fh.read())
            if not payloads:
                print("No QR code found in the image.", file=sys.stderr)
                return 3
        else:
            q.error("give an image path or --payload")
        reports += [analyze_qr_payload(p) for p in payloads]

    if a.json:
        print(json.dumps([r.to_dict() for r in reports], indent=2, ensure_ascii=False))
    else:
        print("\n\n".join(render_text(r) for r in reports))
    return 1 if any(r.score >= 50 for r in reports) else 0  # non-zero exit = likely scam


if __name__ == "__main__":
    raise SystemExit(main())
