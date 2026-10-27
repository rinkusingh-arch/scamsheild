from __future__ import annotations

import re
from typing import List
from urllib.parse import urlparse, parse_qs

from .scoring import Finding, Report, build_report
from .url_analysis import analyze_url


def classify(payload: str) -> str:
    low = payload.strip().lower()
    if low.startswith(("http://", "https://", "www.")):
        return "url"
    for prefix, kind in (("upi://", "upi"), ("wifi:", "wifi"), ("smsto:", "sms"), ("sms:", "sms"),
                         ("tel:", "tel"), ("mailto:", "email"), ("bitcoin:", "crypto"),
                         ("ethereum:", "crypto"), ("begin:vcard", "vcard")):
        if low.startswith(prefix):
            return kind
    return "text"


def analyze_qr_payload(payload: str) -> Report:
    kind = classify(payload)
    f: List[Finding] = []
    if kind == "url":
        f += analyze_url(payload)
    elif kind == "upi":
        q = {k.lower(): v[0] for k, v in parse_qs(urlparse(payload).query).items()}
        if "collect" in payload.lower().split("?")[0]:
            f.append(Finding(0.5, "UPI *collect* request: approving it sends money OUT"))
        else:
            f.append(Finding(0.15, "Payment QR: confirm the payee name before paying. You never need a PIN to receive money"))
        if "am" in q:
            f.append(Finding(0.1, "Amount is pre-filled by the QR creator"))
        if "pn" not in q:
            f.append(Finding(0.1, "No payee name embedded"))
    elif kind == "wifi":
        if re.search(r"T:(nopass|);", payload, re.I) or "T:" not in payload.upper():
            f.append(Finding(0.2, "Open Wi-Fi network with no password"))
    elif kind == "sms":
        f.append(Finding(0.3, "Pre-filled SMS: may subscribe you to premium services or send a scam message"))
    elif kind == "tel":
        f.append(Finding(0.2, "Dials a number automatically (check for premium-rate numbers)"))
    elif kind == "crypto":
        f.append(Finding(0.3, "Crypto payment request: irreversible, common scam payment method"))
    elif kind == "email":
        f.append(Finding(0.1, "Pre-filled email"))
    else:
        for m in re.finditer(r"(?:https?://|www\.)\S+", payload):
            f += analyze_url(m.group(0))
    return build_report(f"qr:{kind}", payload, f)


def decode_qr_image(data: bytes) -> List[str]:
    """Decode every QR code in an image. Needs: pip install 'scamshield[qr]'."""
    try:
        import cv2
        import numpy as np
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("QR image decoding needs: pip install 'scamshield[qr]'") from e
    img = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("Could not read the file as an image")
    det = cv2.QRCodeDetector()
    results: List[str] = []
    try:
        ok, decoded, _, _ = det.detectAndDecodeMulti(img)
        if ok:
            results = [d for d in decoded if d]
    except cv2.error:
        pass
    if not results:
        text, _, _ = det.detectAndDecode(img)
        if text:
            results = [text]
    return results
