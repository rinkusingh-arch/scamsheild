"""ScamShield: heuristic detection of job scams and malicious QR codes."""
from .job_scam import analyze_job_text
from .qr_check import analyze_qr_payload, decode_qr_image
from .url_analysis import analyze_url_report

__all__ = ["analyze_job_text", "analyze_qr_payload", "decode_qr_image", "analyze_url_report"]
__version__ = "0.1.0"
