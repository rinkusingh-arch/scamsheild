from scamshield import analyze_job_text, analyze_qr_payload, analyze_url_report

SCAM_JOB = """Dear Candidate, you are selected! Earn $300 per day, no experience needed.
Pay a refundable registration fee of 2000 to secure your slot. Contact HR on Telegram.
hr.recruiter@gmail.com"""
REAL_JOB = """Hi Priya, thanks for interviewing with us on Tuesday. We'd like to offer you the
Software Engineer role. The offer letter is attached; please reply by Friday. - Sam, Acme Corp"""


def test_scam_job_is_critical():
    r = analyze_job_text(SCAM_JOB)
    assert r.score >= 75 and r.level == "CRITICAL"


def test_normal_job_is_low():
    assert analyze_job_text(REAL_JOB).level == "LOW"


def test_url_typosquat_and_ip():
    assert analyze_url_report("http://paypa1.com/login").score >= 50
    assert analyze_url_report("http://192.168.4.9/verify").score >= 50


def test_url_legit():
    assert analyze_url_report("https://www.linkedin.com/jobs/").score < 20


def test_brand_in_subdomain_trick():
    assert analyze_url_report("https://linkedin.careers-verify.xyz/apply").score >= 50


def test_qr_upi_collect_flagged():
    r = analyze_qr_payload("upi://collect?pa=x@upi&am=5000")
    assert any("collect" in f.reason for f in r.findings)


def test_qr_shortener():
    assert analyze_qr_payload("https://bit.ly/3abcde").score >= 20


def test_qr_plain_text_is_safe():
    assert analyze_qr_payload("hello world").score == 0
