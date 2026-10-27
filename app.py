"""Tiny web UI.  Run:  pip install -e ".[qr,web]" && python app.py"""
from flask import Flask, render_template_string, request

from scamshield import analyze_job_text, analyze_qr_payload, decode_qr_image

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB uploads; nothing is stored on disk

PAGE = """<!doctype html><meta name=viewport content="width=device-width,initial-scale=1">
<title>ScamShield</title>
<style>
body{font-family:system-ui,sans-serif;max-width:720px;margin:2rem auto;padding:0 1rem;line-height:1.5}
textarea{width:100%;height:9rem}.card{border:1px solid #8884;border-radius:10px;padding:1rem;margin:1rem 0}
.LOW{border-color:#2a9d4a}.MEDIUM{border-color:#e0a800}.HIGH,.CRITICAL{border-color:#d33}
button{padding:.5rem 1rem}
</style>
<h1>ScamShield</h1>
<div class=card><h3>Job offer check</h3>
<form method=post action="/job"><textarea name=text placeholder="Paste the job message or email here" required></textarea>
<button>Analyze</button></form></div>
<div class=card><h3>QR code check</h3>
<form method=post action="/qr" enctype="multipart/form-data">
<input type=file name=image accept="image/*" required> <button>Scan &amp; analyze</button></form></div>
{% for r in reports %}
<div class="card {{r.level}}"><b>{{r.kind}}</b>: {{r.subject}}<br>
<b>Risk: {{r.level}} ({{r.score}}/100)</b><br>{{r.advice}}
<ul>{% for f in r.findings %}<li>{{f.reason}}</li>{% endfor %}</ul></div>
{% endfor %}
{% if error %}<p style="color:#d33">{{error}}</p>{% endif %}
<p><small>Heuristic tool: it can miss scams and can flag safe items. Always verify independently.</small></p>
"""


@app.get("/")
def index():
    return render_template_string(PAGE, reports=[], error=None)


@app.post("/job")
def job():
    return render_template_string(PAGE, reports=[analyze_job_text(request.form["text"])], error=None)


@app.post("/qr")
def qr():
    try:
        payloads = decode_qr_image(request.files["image"].read())
    except (ValueError, RuntimeError) as e:
        return render_template_string(PAGE, reports=[], error=str(e))
    if not payloads:
        return render_template_string(PAGE, reports=[], error="No QR code found in that image.")
    return render_template_string(PAGE, reports=[analyze_qr_payload(p) for p in payloads], error=None)


if __name__ == "__main__":
    app.run(debug=False)
