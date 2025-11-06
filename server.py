# server.py
from flask import Flask, request, jsonify, render_template_string, g, make_response
from datetime import datetime
import sqlite3, os

DB = os.getenv("REMOTE_DB_PATH", "remote_tokens.db")
APP_NAME = os.getenv("APP_NAME", "DayPlan Verification")

# ---------- SQLite helpers ----------
def _connect_db():
    conn = sqlite3.connect(DB, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Settings para concurrencia/consistencia
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    # Tabla (create-if-not-exists)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS tokens(
               token TEXT PRIMARY KEY,
               email TEXT,
               expires_at TEXT,
               used INTEGER DEFAULT 0
           )"""
    )
    return conn

def get_conn():
    if "db" not in g:
        g.db = _connect_db()
    return g.db

def close_conn(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

# ---------- Flask app ----------
app = Flask(__name__)
app.teardown_appcontext(close_conn)

# ---------- Helpers ----------
def _no_store(resp):
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    return resp

def _parse_token(raw):
    token = (raw or "").strip()
    # mínima validación (evita basura obvia)
    if not token or len(token) > 256:
        return ""
    return token

def _parse_email(raw):
    return (raw or "").strip().lower()

def _html_page(title, message, ok=True):
    # Página simple y centrada; adapta colores según tema del navegador
    template = f"""
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>{APP_NAME} – {title}</title>
<meta name="robots" content="noindex,nofollow" />
<style>
  :root {{
    color-scheme: light dark;
  }}
  body {{
    margin: 0; padding: 0;
    font-family: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial;
    display: grid; place-items: center; min-height: 100dvh;
    background: Canvas; color: CanvasText;
  }}
  .card {{
    border-radius: 16px; padding: 28px; max-width: 640px; width: calc(100% - 32px);
    border: 2px solid {('#2e7d32' if ok else '#c62828')};
    box-shadow: 0 12px 28px rgba(0,0,0,.08);
  }}
  h1 {{ margin: 0 0 8px 0; font-size: 1.4rem; }}
  p  {{ margin: 4px 0 0 0; line-height: 1.5; }}
  .ok  {{ color: #2e7d32; font-weight: 700; }}
  .bad {{ color: #c62828; font-weight: 700; }}
  .muted {{ opacity: .8; font-size: .95rem; margin-top: 12px; }}
</style>
</head>
<body>
  <main class="card">
    <h1>{APP_NAME}</h1>
    <p class="{('ok' if ok else 'bad')}">{message}</p>
    <p class="muted">Ya puedes volver a la aplicación de escritorio.</p>
  </main>
</body>
</html>
"""
    return template

# ---------- Rutas ----------
@app.get("/")
def root():
    resp = make_response(
        _html_page("Backend activo", "Backend de verificación activo ✅", ok=True)
    )
    return _no_store(resp)

@app.get("/healthz")
def healthz():
    # simple healthcheck (Render puede usarlo)
    try:
        conn = get_conn()
        conn.execute("SELECT 1;")
        return _no_store(jsonify(status="ok", time=datetime.utcnow().isoformat()))
    except Exception as e:
        return _no_store(jsonify(status="error", detail=str(e))), 500

@app.get("/robots.txt")
def robots():
    resp = make_response("User-agent: *\nDisallow: /", 200)
    resp.headers["Content-Type"] = "text/plain; charset=utf-8"
    return _no_store(resp)

@app.post("/register")
def register():
    try:
        data = request.get_json(force=True, silent=False)
    except Exception:
        return _no_store(jsonify(ok=False, error="JSON inválido")), 400

    token = _parse_token(data.get("token"))
    email = _parse_email(data.get("email"))
    expires_at = (data.get("expires_at") or "").strip()  # "YYYY-MM-DD HH:MM:SS"

    if not token or not expires_at:
        return _no_store(jsonify(ok=False, error="Faltan campos (token, expires_at).")), 400

    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO tokens(token, email, expires_at, used)
              VALUES(?,?,?,0)
           ON CONFLICT(token) DO UPDATE
              SET email=excluded.email,
                  expires_at=excluded.expires_at,
                  used=0""",
        (token, email, expires_at),
    )
    conn.commit()
    return _no_store(jsonify(ok=True))

@app.get("/verify")
def verify():
    token = _parse_token(request.args.get("token"))
    if not token:
        html = _html_page("Token inválido", "Token inválido o ausente.", ok=False)
        return _no_store(render_template_string(html)), 400

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT expires_at, used FROM tokens WHERE token=?", (token,))
    row = cur.fetchone()

    if not row:
        html = _html_page("Token inválido", "Token inválido.", ok=False)
        return _no_store(render_template_string(html)), 404

    # Validar expiración
    try:
        exp = datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S")
    except Exception:
        exp = None

    if int(row["used"] or 0) == 1:
        html = _html_page("Ya utilizado", "Este enlace ya fue utilizado.", ok=True)
        return _no_store(render_template_string(html))

    if exp and datetime.utcnow() > exp:
        html = _html_page("Expirado", "El enlace expiró.", ok=False)
        return _no_store(render_template_string(html)), 410

    # Marcar como usado
    cur.execute("UPDATE tokens SET used=1 WHERE token=?", (token,))
    conn.commit()

    html = _html_page("Verificado", "¡Correo verificado! ✔", ok=True)
    return _no_store(render_template_string(html))

@app.get("/status")
def status():
    token = _parse_token(request.args.get("token"))
    if not token:
        return _no_store(jsonify(used=False, error="Token inválido")), 400
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT used FROM tokens WHERE token=?", (token,))
    row = cur.fetchone()
    return _no_store(jsonify(used=bool(row and int(row["used"] or 0) == 1)))

# ---------- Main ----------
if __name__ == "__main__":
    # En local: python server.py
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")), debug=bool(os.getenv("DEBUG")))