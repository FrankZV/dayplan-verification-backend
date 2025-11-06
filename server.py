# server.py
from flask import Flask, request, jsonify, render_template_string
from datetime import datetime
import sqlite3, os

DB = os.getenv("REMOTE_DB_PATH", "remote_tokens.db")

def get_conn():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    conn.execute("""CREATE TABLE IF NOT EXISTS tokens(
        token TEXT PRIMARY KEY,
        email TEXT,
        expires_at TEXT,
        used INTEGER DEFAULT 0
    )""")
    return conn

app = Flask(__name__)

@app.post("/register")
def register():
    data = request.get_json(force=True)
    token = data["token"]
    email = (data.get("email") or "").lower().strip()
    expires_at = data.get("expires_at")  # "YYYY-MM-DD HH:MM:SS"
    conn = get_conn(); cur = conn.cursor()
    cur.execute("""INSERT INTO tokens(token, email, expires_at, used)
                   VALUES(?,?,?,0)
                   ON CONFLICT(token) DO UPDATE
                     SET email=excluded.email, expires_at=excluded.expires_at, used=0""",
                (token, email, expires_at))
    conn.commit(); conn.close()
    return jsonify({"ok": True})

@app.get("/verify")
def verify():
    token = (request.args.get("token") or "").strip()
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT expires_at, used FROM tokens WHERE token=?", (token,))
    row = cur.fetchone()
    if not row:
        msg = "Token inválido."
    else:
        try:
            exp = datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S")
        except Exception:
            exp = None
        if row["used"] == 1:
            msg = "Este enlace ya fue utilizado."
        elif exp and datetime.utcnow() > exp:
            msg = "El enlace expiró."
        else:
            cur.execute("UPDATE tokens SET used=1 WHERE token=?", (token,))
            conn.commit()
            msg = "¡Correo verificado! Ya puedes volver a la app."
    conn.close()
    return render_template_string(f"<h2>{msg}</h2>")

@app.get("/status")
def status():
    token = (request.args.get("token") or "").strip()
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT used FROM tokens WHERE token=?", (token,))
    row = cur.fetchone(); conn.close()
    return jsonify({"used": bool(row and int(row["used"] or 0)==1)})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
