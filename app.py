import os
import sqlite3
import ipaddress
import socket
import time
import secrets
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash

APP_DIR = Path(__file__).resolve().parent
DB_PATH = APP_DIR / "cybershield.db"

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "CAMBIAR-ESTA-CLAVE-ANTES-DE-USAR-EN-PRODUCCION")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Lista fija del MVP. Los puertos marcados como riesgosos generan alertas.
PORTS_TO_SCAN = {
    21: ("FTP", True, "FTP puede transmitir credenciales sin cifrado."),
    22: ("SSH", False, "Servicio de administración remota SSH."),
    23: ("Telnet", True, "Telnet transmite información sin cifrado."),
    80: ("HTTP", False, "Servicio web sin cifrado TLS."),
    443: ("HTTPS", False, "Servicio web cifrado."),
    445: ("SMB", True, "SMB expuesto puede facilitar movimientos laterales."),
    3306: ("MySQL", True, "Base de datos MySQL accesible por red."),
    3389: ("RDP", True, "Escritorio remoto accesible por red."),
    5432: ("PostgreSQL", True, "Base de datos PostgreSQL accesible por red."),
    8080: ("HTTP alternativo", False, "Servicio web en puerto alternativo."),
}

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    with get_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            ip TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER NOT NULL,
            scanned_at TEXT NOT NULL,
            duration_seconds REAL NOT NULL DEFAULT 0,
            FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS scan_ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            port INTEGER NOT NULL,
            service TEXT NOT NULL,
            is_risky INTEGER NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER NOT NULL,
            scan_id INTEGER NOT NULL,
            port INTEGER NOT NULL,
            service TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            detected_at TEXT NOT NULL,
            emitted_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Pendiente',
            FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE,
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );
        """)
        user = db.execute("SELECT id FROM users WHERE username = ?", ("admin",)).fetchone()
        if not user:
            db.execute(
                "INSERT INTO users(username, password_hash) VALUES (?, ?)",
                ("admin", generate_password_hash("Admin123!"))
            )

def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]

@app.context_processor
def inject_csrf():
    return {"csrf_token": csrf_token}

def validate_csrf():
    sent = request.form.get("_csrf", "")
    if not sent or not secrets.compare_digest(sent, session.get("_csrf", "")):
        abort(400, description="Token de seguridad inválido. Recarga la página e inténtalo nuevamente.")

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

def now_text():
    return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")

def validate_private_ip(value):
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    # El MVP solo permite IPv4 privadas o loopback: evita escanear objetivos públicos.
    if not isinstance(ip, ipaddress.IPv4Address) or not (ip.is_private or ip.is_loopback):
        return None
    return str(ip)

@app.route("/", methods=["GET"])
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        validate_csrf()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with get_db() as db:
            user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash("Sesión iniciada correctamente.", "success")
            return redirect(url_for("dashboard"))
        flash("Usuario o contraseña incorrectos.", "danger")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    validate_csrf()
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    with get_db() as db:
        assets_count = db.execute("SELECT COUNT(*) n FROM assets").fetchone()["n"]
        open_ports = db.execute("""
            SELECT COUNT(*) n FROM scan_ports sp
            JOIN scans s ON s.id = sp.scan_id
            WHERE s.id = (SELECT MAX(id) FROM scans s2 WHERE s2.asset_id = s.asset_id)
        """).fetchone()["n"]
        pending = db.execute("SELECT COUNT(*) n FROM alerts WHERE status='Pendiente'").fetchone()["n"]
        avg_delay = db.execute("""
            SELECT AVG((julianday(emitted_at)-julianday(detected_at))*86400) n FROM alerts
        """).fetchone()["n"]
        recent = db.execute("""
            SELECT a.*, al.name AS asset_name, al.ip
            FROM alerts a JOIN assets al ON al.id=a.asset_id
            ORDER BY a.id DESC LIMIT 6
        """).fetchall()
        latest_scans = db.execute("""
            SELECT s.*, a.name asset_name, a.ip,
                   (SELECT COUNT(*) FROM scan_ports p WHERE p.scan_id=s.id) open_count
            FROM scans s JOIN assets a ON a.id=s.asset_id
            ORDER BY s.id DESC LIMIT 5
        """).fetchall()
    return render_template("dashboard.html", assets_count=assets_count, open_ports=open_ports,
                           pending=pending, avg_delay=avg_delay or 0, recent=recent,
                           latest_scans=latest_scans)

@app.route("/assets", methods=["GET", "POST"])
@login_required
def assets():
    if request.method == "POST":
        validate_csrf()
        name = request.form.get("name", "").strip()
        ip = validate_private_ip(request.form.get("ip", ""))
        if not name or len(name) > 80:
            flash("Ingresa un nombre válido de máximo 80 caracteres.", "danger")
        elif not ip:
            flash("IP no válida. Por seguridad, registra únicamente IPv4 privadas o localhost autorizadas.", "danger")
        else:
            try:
                with get_db() as db:
                    db.execute("INSERT INTO assets(name, ip, created_at) VALUES (?, ?, ?)", (name, ip, now_text()))
                flash("Equipo registrado correctamente.", "success")
            except sqlite3.IntegrityError:
                flash("Esa dirección IP ya está registrada.", "warning")
        return redirect(url_for("assets"))
    with get_db() as db:
        rows = db.execute("""
            SELECT a.*,
              (SELECT MAX(scanned_at) FROM scans s WHERE s.asset_id=a.id) last_scan
            FROM assets a ORDER BY a.id DESC
        """).fetchall()
    return render_template("assets.html", assets=rows)

@app.route("/assets/<int:asset_id>/delete", methods=["POST"])
@login_required
def delete_asset(asset_id):
    validate_csrf()
    with get_db() as db:
        db.execute("DELETE FROM assets WHERE id=?", (asset_id,))
    flash("Equipo y sus registros asociados eliminados.", "success")
    return redirect(url_for("assets"))

def scan_tcp(ip, port, timeout=0.55):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((ip, port)) == 0
    except OSError:
        return False
    finally:
        sock.close()

@app.route("/scan", methods=["GET", "POST"])
@login_required
def scan():
    if request.method == "POST":
        validate_csrf()
        try:
            asset_id = int(request.form.get("asset_id", ""))
        except ValueError:
            flash("Selecciona un equipo válido.", "danger")
            return redirect(url_for("scan"))
        with get_db() as db:
            asset = db.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
        if not asset:
            flash("El equipo seleccionado no existe.", "danger")
            return redirect(url_for("scan"))
        # Revalidación al momento del escaneo.
        ip = validate_private_ip(asset["ip"])
        if not ip:
            flash("La IP del equipo no cumple las restricciones de seguridad.", "danger")
            return redirect(url_for("scan"))

        start = time.perf_counter()
        results = []
        for port, (service, risky, description) in PORTS_TO_SCAN.items():
            if scan_tcp(ip, port):
                results.append((port, service, risky, description))
        duration = time.perf_counter() - start
        detected = now_text()
        with get_db() as db:
            cur = db.execute(
                "INSERT INTO scans(asset_id, scanned_at, duration_seconds) VALUES (?, ?, ?)",
                (asset_id, detected, duration)
            )
            scan_id = cur.lastrowid
            for port, service, risky, description in results:
                db.execute(
                    "INSERT INTO scan_ports(scan_id, port, service, is_risky) VALUES (?, ?, ?, ?)",
                    (scan_id, port, service, int(risky))
                )
                if risky:
                    emitted = now_text()
                    severity = "Alta" if port in (23, 445, 3389, 3306, 5432) else "Baja"
                    db.execute("""
                        INSERT INTO alerts(asset_id, scan_id, port, service, severity,
                                           description, detected_at, emitted_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (asset_id, scan_id, port, service, severity, description, detected, emitted))
        session["last_scan_id"] = scan_id
        flash(f"Escaneo finalizado: {len(results)} puerto(s) abierto(s).", "success")
        return redirect(url_for("scan_result", scan_id=scan_id))

    with get_db() as db:
        asset_rows = db.execute("SELECT * FROM assets ORDER BY name").fetchall()
    return render_template("scan.html", assets=asset_rows, ports=PORTS_TO_SCAN)

@app.route("/scan/<int:scan_id>")
@login_required
def scan_result(scan_id):
    with get_db() as db:
        scan_row = db.execute("""
            SELECT s.*, a.name asset_name, a.ip FROM scans s
            JOIN assets a ON a.id=s.asset_id WHERE s.id=?
        """, (scan_id,)).fetchone()
        if not scan_row:
            abort(404)
        results = db.execute("SELECT * FROM scan_ports WHERE scan_id=? ORDER BY port", (scan_id,)).fetchall()
    return render_template("scan_result.html", scan=scan_row, results=results)

@app.route("/alerts")
@login_required
def alerts():
    status = request.args.get("status", "Todas")
    query = """
        SELECT al.*, a.name asset_name, a.ip
        FROM alerts al JOIN assets a ON a.id=al.asset_id
    """
    params = []
    if status in ("Pendiente", "Atendida"):
        query += " WHERE al.status=?"
        params.append(status)
    query += " ORDER BY al.id DESC"
    with get_db() as db:
        rows = db.execute(query, params).fetchall()
    return render_template("alerts.html", alerts=rows, selected=status)

@app.route("/alerts/<int:alert_id>/attend", methods=["POST"])
@login_required
def attend_alert(alert_id):
    validate_csrf()
    with get_db() as db:
        db.execute("UPDATE alerts SET status='Atendida' WHERE id=?", (alert_id,))
    flash("Alerta marcada como atendida.", "success")
    return redirect(url_for("alerts"))

@app.errorhandler(400)
def bad_request(error):
    return render_template("error.html", code=400, message=getattr(error, "description", "Solicitud incorrecta.")), 400

@app.errorhandler(404)
def not_found(error):
    return render_template("error.html", code=404, message="No encontramos el recurso solicitado."), 404

init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
