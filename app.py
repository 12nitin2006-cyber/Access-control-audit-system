import csv
import io
import os
import sqlite3
from datetime import datetime
from functools import wraps

from flask import (Flask, Response, flash, g, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import audit_rules
import seed

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, "audit.db")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-before-real-use")


# database helpers 
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.executescript(open(os.path.join(BASE, "schema.sql")).read())
    seed.load(db)
    db.commit()
    db.close()


#login / permission decorators 
def login_required(*allowed):
    def deco(view):
        @wraps(view)
        def inner(*a, **kw):
            if "uid" not in session:
                return redirect(url_for("login"))
            if allowed and session["app_role"] not in allowed:
                flash("You do not have permission to open that page.", "error")
                return redirect(url_for("dashboard"))
            return view(*a, **kw)
        return inner
    return deco


def has_permission(db, user_id, resource_id, action):
    row = db.execute("""SELECT 1 FROM user_roles ur
                        JOIN role_permissions rp ON rp.role_id = ur.role_id
                        JOIN users u ON u.id = ur.user_id
                        WHERE ur.user_id = ? AND rp.resource_id = ? AND rp.permission = ?
                          AND u.status = 'active'""", (user_id, resource_id, action)).fetchone()
    return row is not None


# authentication
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?",
                          (request.form["username"].strip(),)).fetchone()
        if user and user["status"] == "active" and check_password_hash(user["password_hash"], request.form["password"]):
            if user["app_role"] == "staff":
                flash("Only admins and auditors can sign in to this tool.", "error")
                return render_template("login.html")
            session.update(uid=user["id"], name=user["full_name"], app_role=user["app_role"])
            db.execute("UPDATE users SET last_login = ? WHERE id = ?",
                       (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), user["id"]))
            db.commit()
            return redirect(url_for("dashboard"))
        flash("Wrong username or password.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# pages 
@app.route("/")
@login_required()
def dashboard():
    db = get_db()
    stats = {
        "users": db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "active": db.execute("SELECT COUNT(*) FROM users WHERE status='active'").fetchone()[0],
        "resources": db.execute("SELECT COUNT(*) FROM resources").fetchone()[0],
        "denied": db.execute("SELECT COUNT(*) FROM access_logs WHERE result='denied'").fetchone()[0],
    }
    last = db.execute("SELECT * FROM audit_runs ORDER BY id DESC LIMIT 1").fetchone()
    sev = {}
    if last:
        for r in db.execute("SELECT severity, COUNT(*) c FROM findings WHERE run_id=? AND status='open' GROUP BY severity", (last["id"],)):
            sev[r["severity"]] = r["c"]
    return render_template("dashboard.html", stats=stats, last=last, sev=sev)


@app.route("/users")
@login_required()
def users():
    rows = get_db().execute("""
        SELECT u.*, GROUP_CONCAT(r.name, ', ') AS roles
        FROM users u LEFT JOIN user_roles ur ON ur.user_id = u.id
        LEFT JOIN roles r ON r.id = ur.role_id
        GROUP BY u.id ORDER BY u.full_name""").fetchall()
    return render_template("users.html", users=rows)


@app.route("/users/<int:uid>", methods=["GET", "POST"])
@login_required()
def user_detail(uid):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not user:
        return redirect(url_for("users"))
    if request.method == "POST":
        if session["app_role"] != "admin":
            flash("Only an admin can change access.", "error")
            return redirect(url_for("user_detail", uid=uid))
        if "status" in request.form:
            db.execute("UPDATE users SET status=? WHERE id=?", (request.form["status"], uid))
        if "add_role" in request.form:
            db.execute("INSERT OR IGNORE INTO user_roles VALUES (?,?)", (uid, request.form["add_role"]))
        if "remove_role" in request.form:
            db.execute("DELETE FROM user_roles WHERE user_id=? AND role_id=?", (uid, request.form["remove_role"]))
        db.commit()
        flash("Changes saved.", "ok")
        return redirect(url_for("user_detail", uid=uid))
    roles = db.execute("SELECT r.* FROM roles r JOIN user_roles ur ON ur.role_id=r.id WHERE ur.user_id=?", (uid,)).fetchall()
    free = db.execute("SELECT * FROM roles WHERE id NOT IN (SELECT role_id FROM user_roles WHERE user_id=?)", (uid,)).fetchall()
    perms = db.execute("""SELECT DISTINCT res.name, res.sensitivity, rp.permission
                          FROM user_roles ur JOIN role_permissions rp ON rp.role_id=ur.role_id
                          JOIN resources res ON res.id=rp.resource_id
                          WHERE ur.user_id=? ORDER BY res.name""", (uid,)).fetchall()
    return render_template("user_detail.html", user=user, roles=roles, free=free, perms=perms)


@app.route("/matrix")
@login_required()
def matrix():
    db = get_db()
    roles = db.execute("SELECT * FROM roles ORDER BY name").fetchall()
    resources = db.execute("SELECT * FROM resources ORDER BY name").fetchall()
    cell = {}
    for r in db.execute("SELECT * FROM role_permissions"):
        cell.setdefault((r["role_id"], r["resource_id"]), []).append(r["permission"])
    return render_template("matrix.html", roles=roles, resources=resources, cell=cell)


@app.route("/simulate", methods=["GET", "POST"])
@login_required()
def simulate():
    db = get_db()
    result = None
    if request.method == "POST":
        uid, rid, action = int(request.form["user"]), int(request.form["resource"]), request.form["action"]
        ok = has_permission(db, uid, rid, action)
        db.execute("INSERT INTO access_logs (user_id, resource_id, action, result, logged_at) VALUES (?,?,?,?,?)",
                   (uid, rid, action, "granted" if ok else "denied", datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        db.commit()
        result = "granted" if ok else "denied"
    return render_template("simulate.html", result=result,
                           users=db.execute("SELECT id, full_name FROM users ORDER BY full_name").fetchall(),
                           resources=db.execute("SELECT id, name FROM resources ORDER BY name").fetchall())


@app.route("/logs")
@login_required()
def logs():
    result = request.args.get("result", "")
    sql = """SELECT l.*, u.full_name, r.name AS resource FROM access_logs l
             JOIN users u ON u.id=l.user_id JOIN resources r ON r.id=l.resource_id"""
    args = []
    if result in ("granted", "denied"):
        sql += " WHERE l.result = ?"
        args.append(result)
    sql += " ORDER BY l.logged_at DESC LIMIT 200"
    return render_template("logs.html", logs=get_db().execute(sql, args).fetchall(), result=result)


# audit 
@app.route("/audit/run", methods=["POST"])
@login_required("admin", "auditor")
def run_audit():
    db = get_db()
    cur = db.execute("INSERT INTO audit_runs (run_at, run_by) VALUES (?,?)",
                     (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), session["name"]))
    run_id = cur.lastrowid
    total = audit_rules.run_all(db, run_id)
    db.execute("UPDATE audit_runs SET total_findings=? WHERE id=?", (total, run_id))
    db.commit()
    flash(f"Audit finished. {total} finding(s) recorded.", "ok")
    return redirect(url_for("findings"))


@app.route("/findings")
@login_required()
def findings():
    db = get_db()
    run = db.execute("SELECT * FROM audit_runs ORDER BY id DESC LIMIT 1").fetchone()
    rows = []
    if run:
        rows = db.execute("""SELECT f.*, u.full_name FROM findings f JOIN users u ON u.id=f.user_id
                             WHERE f.run_id=? ORDER BY CASE f.severity WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, f.id""",
                          (run["id"],)).fetchall()
    return render_template("findings.html", run=run, findings=rows)


@app.route("/findings/<int:fid>/resolve", methods=["POST"])
@login_required("admin", "auditor")
def resolve(fid):
    db = get_db()
    db.execute("UPDATE findings SET status='resolved' WHERE id=?", (fid,))
    db.commit()
    return redirect(url_for("findings"))


@app.route("/findings/export")
@login_required()
def export():
    rows = get_db().execute("""SELECT f.id, f.rule, f.severity, u.full_name, f.detail, f.status
                               FROM findings f JOIN users u ON u.id=f.user_id
                               WHERE f.run_id=(SELECT MAX(id) FROM audit_runs)""").fetchall()
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["ID", "Rule", "Severity", "User", "Detail", "Status"])
    w.writerows([tuple(r) for r in rows])
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=audit_findings.csv"})


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        init_db()
    app.run(debug=True)