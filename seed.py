"""Fills the database with sample data so the project can be demonstrated."""
import random
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash

random.seed(7)
fmt = "%Y-%m-%d %H:%M:%S"


def ago(days, hour=None):
    t = datetime.now() - timedelta(days=days)
    if hour is not None:
        t = t.replace(hour=hour, minute=random.randint(0, 59), second=0)
    return t.strftime(fmt)


def load(db):
    pw = generate_password_hash("password123")
    users = [
        # username, name, dept, app_role, status, last_login(days ago)
        ("admin", "Nitin Sharma", "IT", "admin", "active", 0),
        ("auditor", "Rohan Mehta", "Compliance", "auditor", "active", 1),
        ("kiran", "Kiran Sood", "Finance", "staff", "active", 2),
        ("neha", "Neha Gill", "Finance", "staff", "active", 1),
        ("manpreet", "Manpreet Singh", "HR", "staff", "active", 3),
        ("deepak", "Deepak Rana", "IT", "staff", "active", 0),
        ("sneha", "Sneha Kapoor", "Sales", "staff", "active", 140),
        ("vikram", "Vikram Joshi", "Sales", "staff", "terminated", 60),
        ("pooja", "Pooja Bansal", "Finance", "staff", "active", 5),
        ("arjun", "Arjun Malik", "IT", "staff", "disabled", 200),
        ("simran", "Simran Kaur", "HR", "staff", "active", 4),
        ("harsh", "Harsh Tiwari", "Operations", "staff", "active", 2),
    ]
    for u in users:
        db.execute("INSERT INTO users (username, full_name, department, password_hash, app_role, status, last_login) "
                   "VALUES (?,?,?,?,?,?,?)", (u[0], u[1], u[2], pw, u[3], u[4], ago(u[5])))

    roles = [
        ("Accountant", "Posts entries in the finance system"),
        ("Payment Approver", "Approves outgoing payments"),
        ("HR Officer", "Manages employee records"),
        ("Payroll Admin", "Runs monthly payroll"),
        ("Sales Rep", "Works with customer records"),
        ("DB Admin", "Administers production databases"),
        ("Sysadmin", "Manages servers and backups"),
        ("Employee", "Basic intranet access"),
    ]
    for r in roles:
        db.execute("INSERT INTO roles (name, description) VALUES (?,?)", r)

    resources = [
        ("General Ledger", "Application", "high"),
        ("Payment Gateway", "Application", "high"),
        ("Employee Records", "Database", "high"),
        ("Payroll System", "Application", "high"),
        ("Customer CRM", "Application", "medium"),
        ("Production DB", "Database", "high"),
        ("File Server", "Server", "medium"),
        ("Intranet Portal", "Website", "low"),
    ]
    for r in resources:
        db.execute("INSERT INTO resources (name, type, sensitivity) VALUES (?,?,?)", r)

    perms = {  # role id -> [(resource id, permission)]
        1: [(1, "read"), (1, "write"), (7, "read")],
        2: [(2, "read"), (2, "write"), (1, "read")],
        3: [(3, "read"), (3, "write")],
        4: [(4, "read"), (4, "write"), (4, "admin"), (3, "read")],
        5: [(5, "read"), (5, "write")],
        6: [(6, "read"), (6, "write"), (6, "admin")],
        7: [(7, "read"), (7, "write"), (7, "admin"), (6, "read")],
        8: [(8, "read")],
    }
    for rid, items in perms.items():
        for res, p in items:
            db.execute("INSERT INTO role_permissions VALUES (?,?,?)", (rid, res, p))

    assign = {1: [8, 7], 2: [8], 3: [1, 2, 8], 4: [1, 8], 5: [3, 4, 8], 6: [6, 7, 8],
              7: [5, 8], 8: [5, 8], 9: [1, 8], 10: [6, 7], 11: [3, 8], 12: [8, 7, 5, 1]}
    for uid, rs in assign.items():
        for r in rs:
            db.execute("INSERT INTO user_roles VALUES (?,?)", (uid, r))

    db.execute("INSERT INTO sod_rules (role_a, role_b, description) VALUES (1, 2, 'Same person must not post and approve payments')")
    db.execute("INSERT INTO sod_rules (role_a, role_b, description) VALUES (3, 4, 'HR records and payroll must be separate')")

    # sample access history
    for _ in range(220):
        uid = random.randint(3, 12)
        res = random.randint(1, 8)
        action = random.choice(["read", "read", "write", "delete"])
        if random.random() < 0.92:  # most real requests are things the user is allowed to do
            own = db.execute("""SELECT rp.resource_id, rp.permission FROM user_roles ur
                               JOIN role_permissions rp ON rp.role_id = ur.role_id
                               WHERE ur.user_id = ?""", (uid,)).fetchall()
            if own:
                res, action = random.choice([(o[0], o[1]) for o in own])
        ok = db.execute("""SELECT 1 FROM user_roles ur JOIN role_permissions rp ON rp.role_id = ur.role_id
                           WHERE ur.user_id=? AND rp.resource_id=? AND rp.permission=?""", (uid, res, action)).fetchone()
        db.execute("INSERT INTO access_logs (user_id, resource_id, action, result, logged_at) VALUES (?,?,?,?,?)",
                   (uid, res, action, "granted" if ok else "denied", ago(random.randint(0, 30), random.randint(8, 18))))
    # a few late-night accesses and a burst of denials to make the audit interesting
    for _ in range(3):
        db.execute("INSERT INTO access_logs (user_id, resource_id, action, result, logged_at) VALUES (6,6,'write','granted',?)",
                   (ago(random.randint(1, 10), 23),))
    for _ in range(6):
        db.execute("INSERT INTO access_logs (user_id, resource_id, action, result, logged_at) VALUES (11,4,'write','denied',?)",
                   (ago(random.randint(0, 5), 14),))

