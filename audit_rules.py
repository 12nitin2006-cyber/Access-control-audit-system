"""Audit rules. Each rule is one SQL query that returns the risky users it finds."""

DORMANT_DAYS = 90
MAX_ROLES = 3
DENIED_LIMIT = 5

RULES = []


def rule(name, severity):
    def wrap(fn):
        RULES.append((name, severity, fn))
        return fn
    return wrap


@rule("Orphaned account", "high")
def orphaned(db):
    # Terminated or disabled people who still hold roles
    rows = db.execute("""
        SELECT u.id, u.full_name, u.status, COUNT(ur.role_id) AS n
        FROM users u JOIN user_roles ur ON ur.user_id = u.id
        WHERE u.status != 'active'
        GROUP BY u.id""").fetchall()
    return [(r["id"], f"{r['full_name']} is {r['status']} but still holds {r['n']} role(s).") for r in rows]


@rule("Dormant account", "medium")
def dormant(db):
    rows = db.execute(f"""
        SELECT id, full_name, last_login,
               CAST(julianday('now') - julianday(last_login) AS INTEGER) AS days
        FROM users
        WHERE status = 'active' AND last_login IS NOT NULL
          AND julianday('now') - julianday(last_login) > {DORMANT_DAYS}""").fetchall()
    return [(r["id"], f"{r['full_name']} has not logged in for {r['days']} days.") for r in rows]


@rule("Excessive privilege", "medium")
def excessive(db):
    rows = db.execute(f"""
        SELECT u.id, u.full_name, COUNT(*) AS n
        FROM users u JOIN user_roles ur ON ur.user_id = u.id
        WHERE u.status = 'active'
        GROUP BY u.id HAVING n > {MAX_ROLES}""").fetchall()
    return [(r["id"], f"{r['full_name']} holds {r['n']} roles (limit is {MAX_ROLES}).") for r in rows]


@rule("Segregation of duties conflict", "high")
def sod(db):
    rows = db.execute("""
        SELECT u.id, u.full_name, ra.name AS a, rb.name AS b
        FROM sod_rules s
        JOIN user_roles x ON x.role_id = s.role_a
        JOIN user_roles y ON y.role_id = s.role_b AND y.user_id = x.user_id
        JOIN users u ON u.id = x.user_id
        JOIN roles ra ON ra.id = s.role_a
        JOIN roles rb ON rb.id = s.role_b""").fetchall()
    return [(r["id"], f"{r['full_name']} holds conflicting roles '{r['a']}' and '{r['b']}'.") for r in rows]


@rule("Repeated denied access", "medium")
def denied(db):
    rows = db.execute(f"""
        SELECT u.id, u.full_name, COUNT(*) AS n
        FROM access_logs l JOIN users u ON u.id = l.user_id
        WHERE l.result = 'denied'
        GROUP BY u.id HAVING n >= {DENIED_LIMIT}""").fetchall()
    return [(r["id"], f"{r['full_name']} was denied access {r['n']} times.") for r in rows]


@rule("After-hours access to sensitive data", "low")
def after_hours(db):
    rows = db.execute("""
        SELECT u.id, u.full_name, COUNT(*) AS n
        FROM access_logs l
        JOIN users u ON u.id = l.user_id
        JOIN resources r ON r.id = l.resource_id
        WHERE l.result = 'granted' AND r.sensitivity = 'high'
          AND (CAST(strftime('%H', l.logged_at) AS INTEGER) < 6
               OR CAST(strftime('%H', l.logged_at) AS INTEGER) >= 22)
        GROUP BY u.id""").fetchall()
    return [(r["id"], f"{r['full_name']} accessed high-sensitivity data {r['n']} time(s) between 10 PM and 6 AM.") for r in rows]


def run_all(db, run_id):
    total = 0
    for name, severity, fn in RULES:
        for user_id, detail in fn(db):
            db.execute("INSERT INTO findings (run_id, rule, severity, user_id, detail) VALUES (?,?,?,?,?)",
                       (run_id, name, severity, user_id, detail))
            total += 1
    return total
