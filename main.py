import sqlite3
from flask import Flask, request, jsonify, send_from_directory
import hashlib, secrets, os, csv
from functools import wraps
from datetime import datetime, timedelta

# --- DATABASE ---
DB_PATH = "database.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL, token TEXT, created_at TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS cashflows (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
        week_name TEXT, week_date TEXT,
        income REAL DEFAULT 0, gas REAL DEFAULT 0,
        debt_deduction REAL DEFAULT 0, reserve_withdrawal REAL DEFAULT 0,
        spending REAL DEFAULT 0, payment REAL DEFAULT 0,
        reserve_balance REAL DEFAULT 0, debt_balance REAL DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id))""")
    c.execute("""CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
        cashflow_id INTEGER, week_name TEXT, field TEXT, old_value REAL, new_value REAL,
        changed_at TEXT, FOREIGN KEY (user_id) REFERENCES users(id))""")
    c.execute("""CREATE TABLE IF NOT EXISTS banks (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
        name TEXT NOT NULL, role TEXT DEFAULT '',
        color TEXT DEFAULT '#3b82f6', is_hidden INTEGER DEFAULT 0,
        created_at TEXT, FOREIGN KEY (user_id) REFERENCES users(id))""")
    c.execute("""CREATE TABLE IF NOT EXISTS loans (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        principal REAL NOT NULL,
        interest_rate REAL NOT NULL DEFAULT 0,
        term_months INTEGER NOT NULL,
        start_date TEXT NOT NULL,
        payment_day INTEGER NOT NULL DEFAULT 1,
        lender TEXT DEFAULT '',
        purpose TEXT DEFAULT 'purchase',
        refinance_target_id INTEGER,
        color TEXT DEFAULT '#2962ff',
        status TEXT DEFAULT 'active',
        notify_email INTEGER DEFAULT 1,
        payment_mode TEXT DEFAULT 'emi',
        total_interest REAL DEFAULT 0,
        allow_early_payoff INTEGER DEFAULT 1,
        created_at TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id))""")
    # Migrations for older DBs
    cols = {r[1] for r in c.execute("PRAGMA table_info(loans)").fetchall()}
    for col, ddl in [('payment_mode', "ALTER TABLE loans ADD COLUMN payment_mode TEXT DEFAULT 'emi'"),
                     ('total_interest', "ALTER TABLE loans ADD COLUMN total_interest REAL DEFAULT 0"),
                     ('allow_early_payoff', "ALTER TABLE loans ADD COLUMN allow_early_payoff INTEGER DEFAULT 1")]:
        if col not in cols:
            c.execute(ddl)
    c.execute("""CREATE TABLE IF NOT EXISTS loan_schedule (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        loan_id INTEGER NOT NULL,
        installment_no INTEGER NOT NULL,
        amount REAL NOT NULL,
        due_date TEXT,
        FOREIGN KEY (loan_id) REFERENCES loans(id) ON DELETE CASCADE)""")
    c.execute("""CREATE TABLE IF NOT EXISTS cashflow_loan_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cashflow_id INTEGER NOT NULL,
        loan_id INTEGER NOT NULL,
        weekly_deduction REAL DEFAULT 0,
        payment REAL DEFAULT 0,
        debt_balance REAL DEFAULT 0,
        is_payment_week INTEGER DEFAULT 0,
        installment_no INTEGER DEFAULT 0,
        FOREIGN KEY (cashflow_id) REFERENCES cashflows(id) ON DELETE CASCADE,
        FOREIGN KEY (loan_id) REFERENCES loans(id) ON DELETE CASCADE)""")
    item_cols = {r[1] for r in c.execute("PRAGMA table_info(cashflow_loan_items)").fetchall()}
    if 'installment_no' not in item_cols:
        c.execute("ALTER TABLE cashflow_loan_items ADD COLUMN installment_no INTEGER DEFAULT 0")
    if 'payment_covered' not in item_cols:
        c.execute("ALTER TABLE cashflow_loan_items ADD COLUMN payment_covered REAL DEFAULT 0")
    if 'cover_source' not in item_cols:
        c.execute("ALTER TABLE cashflow_loan_items ADD COLUMN cover_source TEXT")
    conn.commit()
    conn.close()

app = Flask(__name__, static_folder='static')
init_db()

def hash_password(pwd):
    return hashlib.sha256(pwd.encode()).hexdigest()

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({"detail": "Unauthorized"}), 401
        token = auth.split(' ')[1]
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE token = ?", (token,)).fetchone()
        conn.close()
        if not user:
            return jsonify({"detail": "Unauthorized"}), 401
        return f(user, *args, **kwargs)
    return decorated

# --- Recalculate all rows from scratch ---
def recalculate_all(user_id):
    conn = get_db()
    c = conn.cursor()
    rows = c.execute("SELECT * FROM cashflows WHERE user_id = ? ORDER BY id ASC", (user_id,)).fetchall()
    prev_res = 0
    prev_debt = 0
    for r in rows:
        if r['week_name'] == 'Số dư ban đầu':
            prev_res = r['reserve_balance']
            prev_debt = r['debt_balance']
            continue
        spending = r['income'] - r['gas'] - r['debt_deduction'] + r['reserve_withdrawal']
        new_res = prev_res - r['reserve_withdrawal']
        new_debt = prev_debt + r['debt_deduction'] - r['payment']
        c.execute("UPDATE cashflows SET spending=?, reserve_balance=?, debt_balance=? WHERE id=?",
                  (spending, new_res, new_debt, r['id']))
        prev_res = new_res
        prev_debt = new_debt
    conn.commit()
    conn.close()

# --- PROFILE ---
@app.route('/api/profile', methods=['GET'])
@require_auth
def get_profile(current_user):
    conn = get_db()
    weeks = conn.execute("SELECT COUNT(*) as c FROM cashflows WHERE user_id = ? AND week_name != 'Số dư ban đầu'", (current_user['id'],)).fetchone()['c']
    changes = conn.execute("SELECT COUNT(*) as c FROM audit_log WHERE user_id = ?", (current_user['id'],)).fetchone()['c']
    conn.close()
    return jsonify({"username": current_user['username'], "created_at": current_user['created_at'] or 'N/A', "total_weeks": weeks, "total_changes": changes})

@app.route('/api/profile', methods=['PUT'])
@require_auth
def update_profile(current_user):
    data = request.json
    old_pw = data.get('old_password', '')
    new_pw = data.get('new_password', '')
    if not old_pw or not new_pw:
        return jsonify({"detail": "Missing fields"}), 400
    if current_user['password_hash'] != hash_password(old_pw):
        return jsonify({"detail": "Wrong current password"}), 400
    conn = get_db()
    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(new_pw), current_user['id']))
    conn.commit()
    conn.close()
    return jsonify({"message": "Password updated"})

# --- AUTH ---
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    conn = get_db()
    c = conn.cursor()
    if c.execute("SELECT * FROM users WHERE username = ?", (data['username'],)).fetchone():
        conn.close()
        return jsonify({"detail": "Username already registered"}), 400
    c.execute("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
              (data['username'], hash_password(data['password']), datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    user_id = c.lastrowid
    # Seed default banks
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    defaults = [
        ('TP Bank', 'income', '#10b981'),
        ('MB Bank', 'spending', '#3b82f6'),
        ('ShopeePay', 'payment', '#f59e0b'),
        ('Quỹ Dự Phòng', 'reserve', '#d4a853'),
    ]
    for name, role, color in defaults:
        c.execute("INSERT INTO banks (user_id, name, role, color, created_at) VALUES (?,?,?,?,?)",
                  (user_id, name, role, color, now))
    conn.commit()
    conn.close()
    return jsonify({"message": "User created successfully"})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (data['username'],)).fetchone()
    if not user or user['password_hash'] != hash_password(data['password']):
        conn.close()
        return jsonify({"detail": "Invalid credentials"}), 401
    token = secrets.token_hex(32)
    conn.execute("UPDATE users SET token = ? WHERE id = ?", (token, user['id']))
    conn.commit()
    conn.close()
    return jsonify({"token": token, "username": data['username']})

# --- CASHFLOW CRUD ---
@app.route('/api/cashflows', methods=['GET'])
@require_auth
def get_cashflows(current_user):
    conn = get_db()
    rows = conn.execute("SELECT * FROM cashflows WHERE user_id = ? ORDER BY id ASC", (current_user['id'],)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/cashflows/<int:rid>', methods=['PUT'])
@require_auth
def update_cashflow(current_user, rid):
    data = request.json
    conn = get_db()
    c = conn.cursor()
    rec = c.execute("SELECT * FROM cashflows WHERE id = ? AND user_id = ?", (rid, current_user['id'])).fetchone()
    if not rec:
        conn.close()
        return jsonify({"detail": "Not found"}), 404
    if rec['week_name'] == 'Số dư ban đầu':
        conn.close()
        return jsonify({"detail": "Cannot edit initial balance"}), 400
    # Log changes to audit_log
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    fields = ['income', 'gas', 'debt_deduction', 'reserve_withdrawal', 'payment']
    for f in fields:
        old_val = float(rec[f])
        new_val = float(data.get(f, old_val))
        if old_val != new_val:
            c.execute("INSERT INTO audit_log (user_id, cashflow_id, week_name, field, old_value, new_value, changed_at) VALUES (?,?,?,?,?,?,?)",
                      (current_user['id'], rid, rec['week_name'], f, old_val, new_val, now))
    c.execute("""UPDATE cashflows SET income=?, gas=?, debt_deduction=?, reserve_withdrawal=?, payment=? WHERE id=?""",
              (float(data.get('income', rec['income'])), float(data.get('gas', rec['gas'])),
               float(data.get('debt_deduction', rec['debt_deduction'])),
               float(data.get('reserve_withdrawal', rec['reserve_withdrawal'])),
               float(data.get('payment', rec['payment'])), rid))
    conn.commit()
    conn.close()
    recalculate_all(current_user['id'])
    return jsonify({"message": "Updated"})

@app.route('/api/cashflows/<int:rid>', methods=['DELETE'])
@require_auth
def delete_cashflow(current_user, rid):
    conn = get_db()
    c = conn.cursor()
    rec = c.execute("SELECT * FROM cashflows WHERE id = ? AND user_id = ?", (rid, current_user['id'])).fetchone()
    if not rec:
        conn.close()
        return jsonify({"detail": "Not found"}), 404
    if rec['week_name'] == 'Số dư ban đầu':
        conn.close()
        return jsonify({"detail": "Cannot delete initial balance"}), 400
    c.execute("DELETE FROM cashflows WHERE id = ?", (rid,))
    conn.commit()
    conn.close()
    recalculate_all(current_user['id'])
    return jsonify({"message": "Deleted"})

# --- LOAN HELPERS ---
def calc_emi(principal, rate_pct, term_months):
    if term_months <= 0:
        return 0.0
    if rate_pct > 0:
        r = rate_pct / 100.0
        return principal * r * ((1+r)**term_months) / (((1+r)**term_months) - 1)
    return principal / term_months

def loan_schedule_amounts(conn, loan):
    """Return list of length term_months with amount due for each installment."""
    n = loan['term_months']
    mode = loan['payment_mode'] if 'payment_mode' in loan.keys() else 'emi'
    if mode == 'custom_schedule':
        rows = conn.execute(
            "SELECT installment_no, amount FROM loan_schedule WHERE loan_id=? ORDER BY installment_no",
            (loan['id'],)).fetchall()
        amounts = [0.0] * n
        for r in rows:
            if 1 <= r['installment_no'] <= n:
                amounts[r['installment_no']-1] = float(r['amount'])
        return amounts
    if mode == 'fixed_total':
        total_interest = float(loan['total_interest'] or 0)
        per = (float(loan['principal']) + total_interest) / n
        return [per] * n
    # default 'emi'
    return [calc_emi(float(loan['principal']), float(loan['interest_rate']), n)] * n

def calc_monthly_payment(principal, rate_pct, term_months):
    """Legacy helper kept for backward-compat callers (returns single EMI value)."""
    return calc_emi(principal, rate_pct, term_months)

def add_months(dt, months):
    """Add N months to a date, clamping day to month-end if needed."""
    y = dt.year + (dt.month - 1 + months) // 12
    m = (dt.month - 1 + months) % 12 + 1
    # last day of target month
    if m == 12:
        last = 31
    else:
        last = (datetime(y, m+1, 1) - timedelta(days=1)).day
    return dt.replace(year=y, month=m, day=min(dt.day, last))

# --- LOANS CRUD ---
@app.route('/api/loans', methods=['GET'])
@require_auth
def list_loans(current_user):
    conn = get_db()
    rows = conn.execute("SELECT * FROM loans WHERE user_id = ? ORDER BY start_date ASC, id ASC",
                        (current_user['id'],)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        amounts = loan_schedule_amounts(conn, r)
        d['schedule'] = amounts
        d['total_payable'] = round(sum(amounts))
        d['monthly_payment'] = round(amounts[0]) if amounts else 0
        # Baseline EMI = what user WOULD pay if no discount (rate% applied straight)
        baseline = calc_emi(float(d['principal']), float(d['interest_rate']), int(d['term_months']))
        d['baseline_monthly'] = round(baseline)
        d['baseline_total'] = round(baseline * d['term_months'])
        d['discount_total'] = max(0, d['baseline_total'] - d['total_payable'])
        try:
            sd = datetime.strptime(d['start_date'], '%Y-%m-%d')
            d['end_date'] = add_months(sd, d['term_months']).strftime('%Y-%m-%d')
        except Exception:
            d['end_date'] = None
        out.append(d)
    conn.close()
    return jsonify(out)

def _save_schedule(c, loan_id, term, schedule):
    """Replace loan_schedule rows for this loan."""
    c.execute("DELETE FROM loan_schedule WHERE loan_id=?", (loan_id,))
    if not schedule:
        return
    for i, amt in enumerate(schedule[:term], start=1):
        c.execute("INSERT INTO loan_schedule (loan_id, installment_no, amount) VALUES (?,?,?)",
                  (loan_id, i, float(amt or 0)))

@app.route('/api/loans', methods=['POST'])
@require_auth
def create_loan(current_user):
    data = request.json
    name = data.get('name', 'Khoản vay')
    principal = float(data.get('principal', 0))
    rate = float(data.get('interest_rate', 0))
    term = int(data.get('term_months', 3))
    if term <= 0:
        return jsonify({"detail": "term_months must be > 0"}), 400
    start_date = data.get('start_date', datetime.now().strftime('%Y-%m-%d'))
    payment_day = int(data.get('payment_day', 1))
    if payment_day < 1 or payment_day > 28:
        return jsonify({"detail": "payment_day must be 1..28"}), 400
    lender = data.get('lender', '')
    purpose = data.get('purpose', 'purchase')
    refinance_target_id = data.get('refinance_target_id')
    color = data.get('color', '#2962ff')
    notify = int(data.get('notify_email', 1))
    payment_mode = data.get('payment_mode', 'emi')  # 'emi' | 'fixed_total' | 'custom_schedule'
    if payment_mode not in ('emi', 'fixed_total', 'custom_schedule'):
        return jsonify({"detail": "invalid payment_mode"}), 400
    total_interest = float(data.get('total_interest', 0) or 0)
    allow_early = int(data.get('allow_early_payoff', 1))
    schedule = data.get('schedule') or []

    conn = get_db()
    c = conn.cursor()
    c.execute("""INSERT INTO loans (user_id, name, principal, interest_rate, term_months,
                 start_date, payment_day, lender, purpose, refinance_target_id, color,
                 status, notify_email, payment_mode, total_interest, allow_early_payoff, created_at)
                 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
              (current_user['id'], name, principal, rate, term, start_date, payment_day,
               lender, purpose, refinance_target_id, color, 'active', notify,
               payment_mode, total_interest, allow_early,
               datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    new_id = c.lastrowid
    if payment_mode == 'custom_schedule':
        _save_schedule(c, new_id, term, schedule)
    conn.commit()
    conn.close()
    return jsonify({"message": "Loan created", "id": new_id})

@app.route('/api/loans/<int:lid>', methods=['PUT'])
@require_auth
def update_loan(current_user, lid):
    data = request.json
    conn = get_db()
    loan = conn.execute("SELECT * FROM loans WHERE id = ? AND user_id = ?",
                        (lid, current_user['id'])).fetchone()
    if not loan:
        conn.close()
        return jsonify({"detail": "Not found"}), 404
    fields = ['name', 'principal', 'interest_rate', 'term_months', 'start_date',
              'payment_day', 'lender', 'purpose', 'color', 'status', 'notify_email',
              'payment_mode', 'total_interest', 'allow_early_payoff', 'refinance_target_id']
    updates = {f: data.get(f, loan[f]) for f in fields}
    if updates['payment_mode'] not in ('emi', 'fixed_total', 'custom_schedule'):
        conn.close()
        return jsonify({"detail": "invalid payment_mode"}), 400
    refi = updates['refinance_target_id']
    refi = int(refi) if refi not in (None, '', 0) else None
    c = conn.cursor()
    c.execute("""UPDATE loans SET name=?, principal=?, interest_rate=?, term_months=?,
                 start_date=?, payment_day=?, lender=?, purpose=?, color=?, status=?,
                 notify_email=?, payment_mode=?, total_interest=?, allow_early_payoff=?,
                 refinance_target_id=? WHERE id=?""",
              (updates['name'], float(updates['principal']), float(updates['interest_rate']),
               int(updates['term_months']), updates['start_date'], int(updates['payment_day']),
               updates['lender'], updates['purpose'], updates['color'], updates['status'],
               int(updates['notify_email']), updates['payment_mode'],
               float(updates['total_interest'] or 0), int(updates['allow_early_payoff']),
               refi, lid))
    if updates['payment_mode'] == 'custom_schedule' and 'schedule' in data:
        _save_schedule(c, lid, int(updates['term_months']), data.get('schedule') or [])
    conn.commit()
    conn.close()
    return jsonify({"message": "Loan updated"})

@app.route('/api/loans/<int:lid>', methods=['DELETE'])
@require_auth
def delete_loan(current_user, lid):
    conn = get_db()
    conn.execute("DELETE FROM loans WHERE id = ? AND user_id = ?", (lid, current_user['id']))
    conn.commit()
    conn.close()
    return jsonify({"message": "Loan deleted"})

@app.route('/api/loans/<int:lid>/installment/<int:k>', methods=['PUT'])
@require_auth
def update_installment(current_user, lid, k):
    """Update a single installment amount. Auto-switches loan to custom_schedule mode."""
    data = request.json
    new_amount = float(data.get('amount', 0))
    conn = get_db()
    loan = conn.execute("SELECT * FROM loans WHERE id=? AND user_id=?",
                        (lid, current_user['id'])).fetchone()
    if not loan:
        conn.close()
        return jsonify({"detail": "Loan not found"}), 404
    n = loan['term_months']
    if k < 1 or k > n:
        conn.close()
        return jsonify({"detail": "Invalid installment number"}), 400
    c = conn.cursor()
    # If not yet in custom mode, snapshot current schedule into rows then switch
    if loan['payment_mode'] != 'custom_schedule':
        amounts = loan_schedule_amounts(conn, loan)
        c.execute("DELETE FROM loan_schedule WHERE loan_id=?", (lid,))
        for i, amt in enumerate(amounts, start=1):
            c.execute("INSERT INTO loan_schedule (loan_id, installment_no, amount) VALUES (?,?,?)",
                      (lid, i, float(amt)))
        c.execute("UPDATE loans SET payment_mode='custom_schedule' WHERE id=?", (lid,))
    # Upsert the requested installment
    existing = c.execute("SELECT id FROM loan_schedule WHERE loan_id=? AND installment_no=?",
                         (lid, k)).fetchone()
    if existing:
        c.execute("UPDATE loan_schedule SET amount=? WHERE id=?", (new_amount, existing['id']))
    else:
        c.execute("INSERT INTO loan_schedule (loan_id, installment_no, amount) VALUES (?,?,?)",
                  (lid, k, new_amount))
    conn.commit()
    conn.close()
    return jsonify({"message": "Installment updated", "amount": new_amount})

# --- UPCOMING PAYMENTS / CALENDAR ---
@app.route('/api/loans/upcoming', methods=['GET'])
@require_auth
def upcoming_payments(current_user):
    """Return next payment due for each active loan, plus all future due dates."""
    days_ahead = int(request.args.get('days', 60))
    conn = get_db()
    loans = conn.execute("SELECT * FROM loans WHERE user_id = ? AND status = 'active'",
                         (current_user['id'],)).fetchall()
    conn.close()
    today = datetime.now().date()
    horizon = today + timedelta(days=days_ahead)
    out = []
    conn2 = get_db()
    try:
        for loan in loans:
            sd = datetime.strptime(loan['start_date'], '%Y-%m-%d').date()
            amounts = loan_schedule_amounts(conn2, loan)
            for k in range(1, loan['term_months'] + 1):
                ref = add_months(datetime.combine(sd, datetime.min.time()), k).date()
                try:
                    due = ref.replace(day=loan['payment_day'])
                except ValueError:
                    due = ref
                if due < today or due > horizon:
                    continue
                out.append({
                    "loan_id": loan['id'],
                    "loan_name": loan['name'],
                    "lender": loan['lender'],
                    "due_date": due.strftime('%Y-%m-%d'),
                    "amount": round(amounts[k-1] if k-1 < len(amounts) else 0),
                    "installment": k,
                    "of_total": loan['term_months']
                })
    finally:
        conn2.close()
    out.sort(key=lambda x: x['due_date'])
    return jsonify(out)

@app.route('/api/loans/calendar.ics', methods=['GET'])
@require_auth
def loans_ics(current_user):
    """Export all upcoming payments as iCalendar (.ics) file. Import into Google Calendar."""
    conn = get_db()
    loans = conn.execute("SELECT * FROM loans WHERE user_id = ? AND status = 'active'",
                         (current_user['id'],)).fetchall()
    conn.close()
    lines = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Cashflow//Loans//VI"]
    conn2 = get_db()
    for loan in loans:
        sd = datetime.strptime(loan['start_date'], '%Y-%m-%d').date()
        amounts = loan_schedule_amounts(conn2, loan)
        for k in range(1, loan['term_months'] + 1):
            ref = add_months(datetime.combine(sd, datetime.min.time()), k).date()
            try:
                due = ref.replace(day=loan['payment_day'])
            except ValueError:
                due = ref
            amt = round(amounts[k-1] if k-1 < len(amounts) else 0)
            uid = f"loan-{loan['id']}-inst-{k}@cashflow"
            dt = due.strftime('%Y%m%d')
            summary = f"Đóng {loan['name']} ({k}/{loan['term_months']}) - {amt:,}đ"
            desc = f"Khoản vay: {loan['name']} | Bên cho vay: {loan['lender']} | Số tiền: {amt:,}đ"
            lines += [
                "BEGIN:VEVENT",
                f"UID:{uid}",
                f"DTSTART;VALUE=DATE:{dt}",
                f"DTEND;VALUE=DATE:{dt}",
                f"SUMMARY:{summary}",
                f"DESCRIPTION:{desc}",
                "BEGIN:VALARM", "TRIGGER:-P2D", "ACTION:DISPLAY",
                f"DESCRIPTION:Còn 2 ngày: {summary}", "END:VALARM",
                "END:VEVENT",
            ]
    conn2.close()
    lines.append("END:VCALENDAR")
    body = "\r\n".join(lines)
    return body, 200, {
        'Content-Type': 'text/calendar; charset=utf-8',
        'Content-Disposition': 'attachment; filename="loans.ics"'
    }

# --- GENERATE PLAN (multi-loan) ---
@app.route('/api/generate_plan', methods=['POST'])
@require_auth
def generate_plan(current_user):
    """
    Generates weekly cashflow rows from ALL active loans.
    Each loan contributes its own weekly_deduction; payment hits on the week
    containing the loan's payment_day for that month.
    """
    data = request.json
    weekly_income = float(data.get('weekly_income', 600000))
    fixed_cost = float(data.get('fixed_cost', 50000))
    init_reserve = float(data.get('init_reserve', 0))
    # Optional: legacy single-loan path — auto-create a loan and continue
    if data.get('principal') and not data.get('skip_legacy'):
        conn0 = get_db()
        existing = conn0.execute("SELECT COUNT(*) c FROM loans WHERE user_id=?",
                                 (current_user['id'],)).fetchone()['c']
        conn0.close()
        if existing == 0:
            sd = data.get('start_date', datetime.now().strftime('%Y-%m-%d'))
            conn0 = get_db()
            conn0.execute("""INSERT INTO loans (user_id, name, principal, interest_rate, term_months,
                          start_date, payment_day, purpose, color, status, created_at)
                          VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                          (current_user['id'], 'Khoản vay 1', float(data['principal']),
                           float(data.get('interest_rate', 0)), int(data.get('term', 3)),
                           sd, int(data.get('payment_day', 1)), 'purchase', '#2962ff', 'active',
                           datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            conn0.commit()
            conn0.close()

    conn = get_db()
    c = conn.cursor()
    loans = c.execute("SELECT * FROM loans WHERE user_id = ? AND status = 'active' ORDER BY start_date ASC",
                      (current_user['id'],)).fetchall()
    if not loans:
        conn.close()
        return jsonify({"detail": "No active loans. Create a loan first via POST /api/loans"}), 400

    # Compute global plan window
    earliest_start = min(datetime.strptime(l['start_date'], '%Y-%m-%d') for l in loans)
    latest_end = max(add_months(datetime.strptime(l['start_date'], '%Y-%m-%d'), l['term_months'])
                     for l in loans)

    # Reset cashflows + items
    c.execute("DELETE FROM cashflow_loan_items WHERE cashflow_id IN (SELECT id FROM cashflows WHERE user_id=?)",
              (current_user['id'],))
    c.execute("DELETE FROM cashflows WHERE user_id = ?", (current_user['id'],))
    c.execute("DELETE FROM audit_log WHERE user_id = ?", (current_user['id'],))

    # Initial balance row
    init_date = (earliest_start - timedelta(days=1)).strftime('%Y-%m-%d')
    c.execute("""INSERT INTO cashflows (user_id, week_name, week_date, income, gas, debt_deduction, reserve_withdrawal, spending, payment, reserve_balance, debt_balance)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (current_user['id'], 'Số dư ban đầu', init_date, 0,0,0,0,0,0, init_reserve, 0))

    # Pre-compute per-loan params
    loan_params = []
    for l in loans:
        sd = datetime.strptime(l['start_date'], '%Y-%m-%d')
        amounts = loan_schedule_amounts(conn, l)
        total_payable = sum(amounts)
        avg_weekly_ded = total_payable / (l['term_months'] * 4.0)
        end_dt = add_months(sd, l['term_months'])
        due_dates = []
        for k in range(1, l['term_months'] + 1):
            ref = add_months(sd, k)
            try:
                due = ref.replace(day=l['payment_day'])
            except ValueError:
                due = ref
            due_dates.append(due.date())
        loan_params.append({
            'loan': l, 'start': sd, 'end': end_dt,
            'amounts': amounts,
            'total_payable': total_payable,
            'weekly_ded': avg_weekly_ded,
            'due_dates': due_dates,
            'remaining_balance': 0.0,
            'paid_count': 0,
        })

    # Walk weeks
    total_days = (latest_end - earliest_start).days
    total_weeks = (total_days // 7) + 1
    prev_res = init_reserve

    # Index loan_params by loan_id for refinance lookup
    lp_by_id = {lp['loan']['id']: lp for lp in loan_params}

    # Pre-compute: for each refinance loan, find the FIRST upcoming due date of its target
    # (after refinance loan's start_date) — that's when the refinance money is "spent"
    # to cover that installment of the target loan.
    for lp in loan_params:
        l = lp['loan']
        target_id = l['refinance_target_id'] if 'refinance_target_id' in l.keys() else None
        lp['refi_target_inst'] = None  # which installment_no of target this loan covers
        lp['refi_apply_date'] = None    # date when the cover happens
        if l['purpose'] == 'refinance' and target_id and target_id in lp_by_id:
            target = lp_by_id[target_id]
            # find first installment of target with due_date >= refinance loan start_date
            for k, due in enumerate(target['due_dates'], start=1):
                if due >= lp['start'].date():
                    lp['refi_target_inst'] = k
                    lp['refi_apply_date'] = due
                    break

    for w in range(1, total_weeks + 1):
        week_start = earliest_start + timedelta(weeks=w-1)
        week_end = week_start + timedelta(days=6)
        week_date_str = week_start.strftime('%Y-%m-%d')

        sum_ded = 0.0
        sum_payment = 0.0
        sum_debt = 0.0
        items = []  # (loan_id, weekly_ded, payment, debt_balance, is_pay_week, inst_no)

        # Refinance: when target loan's covered installment due_date falls in this week,
        # the refinance loan's principal pays for that installment of the target.
        # Map: target_loan_id -> {covered_amount, source_loan_name, target_inst_no}
        refinance_covers = {}
        for lp in loan_params:
            if (lp.get('refi_apply_date') and not lp.get('refinanced_done')
                    and week_start.date() <= lp['refi_apply_date'] <= week_end.date()):
                target = lp_by_id[lp['loan']['refinance_target_id']]
                inst_idx = lp['refi_target_inst'] - 1
                inst_amount = target['amounts'][inst_idx] if inst_idx < len(target['amounts']) else 0
                cover = min(float(lp['loan']['principal']), inst_amount)
                refinance_covers[target['loan']['id']] = {
                    'cover': cover,
                    'inst': lp['refi_target_inst'],
                    'source': lp['loan']['name'],
                }
                lp['refinanced_done'] = True

        for lp in loan_params:
            l = lp['loan']
            # Loan active this week if start <= week_end and not yet ended
            if lp['start'].date() > week_end.date() or lp['end'].date() <= week_start.date():
                continue
            # Weekly deduction accrues only while loan is active and not yet fully paid
            if lp['paid_count'] >= l['term_months']:
                weekly_ded = 0.0
            else:
                weekly_ded = lp['weekly_ded']
            lp['remaining_balance'] += weekly_ded

            # Payment if any due_date falls within this week (use per-installment amount)
            # Check if a refinance loan covers an installment of THIS loan in this week
            cover_info = refinance_covers.pop(l['id'], None)

            payment = 0.0          # what the user actually pays from income
            payment_covered = 0.0  # what was paid by refinance source (informational)
            is_pay_week = 0
            installment_no = 0
            for idx, d in enumerate(lp['due_dates']):
                if week_start.date() <= d <= week_end.date() and lp['paid_count'] < l['term_months']:
                    inst_amt = lp['amounts'][idx] if idx < len(lp['amounts']) else 0
                    # If this is the installment covered by a refinance loan, source covers it
                    if cover_info and cover_info['inst'] == idx + 1:
                        covered = min(cover_info['cover'], inst_amt)
                        payment_covered += covered
                        payment += inst_amt - covered  # user pays the rest (if any)
                    else:
                        payment += inst_amt
                    lp['paid_count'] += 1
                    is_pay_week = 1
                    installment_no = lp['paid_count']
            # Reduce remaining_balance by total paid (user + cover)
            lp['remaining_balance'] -= (payment + payment_covered)

            sum_ded += weekly_ded
            sum_payment += payment  # only user-paid amount affects cashflow sum
            sum_debt += lp['remaining_balance']
            # Encode covered amount in tuple by adding extra slot
            items.append((l['id'], weekly_ded, payment, lp['remaining_balance'], is_pay_week, installment_no, payment_covered, cover_info['source'] if cover_info else None))

        # Spending and reserve logic (same as before, but using sum)
        spending_raw = weekly_income - fixed_cost - sum_ded
        res_withdrawal = 0.0
        if spending_raw < 0 and prev_res > 0:
            res_withdrawal = min(prev_res, abs(spending_raw))
        spending = weekly_income - fixed_cost - sum_ded + res_withdrawal
        new_res = prev_res - res_withdrawal

        c.execute("""INSERT INTO cashflows (user_id, week_name, week_date, income, gas, debt_deduction, reserve_withdrawal, spending, payment, reserve_balance, debt_balance)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (current_user['id'], f'Tuần {w}', week_date_str, weekly_income, fixed_cost,
             sum_ded, res_withdrawal, spending, sum_payment, new_res, sum_debt))
        cashflow_id = c.lastrowid
        for (loan_id, wd, pay, bal, ipw, inst, covered, source) in items:
            c.execute("""INSERT INTO cashflow_loan_items (cashflow_id, loan_id, weekly_deduction, payment, debt_balance, is_payment_week, installment_no, payment_covered, cover_source)
                         VALUES (?,?,?,?,?,?,?,?,?)""", (cashflow_id, loan_id, wd, pay, bal, ipw, inst, covered, source))
        prev_res = new_res

    conn.commit()
    conn.close()
    return jsonify({
        "message": "Plan generated",
        "weeks": total_weeks,
        "loans_count": len(loans),
        "loans": [{"id": lp['loan']['id'], "name": lp['loan']['name'],
                   "schedule": [round(x) for x in lp['amounts']],
                   "total_payable": round(lp['total_payable'])}
                  for lp in loan_params]
    })

@app.route('/api/cashflows/<int:rid>/breakdown', methods=['GET'])
@require_auth
def cashflow_breakdown(current_user, rid):
    """Return per-loan items for a single cashflow row."""
    conn = get_db()
    rec = conn.execute("SELECT * FROM cashflows WHERE id=? AND user_id=?",
                       (rid, current_user['id'])).fetchone()
    if not rec:
        conn.close()
        return jsonify({"detail": "Not found"}), 404
    items = conn.execute("""SELECT i.*, l.name as loan_name, l.color as loan_color, l.lender
                            FROM cashflow_loan_items i JOIN loans l ON l.id = i.loan_id
                            WHERE i.cashflow_id = ?""", (rid,)).fetchall()
    conn.close()
    return jsonify([dict(x) for x in items])

# --- LOAD CSV (optional import) ---
def _import_csv_rows(user_id, reader):
    """Insert rows into cashflows for `user_id`. `reader` already past the header."""
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM cashflows WHERE user_id = ?", (user_id,))
    count = 0
    for row in reader:
        if not row or not row[0].strip():
            continue
        cols = list(row) + [''] * max(0, 9 - len(row))
        c.execute("""INSERT INTO cashflows (user_id, week_name, income, gas, debt_deduction, reserve_withdrawal, spending, payment, reserve_balance, debt_balance)
            VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (user_id, cols[0],
             float(cols[1]) if cols[1] else 0, float(cols[2]) if cols[2] else 0,
             float(cols[3]) if cols[3] else 0, float(cols[4]) if cols[4] else 0,
             float(cols[5]) if cols[5] else 0, float(cols[6]) if cols[6] else 0,
             float(cols[7]) if cols[7] else 0, float(cols[8]) if cols[8] else 0))
        count += 1
    conn.commit()
    conn.close()
    return count

@app.route('/api/import_csv', methods=['POST'])
@require_auth
def import_csv(current_user):
    csv_path = "Bang_Tinh_Dong_Tien.csv"
    if not os.path.exists(csv_path):
        return jsonify({"detail": "CSV file not found"}), 404
    with open(csv_path, mode='r', encoding='utf-8-sig') as f:
        reader = csv.reader(f)
        next(reader, None)
        n = _import_csv_rows(current_user['id'], reader)
    return jsonify({"message": "CSV imported", "rows": n})

@app.route('/api/import_csv_upload', methods=['POST'])
@require_auth
def import_csv_upload(current_user):
    """Import from a CSV file uploaded by the user (multipart/form-data, field name 'file')."""
    f = request.files.get('file')
    if not f:
        return jsonify({"detail": "No file uploaded"}), 400
    try:
        text = f.read().decode('utf-8-sig')
    except UnicodeDecodeError:
        return jsonify({"detail": "File must be UTF-8 encoded"}), 400
    reader = csv.reader(text.splitlines())
    next(reader, None)
    try:
        n = _import_csv_rows(current_user['id'], reader)
    except (ValueError, IndexError) as e:
        return jsonify({"detail": f"Invalid CSV format: {e}"}), 400
    if n == 0:
        return jsonify({"detail": "No valid rows found"}), 400
    return jsonify({"message": "CSV imported", "rows": n})

# --- HISTORY ---
@app.route('/api/history', methods=['GET'])
@require_auth
def get_history(current_user):
    conn = get_db()
    rows = conn.execute("SELECT * FROM audit_log WHERE user_id = ? ORDER BY id DESC LIMIT 50", (current_user['id'],)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# --- BANKS ---
@app.route('/api/banks', methods=['GET'])
@require_auth
def get_banks(current_user):
    show_hidden = request.args.get('all', '0') == '1'
    conn = get_db()
    if show_hidden:
        rows = conn.execute("SELECT * FROM banks WHERE user_id = ? ORDER BY id ASC", (current_user['id'],)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM banks WHERE user_id = ? AND is_hidden = 0 ORDER BY id ASC", (current_user['id'],)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/banks', methods=['POST'])
@require_auth
def add_bank(current_user):
    data = request.json
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO banks (user_id, name, role, color, created_at) VALUES (?,?,?,?,?)",
              (current_user['id'], data.get('name', 'New Bank'), data.get('role', ''),
               data.get('color', '#3b82f6'), datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit()
    conn.close()
    return jsonify({"message": "Bank added"})

@app.route('/api/banks/<int:bid>', methods=['PUT'])
@require_auth
def update_bank(current_user, bid):
    data = request.json
    conn = get_db()
    bank = conn.execute("SELECT * FROM banks WHERE id = ? AND user_id = ?", (bid, current_user['id'])).fetchone()
    if not bank:
        conn.close()
        return jsonify({"detail": "Not found"}), 404
    conn.execute("UPDATE banks SET name=?, role=?, color=?, is_hidden=? WHERE id=?",
                 (data.get('name', bank['name']), data.get('role', bank['role']),
                  data.get('color', bank['color']), int(data.get('is_hidden', bank['is_hidden'])), bid))
    conn.commit()
    conn.close()
    return jsonify({"message": "Bank updated"})

# --- ROUTES ---
@app.route('/')
def read_root():
    return send_from_directory('static', 'index.html')

@app.route('/index.html')
def read_index():
    return send_from_directory('static', 'index.html')

@app.route('/dashboard.html')
def read_dashboard():
    return send_from_directory('static', 'dashboard.html')

@app.route('/manifest.json')
def serve_manifest():
    return send_from_directory('static', 'manifest.json')

@app.route('/sw.js')
def serve_sw():
    return send_from_directory('static', 'sw.js')

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8000, debug=True)
