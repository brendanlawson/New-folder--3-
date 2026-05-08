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
        created_at TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id))""")
    c.execute("""CREATE TABLE IF NOT EXISTS cashflow_loan_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cashflow_id INTEGER NOT NULL,
        loan_id INTEGER NOT NULL,
        weekly_deduction REAL DEFAULT 0,
        payment REAL DEFAULT 0,
        debt_balance REAL DEFAULT 0,
        is_payment_week INTEGER DEFAULT 0,
        FOREIGN KEY (cashflow_id) REFERENCES cashflows(id) ON DELETE CASCADE,
        FOREIGN KEY (loan_id) REFERENCES loans(id) ON DELETE CASCADE)""")
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
def calc_monthly_payment(principal, rate_pct, term_months):
    """EMI calculation, rate is monthly % (e.g., 3.67 means 3.67%/month)."""
    if term_months <= 0:
        return 0.0
    if rate_pct > 0:
        r = rate_pct / 100.0
        return principal * r * ((1+r)**term_months) / (((1+r)**term_months) - 1)
    return principal / term_months

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
    conn.close()
    out = []
    for r in rows:
        d = dict(r)
        d['monthly_payment'] = round(calc_monthly_payment(d['principal'], d['interest_rate'], d['term_months']))
        # end date = start + term months
        try:
            sd = datetime.strptime(d['start_date'], '%Y-%m-%d')
            d['end_date'] = add_months(sd, d['term_months']).strftime('%Y-%m-%d')
        except Exception:
            d['end_date'] = None
        out.append(d)
    return jsonify(out)

@app.route('/api/loans', methods=['POST'])
@require_auth
def create_loan(current_user):
    data = request.json
    name = data.get('name', 'Khoản vay')
    principal = float(data.get('principal', 0))
    rate = float(data.get('interest_rate', 0))
    term = int(data.get('term_months', 3))
    if term not in (3, 6, 9, 12) and term <= 0:
        return jsonify({"detail": "term_months must be > 0"}), 400
    start_date = data.get('start_date', datetime.now().strftime('%Y-%m-%d'))
    payment_day = int(data.get('payment_day', 1))
    if payment_day < 1 or payment_day > 28:
        return jsonify({"detail": "payment_day must be 1..28"}), 400
    lender = data.get('lender', '')
    purpose = data.get('purpose', 'purchase')  # 'purchase' | 'refinance'
    refinance_target_id = data.get('refinance_target_id')
    color = data.get('color', '#2962ff')
    notify = int(data.get('notify_email', 1))

    conn = get_db()
    c = conn.cursor()
    c.execute("""INSERT INTO loans (user_id, name, principal, interest_rate, term_months,
                 start_date, payment_day, lender, purpose, refinance_target_id, color,
                 status, notify_email, created_at)
                 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
              (current_user['id'], name, principal, rate, term, start_date, payment_day,
               lender, purpose, refinance_target_id, color, 'active', notify,
               datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    new_id = c.lastrowid
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
              'payment_day', 'lender', 'purpose', 'color', 'status', 'notify_email']
    updates = {f: data.get(f, loan[f]) for f in fields}
    conn.execute("""UPDATE loans SET name=?, principal=?, interest_rate=?, term_months=?,
                    start_date=?, payment_day=?, lender=?, purpose=?, color=?, status=?,
                    notify_email=? WHERE id=?""",
                 (updates['name'], float(updates['principal']), float(updates['interest_rate']),
                  int(updates['term_months']), updates['start_date'], int(updates['payment_day']),
                  updates['lender'], updates['purpose'], updates['color'], updates['status'],
                  int(updates['notify_email']), lid))
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
    for loan in loans:
        sd = datetime.strptime(loan['start_date'], '%Y-%m-%d').date()
        monthly = calc_monthly_payment(loan['principal'], loan['interest_rate'], loan['term_months'])
        for k in range(1, loan['term_months'] + 1):
            # k-th payment due: start_date + k months, on payment_day of that month
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
                "amount": round(monthly),
                "installment": k,
                "of_total": loan['term_months']
            })
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
    for loan in loans:
        sd = datetime.strptime(loan['start_date'], '%Y-%m-%d').date()
        monthly = round(calc_monthly_payment(loan['principal'], loan['interest_rate'], loan['term_months']))
        for k in range(1, loan['term_months'] + 1):
            ref = add_months(datetime.combine(sd, datetime.min.time()), k).date()
            try:
                due = ref.replace(day=loan['payment_day'])
            except ValueError:
                due = ref
            uid = f"loan-{loan['id']}-inst-{k}@cashflow"
            dt = due.strftime('%Y%m%d')
            summary = f"Đóng {loan['name']} ({k}/{loan['term_months']}) - {monthly:,}đ"
            desc = f"Khoản vay: {loan['name']} | Bên cho vay: {loan['lender']} | Số tiền: {monthly:,}đ"
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
        monthly = calc_monthly_payment(l['principal'], l['interest_rate'], l['term_months'])
        end_dt = add_months(sd, l['term_months'])
        # Compute payment due dates (date when payment is due)
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
            'monthly': monthly, 'weekly_ded': monthly / 4.0,
            'due_dates': due_dates,
            'remaining_balance': 0.0,
            'paid_count': 0,
        })

    # Walk weeks
    total_days = (latest_end - earliest_start).days
    total_weeks = (total_days // 7) + 1
    prev_res = init_reserve

    for w in range(1, total_weeks + 1):
        week_start = earliest_start + timedelta(weeks=w-1)
        week_end = week_start + timedelta(days=6)
        week_date_str = week_start.strftime('%Y-%m-%d')

        sum_ded = 0.0
        sum_payment = 0.0
        sum_debt = 0.0
        items = []  # (loan_id, weekly_ded, payment, debt_balance, is_pay_week)

        for lp in loan_params:
            l = lp['loan']
            # Loan active this week if start <= week_end and not yet ended
            if lp['start'].date() > week_end.date() or lp['end'].date() <= week_start.date():
                # Not active in this week — but include with 0 if there is balance from past payments? No: skip
                # Still emit row only if loan ever produced balance (skip if completely outside window)
                continue
            # Weekly deduction accrues only while loan is active and not yet fully paid
            if lp['paid_count'] >= l['term_months']:
                weekly_ded = 0.0
            else:
                weekly_ded = lp['weekly_ded']
            lp['remaining_balance'] += weekly_ded

            # Payment if any due_date falls within this week
            payment = 0.0
            is_pay_week = 0
            for d in lp['due_dates']:
                if week_start.date() <= d <= week_end.date() and lp['paid_count'] < l['term_months']:
                    payment += lp['monthly']
                    lp['paid_count'] += 1
                    is_pay_week = 1
            lp['remaining_balance'] -= payment

            sum_ded += weekly_ded
            sum_payment += payment
            sum_debt += lp['remaining_balance']
            items.append((l['id'], weekly_ded, payment, lp['remaining_balance'], is_pay_week))

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
        for (loan_id, wd, pay, bal, ipw) in items:
            c.execute("""INSERT INTO cashflow_loan_items (cashflow_id, loan_id, weekly_deduction, payment, debt_balance, is_payment_week)
                         VALUES (?,?,?,?,?,?)""", (cashflow_id, loan_id, wd, pay, bal, ipw))
        prev_res = new_res

    conn.commit()
    conn.close()
    return jsonify({
        "message": "Plan generated",
        "weeks": total_weeks,
        "loans_count": len(loans),
        "loans": [{"id": l['id'], "name": l['name'],
                   "monthly_payment": round(calc_monthly_payment(l['principal'], l['interest_rate'], l['term_months']))}
                  for l in loans]
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
@app.route('/api/import_csv', methods=['POST'])
@require_auth
def import_csv(current_user):
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM cashflows WHERE user_id = ?", (current_user['id'],))
    csv_path = "Bang_Tinh_Dong_Tien.csv"
    if not os.path.exists(csv_path):
        conn.close()
        return jsonify({"detail": "CSV file not found"}), 404
    with open(csv_path, mode='r', encoding='utf-8') as f:
        reader = csv.reader(f)
        next(reader)
        for row in reader:
            if not row or not row[0].strip():
                continue
            c.execute("""INSERT INTO cashflows (user_id, week_name, income, gas, debt_deduction, reserve_withdrawal, spending, payment, reserve_balance, debt_balance)
                VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (current_user['id'], row[0],
                 float(row[1]) if row[1] else 0, float(row[2]) if row[2] else 0,
                 float(row[3]) if row[3] else 0, float(row[4]) if row[4] else 0,
                 float(row[5]) if row[5] else 0, float(row[6]) if row[6] else 0,
                 float(row[7]) if row[7] else 0, float(row[8]) if row[8] else 0))
    conn.commit()
    conn.close()
    return jsonify({"message": "CSV imported"})

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
