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

# --- GENERATE PLAN (core feature) ---
@app.route('/api/generate_plan', methods=['POST'])
@require_auth
def generate_plan(current_user):
    data = request.json
    principal = float(data.get('principal', 3168048))
    term = int(data.get('term', 3))
    rate = float(data.get('interest_rate', 3.67))
    weekly_income = float(data.get('weekly_income', 600000))
    fixed_cost = float(data.get('fixed_cost', 50000))
    init_reserve = float(data.get('init_reserve', 471001))
    start_date_str = data.get('start_date', datetime.now().strftime('%Y-%m-%d'))
    start_date = datetime.strptime(start_date_str, '%Y-%m-%d')

    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM cashflows WHERE user_id = ?", (current_user['id'],))
    c.execute("DELETE FROM audit_log WHERE user_id = ?", (current_user['id'],))

    # Monthly payment (EMI or flat)
    if rate > 0:
        r = rate / 100.0
        monthly_pay = principal * r * ((1+r)**term) / (((1+r)**term) - 1)
    else:
        monthly_pay = principal / term

    weekly_ded = monthly_pay / 4.0
    total_weeks = term * 4

    # Initial balance row
    init_date = (start_date - timedelta(days=1)).strftime('%Y-%m-%d')
    c.execute("""INSERT INTO cashflows (user_id, week_name, week_date, income, gas, debt_deduction, reserve_withdrawal, spending, payment, reserve_balance, debt_balance)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)""", (current_user['id'], 'Số dư ban đầu', init_date, 0,0,0,0,0,0, init_reserve, 0))

    prev_res = init_reserve
    prev_debt = 0.0

    for w in range(1, total_weeks + 1):
        week_dt = start_date + timedelta(weeks=w-1)
        week_date_str = week_dt.strftime('%Y-%m-%d')
        is_pay_week = (w % 4 == 0)
        payment = monthly_pay if is_pay_week else 0

        spending_raw = weekly_income - fixed_cost - weekly_ded
        res_withdrawal = 0
        if spending_raw < 0 and prev_res > 0:
            res_withdrawal = min(prev_res, abs(spending_raw))

        spending = weekly_income - fixed_cost - weekly_ded + res_withdrawal
        new_res = prev_res - res_withdrawal
        new_debt = prev_debt + weekly_ded - payment

        c.execute("""INSERT INTO cashflows (user_id, week_name, week_date, income, gas, debt_deduction, reserve_withdrawal, spending, payment, reserve_balance, debt_balance)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (current_user['id'], f'Tuần {w}', week_date_str, weekly_income, fixed_cost, weekly_ded, res_withdrawal, spending, payment, new_res, new_debt))
        prev_res = new_res
        prev_debt = new_debt

    conn.commit()
    conn.close()
    return jsonify({"message": "Plan generated", "weeks": total_weeks, "monthly_payment": round(monthly_pay)})

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

@app.route('/dashboard.html')
def read_dashboard():
    return send_from_directory('static', 'dashboard.html')

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8000, debug=True)
