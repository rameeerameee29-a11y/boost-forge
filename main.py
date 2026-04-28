import sqlite3
import random
import json
import os
import re
import time
import secrets as _secrets
from functools import wraps
from datetime import datetime, timedelta
from urllib.parse import urlparse
from flask import Flask, render_template, request, redirect, url_for, session, abort
from werkzeug.security import generate_password_hash, check_password_hash

# ============== DATABASE ABSTRACTION (SQLite dev / PostgreSQL prod) ==============
_DATABASE_URL = os.environ.get('DATABASE_URL', '')
if _DATABASE_URL.startswith('postgres://'):
    _DATABASE_URL = _DATABASE_URL.replace('postgres://', 'postgresql://', 1)

IS_PG = bool(_DATABASE_URL)

if IS_PG:
    import psycopg2
    import psycopg2.extras
    def db_conn():
        return psycopg2.connect(_DATABASE_URL)
else:
    def db_conn():
        return sqlite3.connect('database.db')

def q(sql):
    if IS_PG:
        return sql.replace('?', '%s')
    return sql

def db_insert(cursor, sql, params):
    if IS_PG:
        cursor.execute(q(sql) + ' RETURNING id', params)
        return cursor.fetchone()[0]
    else:
        cursor.execute(sql, params)
        return cursor.lastrowid

def is_unique_error(e):
    msg = str(e).lower()
    return 'unique' in msg or 'duplicate' in msg

app = Flask(__name__)

# ============== SECURITY: persistent strong secret key ==============
def _load_secret_key():
    env_key = os.environ.get('FLASK_SECRET_KEY')
    if env_key and len(env_key) >= 32:
        return env_key
    key_file = os.path.join(os.path.dirname(__file__), '.secret_key')
    if os.path.exists(key_file):
        try:
            with open(key_file, 'r') as f:
                k = f.read().strip()
                if len(k) >= 32:
                    return k
        except Exception:
            pass
    new_key = _secrets.token_urlsafe(48)
    try:
        with open(key_file, 'w') as f:
            f.write(new_key)
        os.chmod(key_file, 0o600)
    except Exception:
        pass
    return new_key

app.secret_key = _load_secret_key()

# ============== SECURITY: cookie + session hardening ==============
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False,  # Replit dev runs over HTTP in iframe; production proxy adds HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,  # 2MB max request — protects against huge POST DoS
)

ADMIN_EMAILS = {'rameeerameee29@gmail.com'}

EMAIL_RE = re.compile(r'^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$')

# ============== SECURITY: rate limiting (in-memory) ==============
_rate_buckets = {}
def _rate_limit(key, max_attempts, window_seconds):
    now = time.time()
    bucket = _rate_buckets.get(key, [])
    bucket = [t for t in bucket if now - t < window_seconds]
    if len(bucket) >= max_attempts:
        return False
    bucket.append(now)
    _rate_buckets[key] = bucket
    return True

def _client_ip():
    fwd = request.headers.get('X-Forwarded-For', '')
    if fwd:
        return fwd.split(',')[0].strip()
    return request.remote_addr or 'unknown'

# ============== SECURITY: CSRF via Origin/Referer ==============
SAFE_METHODS = {'GET', 'HEAD', 'OPTIONS'}

def _base_domain(netloc):
    host = netloc.split(':')[0].lower()
    if host.startswith('www.'):
        host = host[4:]
    return host

@app.before_request
def _csrf_protect():
    if request.method in SAFE_METHODS:
        return
    origin = request.headers.get('Origin') or request.headers.get('Referer')
    if not origin:
        return
    try:
        o = urlparse(origin)
        if o.netloc:
            req_base = _base_domain(request.host)
            ori_base = _base_domain(o.netloc)
            if req_base and ori_base and req_base != ori_base:
                abort(403)
    except Exception:
        pass

# ============== SECURITY: response headers ==============
@app.after_request
def _security_headers(resp):
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')
    resp.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    resp.headers.setdefault('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
    resp.headers.setdefault('X-XSS-Protection', '1; mode=block')
    return resp

# ============== SECURITY: auth decorators ==============
def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if 'user_email' not in session:
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return wrapper

def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if 'user_email' not in session:
            return redirect(url_for('login'))
        if session.get('user_email') not in ADMIN_EMAILS:
            abort(403)
        return view(*args, **kwargs)
    return wrapper

def _is_hashed(pw):
    return bool(pw) and (pw.startswith('pbkdf2:') or pw.startswith('scrypt:') or pw.startswith('argon2'))

# دالة إنشاء قاعدة البيانات بالجداول الصحيحة
def init_db():
    conn = db_conn()
    c = conn.cursor()
    if IS_PG:
        c.execute('''CREATE TABLE IF NOT EXISTS referral_codes
                     (id SERIAL PRIMARY KEY,
                      code TEXT UNIQUE,
                      is_active INTEGER DEFAULT 1)''')
        c.execute('''CREATE TABLE IF NOT EXISTS users 
                     (id SERIAL PRIMARY KEY, 
                      user_id_tag TEXT,
                      name TEXT, 
                      email TEXT UNIQUE, 
                      password TEXT, 
                      balance FLOAT DEFAULT 0.0,
                      pin TEXT)''')
        c.execute("SELECT column_name FROM information_schema.columns WHERE table_name='users'")
        cols = [r[0] for r in c.fetchall()]
        if 'pin' not in cols:
            c.execute("ALTER TABLE users ADD COLUMN pin TEXT")
        c.execute('''CREATE TABLE IF NOT EXISTS orders
                     (id SERIAL PRIMARY KEY,
                      user_email TEXT,
                      order_type TEXT,
                      title TEXT,
                      details TEXT,
                      amount FLOAT DEFAULT 0,
                      whatsapp TEXT,
                      status TEXT DEFAULT 'pending',
                      created_at TEXT)''')
        c.execute("SELECT column_name FROM information_schema.columns WHERE table_name='orders'")
        order_cols = [r[0] for r in c.fetchall()]
        if 'admin_note' not in order_cols:
            c.execute("ALTER TABLE orders ADD COLUMN admin_note TEXT")
        if 'balance_applied' not in order_cols:
            c.execute("ALTER TABLE orders ADD COLUMN balance_applied INTEGER DEFAULT 0")
    else:
        c.execute('''CREATE TABLE IF NOT EXISTS referral_codes
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      code TEXT UNIQUE,
                      is_active INTEGER DEFAULT 1)''')
        c.execute('''CREATE TABLE IF NOT EXISTS users 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                      user_id_tag TEXT,
                      name TEXT, 
                      email TEXT UNIQUE, 
                      password TEXT, 
                      balance REAL DEFAULT 0.0,
                      pin TEXT)''')
        cols = [r[1] for r in c.execute("PRAGMA table_info(users)").fetchall()]
        if 'pin' not in cols:
            c.execute("ALTER TABLE users ADD COLUMN pin TEXT")
        c.execute('''CREATE TABLE IF NOT EXISTS orders
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      user_email TEXT,
                      order_type TEXT,
                      title TEXT,
                      details TEXT,
                      amount REAL DEFAULT 0,
                      whatsapp TEXT,
                      status TEXT DEFAULT 'pending',
                      created_at TEXT)''')
        order_cols = [r[1] for r in c.execute("PRAGMA table_info(orders)").fetchall()]
        if 'admin_note' not in order_cols:
            c.execute("ALTER TABLE orders ADD COLUMN admin_note TEXT")
        if 'balance_applied' not in order_cols:
            c.execute("ALTER TABLE orders ADD COLUMN balance_applied INTEGER DEFAULT 0")
    conn.commit()
    conn.close()

init_db()

def save_order(user_email, order_type, title, details, amount=0, whatsapp=''):
    """Save order. For non-payment orders: deduct balance immediately if user is logged in.
       Returns ('ok', order_id), ('insufficient', current_balance), ('guest', None) or ('error', None)."""
    if not user_email:
        try:
            conn = db_conn()
            c = conn.cursor()
            oid = db_insert(c, """INSERT INTO orders (user_email, order_type, title, details, amount, whatsapp, status, created_at, balance_applied)
                         VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, 0)""",
                      (user_email, order_type, title, details, amount, whatsapp,
                       datetime.now().strftime('%Y-%m-%d %H:%M')))
            conn.commit()
            conn.close()
            return ('guest', oid)
        except Exception as e:
            print(f"Order save error: {e}")
            return ('error', None)
    try:
        conn = db_conn()
        c = conn.cursor()
        applied = 0
        if order_type != 'payment' and amount and amount > 0:
            c.execute(q("SELECT COALESCE(balance,0) FROM users WHERE email=?"), (user_email,))
            row = c.fetchone()
            current_balance = float(row[0]) if row else 0.0
            if current_balance < amount:
                conn.close()
                return ('insufficient', current_balance)
            c.execute(q("UPDATE users SET balance=COALESCE(balance,0)-? WHERE email=?"), (amount, user_email))
            applied = 1
        oid = db_insert(c, """INSERT INTO orders (user_email, order_type, title, details, amount, whatsapp, status, created_at, balance_applied)
                     VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)""",
                  (user_email, order_type, title, details, amount, whatsapp,
                   datetime.now().strftime('%Y-%m-%d %H:%M'), applied))
        conn.commit()
        conn.close()
        return ('ok', oid)
    except Exception as e:
        print(f"Order save error: {e}")
        return ('error', None)

def get_user_by_email(email):
    conn = db_conn()
    c = conn.cursor()
    c.execute(q("SELECT name, balance, user_id_tag, pin FROM users WHERE email=?"), (email,))
    row = c.fetchone()
    conn.close()
    return row

@app.route('/')
def home():
    user_data = None
    is_admin = False
    if 'user_email' in session:
        try:
            user_data = get_user_by_email(session['user_email'])
            is_admin = session['user_email'] in ADMIN_EMAILS
        except Exception as e:
            print(f"Error: {e}")
    referral_msg = session.pop('referral_msg', None)
    referral_code = session.get('referral_code', '')
    return render_template('index.html', user=user_data, is_admin=is_admin,
                           referral_msg=referral_msg, referral_code=referral_code)

@app.route('/about')
def about():
    return render_template('about.html')

def load_games():
    path = os.path.join(os.path.dirname(__file__), 'data', 'games_services.json')
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Games load error: {e}")
        return []

@app.route('/games')
def games():
    games_list = load_games()
    return render_template('games.html', games=games_list)

@app.route('/games/<int:game_id>', methods=['GET', 'POST'])
def game_detail(game_id):
    games_list = load_games()
    game = next((g for g in games_list if g['id'] == game_id), None)
    if not game:
        return redirect(url_for('games'))
    if request.method == 'POST':
        pkg_id = request.form.get('package_id', '')
        pid = request.form.get('player_id', '')
        wa = request.form.get('whatsapp', '')
        pkg = next((p for p in game['packages'] if p['id'] == pkg_id), None)
        if not pkg:
            return redirect(url_for('game_detail', game_id=game_id))
        details = (f"الباقة: {pkg['label']}\n"
                   f"معرّف اللاعب: {pid}")
        result, info = save_order(session.get('user_email'), 'game',
                   f"{game['name']} - {pkg['label']}", details,
                   amount=float(pkg['price']), whatsapp=wa)
        if result == 'insufficient':
            session['flash'] = f"رصيدك ${info:.2f} لا يكفي. سعر الطلب ${pkg['price']:.2f}. اشحن رصيدك أولاً."
            return redirect(url_for('payment'))
        msg = (f"طلب جديد من BoostForge\n"
               f"اللعبة: {game['name']}\n"
               f"الباقة: {pkg['label']}\n"
               f"السعر: {pkg['price']}$\n"
               f"معرّف اللاعب: {pid}\n"
               f"واتساب التواصل: {wa}")
        from urllib.parse import quote
        return redirect(f"https://wa.me/96171484779?text={quote(msg)}")
    return render_template('game_detail.html', game=game)

@app.route('/accounts')
def accounts():
    return render_template('accounts.html')

NETFLIX_PLANS = {
    ('low', '1m'): ('نتفلكس Low - 1 شهر', 1.0),
    ('low', '3m'): ('نتفلكس Low - 3 أشهر', 3.0),
    ('low', '6m'): ('نتفلكس Low - 6 أشهر', 6.0),
    ('low', '12m'): ('نتفلكس Low - 12 شهر', 12.0),
    ('high', '1m'): ('نتفلكس High - 1 شهر', 1.6),
    ('high', '3m'): ('نتفلكس High - 3 أشهر', 4.5),
    ('high', '6m'): ('نتفلكس High - 6 أشهر', 9.8),
    ('high', '12m'): ('نتفلكس High - 12 شهر', 15.0),
}
SHAHID_PLANS = {
    ('low', '1m'): ('شاهد Low - 1 شهر', 0.6),
    ('low', '3m'): ('شاهد Low - 3 أشهر', 1.3),
    ('low', '6m'): ('شاهد Low - 6 أشهر', 2.4),
    ('low', '12m'): ('شاهد Low - 12 شهر', 4.0),
    ('high', '1m'): ('شاهد High - 1 شهر', 1.0),
    ('high', '3m'): ('شاهد High - 3 أشهر', 3.0),
    ('high', '6m'): ('شاهد High - 6 أشهر', 5.0),
    ('high', '12m'): ('شاهد High - 12 شهر', 7.0),
}

def _get_referral_discount():
    code = session.get('referral_code')
    if not code:
        return 0.0
    try:
        conn = db_conn()
        c = conn.cursor()
        c.execute(q("SELECT is_active FROM referral_codes WHERE code=?"), (code,))
        row = c.fetchone()
        conn.close()
        if row and row[0]:
            return 0.20
    except Exception:
        pass
    return 0.0

def _account_order(service_label, plans, template_name):
    referral_discount = _get_referral_discount()
    if request.method == 'POST':
        tier = request.form.get('tier', '')
        plan = request.form.get('plan', '')
        wa = request.form.get('whatsapp', '').strip()
        info = plans.get((tier, plan))
        if info:
            label, orig_price = info
            price = round(orig_price * (1 - referral_discount), 2) if referral_discount else orig_price
            details = f"الاشتراك: {label}" + (f"\nكود إحالة: {session.get('referral_code')} (خصم 20%)" if referral_discount else "")
            result, info2 = save_order(session.get('user_email'), 'account',
                                       label, details, amount=price, whatsapp=wa)
            if result == 'insufficient':
                session['flash'] = f"رصيدك ${info2:.2f} لا يكفي. سعر الاشتراك ${price:.2f}. اشحن رصيدك أولاً."
                return redirect(url_for('payment'))
            from urllib.parse import quote
            msg = (f"طلب اشتراك جديد - BoostForge\n"
                   f"الخدمة: {label}\n"
                   f"السعر: {price}$" + (f" (خصم 20%)" if referral_discount else "") + f"\n"
                   f"واتساب التواصل: {wa}")
            return redirect(f"https://wa.me/96171484779?text={quote(msg)}")
    return render_template(template_name, referral_discount=referral_discount,
                           referral_code=session.get('referral_code', ''))

@app.route('/accounts/netflix', methods=['GET', 'POST'])
def netflix():
    return _account_order('نتفلكس', NETFLIX_PLANS, 'netflix.html')

@app.route('/accounts/shahid', methods=['GET', 'POST'])
def shahid():
    return _account_order('شاهد', SHAHID_PLANS, 'shahid.html')

@app.route('/apply-referral', methods=['POST'])
def apply_referral():
    code = (request.form.get('referral_code') or '').strip().upper()
    if not code:
        session.pop('referral_code', None)
        session['referral_msg'] = ('err', 'الكود فارغ')
        return redirect(url_for('home'))
    try:
        conn = db_conn()
        c = conn.cursor()
        c.execute(q("SELECT is_active FROM referral_codes WHERE code=?"), (code,))
        row = c.fetchone()
        conn.close()
        if row and row[0]:
            session['referral_code'] = code
            session['referral_msg'] = ('ok', f'تم تطبيق كود الإحالة! خصم 20% على الحسابات ✓')
        else:
            session.pop('referral_code', None)
            session['referral_msg'] = ('err', 'الكود غير صحيح أو غير نشط')
    except Exception as e:
        session['referral_msg'] = ('err', 'حدث خطأ، حاول مجدداً')
    return redirect(url_for('home'))

@app.route('/remove-referral', methods=['POST'])
def remove_referral():
    session.pop('referral_code', None)
    session.pop('referral_msg', None)
    return redirect(url_for('home'))

@app.route('/admin/referrals', methods=['GET', 'POST'])
@admin_required
def admin_referrals():
    conn = db_conn()
    c = conn.cursor()
    msg = None
    err = None
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add':
            code = (request.form.get('code') or '').strip().upper()
            if code:
                try:
                    db_insert(c, "INSERT INTO referral_codes (code, is_active) VALUES (?, 1)", (code,))
                    conn.commit()
                    msg = f'تم إضافة الكود: {code}'
                except Exception as e:
                    if is_unique_error(e):
                        err = 'هذا الكود موجود مسبقاً'
                    else:
                        err = f'خطأ: {e}'
        elif action == 'toggle':
            rid = request.form.get('rid')
            c.execute(q("UPDATE referral_codes SET is_active = CASE WHEN is_active=1 THEN 0 ELSE 1 END WHERE id=?"), (rid,))
            conn.commit()
            msg = 'تم تغيير حالة الكود'
        elif action == 'delete':
            rid = request.form.get('rid')
            c.execute(q("DELETE FROM referral_codes WHERE id=?"), (rid,))
            conn.commit()
            msg = 'تم حذف الكود'
    c.execute("SELECT id, code, is_active FROM referral_codes ORDER BY id DESC")
    codes = c.fetchall()
    conn.close()
    return render_template('admin_referrals.html', codes=codes, msg=msg, err=err)

def load_smm_services():
    path = os.path.join(os.path.dirname(__file__), 'data', 'smm_services.json')
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"SMM load error: {e}")
        return {}

@app.route('/smm', methods=['GET', 'POST'])
def smm():
    data = load_smm_services()
    categories = sorted(data.keys())
    if request.method == 'POST':
        cat = request.form.get('category', '')
        sname = request.form.get('service_name', '')
        link = request.form.get('link', '').strip()
        qty = request.form.get('quantity', '0')
        wa = request.form.get('whatsapp', '').strip()
        try:
            qty_n = int(float(qty))
        except Exception:
            qty_n = 0
        svc = next((s for s in data.get(cat, []) if s['name'] == sname), None)
        if svc and qty_n > 0:
            total = round(qty_n * svc['price'] / 1000.0, 4)
            details = (f"القسم: {cat}\n"
                       f"الكمية: {qty_n:,}\n"
                       f"الرابط: {link}")
            result, info = save_order(session.get('user_email'), 'smm',
                       sname, details, amount=total, whatsapp=wa)
            if result == 'insufficient':
                session['flash'] = f"رصيدك ${info:.2f} لا يكفي. سعر الطلب ${total:.4f}. اشحن رصيدك أولاً."
                return redirect(url_for('payment'))
            from urllib.parse import quote
            msg = (f"طلب SMM جديد من BoostForge\n"
                   f"الخدمة: {sname}\n"
                   f"الكمية: {qty_n:,}\n"
                   f"الرابط: {link}\n"
                   f"السعر الإجمالي: {total}$\n"
                   f"واتساب التواصل: {wa}")
            return redirect(f"https://wa.me/96171484779?text={quote(msg)}")
    return render_template('smm.html', categories=categories, data=data)

def load_apps():
    path = os.path.join(os.path.dirname(__file__), 'data', 'apps_services.json')
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Apps load error: {e}")
        return []

@app.route('/apps')
def apps_page():
    apps = load_apps()
    apps = sorted(apps, key=lambda a: a['name'].lower())
    return render_template('apps.html', apps=apps)

@app.route('/apps/<int:app_id>', methods=['GET', 'POST'])
def app_detail(app_id):
    apps = load_apps()
    app_item = next((a for a in apps if a['id'] == app_id), None)
    if not app_item:
        return redirect(url_for('apps_page'))
    if request.method == 'POST':
        qty = request.form.get('quantity', '0')
        pid = request.form.get('player_id', '')
        wa = request.form.get('whatsapp', '')
        try:
            qty_n = int(float(qty))
        except Exception:
            qty_n = 0
        total = round(qty_n * (app_item.get('markup_perc') or 0), 2)
        details = (f"الكمية: {qty_n:,}\n"
                   f"المعرّف: {pid}")
        result, info = save_order(session.get('user_email'), 'app',
                   f"{app_item['name']}", details,
                   amount=total, whatsapp=wa)
        if result == 'insufficient':
            session['flash'] = f"رصيدك ${info:.2f} لا يكفي. سعر الطلب ${total:.2f}. اشحن رصيدك أولاً."
            return redirect(url_for('payment'))
        msg = (f"طلب جديد من BoostForge\n"
               f"التطبيق: {app_item['name']}\n"
               f"الكمية: {qty_n:,}\n"
               f"المعرّف: {pid}\n"
               f"السعر الإجمالي: {total}$")
        from urllib.parse import quote
        return redirect(f"https://wa.me/96171484779?text={quote(msg)}")
    return render_template('app_detail.html', app=app_item)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''
        # Rate limit: 8 attempts per 10 minutes per IP+email
        rl_key = f"login:{_client_ip()}:{email}"
        if not _rate_limit(rl_key, max_attempts=8, window_seconds=600):
            error = "محاولات كثيرة. حاول لاحقًا بعد 10 دقائق."
            return render_template('login.html', error=error)
        if not EMAIL_RE.match(email) or not password:
            error = "البريد الإلكتروني أو كلمة المرور غير صحيحة"
            return render_template('login.html', error=error)
        conn = db_conn()
        c = conn.cursor()
        c.execute(q("SELECT email, pin, password FROM users WHERE email=?"), (email,))
        row = c.fetchone()
        ok = False
        if row:
            user_email, user_pin, stored_pw = row
            if _is_hashed(stored_pw):
                ok = check_password_hash(stored_pw, password)
            else:
                # Legacy plaintext: verify and auto-migrate to hashed
                if stored_pw == password:
                    ok = True
                    new_hash = generate_password_hash(password)
                    c.execute(q("UPDATE users SET password=? WHERE email=?"), (new_hash, user_email))
                    conn.commit()
        conn.close()
        if ok:
            # Anti-fixation: clear and regenerate session
            session.clear()
            if user_pin:
                session['pending_2fa_email'] = user_email
                return redirect(url_for('verify_pin'))
            session['user_email'] = user_email
            session.permanent = True
            app.permanent_session_lifetime = timedelta(days=30)
            return redirect(url_for('home'))
        error = "البريد الإلكتروني أو كلمة المرور غير صحيحة"
    return render_template('login.html', error=error)

@app.route('/verify-pin', methods=['GET', 'POST'])
def verify_pin():
    pending = session.get('pending_2fa_email')
    if not pending:
        return redirect(url_for('login'))
    error = None
    if request.method == 'POST':
        rl_key = f"pin:{_client_ip()}:{pending}"
        if not _rate_limit(rl_key, max_attempts=6, window_seconds=600):
            session.pop('pending_2fa_email', None)
            return redirect(url_for('login'))
        entered = request.form.get('pin', '').strip()
        conn = db_conn()
        c = conn.cursor()
        c.execute(q("SELECT pin FROM users WHERE email=?"), (pending,))
        row = c.fetchone()
        conn.close()
        if row and row[0] and entered and _secrets.compare_digest(entered, row[0]):
            session.pop('pending_2fa_email', None)
            session['user_email'] = pending
            session.permanent = True
            app.permanent_session_lifetime = timedelta(days=30)
            return redirect(url_for('home'))
        error = "رمز PIN غير صحيح"
    return render_template('verify_pin.html', error=error)

@app.route('/security', methods=['GET', 'POST'])
@login_required
def security():
    email = session['user_email']
    user = get_user_by_email(email)
    if not user:
        session.clear()
        return redirect(url_for('login'))
    name, balance, tag, current_pin = user
    msg = None
    err = None
    if request.method == 'POST':
        rl_key = f"security:{_client_ip()}:{email}"
        if not _rate_limit(rl_key, max_attempts=10, window_seconds=600):
            err = "محاولات كثيرة. حاول لاحقًا."
            return render_template('security.html', user=(name, balance, tag, current_pin), msg=msg, err=err)
        action = request.form.get('action')
        password = request.form.get('password', '')
        conn = db_conn()
        c = conn.cursor()
        c.execute(q("SELECT password FROM users WHERE email=?"), (email,))
        prow = c.fetchone()
        ok = False
        if prow:
            stored = prow[0]
            if _is_hashed(stored):
                ok = check_password_hash(stored, password)
            else:
                ok = (stored == password)
        if not ok:
            err = "كلمة المرور غير صحيحة"
        else:
            if action == 'enable':
                pin = request.form.get('pin', '').strip()
                pin2 = request.form.get('pin_confirm', '').strip()
                if not pin.isdigit() or len(pin) < 4 or len(pin) > 8:
                    err = "PIN يجب أن يكون أرقامًا فقط (4 إلى 8 خانات)"
                elif pin != pin2:
                    err = "تأكيد PIN غير مطابق"
                else:
                    c.execute(q("UPDATE users SET pin=? WHERE email=?"), (pin, email))
                    conn.commit()
                    current_pin = pin
                    msg = "تم تفعيل التحقق بخطوتين بنجاح"
            elif action == 'disable':
                c.execute(q("UPDATE users SET pin=NULL WHERE email=?"), (email,))
                conn.commit()
                current_pin = None
                msg = "تم إلغاء التحقق بخطوتين"
        conn.close()
    return render_template('security.html', user=(name, balance, tag, current_pin), msg=msg, err=err)

@app.route('/payment', methods=['GET', 'POST'])
def payment():
    user_data = None
    if 'user_email' in session:
        try:
            user_data = get_user_by_email(session['user_email'])
        except Exception as e:
            print(f"Error: {e}")
    flash = session.pop('flash', None)
    if request.method == 'POST':
        amount = request.form.get('amount', '').strip()
        sender_name = request.form.get('sender_name', '').strip()
        note = request.form.get('note', '').strip()
        try:
            amount_n = float(amount)
        except Exception:
            amount_n = 0
        details = (f"الاسم: {sender_name}\n"
                   f"ملاحظات: {note or '-'}")
        save_order(session.get('user_email'), 'payment',
                   f"شحن رصيد - Whish Money", details,
                   amount=amount_n, whatsapp='')
        session.pop('flash', None)
        from urllib.parse import quote
        msg = ("فاتورة دفع جديدة - BoostForge\n"
               "طريقة الدفع: Whish Money\n"
               f"الاسم: {sender_name}\n"
               f"المبلغ المُحوّل: {amount}$\n"
               f"ملاحظات: {note or '-'}\n"
               "تم إرسال المبلغ إلى: +961 70 862 314")
        return redirect(f"https://wa.me/96171484779?text={quote(msg)}")
    return render_template('payment.html', user=user_data, flash=flash)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        rl_key = f"register:{_client_ip()}"
        if not _rate_limit(rl_key, max_attempts=5, window_seconds=3600):
            return render_template('register.html', error="محاولات كثيرة. حاول لاحقًا.")
        name = (request.form.get('name') or '').strip()
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''
        if not name or len(name) > 50:
            return render_template('register.html', error="الاسم مطلوب (حتى 50 حرفًا)")
        if not EMAIL_RE.match(email) or len(email) > 120:
            return render_template('register.html', error="بريد إلكتروني غير صالح")
        if len(password) < 8 or len(password) > 128:
            return render_template('register.html', error="كلمة المرور يجب أن تكون 8 خانات على الأقل")
        user_id_tag = "#" + str(random.randint(100, 999))
        hashed_pw = generate_password_hash(password)
        try:
            conn = db_conn()
            c = conn.cursor()
            db_insert(c, "INSERT INTO users (user_id_tag, name, email, password) VALUES (?, ?, ?, ?)",
                      (user_id_tag, name, email, hashed_pw))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except Exception as e:
            if is_unique_error(e):
                return render_template('register.html', error="هذا البريد مسجل بالفعل")
            return render_template('register.html', error="حدث خطأ غير متوقع")
    return render_template('register.html')

@app.route('/my-orders')
@login_required
def my_orders():
    email = session['user_email']
    user = get_user_by_email(email)
    conn = db_conn()
    c = conn.cursor()
    c.execute(q("SELECT id, order_type, title, details, amount, status, created_at, admin_note FROM orders WHERE user_email=? ORDER BY id DESC"), (email,))
    rows = c.fetchall()
    conn.close()
    pending = [r for r in rows if r[5] == 'pending']
    success = [r for r in rows if r[5] == 'success']
    cancelled = [r for r in rows if r[5] == 'cancelled']
    return render_template('my_orders.html', user=user,
                           pending=pending, success=success, cancelled=cancelled,
                           is_admin=(email in ADMIN_EMAILS))

@app.route('/admin/users', methods=['GET', 'POST'])
@admin_required
def admin_users():
    msg = None
    err = None
    conn = db_conn()
    c = conn.cursor()
    if request.method == 'POST':
        action = request.form.get('action')
        uid = request.form.get('user_id')
        if action == 'set' and uid:
            try:
                new_bal = float(request.form.get('balance', '0'))
                c.execute(q("UPDATE users SET balance=? WHERE id=?"), (new_bal, uid))
                conn.commit()
                msg = "تم تحديث الرصيد"
            except Exception as e:
                err = f"خطأ: {e}"
        elif action == 'add' and uid:
            try:
                delta = float(request.form.get('delta', '0'))
                c.execute(q("UPDATE users SET balance=COALESCE(balance,0)+? WHERE id=?"), (delta, uid))
                conn.commit()
                msg = ("تم إضافة" if delta >= 0 else "تم خصم") + f" {abs(delta)}$"
            except Exception as e:
                err = f"خطأ: {e}"
    search = request.args.get('q', '').strip()
    if search:
        like = f"%{search}%"
        c.execute(q("""SELECT id, user_id_tag, name, email, COALESCE(balance,0)
                     FROM users WHERE email LIKE ? OR name LIKE ? OR user_id_tag LIKE ?
                     ORDER BY id DESC"""), (like, like, like))
    else:
        c.execute("""SELECT id, user_id_tag, name, email, COALESCE(balance,0)
                     FROM users ORDER BY id DESC""")
    users = c.fetchall()
    conn.close()
    return render_template('admin_users.html', users=users, q=search, msg=msg, err=err)

@app.route('/admin/orders', methods=['GET', 'POST'])
@admin_required
def admin_orders():
    conn = db_conn()
    c = conn.cursor()
    if request.method == 'POST':
        oid = request.form.get('order_id')
        action = request.form.get('action', 'status')
        if action == 'note' and oid:
            note = request.form.get('admin_note', '').strip()
            c.execute(q("UPDATE orders SET admin_note=? WHERE id=?"), (note, oid))
            conn.commit()
        else:
            new_status = request.form.get('status')
            if oid and new_status in ('pending', 'success', 'cancelled'):
                c.execute(q("SELECT user_email, amount, status, order_type, COALESCE(balance_applied,0) FROM orders WHERE id=?"), (oid,))
                row = c.fetchone()
                if row:
                    o_email, o_amount, o_status, o_type, o_applied = row
                    o_amount = float(o_amount or 0)
                    if o_email and o_amount > 0:
                        if o_type == 'payment':
                            if new_status == 'success' and not o_applied:
                                c.execute(q("UPDATE users SET balance=COALESCE(balance,0)+? WHERE email=?"), (o_amount, o_email))
                                c.execute(q("UPDATE orders SET balance_applied=1 WHERE id=?"), (oid,))
                            elif new_status != 'success' and o_applied:
                                c.execute(q("UPDATE users SET balance=COALESCE(balance,0)-? WHERE email=?"), (o_amount, o_email))
                                c.execute(q("UPDATE orders SET balance_applied=0 WHERE id=?"), (oid,))
                        else:
                            if new_status == 'cancelled' and o_applied:
                                c.execute(q("UPDATE users SET balance=COALESCE(balance,0)+? WHERE email=?"), (o_amount, o_email))
                                c.execute(q("UPDATE orders SET balance_applied=0 WHERE id=?"), (oid,))
                            elif new_status != 'cancelled' and not o_applied:
                                c.execute(q("UPDATE users SET balance=COALESCE(balance,0)-? WHERE email=?"), (o_amount, o_email))
                                c.execute(q("UPDATE orders SET balance_applied=1 WHERE id=?"), (oid,))
                c.execute(q("UPDATE orders SET status=? WHERE id=?"), (new_status, oid))
                conn.commit()
    c.execute("""SELECT id, user_email, order_type, title, details, amount, whatsapp, status, created_at, admin_note
                 FROM orders ORDER BY id DESC""")
    rows = c.fetchall()
    conn.close()
    return render_template('admin_orders.html', orders=rows)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.errorhandler(403)
def _err_403(e):
    return render_template('error.html', code=403, msg="غير مسموح بالوصول"), 403

@app.errorhandler(404)
def _err_404(e):
    return render_template('error.html', code=404, msg="الصفحة غير موجودة"), 404

@app.errorhandler(413)
def _err_413(e):
    return render_template('error.html', code=413, msg="حجم الطلب كبير جدًا"), 413

@app.errorhandler(500)
def _err_500(e):
    return render_template('error.html', code=500, msg="حدث خطأ في الخادم"), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False, threaded=False)