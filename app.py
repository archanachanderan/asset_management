import os
import io
import random
import string
import psycopg2
import psycopg2.extras
from datetime import datetime
from flask import (Flask, render_template, request, redirect, url_for, session, flash,send_file, send_from_directory, abort, jsonify)
from flask_login import (LoginManager, login_user, logout_user, login_required, current_user, UserMixin)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from flask_mail import Mail, Message
import qrcode
from captcha.image import ImageCaptcha
from fpdf import FPDF
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime
from dateutil.relativedelta import relativedelta 
from datetime import timedelta
import pytz
import re
import json, os
import json

# --- Load env vars (make sure .env is set in Render dashboard too) ---
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# --- Load env vars (make sure .env is set in Render dashboard too) ---
UPLOAD_FOLDER = os.path.join('static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'docx'}

# Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.getenv('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_PASS')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
mail = Mail(app)

# --- DB Connection ---
def get_db_connection():
    return psycopg2.connect(os.getenv("DATABASE_URL"), sslmode='require')

# Setup serializer and mail in your app init
s = URLSafeTimedSerializer(app.secret_key)

# --- Flask-Login ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- User model using Flask-Login ---
class User(UserMixin):
    def __init__(self, id, email, password_hash, role,force_password_reset, last_login=None):
        self.id = id
        self.email = email
        self.password = password_hash
        self.roles = role
        self.last_login = last_login
        self.force_password_reset = force_password_reset

    def has_role(self, role_name):
        return role_name in self.roles

allowed_extensions = {'pdf', 'png', 'jpg', 'jpeg', 'docx'}    

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions
    
@app.route('/')
def welcome():
    return render_template('welcome.html')

# --- Dummy function to fetch user from DB ---
def get_user_by_email(email):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT u.id, u.email, u.password_hash, u.force_password_reset, array_agg(r.name)
        FROM user_details u
        JOIN role r ON r.id = u.role_id
        WHERE u.email = %s AND u.is_active = TRUE
        GROUP BY u.id
    """, (email,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if row:
        return User(id=row[0], email=row[1], password_hash=row[2], force_password_reset=row[3], role=row[4] )
    return None

# --- CAPTCHA ---
@app.route('/captcha')
def captcha():
    image = ImageCaptcha()
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
    session['captcha_text'] = captcha_text
    data = image.generate(captcha_text)
    return send_file(data, mimetype='image/png')

def is_strong_password(password):
    """
    Checks password strength:
    - At least 8 characters
    - At least 1 uppercase letter
    - At least 1 lowercase letter
    - At least 1 digit
    - At least 1 special character
    """
    if (len(password) >= 8 and
        re.search(r'[A-Z]', password) and
        re.search(r'[a-z]', password) and
        re.search(r'[0-9]', password) and
        re.search(r'[!@#$%^&*(),.?":{}|<>]', password)):
        return True
    return False

# --- Forgot password ---
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id FROM user_details WHERE email = %s", (email,))
        user = cur.fetchone()
        if user:
            token = s.dumps(email, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message('Password Reset', sender='noreply@example.com', recipients=[email])
            msg.body = f'Click the link to reset your password: {reset_url}'
            mail.send(msg)
            flash('Password reset link sent to your email.', 'success')
            return render_template('login.html')
        else:
            flash('Email not found.', 'danger')
            return render_template('login.html')
    cur.close()
    conn.close()
    return render_template('forgot_password.html')

# --- Change password ---
@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():

    notifications = get_notifications()

    if request.method == 'POST':
        current = request.form['current_password']
        new = request.form['new_password']
        confirm = request.form['confirm_password']

        if new != confirm:
            flash('New password and confirm password do not match.', 'danger')
            return render_template('change_password.html')
        
        if not is_strong_password(new):
            flash('Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.', 'danger')
            return render_template('change_password.html')
        
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT password_hash FROM user_details WHERE id = %s", (current_user.id,))
        user = cur.fetchone()
        if user and check_password_hash(user[0], current):
            new_hashed = generate_password_hash(new)
            cur.execute("UPDATE user_details SET password_hash = %s WHERE id = %s", (new_hashed, current_user.id))
            conn.commit()
            flash('Password changed successfully.', 'success')

            # Fetch user role for redirect
            cur.execute("""
                SELECT r.name FROM role r
                JOIN user_details u ON r.id = u.role_id
                WHERE u.id = %s
            """, (current_user.id,))
            role = cur.fetchone()

            cur.close()
            conn.close()

            if role:
                return redirect(url_for('dashboard'))
            else:
                flash('Role not recognized. Please contact administrator.')
                return redirect(url_for('login'))
                
        else:
            flash('Incorrect current password.', 'danger')
        cur.close()
        conn.close()
    return render_template('change_password.html',notifications=notifications,pending_requests=notifications["pending_requests"],
        pending_count=len(notifications["pending_requests"]),
        expiring_warranties=notifications["expiring_warranties"],
        expiring_insurances=notifications["expiring_insurances"],
        total_users=0,
        total_count=notifications["total_count"])

# --- Login ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        captcha_input = request.form.get('captcha')

        # CAPTCHA validation
        if captcha_input.upper() != session.get('captcha_text', ''):
            flash('Incorrect CAPTCHA', 'danger')
            return redirect(url_for('login', animate='true'))

        # Fetch user
        user = get_user_by_email(email)

        if user and check_password_hash(user.password , password):
            login_user(user)
            session['email'] = email 
            session['role'] = user.roles[0] if user.roles else None  

            # Update last_login
            try:
                now = datetime.now(pytz.timezone('Asia/Kolkata'))
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute("UPDATE user_details SET last_login = %s WHERE id = %s", (now, user.id))
                conn.commit()
                cur.close()
                conn.close()
            except Exception as e:
                print(f"[ERROR] Failed to update last_login: {e}")

            # Redirect to force password reset if required
            if user.force_password_reset:
                return redirect(url_for('reset_password'))

            # Normal role-based redirection
            if user.has_role:
                return redirect(url_for('dashboard'))
            else:
                flash('Unauthorized role', 'danger')
                return redirect(url_for('login')) 
        else:
            flash('Invalid credentials or role', 'danger')
            return redirect(url_for('login', animate='true'))

    animate = request.args.get('animate') == 'true'
    return render_template('login.html', animate=animate)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']
        user_id = request.form.get('user_id') 

        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html')
        
        if not is_strong_password(new_password):
            flash('Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.', 'danger')
            return render_template('reset_password.html')

        new_hashed = generate_password_hash(new_password)
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            UPDATE user_details
            SET password_hash = %s, force_password_reset = FALSE
            WHERE id = %s
        """, (new_hashed, user_id))
        conn.commit()
        cur.close()
        conn.close()
        flash('Password reset successfully.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html')

# --- Load user for Flask-Login ---
@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT u.id, u.email, u.password_hash, u.force_password_reset, r.name
        FROM user_details u
        JOIN role r ON u.role_id = r.id
        WHERE u.id = %s AND u.is_active = TRUE
    """, (user_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if row:
        return User(id=row[0], email=row[1], password_hash=row[2], force_password_reset=row[3], role=row[4])
    return None

@app.route("/contact", methods=["POST"])
def contact():
    # If user is logged in, skip saving to outsiders' table
    if current_user.is_authenticated:
        return redirect(url_for("welcome", msg="You are already registered. Please use your account to contact us."))

    conn = get_db_connection()
    name = request.form['name']
    email = request.form['email']
    message = request.form['message']
    phone = request.form['phone']

    cur = conn.cursor()
    cur.execute("""
        INSERT INTO contact_messages (name, email, message, phone)
        VALUES (%s, %s, %s, %s)
    """, (name, email, message, phone))
    conn.commit()
    cur.close()
    return redirect(url_for("welcome", msg="Your message has been sent successfully!"))

@app.route("/admin/messages")
@login_required
def view_messages():
    conn = get_db_connection()
    cur = conn.cursor()

    notifications = get_notifications()

    cur.execute("""
        SELECT id, name AS sender_name, email AS sender_email, phone, message, submitted_at
        FROM contact_messages
        ORDER BY submitted_at DESC
    """)
    messages = cur.fetchall()
    cur.close()
    return render_template("messages.html", messages=messages,pending_requests=notifications["pending_requests"],
        pending_count=len(notifications["pending_requests"]),
        expiring_warranties=notifications["expiring_warranties"],
        expiring_insurances=notifications["expiring_insurances"],
        total_users=0,
        total_count=notifications["total_count"])

# --- Admin Dashboard ---
@app.route('/dashboard')
@login_required
def dashboard():
    
    if 'email' not in session:
        session['email'] = current_user.email

    notifications = get_notifications()

    activities = get_recent_activities()  # fetch latest 8 activities

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
    SELECT COUNT(DISTINCT asset_id) 
    FROM maintenance
    WHERE is_active = TRUE And maintenance_type='Maintenance'
    """)
    assets_under_maintenance = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM asset")
    total_assets = cur.fetchone()[0]

    cur.execute("SELECT sum(purchase_cost) as total FROM asset where is_active='True'")
    total = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM asset WHERE is_active = TRUE")
    assets_active = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM asset WHERE is_active = FALSE")
    assets_inactive = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM requests WHERE status='Pending'")
    pending_assets = cur.fetchone()[0]

    # Fetch asset details for modal
    cur.execute("""
        SELECT a.id, a.tag, a.asset_name, c.name, a.is_active, a.purchase_date, a.purchase_cost
        FROM asset a 
        JOIN category c ON c.id = a.category_id order by a.purchase_cost desc
    """)
    assets = cur.fetchall()

    # Fetch asset details for modal
    cur.execute("""
        SELECT a.id, a.tag, a.asset_name, c.name, a.is_active, a.purchase_date, a.purchase_cost
        FROM asset a 
        JOIN category c ON c.id = a.category_id 
        WHERE a.is_active = TRUE
    """)
    aas = cur.fetchall()

    # Fetch asset details for modal
    cur.execute("""
        SELECT a.id, a.tag, a.asset_name, c.name, a.is_active, a.purchase_date, a.purchase_cost
        FROM asset a 
        JOIN category c ON c.id = a.category_id 
        WHERE a.is_active = FALSE 
    """)
    inas = cur.fetchall()

    # --- Fetch maintenance records ---
    cur.execute("""
        SELECT m.id, m.from_date, m.to_date, m.company, m.serviced_by, m.cost, m.maintenance_type, m.remarks, m.is_active,
               a.asset_name as asset_name,
               p.asset_name AS part_name
        FROM maintenance m
        LEFT JOIN asset p ON m.part_id = p.id
        left join asset a on m.asset_id = a.id
        WHERE m.maintenance_type = 'Maintenance'
    """)
    maintenance_records = cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        'dashboard.html',
        pending_requests=notifications["pending_requests"],
        pending_count=len(notifications["pending_requests"]),
        expiring_warranties=notifications["expiring_warranties"],
        expiring_insurances=notifications["expiring_insurances"],
        total_users=0,
        total_count=notifications["total_count"],
        open_maintenance=0,
        pending_approvals=0,
        recent_logs=[],
        recent_users=[],aas=aas, inas=inas, 
        assets=assets, total=total, 
        total_assets=total_assets, 
        assets_active=assets_active, 
        assets_inactive=assets_inactive, 
        pending_assets=pending_assets,
        assets_under_maintenance=assets_under_maintenance, maintenance_records=maintenance_records, notifications=notifications, activities=activities
    )

@app.route("/api/assets_by_lifecycle")
def assets_by_lifecycle():
    stage = request.args.get("stage", "").lower()
    conn = get_db_connection()
    cur = conn.cursor()
    query = """
        SELECT a.id, a.asset_name, c.name as category, a.purchase_date
        FROM asset a JOIN category c on c.id = a.category_id
        WHERE a.is_active = TRUE
    """
    # Add lifecycle stage filtering based on purchase_date intervals
    if stage == "new":
        query += " AND AGE(CURRENT_DATE, purchase_date) < INTERVAL '2 years'"
    elif stage == "mid-life":
        query += " AND AGE(CURRENT_DATE, purchase_date) >= INTERVAL '2 years' AND AGE(CURRENT_DATE, purchase_date) < INTERVAL '5 years'"
    elif stage == "end-of-life":
        query += " AND AGE(CURRENT_DATE, purchase_date) >= INTERVAL '5 years'"

    cur.execute(query)
    rows = cur.fetchall()
    cur.close()

    assets = []
    for row in rows:
        assets.append({
            "id": row[0],
            "asset_name": row[1],
            "category": row[2],
            "purchase_date": row[3].isoformat() if row[3] else None
        })
    return jsonify(assets)

@app.route('/api/assets_by_category')
def assets_by_category():
    conn = get_db_connection()
    category = request.args.get("category")

    cur = conn.cursor()
    cur.execute("""
        SELECT a.id, a.asset_name, a.purchase_date, a.tag ,a.purchase_cost FROM asset a
        JOIN category sub ON a.category_id = sub.id          -- join to subcategory
        JOIN category parent ON sub.parent_id = parent.id    -- join to parent category
        WHERE parent.name = %s
    """, (category,))
    rows = cur.fetchall()
    cur.close()

    assets = [{"id": r[0], "asset_name": r[1], "purchase_date": r[2], "tag": r[3], "purchase_cost": r[4]} for r in rows]

    return jsonify(assets)

from datetime import datetime

def get_recent_activities():
    conn = get_db_connection()
    cur = conn.cursor()

    activities = []

    cur.execute("""
    SELECT r.id, r.request_type, r.asset_id, r.request_date, u.name
    FROM requests r
    JOIN user_details u ON r.requested_by = u.id 
    WHERE status = 'Pending'
    ORDER BY r.request_date DESC
    """)
    for r in cur.fetchall():
        cur.execute("SELECT asset_name FROM asset WHERE id = %s", (r[2],))
        asset_name = cur.fetchone()[0] if r[2] else "N/A"

        if r[1] == "add":
            msg = f"Requested to add asset '{asset_name}' on {r[3].strftime('%Y-%m-%d')} by {r[4]}"
        elif r[1] == "edit":
            msg = f"Requested to edit asset '{asset_name}' on {r[3].strftime('%Y-%m-%d')} by {r[4]}"
        elif r[1] == "assignment":
            msg = f"Requested assignment for asset '{asset_name}' on {r[3].strftime('%Y-%m-%d')} by {r[4]}"
        elif r[1] == "insurance":
            msg = f"Requested insurance for asset '{asset_name}' on {r[3].strftime('%Y-%m-%d')} by {r[4]}"
        elif r[1] == "maintenance":
            msg = f"Requested maintenance details for asset '{asset_name}' on {r[3].strftime('%Y-%m-%d')} by {r[4]}"
        else:
            msg = f"Request submitted: {r[1]} for {asset_name} by {r[4]}"

        activities.append({
            "id": r[0],
            "message": msg,
            "time": r[3].strftime("%Y-%m-%d %H:%M"),   # full date+time
            "url": "/approve_requests_page"
        })

    cur.close()
    conn.close()

    # Sort all activities by time descending
    activities.sort(key=lambda x: x["time"], reverse=True)

    return activities 

# --- API: Asset Category Distribution ---
@app.route("/api/category_distribution")
def category_distribution():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT parent.name AS category, COUNT(a.id)
        FROM asset a
        JOIN category sub ON a.category_id = sub.id
        JOIN category parent ON sub.parent_id = parent.id
        GROUP BY parent.name
        ORDER BY parent.name;
    """)
    data = cur.fetchall()
    cur.close()
    conn.close()

    categories = [row[0] for row in data]
    counts = [row[1] for row in data]

    return jsonify({"labels": categories, "data": counts})

@app.route("/api/lifecycle_distribution")
def lifecycle_distribution():
    conn = get_db_connection()
    cur = conn.cursor()
    query = """
        SELECT 
            SUM(CASE WHEN AGE(CURRENT_DATE, a.purchase_date) < INTERVAL '2 years' THEN 1 ELSE 0 END) AS new_assets,
            SUM(CASE WHEN AGE(CURRENT_DATE, a.purchase_date) >= INTERVAL '2 years' 
                      AND AGE(CURRENT_DATE, a.purchase_date) < INTERVAL '5 years' THEN 1 ELSE 0 END) AS mid_life_assets,
            SUM(CASE WHEN AGE(CURRENT_DATE, a.purchase_date) >= INTERVAL '5 years' THEN 1 ELSE 0 END) AS end_of_life_assets
        FROM asset a
        WHERE a.is_active = TRUE;
    """
    cur.execute(query)
    row = cur.fetchone()
    cur.close()

    data = {
        "labels": ["New", "Mid-Life", "End-of-Life"],
        "data": [row[0], row[1], row[2]]
    }
    return jsonify(data)

@app.route("/api/maintenance_trend")
def maintenance_trend():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT TO_CHAR(from_date, 'YYYY-MM') AS month,
               SUM(cost) AS total_cost
        FROM maintenance 
        WHERE is_active = true AND maintenance_type = 'Maintenance'
        GROUP BY month
        ORDER BY month
    """)
    rows = cur.fetchall()
    cur.close()
    return jsonify({
        "labels": [r[0] for r in rows],
        "data": [float(r[1]) for r in rows]
    })

@app.route("/api/maintenance_events")
def maintenance_events():
    conn = get_db_connection()
    cur = conn.cursor()

    # Normal maintenance
    cur.execute("""
        SELECT m.id, a.asset_name, m.from_date, m.to_date, m.maintenance_type, m.serviced_by, m.company, m.cost, m.remarks, p.asset_name
        FROM maintenance m
        JOIN asset a ON m.asset_id = a.id
        LEFT JOIN asset p on m.part_id = p.id
        WHERE m.is_active = TRUE
    """)
    maintenance_rows = cur.fetchall()

    # Monthly maintenance
    cur.execute("""
        SELECT mm.id, a.asset_name, mm.maintenance_date, mm.serviced_by, mm.remarks, p.asset_name
        FROM monthly_maintenance mm
        JOIN asset a ON mm.asset_id = a.id
        LEFT JOIN asset p on mm.part_id = p.id
        WHERE mm.is_active = TRUE
    """)
    monthly_rows = cur.fetchall()

    events = []

    for row in maintenance_rows:
        events.append({
            "id": f"m-{row[0]}",
            "title": f"{row[1]} - {row[4]}",
            "start": row[2].isoformat(),
            "end": row[3].isoformat() if row[3] else None,
            "color": "#fd7e14" if row[4].lower() == "repair" else "#28a745",
            "serviced_by": row[5],
            "asset_name": row[1],
            "company": row[6],
            "cost": row[7],
            "maintenance_type": row[4],
            "remarks": row[8],
            "part_name": row[9]
        })

    for row in monthly_rows:
        events.append({
            "id": f"mm-{row[0]}",
            "title": f"{row[1]} - Monthly",
            "start": row[2].isoformat(),
            "color": "#007bff",
            "serviced_by": row[3],
            "asset_name": row[1],
            "company": None,
            "cost": None,
            "maintenance_type": "Monthly Maintenance",
            "remarks": row[4],
            "part_name": row[5]
        })

    return jsonify(events)

def get_notifications():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # Warranty expiring in next 30 days
    cur.execute("""
        SELECT a.id AS asset_id, a.asset_name, a.purchase_date, 
               w.years AS warranty_years,
               (a.purchase_date + (w.years || ' years')::interval) AS expiry_date
        FROM asset a
        JOIN warranty w ON a.id = w.asset_id
        WHERE w.is_active = TRUE
          AND a.is_active = TRUE
          AND (a.purchase_date + (w.years || ' years')::interval) <= CURRENT_DATE + INTERVAL '30 days'
          AND (a.purchase_date + (w.years || ' years')::interval) >= CURRENT_DATE
    """)
    expiring_warranties = cur.fetchall()

    # Insurance expiring in next 30 days
    cur.execute("""
        SELECT a.id AS asset_id, a.asset_name, i.end_date
        FROM asset a
        JOIN insurances i ON a.id = i.asset_id
        WHERE i.is_active = TRUE
          AND a.is_active = TRUE
          AND i.end_date <= CURRENT_DATE + INTERVAL '30 days'
          AND i.end_date >= CURRENT_DATE
    """)
    expiring_insurances = cur.fetchall()

    pending_requests = []
    if current_user.has_role('Asset Manager'):
        cur.execute("""
            SELECT r.id, r.request_type, u.name AS requested_by
            FROM requests r
            JOIN user_details u ON r.requested_by = u.id
            WHERE r.status = 'Pending' AND r.is_active = TRUE
        """)
        pending_requests = cur.fetchall()

    conn.close()
    cur.close()

    return {
        "expiring_warranties": expiring_warranties,
        "expiring_insurances": expiring_insurances,
        "pending_requests": pending_requests,
        "total_count": len(expiring_warranties) + len(expiring_insurances) + len(pending_requests)
    }

@app.route('/notifications')
@login_required  # if you want to restrict to logged-in users
def view_notifications():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    notifications = get_notifications()

    save_all_notifications()

    cur.execute("""
        SELECT *
        FROM notification
        ORDER BY created_at DESC
    """)
    notification = cur.fetchall()

    cur.close()
    conn.close()

    return render_template('notification.html', pending_requests=notifications["pending_requests"],
        pending_count=len(notifications["pending_requests"]),
        expiring_warranties=notifications["expiring_warranties"],
        expiring_insurances=notifications["expiring_insurances"],
        total_users=0,
        total_count=notifications["total_count"],
        open_maintenance=0,
        pending_approvals=0,
        recent_logs=[],
        recent_users=[], notifications=notifications ,notification=notification   )

def save_all_notifications():
    conn = get_db_connection()
    cur = conn.cursor()

    # Save warranty expiry notifications
    cur.execute("""
        SELECT 
            a.id AS asset_id,
            a.asset_name,
            (a.purchase_date + (w.years || ' years')::interval) AS expiry_date
        FROM asset a
        JOIN warranty w ON a.id = w.asset_id
        WHERE w.is_active = TRUE
        AND (a.purchase_date + (w.years || ' years')::interval) <= CURRENT_DATE + INTERVAL '30 days'
        AND (a.purchase_date + (w.years || ' years')::interval) >= CURRENT_DATE
    """)
    warranties = cur.fetchall()
    for w in warranties:
        cur.execute("""
            INSERT INTO notification (user_id, message, type, related_id)
            VALUES (%s, %s, %s, %s)
        """, (
            None,  # or system user ID
            f"Warranty for asset '{w[1]}' is expiring on {w[2]}",
            'warranty',
            w[0]
        ))

    # Save insurance expiry notifications
    cur.execute("""
        SELECT 
            a.id AS asset_id,
            a.asset_name,
            i.end_date
        FROM asset a
        JOIN insurances i ON a.id = i.asset_id
        WHERE i.is_active = TRUE
        AND i.end_date <= CURRENT_DATE + INTERVAL '30 days'
        AND i.end_date >= CURRENT_DATE
    """)
    insurances = cur.fetchall()
    for i in insurances:
        cur.execute("""
            INSERT INTO notification(user_id, message, type, related_id)
            VALUES (%s, %s, %s, %s)
        """, (
            None,  # or system user ID
            f"Insurance for asset '{i[1]}' is expiring on {i[2]}",
            'insurance',
            i[0]
        ))

    conn.commit()
    cur.close()
    conn.close()

@app.route('/admin/view_users')
@login_required
def view_users():
    if not (current_user.has_role('Super Admin') or current_user.has_role('Asset Manager')):
        return redirect(url_for('unauthorized'))
    
    notifications = get_notifications()

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT 
            u.id,
            u.email,
            u.name,
            r.name,
            u.last_login,
            u.date_of_joining,
            u.phone,
            u.is_active
        FROM user_details u
        JOIN role r ON u.role_id = r.id
        ORDER BY u.id;
    """)
    users = cur.fetchall()
    cur.close()
    conn.close()

    return render_template('view_users.html', users=users,pending_requests=notifications["pending_requests"],pending_count=len(notifications["pending_requests"]),
        expiring_warranties=notifications["expiring_warranties"],expiring_insurances=notifications["expiring_insurances"],
        total_users=0,total_count=notifications["total_count"],open_maintenance=0,pending_approvals=0,recent_logs=[])

@app.route('/admin/user/<int:user_id>')
@login_required
def user_detail(user_id):
    if not (current_user.has_role('Super Admin') or current_user.has_role('Asset Manager')):
        return redirect(url_for('unauthorized'))

    conn = get_db_connection()
    cur = conn.cursor()

    notifications = get_notifications()

    # Fetch user details
    cur.execute("SELECT u.*,r.name as role_name FROM user_details u join role r on r.id=u.role_id WHERE u.id = %s", (user_id,))
    user_row = cur.fetchone()
    user_columns = [desc[0] for desc in cur.description]
    user = dict(zip(user_columns, user_row))

    if not user.get('bank_details'):
        user['bank_details'] = {}

    # Fetch files for the user
    cur.execute("SELECT * FROM files WHERE user_id = %s AND is_active = true", (user_id,))
    file_rows = cur.fetchall()
    file_columns = [desc[0] for desc in cur.description]
    files = [dict(zip(file_columns, row)) for row in file_rows]

    # Fetch role & salary history
    cur.execute("""
        SELECT ursh.*, r.name AS role_name
        FROM user_role_salary_history ursh
        JOIN role r ON r.id = ursh.role_id
        WHERE ursh.user_id = %s
        ORDER BY ursh.start_date DESC
    """, (user_id,))
    history_rows = cur.fetchall()
    history_columns = [desc[0] for desc in cur.description]
    history = [dict(zip(history_columns, row)) for row in history_rows]

    # Get all assets assigned to this user
    cur.execute("""
    SELECT a.id AS asset_id, a.asset_name, ass.assigned_from, ass.assigned_until, ass.remarks, u.name AS assigned_to
    FROM assignments ass
    JOIN asset a ON a.id = ass.asset_id
    LEFT JOIN user_details u ON u.id = ass.user_id
    WHERE ass.user_id = %s
    ORDER BY ass.assigned_from DESC
""", (user_id,))
    assignments = cur.fetchall()
    assignment_columns = [desc[0] for desc in cur.description]
    assignments = [dict(zip(assignment_columns, row)) for row in assignments]


    cur.close()
    conn.close()

    return render_template('user_detail.html', user=user, files=files, history=history, assignments=assignments,pending_requests=notifications["pending_requests"],pending_count=len(notifications["pending_requests"]),
        expiring_warranties=notifications["expiring_warranties"],expiring_insurances=notifications["expiring_insurances"],
        total_users=0,total_count=notifications["total_count"],open_maintenance=0,pending_approvals=0,recent_logs=[])

@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if not current_user.has_role('Asset Manager'):
        return redirect(url_for('unauthorized'))
    
    notifications = get_notifications()

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, name FROM role")
    roles = cur.fetchall()

    if request.method == 'POST':
        try:
            name = request.form.get('name')
            email = request.form['email']
            role_id = request.form['role_id']
            phone = request.form.get('phone')
            address = request.form.get('address')
            date_of_birth = request.form.get('date_of_birth')
            gender = request.form.get('gender')
            date_of_joining = request.form.get('date_of_joining')

            bank_details = json.dumps({
                "bank_name": request.form['bank_name'],
                "account_number": request.form['account_number'],
                "ifsc": request.form['ifsc'],
                "branch": request.form.get('branch', ''),
                "account_type": request.form.get('account_type', '')
            })

            aadhaar_number = request.form.get('aadhaar_number')
            pan_number = request.form.get('pan_number')
            salary = request.form.get('salary')
            qualification = request.form.get('qualification')
            remarks = request.form.get('remarks')
            new_role = request.form.get('new_role') 
            is_active = request.form.get('is_active') == 'on'

            password_hash = generate_password_hash('default123')
            created_at = datetime.utcnow()

            # Handle new role if selected
            if role_id == 'new' and new_role:
                cur.execute("SELECT id FROM role WHERE name = %s", (new_role,))
                existing = cur.fetchone()
                if existing:
                    role_id = existing[0]
                else:
                    cur.execute("INSERT INTO role (name) VALUES (%s) RETURNING id", (new_role,))
                    role_id = cur.fetchone()[0]
                    conn.commit()
                    cur.execute("SELECT setval(pg_get_serial_sequence('role', 'id'), (SELECT MAX(id) FROM role))")
                    conn.commit()

            # Insert user
            cur.execute("""
                INSERT INTO user_details
                (name, email, password_hash, role_id, is_active, created_at, force_password_reset, 
                 phone, address, date_of_birth, gender, date_of_joining, bank_details, 
                 aadhaar_number, pan_number, salary, qualification, remarks)
                VALUES (%s, %s, %s, %s, %s, %s, TRUE, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (name, email, password_hash, role_id, is_active, created_at, phone, address, 
                  date_of_birth, gender, date_of_joining, bank_details, aadhaar_number, pan_number, 
                  salary, qualification, remarks))
            
            new_user_id = cur.fetchone()[0]
            conn.commit()

            start_date = datetime.strptime(date_of_joining, '%Y-%m-%d').date() if date_of_joining else datetime.now().date()

            # Record initial role and salary in history table
            cur.execute("""INSERT INTO user_role_salary_history (user_id, role_id, salary, start_date, remarks,is_active) VALUES (%s, %s, %s, %s, %s,%s)
            """, (new_user_id, role_id, salary, start_date, 'Initial role and salary',True))
            conn.commit()

            # File types mapping
            file_fields = {'photo': 'Profile Photo','aadhaar_file': 'Aadhaar Card','pan_file': 'PAN Card'}

            for form_field, file_type in file_fields.items():
                file = request.files.get(form_field)
                if file and file.filename.strip():
                    filename = secure_filename(file.filename)

                    if file_type == 'Profile Photo':
                        folder_path = os.path.join('static', 'uploads', 'profile_photos')
                    else:
                        folder_path = os.path.join('static', 'uploads')

                    os.makedirs(folder_path, exist_ok=True)

                    filepath = os.path.join(folder_path, filename)
                    file.save(filepath)

        # Store relative path for DB
                    relative_path = os.path.relpath(filepath, 'static').replace("\\", "/")
                    relative_path = f"static/{relative_path}"

        # Insert into files table
                    cur.execute("""
            INSERT INTO files (user_id, file_name, file_path, uploaded_by, is_active)
            VALUES (%s, %s, %s, %s, TRUE)
        """, (new_user_id, filename, relative_path, current_user.id))
                    conn.commit()

            # Send welcome email
            msg = Message(
                subject="Welcome to SVE System",
                recipients=[email],
                body=f"""Hello {name},

welcome to Sree Venkateshwara Enterprises!!
Your account has been created in the SVE System. Please check your details below:

Name: {name}
Email: {email}
Phone: {phone}
Address: {address}
Date of Birth: {date_of_birth}
Gender: {gender}
Date of Joining: {date_of_joining}
Aadhaar Number: {aadhaar_number}
PAN Number: {pan_number}
Salary: {salary}
Qualification: {qualification}

Bank Details:
  Bank Name: {bank_details.get('bank_name', '')}
  Account Number: {bank_details.get('account_number', '')}
  IFSC: {bank_details.get('ifsc', '')}
  Branch: {bank_details.get('branch', '')}
  Account Type: {bank_details.get('account_type', '')}

Temporary Password: default123

Please login and change your password.

If any of the above details are incorrect, please contact the SVE Admin Team.

Regards,  
SVE Admin Team
"""
            )
            mail.send(msg)

            flash("User created successfully with default password 'default123'", 'success')
            return redirect(url_for('view_users'))

        except Exception as e:
            conn.rollback()
            flash(f'Error adding user: {e}', 'danger')

        finally:
            cur.close()
            conn.close()

    return render_template('add_user.html', roles=roles,pending_requests=notifications["pending_requests"],pending_count=len(notifications["pending_requests"]),
        expiring_warranties=notifications["expiring_warranties"],expiring_insurances=notifications["expiring_insurances"],
        total_users=0,total_count=notifications["total_count"],open_maintenance=0,pending_approvals=0,recent_logs=[])

@app.route('/manager/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.has_role('Asset Manager'):
        return redirect(url_for('unauthorized'))

    conn = get_db_connection()
    cur = conn.cursor()

    notifications = get_notifications()

    # Fetch user record including all fields
    cur.execute("""
        SELECT id, name, email, role_id, is_active, phone, address, date_of_birth, gender,
               date_of_joining, bank_details, aadhaar_number, pan_number, salary, qualification, remarks
        FROM user_details
        WHERE id = %s
    """, (user_id,))
    user = cur.fetchone()
    if not user:
        flash("User not found.", "danger")
        cur.close()
        conn.close()
        return redirect(url_for('dashboard'))

    # Convert tuple to dict
    user = dict(zip([desc[0] for desc in cur.description], user))

    # Convert bank_details JSON string to dict
    if user.get('bank_details'):
        if isinstance(user['bank_details'], str):
            user['bank_details'] = json.loads(user['bank_details'])
        else:
            user['bank_details'] = user['bank_details']
    else:
        user['bank_details'] = {}

    # Fetch roles
    cur.execute("SELECT id, name FROM role")
    roles = cur.fetchall()

    user_files = {'photo': None, 'aadhaar_file': None, 'pan_file': None}# always initialize
    cur.execute("SELECT file_name, file_path FROM files WHERE user_id=%s AND is_active=TRUE", (user_id,))
    files = cur.fetchall()

    for f in files:
        name, path = f
        if 'profile_photos' in path.lower():
            user_files['photo'] = path
        elif 'aadhaar' in name.lower():
            user_files['aadhaar_file'] = path
        elif 'pan' in name.lower():
            user_files['pan_file'] = path

    if request.method == 'POST':
        try:
            name = request.form.get('name')
            email = request.form['email']
            role_id = int(request.form['role_id'])
            is_active = request.form.get('is_active') == 'on'
            phone = request.form.get('phone')
            address = request.form.get('address')
            date_of_birth = request.form.get('date_of_birth')
            gender = request.form.get('gender')
            date_of_joining = request.form.get('date_of_joining')
            aadhaar_number = request.form.get('aadhaar_number')
            pan_number = request.form.get('pan_number')
            salary = request.form.get('salary')
            qualification = request.form.get('qualification')
            remarks = request.form.get('remarks')

            bank_details = {
                "bank_name": request.form.get('bank_name', ''),
                "account_number": request.form.get('account_number', ''),
                "ifsc": request.form.get('ifsc', ''),
                "branch": request.form.get('branch', ''),
                "account_type": request.form.get('account_type', '')
            }

            cur.execute("""
                UPDATE user_details
                SET name=%s, email=%s, role_id=%s, is_active=%s,
                    phone=%s, address=%s, date_of_birth=%s, gender=%s,
                    date_of_joining=%s, bank_details=%s, aadhaar_number=%s,
                    pan_number=%s, salary=%s, qualification=%s, remarks=%s
                WHERE id=%s
            """, (name, email, role_id, is_active, phone, address, date_of_birth, gender,
                  date_of_joining, json.dumps(bank_details), aadhaar_number, pan_number,
                  salary, qualification, remarks, user_id))
            conn.commit()

            # Check if role or salary changed
            cur.execute("""
                SELECT * FROM user_role_salary_history
                WHERE user_id=%s AND is_active=TRUE
            """, (user_id,))
            active_history = cur.fetchone()

            if active_history:
                old_role_id = active_history[2]
                old_salary = active_history[3]

                if str(old_role_id) != str(role_id) or str(old_salary) != str(salary):
                    # Make old history inactive
                    cur.execute("""
                        UPDATE user_role_salary_history
                        SET is_active=FALSE, end_date=CURRENT_DATE
                        WHERE id=%s
                    """, (active_history[0],))
                    conn.commit()

                    # Insert new history record
                    cur.execute("""
                        INSERT INTO user_role_salary_history
                        (user_id, role_id, salary, start_date, remarks, is_active)
                        VALUES (%s, %s, %s, CURRENT_DATE, 'Updated role/salary', TRUE)
                    """, (user_id, role_id, salary))
                    conn.commit()

            # Handle file uploads
            file_fields = {'photo':'photo','aadhaar_file':'aadhaar_file','pan_file':'pan_file'}
            for form_field, key in file_fields.items():
                file = request.files.get(form_field)
                if file and file.filename.strip():
                    filename = secure_filename(file.filename)
                    folder = 'static/uploads/profile_photos' if key=='photo' else 'static/uploads'
                    os.makedirs(folder, exist_ok=True)
                    filepath = os.path.join(folder, filename)
                    file.save(filepath)
                    relative_path = os.path.relpath(filepath, 'static').replace("\\","/")
                    relative_path = f"static/{relative_path}"

                    # Insert or update file record
                    cur.execute("SELECT id FROM files WHERE user_id=%s AND file_name=%s AND is_active=TRUE", (user_id, filename))
                    existing_file = cur.fetchone()
                    if existing_file:
                        cur.execute("UPDATE files SET file_path=%s WHERE id=%s", (relative_path, existing_file[0]))
                    else:
                        cur.execute("""
                            INSERT INTO files (user_id, file_name, file_path, uploaded_by, is_active)
                            VALUES (%s,%s,%s,%s,TRUE)
                        """, (user_id, filename, relative_path, current_user.id))
                    conn.commit()

            # Send update email
            msg = Message(
                subject="Your SVE Account Was Updated",
                recipients=[email],
                body=f"""Hello {name},

Your account information has been updated. Please check your details below:

Name: {name}
Email: {email}
Phone: {phone}
Address: {address}
Date of Birth: {date_of_birth}
Gender: {gender}
Date of Joining: {date_of_joining}
Aadhaar Number: {aadhaar_number}
PAN Number: {pan_number}
Salary: {salary}
Qualification: {qualification}

Bank Details:
  Bank Name: {bank_details.get('bank_name','')}
  Account Number: {bank_details.get('account_number','')}
  IFSC: {bank_details.get('ifsc','')}
  Branch: {bank_details.get('branch','')}
  Account Type: {bank_details.get('account_type','')}

If any of the above details are incorrect, please contact the SVE Admin Team.

Regards,
SVE Admin Team
"""
            )
            mail.send(msg)

            flash('User updated successfully.', 'success')
            cur.close()
            conn.close()
            return redirect(url_for('user_detail', user_id=user_id))

        except Exception as e:
            conn.rollback()
            flash(f'Error updating user: {e}', 'danger')

    cur.close()
    conn.close()
    return render_template('edit_user.html', user=user, roles=roles, user_files=user_files, pending_requests=notifications["pending_requests"],pending_count=len(notifications["pending_requests"]),
        expiring_warranties=notifications["expiring_warranties"],expiring_insurances=notifications["expiring_insurances"],
        total_users=0,total_count=notifications["total_count"],open_maintenance=0,pending_approvals=0,recent_logs=[])

@app.route('/asset/qr/<string:asset_tag>')
def view_asset_by_tag(asset_tag):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    cur.execute("SELECT a.*, c.name FROM asset a join category c on a.category_id=c.id WHERE tag = %s", (asset_tag,))
    asset = cur.fetchone()
    cur.close()
    conn.close()

    if not asset:
        return "Asset not found", 404

    return render_template("view_qr.html", asset=asset)

#----------------------------------------------------------------------------------------------------------------------------------------------------

@app.route('/view_assets')
@login_required
def view_assets():
    conn = get_db_connection()
    cur = conn.cursor()
    user_pending_requests = []
    is_asset_entry_officer = current_user.has_role('Asset Entry Officer')

    notifications = get_notifications()

    if is_asset_entry_officer:
        cur.execute("""
        SELECT r.id AS request_id, r.asset_id, r.request_type, r.request_date, a.asset_name, r.assignment_id, r.insurance_id 
        FROM requests r
        JOIN asset a ON r.asset_id = a.id
        WHERE r.requested_by = %s 
          AND r.status = 'Pending' 
          AND r.is_active = TRUE
        ORDER BY r.request_date DESC
    """, (current_user.id,))
        user_pending_requests = cur.fetchall()
        
    cur.execute("""
        SELECT a.id, a.tag, a.asset_name, c.name, a.is_active, a.purchase_date
        FROM asset a 
        JOIN category c ON c.id = a.category_id 
    """)
    assets = cur.fetchall()

    cur.close()
    conn.close()
    return render_template(
        'view_assets.html',
        assets=assets,
        user_pending_requests=user_pending_requests,
        is_asset_entry_officer=is_asset_entry_officer,pending_requests=notifications["pending_requests"],pending_count=len(notifications["pending_requests"]),
        expiring_warranties=notifications["expiring_warranties"],expiring_insurances=notifications["expiring_insurances"],
        total_users=0,total_count=notifications["total_count"],open_maintenance=0,pending_approvals=0,recent_logs=[]
    )

@app.route("/asset/<int:asset_id>")
def asset_details(asset_id):
    conn = get_db_connection()
    cur = conn.cursor()

    notifications = get_notifications()

    # Get main asset details
    cur.execute("""
        SELECT 
    a.id,
    a.asset_name,
    a.description,
    a.purchase_date,
    a.purchase_cost,
    a.remarks,
    a.is_active,
    a.tag,

    -- Subcategory name if present
    child_cat.name AS subcategory,
    -- Parent category name if present, else child is itself the category
    COALESCE(parent_cat.name, child_cat.name) AS category,

    v.name AS vendor_name,
    v.phone,
    v.email,
    v.address

FROM asset a
LEFT JOIN category child_cat ON a.category_id = child_cat.id
LEFT JOIN category parent_cat ON child_cat.parent_id = parent_cat.id
LEFT JOIN vendors v ON a.id = v.asset_id
WHERE a.id = %s;

    """, (asset_id,))
    asset = cur.fetchone()

    # Get assignment history
    cur.execute("""
        SELECT u.name, ass.assigned_from, ass.assigned_until, ass.remarks
        FROM assignments ass
        LEFT JOIN user_details u ON ass.user_id = u.id
        WHERE ass.asset_id = %s ORDER BY ass.assigned_from DESC
    """, (asset_id,))
    assignments = cur.fetchall()


    # Get warranty info
    cur.execute("""
        SELECT years
        FROM warranty WHERE asset_id = %s
    """, (asset_id,))
    warranty = cur.fetchone()

    expiry_date = None
    if warranty and asset[3]:
        try:
        # Only add relativedelta if asset[2] is a proper date object
            expiry_date = asset[3] + relativedelta(years=warranty[0])
        except TypeError:
        # If asset[2] is not a date, skip calculation
            expiry_date = None

    # Get insurance info
    cur.execute("""
    SELECT policy_number, provider_details, insured_value, start_date, end_date, insurance_premium
    FROM insurances
    WHERE asset_id = %s 
    """, (asset_id,))
    insurance_records = cur.fetchall()

    # --- Fetch maintenance records ---
    cur.execute("""
        SELECT m.id, m.from_date, m.to_date, m.company, m.serviced_by, m.cost, m.maintenance_type, m.remarks, m.is_active,
               p.asset_name AS part_name
        FROM maintenance m
        LEFT JOIN asset p ON m.part_id = p.id
        WHERE m.asset_id = %s
        ORDER BY m.from_date DESC
    """, (asset_id,))
    maintenance_records = cur.fetchall()

    # --- Fetch maintenance records ---
    cur.execute("""
        SELECT m.id, m.from_date, m.to_date, m.company, m.serviced_by, m.cost, m.maintenance_type, m.remarks, m.is_active,
               p.asset_name AS part_name
        FROM maintenance m
        LEFT JOIN asset p ON m.part_id = p.id
        WHERE m.asset_id = %s AND m.maintenance_type='Maintenance'
        ORDER BY m.from_date DESC
    """, (asset_id,))
    ma_records = cur.fetchall()

    # --- Fetch monthly maintenance records ---
    cur.execute("""
        SELECT mm.id, mm.maintenance_date, mm.remarks, mm.serviced_by, mm.is_active,
               p.asset_name AS part_name
        FROM monthly_maintenance mm
        LEFT JOIN asset p ON mm.part_id = p.id
        WHERE mm.asset_id = %s
        ORDER BY mm.maintenance_date DESC
    """, (asset_id,))
    monthly_records = cur.fetchall()

        # Get uploaded files
    upload_folder = os.path.join(app.root_path, 'static', 'uploads')
    os.makedirs(upload_folder, exist_ok=True)

    file = request.files.get('file')  # Ensure this line is present

    if file and file.filename:
        filename = secure_filename(file.filename)
        file_path = os.path.join(upload_folder, filename)  # for DB (relative path)
        full_path = os.path.join(app.root_path, file_path)       # full path to save

        file.save(full_path)


        # Insert metadata into database
        cur.execute("""
            INSERT INTO files (asset_id, file_name, file_path, uploaded_at)
            VALUES (%s, %s, %s, NOW())
        """, (asset_id, filename, file_path))
    
    cur.execute("""
    SELECT id, file_name, file_path, uploaded_at
    FROM files
    WHERE asset_id = %s
    """, (asset_id,))
    files = cur.fetchall()

    return render_template("asset_details.html", asset=asset, assignments=assignments, warranty=warranty,ma_records=ma_records,
                           insurance_records=insurance_records, files=files, expiry_date=expiry_date, maintenance_records=maintenance_records, 
                           monthly_records=monthly_records, pending_requests=notifications["pending_requests"],pending_count=len(notifications["pending_requests"]),
        expiring_warranties=notifications["expiring_warranties"],expiring_insurances=notifications["expiring_insurances"],
        total_users=0,total_count=notifications["total_count"],open_maintenance=0,pending_approvals=0,recent_logs=[])

@app.route('/asset/<int:asset_id>/download_pdf')
@login_required
def download_asset_pdf(asset_id):
    conn = get_db_connection()
    cur = conn.cursor()

    # Get asset and related data
    cur.execute("""
        SELECT a.asset_name, a.description, a.purchase_date, a.purchase_cost, a.remarks,
               c.name AS category, v.name AS vendor, a.tag, a.is_active
        FROM asset a
        LEFT JOIN category c ON a.category_id = c.id
        LEFT JOIN vendors v ON a.id = v.asset_id
        WHERE a.id = %s
    """, (asset_id,))
    asset = cur.fetchone()
    if not asset:
        abort(404)

    cur.execute("""
        SELECT u.name, ass.assigned_from, ass.assigned_until, ass.remarks
        FROM assignments ass
        LEFT JOIN user_details u ON ass.user_id = u.id
        WHERE ass.asset_id = %s ORDER BY ass.assigned_from DESC
    """, (asset_id,))
    assignments = cur.fetchall()

    cur.execute("""
        SELECT task_done, maintenance_date, cost, service_by
        FROM maintenance
        WHERE asset_id = %s ORDER BY maintenance_date DESC
    """, (asset_id,))
    maintenance = cur.fetchall()

    cur.execute("""
        SELECT years
        FROM warranty WHERE asset_id = %s
    """, (asset_id,))
    warranty = cur.fetchone()

    cur.execute("""
        SELECT policy_number, provider_details, insured_value, start_date, end_date, insurance_premium
        FROM insurances WHERE asset_id = %s
    """, (asset_id,))
    insurance = cur.fetchone()

    cur.close()
    conn.close()

    # Generate PDF
    pdf = FPDF()
    pdf.add_page()

    # Header
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 10, "SREE VENKATESHWARA ENTERPRISES", ln=True, align='C')
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, f"Asset Report - {asset[1]}", ln=True, align='C')
    pdf.ln(10)

    # Asset Details
    pdf.set_font("Arial", 'B', 11)
    pdf.cell(0, 10, "Asset Details", ln=True)
    pdf.set_font("Arial", '', 10)
    labels = ["Name", "Description", "Purchase Date", "Purchase Cost", "Remarks", "Category", "Vendor", "Tag", "Is Active"]
    for i, label in enumerate(labels):
        value = asset[i] if asset[i] else '-'
        if label == "Purchase Cost":
            value = f"Rs. {value}"
        pdf.cell(0, 8, f"{label}: {value}", ln=True)
    pdf.ln(5)

    # Assignment History
    pdf.set_font("Arial", 'B', 11)
    pdf.cell(0, 10, "Assignment History", ln=True)
    pdf.set_font("Arial", '', 10)
    if assignments:
        for ass in assignments:
            pdf.multi_cell(0, 8, f"User: {ass[0]}\nFrom: {ass[1]}\nUntil: {ass[2]}\nRemarks: {ass[3]}", border=1)
            pdf.ln(2)
    else:
        pdf.cell(0, 8, "No assignment records.", ln=True)

    # Maintenance
    pdf.set_font("Arial", 'B', 11)
    pdf.cell(0, 10, "Maintenance Records", ln=True)
    pdf.set_font("Arial", '', 10)
    if maintenance:
        for m in maintenance:
            pdf.multi_cell(0, 8, f"Task Done: {m[0]}\nDate: {m[1]}\nCost: Rs. {m[2]}\nService By: {m[3]}", border=1)
            pdf.ln(2)
    else:
        pdf.cell(0, 8, "No maintenance records.", ln=True)

    # Warranty Info
    pdf.set_font("Arial", 'B', 11)
    pdf.cell(0, 10, "Warranty Info", ln=True)
    pdf.set_font("Arial", '', 10)
    if warranty:
        pdf.cell(0, 8, f"Warranty Duration: {warranty[0]} Year(s)", ln=True)
    else:
        pdf.cell(0, 8, "No warranty info.", ln=True)

    # Insurance Info
    pdf.set_font("Arial", 'B', 11)
    pdf.cell(0, 10, "Insurance Info", ln=True)
    pdf.set_font("Arial", '', 10)
    if insurance:
        pdf.multi_cell(0, 8, f"Policy #: {insurance[0]}\nProvider Details: {insurance[1]}\nInsured Value: Rs. {insurance[2]}\nStart Date: {insurance[3]}\nEnd Date: {insurance[4]}\nInsurance Premium: {insurance[4]}", border=1)
    else:
        pdf.cell(0, 8, "No insurance info.", ln=True)

    # Return PDF
    pdf_output = io.BytesIO()
    pdf_bytes = pdf.output(dest='S').encode('latin-1', errors='replace')
    pdf_output.write(pdf_bytes)
    pdf_output.seek(0)
    return send_file(pdf_output, as_attachment=True, download_name=f"{asset[0]}_report.pdf", mimetype='application/pdf')

@app.route('/asset/<string:asset_tag>/download_qr')
@login_required
def download_qr(asset_tag):
    qr_data = f"https://asset-management-u3dy.onrender.com/asset/qr/{asset_tag}"

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=4
    )
    qr.add_data(qr_data)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)

    return send_file(
        buf,
        mimetype='image/png',
        as_attachment=True,
        download_name=f"{asset_tag}_qr.png"
    )

@app.route('/asset/qr_img/<string:asset_tag>')
def qr_img(asset_tag):
    qr_data = f"https://asset-management-u3dy.onrender.com/asset/qr/{asset_tag}"

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=4
    )
    qr.add_data(qr_data)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)

    # Serve image inline (no download)
    return send_file(buf, mimetype='image/png')
    
@app.route('/view_requests')
@login_required
def view_requests():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    notifications = get_notifications()

    cur.execute("""
        SELECT r.id, r.request_type, r.status, r.request_date,
               a.asset_name, u.name as requested_by
        FROM requests r
        JOIN asset a ON a.id = r.asset_id
        JOIN user_details u ON u.id = r.requested_by
        ORDER BY (status='Pending') DESC, request_date DESC;
    """)
    requests = cur.fetchall()

    return render_template("view_requests.html", requests=requests,pending_requests=notifications["pending_requests"],pending_count=len(notifications["pending_requests"]),
        expiring_warranties=notifications["expiring_warranties"],expiring_insurances=notifications["expiring_insurances"],
        total_users=0,total_count=notifications["total_count"],open_maintenance=0,pending_approvals=0,recent_logs=[])

@app.route('/approve_request/<int:request_id>', methods=['GET', 'POST'])
@login_required
def approve_request_page(request_id):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    notifications = get_notifications()

    # Get request + asset + category + user info
    cur.execute("""
        SELECT r.*, a.*, c.name AS category_name, u.name AS requested_by_name, r.request_date
        FROM requests r
        JOIN asset a ON r.asset_id = a.id
        LEFT JOIN category c ON a.category_id = c.id
        LEFT JOIN user_details u ON r.requested_by = u.id
        WHERE r.id = %s
    """, (request_id,))
    request_data = cur.fetchone()

    if not request_data:
        flash("Request not found.", "danger")
        return redirect(url_for('view_requests'))

    asset_id = request_data['asset_id']

    # Additional related data (warranty, insurance, vendor, file, assignments)
    cur.execute("SELECT * FROM warranty WHERE asset_id = %s", (asset_id,))
    warranty = cur.fetchone()

    # Get insurance info
    cur.execute("""
    SELECT policy_number, provider_details, insured_value, start_date, end_date, insurance_premium
    FROM insurances
    WHERE asset_id = %s 
    """, (asset_id,))
    insurance_records = cur.fetchall()

    cur.execute("SELECT * FROM vendors WHERE asset_id = %s", (asset_id,))
    vendor = cur.fetchone()

    # --- Fetch maintenance records ---
    cur.execute("""
        SELECT m.id, m.from_date, m.to_date, m.company, m.serviced_by, m.cost, m.maintenance_type, m.remarks, m.is_active,
               p.asset_name AS part_name
        FROM maintenance m
        LEFT JOIN asset p ON m.part_id = p.id
        WHERE m.asset_id = %s
        ORDER BY m.from_date DESC
    """, (asset_id,))
    maintenance_records = cur.fetchall()

    # --- Fetch monthly maintenance records ---
    cur.execute("""
        SELECT mm.id, mm.maintenance_date, mm.remarks, mm.serviced_by, mm.is_active,
               p.asset_name AS part_name
        FROM monthly_maintenance mm
        LEFT JOIN asset p ON mm.part_id = p.id
        WHERE mm.asset_id = %s
        ORDER BY mm.maintenance_date DESC
    """, (asset_id,))
    monthly_records = cur.fetchall()

    cur.execute("""
    SELECT file_name, file_path
    FROM files
    WHERE asset_id = %s
""", (asset_id,))
    files = cur.fetchall()

    cur.execute("""
        SELECT ad.*, u.name AS assigned_user_name, ad.assigned_from, ad.assigned_until, ad.is_active
        FROM assignments ad
        LEFT JOIN user_details u ON ad.user_id = u.id
        WHERE ad.asset_id = %s
    """, (asset_id,))
    assignments = cur.fetchall()

    # POST logic for approval or rejection
    if request.method == 'POST' and request_data['status'].lower() == 'pending':
        action = request.form.get('action')
        remarks = request.form.get('remarks', '')
        new_status = 'Approved' if action == 'approve' else 'Rejected'
        asset_remark = 'Active' if new_status == 'Approved' else 'Rejected by Manager'
        is_active_flag = True if new_status == 'Approved' else False

        now = datetime.now()

        cur.execute("""
            INSERT INTO approval (request_id, approved_by, status, remarks)
            VALUES (%s, %s, %s, %s)
        """, (request_id, current_user.id, new_status, remarks))

        cur.execute("""
            UPDATE requests SET status = %s WHERE id = %s
        """, (new_status, request_id))

        cur.execute("""
            UPDATE asset
            SET is_active = %s, remarks = %s, updated_at = %s
            WHERE id = %s
        """, (is_active_flag, asset_remark, now, asset_id))

        conn.commit()
        flash(f"Request {new_status}.", "success")
        return redirect(url_for('view_requests'))

    return render_template('approve_requests.html',
                           request_data=request_data,
                           warranty=warranty,
                           insurance_records=insurance_records,
                           vendor=vendor,
                           files=files,
                           assignments=assignments,
                           maintenance_records=maintenance_records,monthly_records=monthly_records,
                           pending_requests=notifications["pending_requests"],pending_count=len(notifications["pending_requests"]),
        expiring_warranties=notifications["expiring_warranties"],expiring_insurances=notifications["expiring_insurances"],
        total_users=0,total_count=notifications["total_count"],open_maintenance=0,pending_approvals=0,recent_logs=[])

def clean_input(value, is_int=False, is_date=False):
    if value is None or value.strip() == "":
        return None
    if is_int:
        return int(value)
    if is_date:
        return value  # or datetime.strptime(value, '%Y-%m-%d') if needed
    return value

@app.route('/edit_asset/<int:asset_id>', methods=['GET', 'POST'])
@login_required
def edit_asset(asset_id):
    conn = get_db_connection()
    cur = conn.cursor()

    notifications = get_notifications()

    cur.execute("""
    SELECT a.*, 
           subcat.name AS subcategory_name,
           parentcat.name AS category_name
    FROM asset a
    LEFT JOIN category subcat ON a.category_id = subcat.id
    LEFT JOIN category parentcat ON subcat.parent_id = parentcat.id
    WHERE a.id = %s
""", (asset_id,))
    asset = cur.fetchone()

    if not asset:
        flash("Asset not found.", "danger")
        return redirect(url_for('view_assets'))

    # Fetch all categories and subcategories
    cur.execute("SELECT id, name, parent_id FROM category WHERE is_active = TRUE")
    categories = cur.fetchall()

    cur.execute("SELECT id, name FROM user_details WHERE is_active = TRUE")
    users = cur.fetchall()

    cur.execute("SELECT * FROM asset WHERE id = %s", (asset_id,))
    asset = cur.fetchone()
    if not asset:
        flash("Asset not found.", "danger")
        return redirect(url_for('view_assets'))

    cur.execute("SELECT * FROM warranty WHERE asset_id = %s", (asset_id,))
    warranty = cur.fetchone()

    cur.execute("SELECT * FROM vendors WHERE asset_id = %s", (asset_id,))
    vendor = cur.fetchone()

    cur.execute("SELECT * FROM files WHERE asset_id = %s", (asset_id,))
    files = cur.fetchone()

    def none_if_empty(value):
        return None if value is None or str(value).strip() == '' else value

    def parse_float(value):
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def parse_int(value):
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    if request.method == 'POST':
        asset_name = request.form['asset_name']
        description = request.form['description']
        category_id = none_if_empty(request.form.get('category_id')) or none_if_empty(request.form.get('subcategory_id'))
        purchase_date = none_if_empty(request.form.get('purchase_date'))
        purchase_cost = parse_float(request.form.get('purchase_cost'))
        remarks = none_if_empty(request.form.get('remarks'))
        parent_asset_id = none_if_empty(request.form.get('parent_asset_id'))
        warranty_years = parse_int(request.form.get('warranty_years'))
        vendor_name = none_if_empty(request.form.get('vendor_name'))
        vendor_email = none_if_empty(request.form.get('vendor_email'))
        vendor_phone = none_if_empty(request.form.get('vendor_phone'))
        vendor_address = none_if_empty(request.form.get('vendor_address'))
        subcategory_id = none_if_empty(request.form.get('subcategory_id'))
        now = datetime.now()
        category_to_save = subcategory_id
        cur.execute("UPDATE asset SET updated_at = %s WHERE id = %s", (now, asset_id))

        cur.execute("""
            UPDATE asset SET
                asset_name=%s, description=%s, category_id=%s, purchase_date=%s,
                purchase_cost=%s, updated_at=%s, remarks=%s, parent_asset_id=%s
            WHERE id=%s
        """, (asset_name, description, category_to_save, purchase_date, purchase_cost,
              now,remarks, parent_asset_id, asset_id))

        if warranty:
            cur.execute("UPDATE warranty SET years=%s, is_active=TRUE WHERE asset_id=%s", (warranty_years, asset_id))
        else:
            cur.execute("INSERT INTO warranty (asset_id, years, is_active) VALUES (%s, %s, TRUE)", (asset_id, warranty_years))

        # Vendor
        if vendor:
            cur.execute("""
                UPDATE vendors SET name=%s, email=%s, phone=%s, address=%s, is_active=TRUE
                WHERE asset_id=%s
            """, (vendor_name, vendor_email, vendor_phone, vendor_address, asset_id))
        else:
            cur.execute("""
                INSERT INTO vendors (name, email, phone, address, is_active, asset_id)
                VALUES (%s, %s, %s, %s, TRUE, %s)
            """, (vendor_name, vendor_email, vendor_phone, vendor_address, asset_id))

        upload_folder = os.path.join(app.root_path, 'static', 'uploads')

        file = request.files.get('file')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)

    # Save path on disk
            file_save_path = os.path.join(upload_folder, filename)
            file.save(file_save_path)

    # Relative path for DB (normalize slashes for safety)
            file_path_for_db = f'uploads/{filename}'.replace('\\', '/')

            now = datetime.now()

            cur.execute("""
        INSERT INTO files (asset_id, file_name, file_path, uploaded_by, uploaded_at, is_active)
        VALUES (%s, %s, %s, %s, %s, TRUE)
        """, (asset_id, filename, file_path_for_db, current_user.id, now))
        conn.commit()
        cur.close()
        conn.close()
        flash("Asset update submitted for approval.", "success")
        return redirect(url_for('view_assets'))
    
    selected_category_id = None
    selected_subcategory_id = None

    if asset and asset[3]:  # Assuming column 3 is category_id
        category_id = asset[3]
        cur.execute("SELECT parent_id FROM category WHERE id = %s", (category_id,))
        parent = cur.fetchone()

        if parent and parent[0]:
        # asset is linked to a subcategory
            selected_subcategory_id = category_id
            selected_category_id = parent[0]
        else:
        # asset is linked to a top-level category
            selected_category_id = category_id

    return render_template('edit_asset.html', asset=asset, warranty=warranty, vendor=vendor, categories=categories, users=users, selected_category_id=selected_category_id,
                           selected_subcategory_id=selected_subcategory_id, files=files, pending_requests=notifications["pending_requests"],pending_count=len(notifications["pending_requests"]),
        expiring_warranties=notifications["expiring_warranties"],expiring_insurances=notifications["expiring_insurances"],
        total_users=0,total_count=notifications["total_count"],open_maintenance=0,pending_approvals=0,recent_logs=[])

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'docx'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/download/<file_id>')
@login_required
def download_file(file_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT filename FROM files WHERE id = %s", (file_id,))
    result = cur.fetchone()
    cur.close()
    conn.close()

    if result:
        filename = result[0]
        upload_folder = os.path.join(os.getcwd(), 'uploads')  # adjust if different
        return send_from_directory(upload_folder, filename, as_attachment=True)
    else:
        flash("File not found.", "danger")
        return redirect(url_for('view_requests'))  # or any other fallback page

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/add_asset', methods=['GET', 'POST'])
@login_required
def add_asset():
    conn = get_db_connection()
    cur = conn.cursor()

    notifications = get_notifications()

    # Get top-level categories (parent_id IS NULL)
    cur.execute("SELECT id, name FROM category WHERE parent_id IS NULL AND is_active = TRUE")
    categories = cur.fetchall()

    # Get subcategories (parent_id IS NOT NULL)
    cur.execute("SELECT id, name, parent_id FROM category WHERE parent_id IS NOT NULL AND is_active = TRUE")
    subcategories = cur.fetchall()


    cur.execute("SELECT id, name FROM user_details WHERE is_active = TRUE")
    users = cur.fetchall()

    def none_if_empty(value):
        return None if value is None or str(value).strip() == '' else value

    if request.method == 'POST':
        asset_name = request.form['asset_name']
        description = request.form['description']
        purchase_date = none_if_empty(request.form.get('purchase_date'))
        purchase_cost = none_if_empty(request.form.get('purchase_cost'))
        remarks = none_if_empty(request.form.get('remarks'))
        parent_asset_id = none_if_empty(request.form.get('parent_asset_id'))
        warranty_years = none_if_empty(request.form.get('warranty_years'))
        vendor_name = none_if_empty(request.form.get('vendor_name'))
        vendor_email = none_if_empty(request.form.get('vendor_email'))
        vendor_phone = none_if_empty(request.form.get('vendor_phone'))
        vendor_address = none_if_empty(request.form.get('vendor_address'))

        now = datetime.now()
        is_active = False

        # NEW: Handle category/subcategory creation
        category_id = request.form.get('category_id')
        subcategory_id = request.form.get('subcategory_id')
        new_category = request.form.get('new_category')
        new_subcategory = request.form.get('new_subcategory')

        # Insert new category if selected
        if category_id == 'new' and new_category:
            cur.execute("""
                INSERT INTO category (name, parent_id, is_active) VALUES (%s, NULL, TRUE) RETURNING id
            """, (new_category,))
            category_id = cur.fetchone()[0]
            conn.commit()

        # Insert new subcategory if selected
        if subcategory_id == 'new' and new_subcategory and category_id:
            cur.execute("""
                INSERT INTO category (name, parent_id, is_active) VALUES (%s, %s, TRUE) RETURNING id
            """, (new_subcategory, category_id))
            subcategory_id = cur.fetchone()[0]
            conn.commit()

        # Final category ID
        final_category_id = subcategory_id or category_id

        cur.execute("""
            SELECT tag FROM asset 
            WHERE tag LIKE 'SVE-%' 
            ORDER BY id DESC 
            LIMIT 1
        """)
        last_tag_row = cur.fetchone()
        if last_tag_row and last_tag_row[0]:
            last_number = int(last_tag_row[0].split('-')[1])
            next_number = last_number + 1
        else:
            next_number = 1
        tag = f"SVE-{next_number:06d}"

        # Asset table
        cur.execute("""INSERT INTO asset (asset_name, description, category_id, purchase_date, purchase_cost, is_active, created_at, updated_at, tag, remarks, parent_asset_id
            ) VALUES (%s, %s, %s, %s, %s, FALSE, %s, %s, %s, %s, %s) RETURNING id
            """, (asset_name, description, final_category_id, purchase_date, purchase_cost, now, now, tag, remarks, None))
        asset_id = cur.fetchone()[0]

        # Request entry
        cur.execute("""
            INSERT INTO requests (request_type, requested_by, asset_id, status)
            VALUES ('add', %s, %s, 'Pending')
        """, (current_user.id, asset_id))

        # Warranty
        cur.execute("""
            INSERT INTO warranty (asset_id, years, is_active)
            VALUES (%s, %s, %s)
        """, (asset_id, warranty_years, True))

        # Vendor
        cur.execute("""
            INSERT INTO vendors (name, email, phone, address, is_active, asset_id)
            VALUES (%s, %s, %s, %s, TRUE, %s)
        """, (vendor_name, vendor_email, vendor_phone, vendor_address, asset_id))

        upload_folder = os.path.join(app.root_path, 'static', 'uploads')
        os.makedirs(upload_folder, exist_ok=True)

        file = request.files.get('file')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)

    # Save path on disk
            file_save_path = os.path.join(upload_folder, filename)
            file.save(file_save_path)

    # Relative path for DB (normalize slashes for safety)
            file_path_for_db = f'uploads/{filename}'.replace('\\', '/')

            now = datetime.now()

            cur.execute("""
        INSERT INTO files (asset_id, file_name, file_path, uploaded_by, uploaded_at, is_active)
        VALUES (%s, %s, %s, %s, %s, TRUE)
        """, (asset_id, filename, file_path_for_db, current_user.id, now))

        conn.commit()
        cur.close()
        conn.close()
        flash("Asset submitted for approval.", "success")
        return redirect(url_for('dashboard'))

    return render_template('add_asset.html', categories=categories, users=users, subcategories=subcategories,pending_requests=notifications["pending_requests"],pending_count=len(notifications["pending_requests"]),
        expiring_warranties=notifications["expiring_warranties"],expiring_insurances=notifications["expiring_insurances"],
        total_users=0,total_count=notifications["total_count"],open_maintenance=0,pending_approvals=0,recent_logs=[])

def none_if_empty(value):
    """
    Converts empty strings or whitespace-only strings to Python None.
    Leaves non-empty values untouched.

    This helps avoid psycopg2 errors when inserting into INTEGER, NUMERIC, or DATE fields.
    """
    if value is None:
        return None
    value = str(value).strip()
    return value if value != '' else None

@app.route('/extend_assignment/<int:asset_id>', methods=['GET', 'POST'])
@login_required
def extend_assignment(asset_id):
    conn = get_db_connection()
    cur = conn.cursor()

    notifications = get_notifications()

    # 1. Get the latest active or pending assignment for this asset
    cur.execute("""
        SELECT id, user_id, assigned_from, assigned_until, remarks, is_active
        FROM assignments
        WHERE asset_id = %s
        ORDER BY id DESC
        LIMIT 1
    """, (asset_id,))
    previous = cur.fetchone()

    previous_assignment_id = previous[0] if previous else None
    previous_user_id = previous[1] if previous else None

    # 2. Get all active users for dropdown
    cur.execute("SELECT id, name FROM user_details WHERE is_active = TRUE")
    users = cur.fetchall()

    if request.method == 'POST':
        if previous and previous[5]:  # previous[5] is is_active
            prev_until = request.form.get('previous_assigned_until') or previous[3]
            prev_remarks = request.form.get('previous_remarks') or previous[4]
            cur.execute("""
                UPDATE assignments
                SET assigned_until=%s, remarks=%s
                WHERE id=%s
            """, (prev_until, prev_remarks, previous_assignment_id))

        # Insert new assignment for a potentially new user
        new_user_id = request.form.get('new_user_id') or previous_user_id
        new_from = request.form.get('new_assigned_from')
        new_until = request.form.get('new_assigned_until') or None
        new_remarks = request.form.get('new_remarks') or None

        cur.execute("""
            INSERT INTO assignments (asset_id, user_id, assigned_from, assigned_until, remarks, is_active)
            VALUES (%s, %s, %s, %s, %s, TRUE)
            RETURNING id
        """, (asset_id, new_user_id, new_from, new_until, new_remarks))
        new_assignment_id = cur.fetchone()[0]

        # Insert request for approval
        cur.execute("""
            INSERT INTO requests (request_type, requested_by, asset_id, assignment_id, status)
            VALUES ('assignment', %s, %s, %s, 'Pending')
        """, (current_user.id, asset_id, new_assignment_id))

        conn.commit()
        flash("Assignment extended successfully.", "success")
        return redirect(url_for('view_assets'))

    cur.close()
    conn.close()

    return render_template(
        'extend_assignment.html',pending_requests=notifications["pending_requests"],pending_count=len(notifications["pending_requests"]),
        expiring_warranties=notifications["expiring_warranties"],expiring_insurances=notifications["expiring_insurances"],
        total_users=0,total_count=notifications["total_count"],open_maintenance=0,pending_approvals=0,recent_logs=[],
        previous=previous,
        users=users,
        asset_id=asset_id
    )

@app.route('/add_insurance/<int:asset_id>', methods=['GET', 'POST'])
@login_required
def add_insurance(asset_id):
    if not (current_user.has_role('Asset Manager') or current_user.has_role('Asset Entry Officer')):
        return redirect(url_for('unauthorized'))

    conn = get_db_connection()
    cur = conn.cursor()

    notifications = get_notifications()

    now = datetime.now()

    if request.method == 'POST':
        policy_number = request.form['policy_number']
        provider_details = request.form['provider_details']
        provider_contact = request.form['provider_contact']
        insured_value = request.form['insured_value']
        premium = request.form['premium']
        start_date = request.form['start_date']
        end_date = request.form['end_date']

        # Check if this asset already has insurance
        cur.execute("SELECT COUNT(*) FROM insurances WHERE asset_id = %s", (asset_id,))
        insurance_count = cur.fetchone()[0]

        if insurance_count == 0:
            # First time → Needs approval
            cur.execute("""
                INSERT INTO insurances 
                    (asset_id, policy_number, provider_details, provider_contact, insured_value, insurance_premium, start_date, end_date, is_active)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s, TRUE)
                RETURNING id
            """, (asset_id, policy_number, provider_details, provider_contact, insured_value, premium, start_date, end_date))
            insurance_id = cur.fetchone()[0]

            # Create approval request
            cur.execute("""
                INSERT INTO requests (request_type, requested_by, asset_id, insurance_id, remarks, is_active)
                VALUES ('insurance', %s, %s, %s, %s, TRUE)
            """, (current_user.id, asset_id, insurance_id, f"First insurance request for asset {asset_id}"))

            flash("First-time insurance request submitted for approval.", "info")
        else:
            # Not first time → Directly active (no approval)
            cur.execute("""
                INSERT INTO insurances 
                    (asset_id, policy_number, provider_details, provider_contact, insured_value, insurance_premium, start_date, end_date, is_active, created_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s, TRUE,%s)
            """, (asset_id, policy_number, provider_details, provider_contact, insured_value, premium, start_date, end_date, now))

            flash("Insurance added successfully.", "success")

        conn.commit()
        cur.close()
        conn.close()

        return redirect(url_for('asset_details', asset_id=asset_id))

    # If GET, fetch the latest active insurance (for renewal auto-fill)
    cur.execute("""
        SELECT policy_number, provider_details, provider_contact, insured_value, end_date
        FROM insurances
        WHERE asset_id = %s 
        ORDER BY end_date DESC
        LIMIT 1
    """, (asset_id,))
    last_insurance = cur.fetchone()

    suggested_start = None
    suggested_end = None
    if last_insurance and last_insurance[4]:
        last_end_date = last_insurance[4]
        suggested_start = last_end_date + timedelta(days=1)
        suggested_end = suggested_start + relativedelta(years=1)

    cur.close()
    conn.close()

    return render_template(
        'add_insurance.html',asset_id=asset_id,last_insurance=last_insurance,suggested_start=suggested_start,
        suggested_end=suggested_end,pending_requests=notifications["pending_requests"],pending_count=len(notifications["pending_requests"]),
        expiring_warranties=notifications["expiring_warranties"],expiring_insurances=notifications["expiring_insurances"],
        total_users=0,total_count=notifications["total_count"],open_maintenance=0,pending_approvals=0,recent_logs=[]
    )

@app.route('/edit_insurance/<int:insurance_id>', methods=['GET', 'POST'])
@login_required
def edit_insurance(insurance_id):
    if not (current_user.has_role('Asset Manager') or current_user.has_role('Asset Entry Officer')):
        return redirect(url_for('unauthorized'))

    conn = get_db_connection()
    cur = conn.cursor()

    notifications= get_notifications()

    # Fetch current insurance record
    cur.execute("""
        SELECT id, asset_id, policy_number, provider_details, provider_contact,
               insured_value, insurance_premium, start_date, end_date
        FROM insurances
        WHERE id = %s
    """, (insurance_id,))
    insurance = cur.fetchone()

    if not insurance:
        cur.close()
        conn.close()
        flash("Insurance record not found.", "danger")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        policy_number = request.form['policy_number']
        provider_details = request.form['provider_details']
        provider_contact = request.form['provider_contact']
        insured_value = request.form['insured_value']
        premium = request.form['premium']
        start_date = request.form['start_date']
        end_date = request.form['end_date']

        # Update insurance record directly (no approval request)
        cur.execute("""
            UPDATE insurances
            SET policy_number=%s,
                provider_details=%s,
                provider_contact=%s,
                insured_value=%s,
                insurance_premium=%s,
                start_date=%s,
                end_date=%s
            WHERE id=%s
        """, (policy_number, provider_details, provider_contact,
              insured_value, premium, start_date, end_date, insurance_id))

        conn.commit()
        cur.close()
        conn.close()

        flash("Insurance updated successfully.", "success")
        return redirect(url_for('asset_details', asset_id=insurance[1]))

    cur.close()
    conn.close()
    return render_template("edit_insurance.html", insurance=insurance,pending_requests=notifications["pending_requests"],pending_count=len(notifications["pending_requests"]),
        expiring_warranties=notifications["expiring_warranties"],expiring_insurances=notifications["expiring_insurances"],
        total_users=0,total_count=notifications["total_count"],open_maintenance=0,pending_approvals=0,recent_logs=[])

@app.route('/edit_assignment/<int:assignment_id>', methods=['GET', 'POST'])
@login_required
def edit_assignment(assignment_id):
    conn = get_db_connection()
    cur = conn.cursor()

    notifications = get_notifications()

    # Get the assignment details
    cur.execute("""
        SELECT asset_id, user_id, assigned_from, assigned_until, remarks 
        FROM assignments 
        WHERE id = %s
    """, (assignment_id,))
    assignment = cur.fetchone()

    if not assignment:
        flash("Assignment not found.", "danger")
        return redirect(url_for('view_assets'))

    # Get all active assets and users for dropdowns
    cur.execute("SELECT id, asset_name FROM asset WHERE is_active = TRUE")
    assets = cur.fetchall()
    cur.execute("SELECT id, name FROM user_details WHERE is_active = TRUE")
    users = cur.fetchall()

    if request.method == 'POST':
        asset_id = request.form.get('asset_id')
        assigned_user_id = request.form.get('assigned_user_id')
        assigned_from = request.form.get('assigned_from')
        assigned_until = request.form.get('assigned_until') or None
        assignment_remarks = request.form.get('assignment_remarks') or None

        if asset_id and assigned_user_id:
            # Directly update the existing assignment
            cur.execute("""
                UPDATE assignments
                SET asset_id = %s,
                    user_id = %s,
                    assigned_from = %s,
                    assigned_until = %s,
                    remarks = %s
                WHERE id = %s
            """, (asset_id, assigned_user_id, assigned_from, assigned_until, assignment_remarks, assignment_id))

            conn.commit()
            flash("Assignment details updated successfully.", "success")
            return redirect(url_for('view_assets'))

    cur.close()
    conn.close()

    return render_template('edit_assignment.html', assignment=assignment, assets=assets, users=users,pending_requests=notifications["pending_requests"],pending_count=len(notifications["pending_requests"]),
        expiring_warranties=notifications["expiring_warranties"],expiring_insurances=notifications["expiring_insurances"],
        total_users=0,total_count=notifications["total_count"],open_maintenance=0,pending_approvals=0,recent_logs=[])

@app.route('/add_maintenance', methods=['GET', 'POST'])
@login_required
def add_maintenance():
    conn = get_db_connection()
    cur = conn.cursor()

    notifications = get_notifications()

    # Fetch assets and categories for dropdowns
    cur.execute("SELECT id, asset_name FROM asset WHERE is_active = TRUE")
    assets = cur.fetchall()

    cur.execute("SELECT id, name FROM category WHERE parent_id IS NULL AND is_active = TRUE")
    categories = cur.fetchall()

    cur.execute("SELECT id, name, parent_id FROM category WHERE parent_id IS NOT NULL AND is_active = TRUE")
    subcategories = cur.fetchall()

    cur.execute("SELECT id, name FROM user_details WHERE is_active = TRUE")
    users = cur.fetchall()

    now = datetime.now()

    if request.method == 'POST':
        # --- Maintenance data ---
        asset_id = request.form['asset_id']
        from_date = request.form['from_date']
        to_date = request.form.get('to_date') or None
        company = request.form.get('company') or None
        serviced_by = request.form.get('serviced_by') or None
        maintenance_type = request.form['maintenance_type']
        cost = request.form.get('cost') or 0
        remarks = request.form.get('remarks')
        has_parts_involved = True if request.form.get('has_parts_involved') else False

        part_id = None
        now = datetime.now()

        # --- Insert Part if involved ---
        if has_parts_involved:
            # Fetch part fields from form
            part_name = request.form['part_name']
            part_description = request.form.get('part_description')
            part_subcategory_id = request.form.get('part_subcategory_id') or None
            part_purchase_date = request.form.get('part_purchase_date') or None
            part_purchase_cost = request.form.get('part_purchase_cost') or 0
            part_remarks = request.form.get('part_remarks')
            warranty_years = request.form.get('warranty_years')
            vendor_name = request.form.get('vendor_name')
            vendor_email = request.form.get('vendor_email')
            vendor_phone = request.form.get('vendor_phone')
            vendor_address = request.form.get('vendor_address')

            # Generate unique tag
            cur.execute("SELECT tag FROM asset WHERE tag LIKE 'SVE-%' ORDER BY id DESC LIMIT 1")
            last_tag_row = cur.fetchone()
            next_number = int(last_tag_row[0].split('-')[1]) + 1 if last_tag_row else 1
            tag = f"SVE-{next_number:06d}"

            # Insert part as a new asset
            cur.execute("""
                INSERT INTO asset (asset_name, description, category_id, purchase_date, purchase_cost,
                                   is_active, created_at, updated_at, tag, remarks, parent_asset_id)
                VALUES (%s,%s,%s,%s,%s,FALSE,%s,%s,%s,%s,%s)
                RETURNING id
            """, (
                part_name, part_description, part_subcategory_id, part_purchase_date,
                part_purchase_cost, now, now, tag, part_remarks, asset_id
            ))
            part_id = cur.fetchone()[0]

            # Insert Vendor
            if vendor_name:
                cur.execute("""
                    INSERT INTO vendors (name, email, phone, address, is_active, asset_id)
                    VALUES (%s,%s,%s,%s,TRUE,%s)
                """, (vendor_name, vendor_email, vendor_phone, vendor_address, part_id))

            # Insert Warranty
            if warranty_years:
                cur.execute("""
                    INSERT INTO warranty (asset_id, years, is_active)
                    VALUES (%s,%s,TRUE)
                """, (part_id, warranty_years))

            # File upload
            file = request.files.get('file')
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                upload_folder = os.path.join(app.root_path, 'static', 'uploads')
                os.makedirs(upload_folder, exist_ok=True)
                file_path = os.path.join(upload_folder, filename)
                file.save(file_path)
                file_db_path = f'uploads/{filename}'
                cur.execute("""
                    INSERT INTO files (asset_id, file_name, file_path, uploaded_by, uploaded_at, is_active)
                    VALUES (%s,%s,%s,%s,%s,TRUE)
                """, (part_id, filename, file_db_path, current_user.id, now))
            
            cur.execute("""
            INSERT INTO requests (request_type, requested_by, asset_id, status)
            VALUES ('add', %s, %s ,'Pending')
        """, (current_user.id, part_id))

        # --- Insert Maintenance record ---
        cur.execute("""INSERT INTO maintenance (asset_id, part_id, from_date, to_date, company, serviced_by,
        has_parts_involved, cost, maintenance_type, remarks, is_active, created_at
        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,TRUE,%s) RETURNING id
        """, (asset_id, part_id, from_date, to_date, company, serviced_by,has_parts_involved, cost, maintenance_type, remarks, now))
        maintenance_id = cur.fetchone()[0]   # now it works


        # --- Insert request for approval ---
        cur.execute("""
            INSERT INTO requests (request_type, requested_by, asset_id, maintenance_id, status)
            VALUES ('maintenance', %s, %s, %s ,'Pending')
        """, (current_user.id, asset_id, maintenance_id))

        conn.commit()
        cur.close()
        conn.close()

        flash("Maintenance/Repair record added successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template('add_maintenance.html',assets=assets,categories=categories,subcategories=subcategories,
        users=users,pending_requests=notifications["pending_requests"],pending_count=len(notifications["pending_requests"]),
        expiring_warranties=notifications["expiring_warranties"],expiring_insurances=notifications["expiring_insurances"],
        total_users=0,total_count=notifications["total_count"],open_maintenance=0,pending_approvals=0,recent_logs=[]
        )

@app.route('/add_monthly_maintenance/<int:asset_id>', methods=['GET', 'POST'])
@login_required
def add_monthly_maintenance(asset_id):
    conn = get_db_connection()
    cur = conn.cursor()

    notifications = get_notifications()

    now = datetime.now()

    # Fetch active maintenance record
    cur.execute("""
        SELECT id
        FROM maintenance
        WHERE asset_id = %s AND maintenance_type = 'Maintenance' AND is_active = TRUE
        LIMIT 1
    """, (asset_id,))
    row = cur.fetchone()
    maintenance_id = row[0] if row else None

    if maintenance_id is None:
        flash("No active maintenance record found for this asset.", "danger")
        return redirect(url_for('asset_detail', asset_id=asset_id))

    # Fetch categories for parts dropdown if needed
    cur.execute("SELECT id, name FROM category WHERE parent_id IS NULL AND is_active = TRUE")
    categories = cur.fetchall()

    cur.execute("SELECT id, name, parent_id FROM category WHERE parent_id IS NOT NULL AND is_active = TRUE")
    subcategories = cur.fetchall()

    if request.method == 'POST':
        maintenance_date = request.form['maintenance_date']
        remarks = request.form.get('remarks')
        serviced_by = request.form['serviced_by']
        has_parts_involved = bool(request.form.get('has_parts_involved'))

        part_id = None
        now = datetime.now()

        # --- Insert part if involved ---
        if has_parts_involved:
            part_name = request.form.get('part_name')
            part_description = request.form.get('part_description')
            part_subcategory_id = request.form.get('part_subcategory_id')
            part_purchase_date = request.form.get('part_purchase_date')
            part_purchase_cost = request.form.get('part_purchase_cost') or 0
            part_remarks = request.form.get('part_remarks')
            warranty_years = request.form.get('warranty_years')
            vendor_name = request.form.get('vendor_name')
            vendor_email = request.form.get('vendor_email')
            vendor_phone = request.form.get('vendor_phone')
            vendor_address = request.form.get('vendor_address')

            # Generate unique tag
            cur.execute("SELECT tag FROM asset WHERE tag LIKE 'SVE-%' ORDER BY id DESC LIMIT 1")
            last_tag_row = cur.fetchone()
            next_number = int(last_tag_row[0].split('-')[1]) + 1 if last_tag_row else 1
            tag = f"SVE-{next_number:06d}"

            # Insert part
            cur.execute("""
                INSERT INTO asset (asset_name, description, category_id, purchase_date, purchase_cost,
                                   is_active, created_at, updated_at, tag, remarks, parent_asset_id)
                VALUES (%s,%s,%s,%s,%s,FALSE,%s,%s,%s,%s,%s)
                RETURNING id
            """, (
                part_name, part_description, part_subcategory_id, part_purchase_date,
                part_purchase_cost, now, now, tag, part_remarks, asset_id
            ))
            part_id = cur.fetchone()[0]

            # Vendor and warranty
            cur.execute("""
                INSERT INTO vendors (name, email, phone, address, is_active, asset_id)
                VALUES (%s,%s,%s,%s,TRUE,%s)
            """, (vendor_name, vendor_email, vendor_phone, vendor_address, part_id))

            if warranty_years:
                cur.execute("""
                    INSERT INTO warranty (asset_id, years, is_active)
                    VALUES (%s,%s,TRUE)
                """, (part_id, warranty_years))

            # File upload
            file = request.files.get('file')
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                upload_folder = os.path.join(app.root_path, 'static', 'uploads')
                os.makedirs(upload_folder, exist_ok=True)
                file_path = os.path.join(upload_folder, filename)
                file.save(file_path)
                file_db_path = f'uploads/{filename}'
                cur.execute("""
                    INSERT INTO files (asset_id, file_name, file_path, uploaded_by, uploaded_at, is_active)
                    VALUES (%s,%s,%s,%s,%s,TRUE)
                """, (part_id, filename, file_db_path, current_user.id, now))

            cur.execute("""
            INSERT INTO requests (request_type, requested_by, asset_id, status)
            VALUES ('add', %s, %s ,'Pending')
        """, (current_user.id, part_id))

        # --- Insert monthly maintenance as inactive/pending ---
        cur.execute("""
            INSERT INTO monthly_maintenance (
                maintenance_id, asset_id, part_id, maintenance_date,
                remarks, serviced_by, has_parts_involved, is_active
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,TRUE)
        """, (
            maintenance_id, asset_id, part_id, maintenance_date,
            remarks, serviced_by, has_parts_involved
        ))

        # --- Insert request for approval ---
        cur.execute("""
            INSERT INTO requests (request_type, requested_by, asset_id, status)
            VALUES ('maintenance', %s, %s, 'Pending')
        """, (current_user.id, asset_id))

        conn.commit()
        cur.close()
        conn.close()

        flash("Monthly Maintenance added successfully and pending approval!", "success")
        return redirect(url_for('asset_details', asset_id=asset_id))

    cur.close()
    conn.close()
    return render_template('add_monthly_maintenance.html',
                           asset_id=asset_id, row=row,
                           categories=categories,pending_requests=notifications["pending_requests"],
        pending_count=len(notifications["pending_requests"]),
        expiring_warranties=notifications["expiring_warranties"],
        expiring_insurances=notifications["expiring_insurances"],
        total_users=0,
        total_count=notifications["total_count"],
        open_maintenance=0,
        pending_approvals=0,
        recent_logs=[],subcategories=subcategories)

@app.route("/update_asset_status/<int:asset_id>", methods=["POST"])
@login_required
def update_asset_status(asset_id):
    if session.get("role") != "Asset Manager":
        flash("Unauthorized action", "danger")
        return redirect(url_for("view_asset_details", asset_id=asset_id))

    is_active = request.form.get("is_active") == "true"
    remarks = request.form.get("remarks", "")

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        UPDATE asset
        SET is_active = %s,
            remarks = %s,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = %s
    """, (is_active, remarks, asset_id))

    conn.commit()
    cur.close()
    conn.close()

    flash("Asset status updated successfully!", "success")
    return redirect(url_for("asset_details", asset_id=asset_id))

@app.route('/')
def index():
    return render_template('welcome.html')

@app.route('/contact_us')
def contact_us():
    return render_template('contact_us.html')

@app.route('/about_us')
def about_us():
    return render_template('about_us.html')

@app.route('/product')
def product():
    return render_template('product.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('index'))

@app.route('/unauthorized')
def unauthorized():
    return redirect(url_for('index'))

# --- Run the app ---
if __name__ == '__main__':
    app.run(debug=True)