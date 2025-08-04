from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import psycopg2
from datetime import datetime, timedelta
import os
import io
import random
import string
import pytz
from dotenv import load_dotenv
from captcha.image import ImageCaptcha
from fpdf import FPDF
import qrcode
from PIL import Image
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from flask import send_file, abort
from uuid import uuid4
from psycopg2 import extras
from flask import send_from_directory



# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = '201025'
UPLOAD_FOLDER = os.path.join('static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Upload config
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}

# Setup serializer and mail in your app init
s = URLSafeTimedSerializer(app.secret_key)
mail = Mail(app)

# --- Flask-Login ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.getenv('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_PASS')
mail = Mail(app)

# --- DB Connection ---
def get_db_connection():
    return psycopg2.connect(os.getenv("DATABASE_URL"))

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
    
@app.route('/')
def welcome():
    return render_template('welcome.html')

# --- Dummy function to fetch user from DB ---
def get_user_by_email_role(email, role_name):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT u.id, u.email, u.password_hash, u.force_password_reset, array_agg(r.name)
        FROM user_details u
        JOIN role r ON r.id = u.role_id
        WHERE u.email = %s AND r.name = %s AND u.is_active = TRUE
        GROUP BY u.id
    """, (email, role_name))
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

# --- Forgot password ---
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        if user:
            token = s.dumps(email, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message('Password Reset', sender='noreply@example.com', recipients=[email])
            msg.body = f'Click the link to reset your password: {reset_url}'
            mail.send(msg)
            flash('Password reset link sent to your email.', 'success')
        else:
            flash('Email not found.', 'danger')
        cur.close()
        conn.close()
    return render_template('forgot_password.html')

# --- Change password ---
@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current = request.form['current_password']
        new = request.form['new_password']
        confirm = request.form['confirm_password']

        if new != confirm:
            flash('New password and confirm password do not match.', 'danger')
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
                role_name = role[0]
                if role_name == 'Super Admin':
                    return redirect(url_for('admin_dashboard'))
                elif role_name == 'Asset Manager':
                    return redirect(url_for('manager_dashboard'))
                elif role_name == 'Asset Entry Officer':
                    return redirect(url_for('assetentryofficer_dashboard'))
                elif role_name == 'Technician':
                    return redirect(url_for('technician_dashboard'))
                else:
                    flash('Role not recognized. Please contact administrator.')
                    return redirect(url_for('login'))
                
        else:
            flash('Incorrect current password.', 'danger')
        cur.close()
        conn.close()
    return render_template('change_password.html')

# --- Login ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        captcha_input = request.form.get('captcha')

        # CAPTCHA validation
        if captcha_input.upper() != session.get('captcha_text', ''):
            flash('Incorrect CAPTCHA', 'danger')
            return redirect(url_for('login', animate='true'))

        # Fetch user
        user = get_user_by_email_role(email, role)

        if user and check_password_hash(user.password, password):
            login_user(user)
            session['role'] = role
            session['email'] = email   

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
            if user.force_password_reset and (user.has_role('Technician') or user.has_role('Asset Entry Officer')):
                return redirect(url_for('reset_password'))

            # Normal role-based redirection
            if user.has_role('Super Admin'):
                return redirect(url_for('admin_dashboard'))
            elif user.has_role('Asset Manager'):
                return redirect(url_for('manager_dashboard'))
            elif user.has_role('Technician'):
                return redirect(url_for('technician_dashboard'))
            elif user.has_role('Asset Entry Officer'):
                return redirect(url_for('assetentryofficer_dashboard'))
            else:
                flash('Unauthorized role', 'danger')
                return redirect(url_for('login')) 
        else:
            flash('Invalid credentials or role', 'danger')
            return redirect(url_for('login', animate='true'))

    animate = request.args.get('animate') == 'true'
    return render_template('login.html', animate=animate)

@app.route('/reset_password', methods=['GET', 'POST'])
@login_required
def reset_password():
    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html')
        hashed = generate_password_hash(new_password)
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            UPDATE user_details
            SET password_hash = %s, force_password_reset = FALSE
            WHERE id = %s
        """, (hashed, current_user.id))
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

# --- Admin Dashboard ---
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.has_role('Super Admin'):
        return redirect(url_for('unauthorized'))
    
    if 'email' not in session:
        session['email'] = current_user.email

    return render_template(
        'admin_dashboard.html',
        total_assets=0,
        total_users=0,
        open_maintenance=0,
        pending_approvals=0,
        recent_logs=[],
        recent_users=[]
    )

@app.route('/assetmanager/dashboard')
@login_required
def manager_dashboard():
    if not current_user.has_role('Asset Manager'):
        return redirect(url_for('unauthorized'))
    
    if 'email' not in session:
        session['email'] = current_user.email

    return render_template(
        'manager_dashboard.html',
        total_assets=0,
        total_users=0,
        open_maintenance=0,
        pending_approvals=0,
        recent_logs=[],
        recent_users=[]
    )

@app.route('/assetentryofficer/dashboard')
@login_required
def assetentryofficer_dashboard():
    if not current_user.has_role('Asset Entry Officer'):
        return redirect(url_for('unauthorized'))
    
    if 'email' not in session:
        session['email'] = current_user.email

    # Replace below with actual ORM/db fetch or dummy values for now
    return render_template(
        'assetentryofficer_dashboard.html',
        total_assets=0,
        total_users=0,
        open_maintenance=0,
        pending_approvals=0,
        recent_logs=[],
        recent_users=[]
    )


@app.route('/technician/dashboard')
@login_required
def technician_dashboard():
    if not current_user.has_role('Technician'):
        return redirect(url_for('unauthorized'))
    
    if 'email' not in session:
        session['email'] = current_user.email

    return render_template(
        'technician_dashboard.html',
        total_assets=0,
        total_users=0,
        open_maintenance=0,
        pending_approvals=0,
        recent_logs=[],
        recent_users=[]
    )

# ------------------------------------------------------------------------------------------------------------------------------------------------------------------------

@app.route('/admin/view_users')
@login_required
def view_users():
    if not (current_user.has_role('Super Admin') or current_user.has_role('Asset Manager')):
        return redirect(url_for('unauthorized'))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT 
            u.id,
            u.email,
            u.name,
            r.name,
            u.last_login
        FROM user_details u
        JOIN role r ON u.role_id = r.id
        ORDER BY u.id;
    """)
    users = cur.fetchall()
    cur.close()
    conn.close()

    return render_template('view_users.html', users=users)

@app.route('/admin/user/<int:user_id>')
@login_required
def user_detail(user_id):
    if not (current_user.has_role('Super Admin') or current_user.has_role('Asset Manager')):
        return redirect(url_for('unauthorized'))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT 
            u.id,
            u.email,
            u.name,
            u.last_login,
            r.name,
            u.created_at,
            u.is_active
        FROM user_details u
        JOIN role r ON u.role_id = r.id
        WHERE u.id = %s;
    """, (user_id,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('view_users'))

    return render_template('user_detail.html', user=user)

@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if not current_user.has_role('Asset Manager'):
        return redirect(url_for('unauthorized'))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, name FROM role")
    roles = cur.fetchall()

    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form['email']
        role_id = request.form['role_id']
        is_active = request.form.get('is_active') == 'on'

        password_hash = generate_password_hash('default123')
        created_at = datetime.utcnow()

        try:
            cur.execute("""
                INSERT INTO user_details (name, email, password_hash, role_id, is_active, created_at, force_password_reset)
                VALUES (%s, %s, %s, %s, %s, %s, TRUE)
                RETURNING id
            """, (name, email, password_hash, role_id, is_active, created_at))
            new_user_id = cur.fetchone()[0]
            conn.commit()
            flash("User created successfully with default password 'default123'", 'success')
            return redirect(url_for('view_users'))
        except Exception as e:
            conn.rollback()
            flash(f'Error adding user: {e}', 'danger')
        finally:
            cur.close()
            conn.close()

    return render_template('add_user.html', roles=roles)

@app.route('/manager/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.has_role('Asset Manager'):
        return redirect(url_for('unauthorized'))

    conn = get_db_connection()
    cur = conn.cursor()

    # Fetch user record
    cur.execute("SELECT id, name, email, password_hash, role_id, is_active FROM user_details WHERE id = %s", (user_id,))
    user = cur.fetchone()

    # Handle missing user
    if not user:
        flash("User not found.", "danger")
        cur.close()
        conn.close()
        return redirect(url_for('manager_dashboard'))
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute("SELECT id, name FROM role")
    roles = cur.fetchall()

    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form['email']
        role_id = int(request.form['role_id'])
        is_active = request.form.get('is_active') == 'on'

        cur.execute("""
            UPDATE user_details 
            SET name=%s, email=%s,  role_id = %s, is_active=%s
            WHERE id=%s
        """, (name, email, role_id, is_active, user_id))
        conn.commit()

        flash('User updated successfully.', 'success')
        cur.close()
        conn.close()
        return redirect(url_for('user_detail', user_id=user_id))

    cur.close()
    conn.close()
    return render_template('edit_user.html', user=user, roles=roles)

@app.route('/view_assets')
@login_required
def view_assets():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT a.id, a.tag, a.asset_name FROM asset a where a.is_active = True ")
    assets = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('view_assets.html', assets=assets)

@app.route("/asset/<int:asset_id>")
def asset_details(asset_id):
    if not (current_user.has_role('Asset Manager') or current_user.has_role('Super Admin') or current_user.has_role('Asset Entry Officer')):
        return redirect(url_for('unauthorized'))
    
    conn = get_db_connection()
    cur = conn.cursor()


    # Get main asset details
    cur.execute("""
        SELECT 
            a.id, a.asset_name, a.description, a.purchase_date, 
            a.purchase_cost, a.remarks, a.is_active, a.tag,

            child_cat.name AS subcategory,
            parent_cat.name AS category,

            v.name AS vendor_name, v.phone, v.email, v.address

        FROM asset a
        LEFT JOIN category child_cat ON a.category_id = child_cat.id
        LEFT JOIN category parent_cat ON child_cat.parent_id = parent_cat.id
        LEFT JOIN vendors v ON a.id = v.asset_id
        WHERE a.id = %s
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

    # Get maintenance records
    cur.execute("""
        SELECT task_done, maintenance_date, cost, service_by
        FROM maintenance
        WHERE asset_id = %s ORDER BY maintenance_date DESC
    """, (asset_id,))
    maintenance = cur.fetchall()

    # Get warranty info
    cur.execute("""
        SELECT years
        FROM warranty WHERE asset_id = %s
    """, (asset_id,))
    warranty = cur.fetchone()

    # Get insurance info
    cur.execute("""
        SELECT policy_number, provider, insured_value, start_date, end_date
        FROM insurances WHERE asset_id = %s
    """, (asset_id,))
    insurance = cur.fetchone()

        # Get uploaded files
    upload_folder = os.path.join(app.root_path, 'static', 'uploads')
    os.makedirs(upload_folder, exist_ok=True)

    file = request.files.get('file')  # Ensure this line is present

    if file and file.filename:
        filename = secure_filename(file.filename)
        file_path = os.path.join('static', 'uploads', filename)  # for DB (relative path)
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

    return render_template("asset_details.html", asset=asset, assignments=assignments,
                           maintenance=maintenance, warranty=warranty,
                           insurance=insurance, files=files)


@app.route('/asset/<int:asset_id>/download_pdf')
@login_required
def download_asset_pdf(asset_id):
    conn = get_db_connection()
    cur = conn.cursor()

    # Get asset and related data
    cur.execute("""
        SELECT a.id, a.asset_name, a.description, a.purchase_date, a.purchase_cost, a.remarks, a.is_active
               c.name AS category, v.name AS vendor, a.tag
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
        SELECT task_done, maintenance_date, cost, service_by, comments
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
        SELECT policy_number, provider, insured_value, start_date, end_date
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
    labels = ["ID", "Name", "Description", "Purchase Date", "Purchase Cost", "Remarks", "Category", "Vendor", "Tag", "Is Active"]
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
            pdf.multi_cell(0, 8, f"Task Done: {m[0]}\nDate: {m[1]}\nCost: Rs. {m[2]}\nService By: {m[3]}\nComments: {m[4]}", border=1)
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
        pdf.multi_cell(0, 8, f"Policy #: {insurance[0]}\nProvider: {insurance[1]}\nInsured Value: Rs. {insurance[2]}\nStart Date: {insurance[3]}\nEnd Date: {insurance[4]}", border=1)
    else:
        pdf.cell(0, 8, "No insurance info.", ln=True)

    # Return PDF
    pdf_output = io.BytesIO()
    pdf_bytes = pdf.output(dest='S').encode('latin-1', errors='replace')
    pdf_output.write(pdf_bytes)
    pdf_output.seek(0)
    return send_file(pdf_output, as_attachment=True, download_name=f"{asset[1]}_report.pdf", mimetype='application/pdf')

@app.route('/asset/<string:asset_tag>/download_qr')
@login_required
def download_qr(asset_tag):
    qr_data = f"http://localhost:5000/asset/qr/{asset_tag}"  # Update URL if deployed
    qr = qrcode.QRCode(box_size=10, border=4)
    qr.add_data(qr_data)
    qr.make(fit=True)
    img = qr.make_image(fill="black", back_color="white")

    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return send_file(buf, mimetype='image/png', as_attachment=True, download_name=f"{asset_tag}_qr.png")
    
@app.route('/view_requests')
@login_required
def view_requests():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    cur.execute("""
        SELECT r.id, r.request_type, r.status, r.request_date,
               a.asset_name, u.name as requested_by
        FROM requests r
        JOIN asset a ON a.id = r.asset_id
        JOIN user_details u ON u.id = r.requested_by
        ORDER BY r.request_date DESC
    """)
    requests = cur.fetchall()

    return render_template("view_requests.html", requests=requests)

@app.route('/approve_request/<int:request_id>', methods=['GET', 'POST'])
@login_required
def approve_request_page(request_id):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

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

    cur.execute("SELECT * FROM insurances WHERE asset_id = %s", (asset_id,))
    insurance = cur.fetchone()

    cur.execute("SELECT * FROM vendors WHERE asset_id = %s", (asset_id,))
    vendor = cur.fetchone()

    cur.execute("SELECT * FROM maintenance m JOIN asset a ON a.id = m.asset_id WHERE asset_id = %s", (asset_id,))
    maintenance = cur.fetchone()

    # Get parts (child assets) related to this maintenance asset
    cur.execute("""
    SELECT a.*, c.name AS category_name
    FROM asset a
    LEFT JOIN category c ON a.category_id = c.id
    WHERE a.parent_asset_id = %s 
""", (asset_id,))
    maintenance_parts = cur.fetchall()

    cur.execute("""
    SELECT file_name
    FROM files
    WHERE asset_id = %s AND is_active = TRUE
""", (asset_id,))
    files = cur.fetchall()

    cur.execute("""
        SELECT ad.*, u.name AS assigned_user_name
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
                           insurance=insurance,
                           vendor=vendor,
                           files=files,
                           assignments=assignments,
                           maintenance=maintenance,
                           maintenance_parts=maintenance_parts)

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

    cur.execute("SELECT * FROM asset WHERE id = %s", (asset_id,))
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

    cur.execute("SELECT * FROM insurances WHERE asset_id = %s", (asset_id,))
    insurance = cur.fetchone()

    cur.execute("SELECT * FROM vendors WHERE asset_id = %s", (asset_id,))
    vendor = cur.fetchone()

    cur.execute("SELECT * FROM assignments WHERE asset_id = %s", (asset_id,))
    assignment = cur.fetchone()

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
        tag = request.form['tag']
        remarks = none_if_empty(request.form.get('remarks'))
        parent_asset_id = none_if_empty(request.form.get('parent_asset_id'))
        warranty_years = parse_int(request.form.get('warranty_years'))

        assigned_user_id = none_if_empty(request.form.get('assigned_user_id'))
        assigned_from = none_if_empty(request.form.get('assigned_from'))
        assigned_until = none_if_empty(request.form.get('assigned_until'))

        policy_number = none_if_empty(request.form.get('policy_number'))
        provider = none_if_empty(request.form.get('provider'))
        insured_value = parse_float(request.form.get('insured_value'))
        start_date = none_if_empty(request.form.get('start_date'))
        end_date = none_if_empty(request.form.get('end_date'))
        provider_contact_raw = request.form.get('provider_contact')
        try:
            provider_contact = int(provider_contact_raw) if provider_contact_raw.strip() else None
        except (ValueError, AttributeError):
            provider_contact = None


        vendor_name = none_if_empty(request.form.get('vendor_name'))
        vendor_email = none_if_empty(request.form.get('vendor_email'))
        vendor_phone = none_if_empty(request.form.get('vendor_phone'))
        vendor_address = none_if_empty(request.form.get('vendor_address'))

        now = datetime.now()

        # Mark existing asset as inactive
        cur.execute("UPDATE asset SET is_active = FALSE, updated_at = %s WHERE id = %s", (now, asset_id))

        # Update asset
        cur.execute("""
            UPDATE asset SET
                asset_name=%s, description=%s, category_id=%s, purchase_date=%s,
                purchase_cost=%s, updated_at=%s, tag=%s, remarks=%s, parent_asset_id=%s
            WHERE id=%s
        """, (asset_name, description, category_id, purchase_date, purchase_cost,
              now, tag, remarks, parent_asset_id, asset_id))

        # Insert pending request for approval
        cur.execute("""
            INSERT INTO requests (request_type, requested_by, asset_id, status)
            VALUES ('edit', %s, %s, 'Pending')
        """, (current_user.id, asset_id))

        # Warranty
        if warranty:
            cur.execute("UPDATE warranty SET years=%s, is_active=FALSE WHERE asset_id=%s", (warranty_years, asset_id))
        else:
            cur.execute("INSERT INTO warranty (asset_id, years, is_active) VALUES (%s, %s, FALSE)", (asset_id, warranty_years))

        # Insurance
        if insurance:
            cur.execute("""UPDATE insurances SET policy_number=%s, provider=%s, insured_value=%s,
            start_date=%s, end_date=%s, provider_contact=%s, is_active=FALSE WHERE asset_id=%s""", (policy_number, provider, insured_value,
            start_date, end_date, provider_contact, asset_id))
        else:
            cur.execute("""INSERT INTO insurances (
            asset_id, policy_number, provider, insured_value,
            start_date, end_date, provider_contact, is_active)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (asset_id, policy_number, provider, insured_value,
        start_date, end_date, provider_contact, False))


        # Vendor
        if vendor:
            cur.execute("""
                UPDATE vendors SET name=%s, email=%s, phone=%s, address=%s, is_active=FALSE
                WHERE asset_id=%s
            """, (vendor_name, vendor_email, vendor_phone, vendor_address, asset_id))
        else:
            cur.execute("""
                INSERT INTO vendors (name, email, phone, address, is_active, asset_id)
                VALUES (%s, %s, %s, %s, FALSE, %s)
            """, (vendor_name, vendor_email, vendor_phone, vendor_address, asset_id))

        # Assignment
        if assigned_user_id:
            if assignment:
                cur.execute("""
                    UPDATE assignments SET user_id=%s, assigned_from=%s, assigned_until=%s, remarks=%s, is_active=FALSE
                    WHERE asset_id=%s
                """, (assigned_user_id, assigned_from, assigned_until, remarks, asset_id))
            else:
                cur.execute("""
                    INSERT INTO assignments (asset_id, user_id, assigned_from, assigned_until, remarks, is_active)
                    VALUES (%s, %s, %s, %s, %s, FALSE)
                """, (asset_id, assigned_user_id, assigned_from, assigned_until, remarks))

        # File Upload
        file = request.files.get('file')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            cur.execute("""
                INSERT INTO files (asset_id, file_name, file_path, uploaded_by, uploaded_at, is_active)
                VALUES (%s, %s, %s, %s, %s, FALSE)
            """, (asset_id, filename, file_path, current_user.id, now))

        conn.commit()
        cur.close()
        conn.close()
        flash("Asset update submitted for approval.", "success")
        return redirect(url_for('view_assets'))
    
    selected_category_id = None
    selected_subcategory_id = None

    if asset and asset[3]:  # Assuming asset[3] is category_id (adjust index if needed)
        selected_subcategory_id = asset[3]

        cur.execute("SELECT parent_id FROM category WHERE id = %s", (selected_subcategory_id,))
        parent = cur.fetchone()

        if parent and parent[0]:  # parent[0] = parent_id
            selected_category_id = parent[0]


    return render_template('edit_asset.html', asset=asset, warranty=warranty, insurance=insurance,
                           vendor=vendor, assignment=assignment, categories=categories, users=users, selected_category_id=selected_category_id,
                           selected_subcategory_id=selected_subcategory_id, files=files)

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
        category_id = none_if_empty(request.form.get('subcategory_id') or request.form.get('category_id'))
        purchase_date = none_if_empty(request.form.get('purchase_date'))
        purchase_cost = none_if_empty(request.form.get('purchase_cost'))
        remarks = none_if_empty(request.form.get('remarks'))
        parent_asset_id = none_if_empty(request.form.get('parent_asset_id'))
        warranty_years = none_if_empty(request.form.get('warranty_years'))

        assigned_user_id = none_if_empty(request.form.get('assigned_user_id'))
        assigned_from = none_if_empty(request.form.get('assigned_from'))
        assigned_until = none_if_empty(request.form.get('assigned_until'))

        policy_number = none_if_empty(request.form.get('policy_number'))
        provider = none_if_empty(request.form.get('provider'))
        insured_value = none_if_empty(request.form.get('insured_value'))
        start_date = none_if_empty(request.form.get('start_date'))
        end_date = none_if_empty(request.form.get('end_date'))
        provider_contact = none_if_empty(request.form.get('provider_contact'))

        vendor_name = none_if_empty(request.form.get('vendor_name'))
        vendor_email = none_if_empty(request.form.get('vendor_email'))
        vendor_phone = none_if_empty(request.form.get('vendor_phone'))
        vendor_address = none_if_empty(request.form.get('vendor_address'))

        now = datetime.now()
        is_active = False

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
            """, (asset_name, description, category_id, purchase_date, purchase_cost, now, now, tag, remarks, parent_asset_id))
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
        """, (asset_id, warranty_years, is_active))

        # Insurance
        cur.execute("""
            INSERT INTO insurances (
                asset_id, policy_number, provider, insured_value, start_date,
                end_date, provider_contact, is_active
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (asset_id, policy_number, provider, insured_value, start_date, end_date, provider_contact, is_active))

        # Vendor
        cur.execute("""
            INSERT INTO vendors (name, email, phone, address, is_active, asset_id)
            VALUES (%s, %s, %s, %s, TRUE, %s)
        """, (vendor_name, vendor_email, vendor_phone, vendor_address, asset_id))

        # Assignment
        if assigned_user_id:
            cur.execute("""
                INSERT INTO assignments (asset_id, user_id, assigned_from, assigned_until, remarks, is_active)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (asset_id, assigned_user_id, assigned_from, assigned_until, remarks, True))

        # File upload
        # Ensure upload folder exists
        upload_folder = os.path.join(app.root_path, 'static', 'uploads')
        os.makedirs(upload_folder, exist_ok=True)

        file = request.files.get('file')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)

            # Path to save the file
            file_save_path = os.path.join(upload_folder, filename)
            file.save(file_save_path)

            # Path to store in DB (relative to /static)
            file_path_for_db = f'uploads/{filename}'

            now = datetime.now()

            cur.execute("""
                INSERT INTO files (asset_id, file_name, file_path, uploaded_by, uploaded_at, is_active)
                VALUES (%s, %s, %s, %s, %s, TRUE)
                """, (asset_id, filename, file_path_for_db, current_user.id, now))


        conn.commit()
        cur.close()
        conn.close()
        flash("Asset submitted for approval.", "success")
        return redirect(url_for('view_assets'))

    return render_template('add_asset.html', categories=categories, users=users, subcategories=subcategories)

def allowed_file(filename):
    allowed_extensions = {'pdf', 'png', 'jpg', 'jpeg', 'docx'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

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

@app.route('/add_maintenance', methods=['GET', 'POST'])
@login_required
def add_maintenance():
    conn = get_db_connection()
    cur = conn.cursor()

    # Fetch active assets
    cur.execute("SELECT id, asset_name FROM asset WHERE is_active = TRUE")
    assets = cur.fetchall()

    if request.method == 'POST':
        asset_id = request.form['asset_id']
        task_done = request.form['task_done']
        maintenance_date = request.form['maintenance_date']
        cost = request.form.get('cost')
        service_by = request.form.get('service_by')
        request_type = request.form.get('request_type')
        has_parts = 'has_parts_involved' in request.form

        # Insert maintenance as inactive
        cur.execute("""
            INSERT INTO maintenance (asset_id, task_done, maintenance_date, cost, service_by, has_parts_involved, is_active)
            VALUES (%s, %s, %s, %s, %s, %s, FALSE)
            RETURNING id
        """, (asset_id, task_done, maintenance_date, cost, service_by, has_parts))
        maintenance_id = cur.fetchone()[0]

        # Create a request
        cur.execute("""
            INSERT INTO requests (request_type, requested_by, asset_id, status, is_active)
            VALUES (%s, %s, %s, 'Pending', TRUE)
        """, (request_type,current_user.id, asset_id))

        conn.commit()
        cur.close()
        conn.close()

        if has_parts:
            return redirect(url_for('add_parts', parent_asset_id=asset_id))

        flash('Maintenance request submitted for approval.', 'success')
        return redirect(url_for('technician_dashboard'))

    cur.close()
    conn.close()
    return render_template('add_maintenance_repair.html', assets=assets)

@app.route('/add_parts', methods=['GET', 'POST'])
@login_required
def add_parts():
    conn = get_db_connection()
    cur = conn.cursor()

    # Fetch dropdowns
    cur.execute("SELECT id, name FROM category WHERE parent_id IS NULL AND is_active = TRUE")
    categories = cur.fetchall()

    cur.execute("SELECT id, name, parent_id FROM category WHERE parent_id IS NOT NULL AND is_active = TRUE")
    subcategories = cur.fetchall()

    cur.execute("SELECT id, name FROM user_details WHERE is_active = TRUE")
    users = cur.fetchall()

    # Get parent_asset_id from URL query param if present
    parent_asset_id = request.args.get('parent_asset_id')

    def none_if_empty(value):
        return None if value is None or str(value).strip() == '' else value

    if request.method == 'POST':
        asset_name = request.form['asset_name']
        description = request.form['description']
        category_id = none_if_empty(request.form.get('subcategory_id') or request.form.get('category_id'))
        purchase_date = none_if_empty(request.form.get('purchase_date'))
        purchase_cost = none_if_empty(request.form.get('purchase_cost'))
        remarks = none_if_empty(request.form.get('remarks'))
        parent_asset_id = none_if_empty(request.form.get('parent_asset_id')) or parent_asset_id
        warranty_years = none_if_empty(request.form.get('warranty_years'))
        vendor_name = none_if_empty(request.form.get('vendor_name'))
        vendor_email = none_if_empty(request.form.get('vendor_email'))
        vendor_phone = none_if_empty(request.form.get('vendor_phone'))
        vendor_address = none_if_empty(request.form.get('vendor_address'))

        now = datetime.now()
        is_active = False

        cur.execute("""
            SELECT tag FROM asset 
            WHERE tag LIKE 'SVE-%' 
            ORDER BY id DESC 
            LIMIT 1
        """)
        last_tag_row = cur.fetchone()
        next_number = int(last_tag_row[0].split('-')[1]) + 1 if last_tag_row else 1
        tag = f"SVE-{next_number:06d}"

        cur.execute("""
            INSERT INTO asset (asset_name, description, category_id, purchase_date, purchase_cost, is_active,
                               created_at, updated_at, tag, remarks, parent_asset_id)
            VALUES (%s, %s, %s, %s, %s, FALSE, %s, %s, %s, %s, %s)
            RETURNING id
        """, (asset_name, description, category_id, purchase_date, purchase_cost, now, now, tag, remarks, parent_asset_id))
        asset_id = cur.fetchone()[0]

        cur.execute("""
            INSERT INTO requests (request_type, requested_by, asset_id, status)
            VALUES ('add', %s, %s, 'Pending')
        """, (current_user.id, asset_id))

        cur.execute("""
            INSERT INTO warranty (asset_id, years, is_active)
            VALUES (%s, %s, %s)
        """, (asset_id, warranty_years, is_active))

        cur.execute("""
            INSERT INTO vendors (name, email, phone, address, is_active, asset_id)
            VALUES (%s, %s, %s, %s, TRUE, %s)
        """, (vendor_name, vendor_email, vendor_phone, vendor_address, asset_id))

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
                VALUES (%s, %s, %s, %s, %s, TRUE)
            """, (asset_id, filename, file_db_path, current_user.id, now))

        conn.commit()
        cur.close()
        conn.close()
        flash("Part submitted for approval.", "success")
        return redirect(url_for('technician_dashboard'))

    return render_template('add_parts.html', categories=categories, users=users, subcategories=subcategories, parent_asset_id=parent_asset_id)

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