from email.mime.text import MIMEText
import smtplib
from flask import Flask, render_template, request, redirect, session, flash, url_for
from flask_mail import Mail, Message
import sqlite3
import bcrypt
import random
import config
import os
import traceback
from flask import current_app
from flask import make_response, render_template
from utils.pdf_generator import generate_pdf
import razorpay
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

razorpay_client = razorpay.Client(
    auth=(config.RAZORPAY_KEY_ID, config.RAZORPAY_KEY_SECRET)
)

app.config['USERS_UPLOAD_FOLDER'] = 'static/uploads/profile_images'
os.makedirs(app.config['USERS_UPLOAD_FOLDER'], exist_ok=True)

serializer = URLSafeTimedSerializer(app.secret_key)

app.config['MAIL_SERVER'] = config.MAIL_SERVER
app.config['MAIL_PORT'] = config.MAIL_PORT
app.config['MAIL_USE_TLS'] = config.MAIL_USE_TLS
app.config['MAIL_USERNAME'] = config.MAIL_USERNAME
app.config['MAIL_PASSWORD'] = config.MAIL_PASSWORD
app.config['MAIL_DEFAULT_SENDER'] = config.MAIL_USERNAME

mail = Mail(app)

# -------------------- DB CONNECTION --------------------
def get_db_connection():
    import sqlite3
    conn = sqlite3.connect(config.DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn
# ---------------------------------------------------------
# ROUTE 1: ADMIN SIGNUP (SEND OTP)
# ---------------------------------------------------------
@app.route('/', methods=['GET', 'POST'])
@app.route('/admin-signup', methods=['GET', 'POST'])
def admin_signup():

    if request.method == "GET":
        return render_template("admin/admin_signup.html")

    name = request.form['name']
    email = request.form['email']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT admin_id FROM admin WHERE email=?",
        (email,)
    )
    existing_admin = cursor.fetchone()

    cursor.close()
    conn.close()

    if existing_admin:
        flash("This email is already registered. Please login instead.", "danger")
        return redirect('/')

    session['signup_name'] = name
    session['signup_email'] = email

    otp = random.randint(100000, 999999)
    session['otp'] = otp

    message = Message(
        subject="SmartCart Admin OTP",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    message.body = f"Your OTP for SmartCart Admin Registration is: {otp}"

    mail.send(message)

    flash("OTP sent to your email!", "success")
    return redirect('/verify-otp')


@app.route('/verify-otp', methods=['GET'])
def verify_otp_get():
    return render_template("admin/verify_otp.html")


@app.route('/verify-otp', methods=['POST'])
def verify_otp_post():

    user_otp = request.form['otp']
    password = request.form['password']

    if str(session.get('otp')) != str(user_otp):
        flash("Invalid OTP. Try again!", "danger")
        return redirect('/verify-otp')

    hashed_password = bcrypt.hashpw(
        password.encode('utf-8'),
        bcrypt.gensalt()
    ).decode('utf-8')   # ✅ SQLite lo TEXT laga save avvadaniki

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO admin (name, email, password) VALUES (?, ?, ?)",
        (session['signup_name'], session['signup_email'], hashed_password)
    )

    conn.commit()
    cursor.close()
    conn.close()

    session.pop('otp', None)
    session.pop('signup_name', None)
    session.pop('signup_email', None)

    flash("Admin Registered Successfully!", "success")
    return redirect('/admin-login')


# =================================================================
# ROUTE 4: ADMIN LOGIN PAGE (GET + POST)
# =================================================================
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():

    if request.method == 'GET':
        return render_template("admin/admin_login.html")

    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM admin WHERE email=?", (email,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    if admin is None:
        flash("Email not found! Please register first.", "danger")
        return redirect('/admin-login')

    stored_hashed_password = admin['password'].encode('utf-8')

    if not bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password):
        flash("Incorrect password! Try again.", "danger")
        return redirect('/admin-login')

    session['admin_id'] = admin['admin_id']
    session['admin_name'] = admin['name']
    session['admin_email'] = admin['email']

    flash("Login Successful!", "success")
    return redirect('/admin-dashboard')


#==================================================================
# forgot password route
#==================================================================
@app.route('/admin/forgot-password', methods=['GET', 'POST'])
def admin_forgot_password():

    if request.method == 'POST':
        email = request.form['email']

        token = serializer.dumps(email, salt='reset-password')

        reset_link = url_for(
            'admin_reset_password',
            token=token,
            _external=True
        )

        msg = Message(
            subject="Reset Password",
            recipients=[email]
        )
        msg.body = f"Click this link to reset your password:\n\n{reset_link}"

        try:
            mail.send(msg)
            flash("Reset link sent to your email!", "success")
        except Exception as e:
            flash(str(e), "danger")

        return redirect('/admin/forgot-password')

    return render_template('admin/forgot_password.html')
#=============================================================
#reset_password
#===============================================================
@app.route('/admin/reset-password/<token>', methods=['GET', 'POST'])
def admin_reset_password(token):
    try:
        email = serializer.loads(token, salt='reset-password', max_age=600)
    except:
        flash("Invalid or expired link", "danger")
        return redirect('/admin/forgot-password')

    if request.method == 'POST':
        password = request.form['password']
        confirm = request.form['confirm_password']

        if password != confirm:
            flash("Passwords do not match", "danger")
            return redirect(request.url)

        hashed = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')   # ✅ SQLite lo TEXT ga save avvadaniki

        conn = get_db_connection()
        cursor = conn.cursor()

        # ✅ %s → ? change
        cursor.execute(
            "UPDATE admin SET password=? WHERE email=?",
            (hashed, email)
        )

        conn.commit()
        cursor.close()
        conn.close()

        flash("Password updated successfully!", "success")
        return redirect(url_for('admin_login'))

    return render_template('admin/reset_password.html')


# =================================================================
# ROUTE 5: ADMIN DASHBOARD (PROTECTED ROUTE)
# =================================================================
@app.route('/admin-dashboard')
def admin_dashboard():

    if 'admin_id' not in session:
        flash("Please login to access dashboard!", "danger")
        return redirect('/admin-login')

    return render_template("admin/dashboard.html", admin_name=session['admin_name'])


# =================================================================
# ROUTE 6: ADMIN LOGOUT
# =================================================================
@app.route('/admin-logout')
def admin_logout():

    session.pop('admin_id', None)
    session.pop('admin_name', None)
    session.pop('admin_email', None)

    flash("Logged out successfully.", "success")
    return redirect('/admin-login')


# ------------------- IMAGE UPLOAD PATH -------------------
UPLOAD_FOLDER = 'static/uploads/product_images'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# =================================================================
# ROUTE 7: SHOW ADD PRODUCT PAGE (Protected Route)
# =================================================================
@app.route('/admin/add-item', methods=['GET'])
def add_item_page():

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    return render_template("admin/add_item.html")


# =================================================================
# ROUTE 8: ADD PRODUCT INTO DATABASE
# =================================================================
@app.route('/admin/add-item', methods=['POST'])
def add_item():

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = request.form['price']
    image_file = request.files['image']

    if image_file.filename == "":
        flash("Please upload a product image!", "danger")
        return redirect('/admin/add-item')

    filename = secure_filename(image_file.filename)
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    image_file.save(image_path)

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    # ✅ %s → ? (SQLite change)
    cursor.execute("""
        INSERT INTO products 
        (name, description, category, price, image, admin_id)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (name, description, category, price, filename, admin_id))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Product added successfully!", "success")
    return redirect('/admin/item-list')
# =================================================================
# ROUTE 9: DISPLAY ALL PRODUCTS (Admin)
# ===============================================================
@app.route('/admin/item-list')
def item_list():

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    # ✅ SQLite: %s -> ?
    cursor.execute(
        "SELECT * FROM products WHERE admin_id=?",
        (admin_id,)
    )
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("admin/item_list.html", products=products)


#=================================================================
# ROUTE 10: VIEW SINGLE PRODUCT DETAILS
#=================================================================
@app.route('/admin/view-item/<int:item_id>')
def view_item(item_id):

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    # ✅ SQLite: %s -> ?
    cursor.execute(
        "SELECT * FROM products WHERE product_id=? AND admin_id=?",
        (item_id, admin_id)
    )
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found or access denied!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/view_item.html", product=product)
# =================================================================
# ROUTE 11: SHOW UPDATE FORM WITH EXISTING DATA
# =================================================================
@app.route('/admin/update-item/<int:item_id>', methods=['GET'])
def update_item_page(item_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    # ✅ %s → ?
    cursor.execute(
        "SELECT * FROM products WHERE product_id=? AND admin_id=?",
        (item_id, admin_id)
    )
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found or access denied!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/update_item.html", product=product)


# =================================================================
# ROUTE-12: UPDATE PRODUCT + OPTIONAL IMAGE REPLACE
# =================================================================
@app.route('/admin/update-item/<int:item_id>', methods=['POST'])
def update_item(item_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = request.form['price']
    new_image = request.files['image']

    conn = get_db_connection()
    cursor = conn.cursor()

    # ✅ %s → ?
    cursor.execute(
        "SELECT * FROM products WHERE product_id=? AND admin_id=?",
        (item_id, admin_id)
    )
    product = cursor.fetchone()

    if not product:
        cursor.close()
        conn.close()
        flash("Product not found or access denied!", "danger")
        return redirect('/admin/item-list')

    old_image_name = product['image']
    final_image_name = old_image_name

    if new_image and new_image.filename != "":
        new_filename = secure_filename(new_image.filename)

        new_image_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
        new_image.save(new_image_path)

        old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], old_image_name)
        if os.path.exists(old_image_path):
            os.remove(old_image_path)

        final_image_name = new_filename

    # ✅ %s → ?
    cursor.execute("""
        UPDATE products
        SET name=?, description=?, category=?, price=?, image=?
        WHERE product_id=? AND admin_id=?
    """, (name, description, category, price, final_image_name, item_id, admin_id))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Product updated successfully!", "success")
    return redirect('/admin/item-list')

# =================================================================
# ROUTE 13: UPDATED PRODUCT LIST WITH SEARCH + CATEGORY FILTER
# =================================================================
@app.route('/admin/item-list')
def admin_item_list():

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT DISTINCT category FROM products WHERE admin_id=?",
        (admin_id,)
    )
    categories = cursor.fetchall()

    query = "SELECT * FROM products WHERE admin_id=?"
    params = [admin_id]

    if search:
        query += " AND name LIKE ?"
        params.append(f"%{search}%")

    if category_filter:
        query += " AND category=?"
        params.append(category_filter)

    cursor.execute(query, tuple(params))
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "admin/item_list.html",
        products=products,
        categories=categories,
        search=search,
        category=category_filter
    )


# =================================================================
# ROUTE 14: DELETE PRODUCT
# =================================================================
@app.route('/admin/delete-item/<int:item_id>')
def delete_item(item_id):

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT image FROM products WHERE product_id=? AND admin_id=?",
        (item_id, admin_id)
    )
    product = cursor.fetchone()

    if not product:
        cursor.close()
        conn.close()
        flash("Product not found or access denied!", "danger")
        return redirect('/admin/item-list')

    image_name = product['image']

    if image_name:
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_name)
        if os.path.exists(image_path):
            os.remove(image_path)

    cursor.execute(
        "DELETE FROM products WHERE product_id=? AND admin_id=?",
        (item_id, admin_id)
    )
    conn.commit()

    cursor.close()
    conn.close()

    flash("Product deleted successfully!", "success")
    return redirect('/admin/item-list')
#==========================================================
# add admin profile
#==========================================================
ADMIN_UPLOAD_FOLDER = 'static/uploads/admin_profiles'
app.config['ADMIN_UPLOAD_FOLDER'] = ADMIN_UPLOAD_FOLDER

# =================================================================
# ROUTE 1: SHOW ADMIN PROFILE DATA
# =================================================================
@app.route('/admin/profile', methods=['GET'])
def admin_profile():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM admin WHERE admin_id=?", (admin_id,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template("admin/admin_profile.html", admin=admin)


# =================================================================
# ROUTE 2: UPDATE ADMIN PROFILE
# =================================================================
@app.route('/admin/profile', methods=['POST'])
def admin_profile_update():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    name = request.form['name']
    email = request.form['email']
    new_password = request.form['password']
    new_image = request.files['profile_image']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM admin WHERE admin_id=?", (admin_id,))
    admin = cursor.fetchone()

    old_image_name = admin['profile_image']

    if new_password:
        hashed_password = bcrypt.hashpw(
            new_password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')   # ✅ SQLite TEXT
    else:
        hashed_password = admin['password']

    if new_image and new_image.filename != "":
        new_filename = secure_filename(new_image.filename)

        image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], new_filename)
        new_image.save(image_path)

        if old_image_name:
            old_image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], old_image_name)
            if os.path.exists(old_image_path):
                os.remove(old_image_path)

        final_image_name = new_filename
    else:
        final_image_name = old_image_name

    cursor.execute("""
        UPDATE admin
        SET name=?, email=?, password=?, profile_image=?
        WHERE admin_id=?
    """, (name, email, hashed_password, final_image_name, admin_id))

    conn.commit()
    cursor.close()
    conn.close()

    session['admin_name'] = name
    session['admin_email'] = email

    flash("Profile updated successfully!", "success")
    return redirect('/admin/profile')


# ================= USER REGISTER =================
@app.route('/user-register', methods=['GET', 'POST'])
def user_register():

    if request.method == 'GET':
        return render_template("user/user_register.html")

    name = request.form['name']
    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    existing_user = cursor.fetchone()

    if existing_user:
        flash("Email already registered! Please login.", "danger")
        cursor.close()
        conn.close()
        return redirect('/user-register')

    hashed_password = bcrypt.hashpw(
        password.encode('utf-8'),
        bcrypt.gensalt()
    ).decode('utf-8')

    cursor.execute(
        "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
        (name, email, hashed_password)
    )
    conn.commit()

    cursor.close()
    conn.close()

    flash("Registration successful! Please login.", "success")
    return redirect('/user-login')


# ================= USER LOGIN =================
@app.route('/user-login', methods=['GET', 'POST'])
def user_login():

    if request.method == 'GET':
        return render_template("user/user_login.html")

    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if not user:
        flash("Email not found!", "danger")
        return redirect('/user-login')

    stored_password = user['password'].encode('utf-8')

    if not bcrypt.checkpw(password.encode('utf-8'), stored_password):
        flash("Incorrect password!", "danger")
        return redirect('/user-login')

    session['user_id'] = user['user_id']
    session['user_name'] = user['name']
    session['user_email'] = user['email']

    flash("Login successful!", "success")
    return redirect('/user-dashboard')

#==================================================================
# forgot paaword route
#==================================================================
@app.route('/user/forgot-password', methods=['GET', 'POST'])
def user_forgot_password():

    if request.method == 'POST':
        email = request.form['email']

        # Generate token
        token = serializer.dumps(email, salt='reset-password')

        # Correct link (HTTP only)
        reset_link = url_for(
            'user_reset_password',
            token=token,
            _external=True
        )

        # Send mail
        msg = Message(
            subject="Reset Password",
            recipients=[email]
        )
        msg.body = f"Click this link to reset your password:\n\n{reset_link}"

        try:
            mail.send(msg)
            flash("Reset link sent to your email!", "success")
        except Exception as e:
            flash(str(e), "danger")

        return redirect('/user/forgot-password')

    return render_template('user/forgot_password.html')
#=============================================================
#reset_password
#===============================================================
@app.route('/user/reset-password/<token>', methods=['GET', 'POST'])
def user_reset_password(token):
    try:
        email = serializer.loads(token, salt='reset-password', max_age=600)
    except:
        flash("Invalid or expired link", "danger")
        return redirect('/user/forgot-password')

    if request.method == 'POST':
        password = request.form['password']
        confirm = request.form['confirm_password']

        if password != confirm:
            flash("Passwords do not match", "danger")
            return redirect(request.url)

        hashed = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "UPDATE users SET password=%s WHERE email=%s",
            (hashed, email)
        )

        conn.commit()
        cursor.close()
        conn.close()

        flash("Password updated successfully!", "success")
        return redirect(url_for('user_login'))

    return render_template('user/reset_password.html')

# ================= DASHBOARD =================
@app.route('/user-dashboard')
def user_dashboard():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    return render_template("user/user_home.html", user_name=session['user_name'])


# ================= LOGOUT =================
@app.route('/user-logout')
def user_logout():

    session.clear()

    flash("Logged out successfully!", "success")
    return redirect('/user-login')


# ================= PRODUCTS =================
@app.route('/user/products')
def user_products():

    if 'user_id' not in session:
        flash("Please login to view products!", "danger")
        return redirect('/user-login')

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT DISTINCT category FROM products")
    categories = cursor.fetchall()

    query = "SELECT * FROM products WHERE 1=1"
    params = []

    if search:
        query += " AND name LIKE ?"
        params.append(f"%{search}%")

    if category_filter:
        query += " AND category=?"
        params.append(category_filter)

    cursor.execute(query, tuple(params))
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "user/user_products.html",
        products=products,
        categories=categories
    )


# ================= PRODUCT DETAILS =================
@app.route('/user/product/<int:product_id>')
def user_product_details(product_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM products WHERE product_id=?", (product_id,))
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/user/products')

    return render_template("user/product_details.html", product=product)

# ================= ADD TO CART =================
@app.route('/user/add-to-cart/<int:product_id>', methods=['GET', 'POST'])
def add_to_cart(product_id):

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    cart = session.get('cart', {})

    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # ✅ SQLite: %s -> ?
        cursor.execute(
            "SELECT * FROM products WHERE product_id=?",
            (product_id,)
        )
        product = cursor.fetchone()

        if not product:
            flash("Product not found.", "danger")
            return redirect('/user/products')

        pid = str(product_id)

        if pid in cart:
            cart[pid]['quantity'] = int(cart[pid]['quantity']) + 1
        else:
            cart[pid] = {
                'name': product['name'],
                'price': float(product['price']),
                'image': product['image'],
                'quantity': 1
            }

        session['cart'] = cart
        session.modified = True

        flash("Item added to cart!", "success")

    except Exception as e:
        print("ADD TO CART ERROR:", e)
        flash("Something went wrong!", "danger")

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    return redirect(request.referrer or '/user/products')


# ================= VIEW CART =================
@app.route('/user/cart')
def view_cart():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    cart = session.get('cart', {})

    grand_total = sum(item['price'] * item['quantity'] for item in cart.values())

    return render_template(
        "user/cart.html",
        cart=cart,
        grand_total=grand_total
    )

# ROUTE 3: Increase Quantity
# ================================
# INCREASE QUANTITY
# ================================
@app.route('/user/cart/increase/<pid>')
def increase_quantity(pid):

    cart = session.get('cart', {})
    pid = str(pid)

    if pid in cart:
        cart[pid]['quantity'] = int(cart[pid]['quantity']) + 1

    session['cart'] = cart
    session.modified = True

    return redirect('/user/cart')


# ================================
# DECREASE QUANTITY
# ================================
@app.route('/user/cart/decrease/<pid>')
def decrease_quantity(pid):

    cart = session.get('cart', {})
    pid = str(pid)

    if pid in cart:
        cart[pid]['quantity'] = int(cart[pid]['quantity']) - 1

        if cart[pid]['quantity'] <= 0:
            cart.pop(pid)

    session['cart'] = cart
    session.modified = True

    return redirect('/user/cart')


# =================================================================
# REMOVE ITEM
# =================================================================
@app.route('/user/cart/remove/<pid>')
def remove_from_cart(pid):

    cart = session.get('cart', {})

    if pid in cart:
        cart.pop(pid)

    session['cart'] = cart
    session.modified = True   # ✅ add this

    flash("Item removed!", "success")
    return redirect('/user/cart')


# ================= USER IMAGE UPLOAD =================
USERS_UPLOAD_FOLDER = 'static/uploads/user_profiles'
app.config['USERS_UPLOAD_FOLDER'] = USERS_UPLOAD_FOLDER
#---------------------checkout select------------------------
@app.route('/checkout-selected', methods=['POST'])
def checkout_selected():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    selected_products = request.form.getlist('selected_products')

    if not selected_products:
        flash("Please select at least one product!", "warning")
        return redirect('/user/cart')

    cart = session.get('cart', {})
    selected_cart = {}

    for pid in selected_products:
        pid = str(pid)

        if pid in cart:
            selected_cart[pid] = cart[pid]

    if not selected_cart:
        flash("Selected products not found in cart!", "danger")
        return redirect('/user/cart')

    session['selected_products'] = list(selected_cart.keys())
    session['selected_cart'] = selected_cart
    session.modified = True

    return redirect('/add-address')


# ==========================================================
# SHOW USER PROFILE
# ==========================================================
@app.route('/user/profile', methods=['GET', 'POST'])
def user_profile():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':

        name = request.form['name']
        email = request.form['email']
        new_password = request.form['password']
        new_image = request.files['profile_image']

        cursor.execute("SELECT * FROM users WHERE user_id=?", (user_id,))
        user = cursor.fetchone()

        old_image_name = user['profile_image'] if user['profile_image'] else ''

        if new_password:
            hashed_password = bcrypt.hashpw(
                new_password.encode('utf-8'),
                bcrypt.gensalt()
            ).decode('utf-8')
        else:
            hashed_password = user['password']

        if new_image and new_image.filename != "":
            filename = secure_filename(new_image.filename)

            image_path = os.path.join(
                app.config['USERS_UPLOAD_FOLDER'],
                filename
            )
            new_image.save(image_path)

            if old_image_name:
                old_path = os.path.join(
                    app.config['USERS_UPLOAD_FOLDER'],
                    old_image_name
                )
                if os.path.exists(old_path):
                    os.remove(old_path)

            final_image_name = filename
        else:
            final_image_name = old_image_name

        cursor.execute("""
            UPDATE users
            SET name=?, email=?, password=?, profile_image=?
            WHERE user_id=?
        """, (name, email, hashed_password, final_image_name, user_id))

        conn.commit()

        session['user_name'] = name
        session['user_email'] = email

        flash("Profile updated successfully!", "success")

    cursor.execute("SELECT * FROM users WHERE user_id=?", (user_id,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template("user/user_profile.html", user=user)
# =================================================================
# ROUTE: CREATE RAZORPAY ORDER
# =================================================================
@app.route('/user/pay')
def user_pay():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    selected_cart = session.get("selected_cart")
    address_id = session.get("selected_address_id")

    print("PAYMENT DEBUG SELECTED CART:", selected_cart)
    print("PAYMENT DEBUG ADDRESS ID:", address_id)

    if not selected_cart:
        flash("No products selected! Please select products first.", "danger")
        return redirect('/user/cart')

    if not address_id:
        flash("Select address first!", "danger")
        return redirect('/add-address')

    total_amount = 0

    for item in selected_cart.values():
        price = float(item['price'])
        quantity = int(item['quantity'])
        total_amount += price * quantity

    razorpay_amount = int(round(total_amount * 100))

    if razorpay_amount <= 0:
        flash("Invalid payment amount!", "danger")
        return redirect('/user/cart')

    try:
        razorpay_order = razorpay_client.order.create({
            "amount": razorpay_amount,
            "currency": "INR",
            "payment_capture": 1
        })

        session['razorpay_order_id'] = razorpay_order['id']
        session['amount'] = total_amount

        session['pending_order'] = {
            "products": list(selected_cart.keys()),
            "address_id": address_id
        }

        session.modified = True

        return render_template(
            "user/payment.html",
            amount=total_amount,
            key_id=config.RAZORPAY_KEY_ID,
            order_id=razorpay_order['id']
        )

    except Exception as e:
        print("RAZORPAY ORDER ERROR:", str(e))
        flash("Payment order creation failed: " + str(e), "danger")
        return redirect('/add-address')


@app.route('/payment-success')
def payment_success():

    payment_id = request.args.get('payment_id')
    order_id = request.args.get('order_id')

    if not payment_id:
        flash("Payment failed!", "danger")
        return redirect('/user/cart')

    return render_template(
        "user/payment_success.html",
        payment_id=payment_id,
        order_id=order_id
    )

# ================= ADD ADDRESS =================
@app.route('/add-address', methods=['GET', 'POST'])
def add_address():
    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        full_name = request.form['full_name']
        phone = request.form['phone']
        address = request.form['address']
        city = request.form['city']
        state = request.form['state']
        pincode = request.form['pincode']

        cursor.execute("""
            INSERT INTO addresses 
            (user_id, full_name, phone, address, city, state, pincode)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            session['user_id'],
            full_name,
            phone,
            address,
            city,
            state,
            pincode
        ))

        conn.commit()
        cursor.close()
        conn.close()

        flash("Address added successfully!", "success")
        return redirect('/add-address')

    cursor.execute(
        "SELECT * FROM addresses WHERE user_id=? ORDER BY id DESC",
        (session['user_id'],)
    )
    addresses = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('user/add_address.html', addresses=addresses)


# ================= EDIT ADDRESS =================
@app.route('/edit-address/<int:address_id>', methods=['GET', 'POST'])
def edit_address(address_id):
    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM addresses WHERE id=? AND user_id=?",
        (address_id, session['user_id'])
    )
    address = cursor.fetchone()

    if not address:
        cursor.close()
        conn.close()
        flash("Address not found!", "danger")
        return redirect('/add-address')

    if request.method == 'POST':
        full_name = request.form['full_name']
        phone = request.form['phone']
        new_address = request.form['address']
        city = request.form['city']
        state = request.form['state']
        pincode = request.form['pincode']

        cursor.execute("""
            UPDATE addresses
            SET full_name=?, phone=?, address=?, city=?, state=?, pincode=?
            WHERE id=? AND user_id=?
        """, (
            full_name,
            phone,
            new_address,
            city,
            state,
            pincode,
            address_id,
            session['user_id']
        ))

        conn.commit()
        cursor.close()
        conn.close()

        flash("Address updated successfully!", "success")
        return redirect('/add-address')

    cursor.close()
    conn.close()

    return render_template('user/edit_address.html', address=address)
# ================= DELETE ADDRESS =================
@app.route('/delete-address/<int:address_id>')
def delete_address(address_id):
    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM addresses WHERE id=? AND user_id=?",
        (address_id, session['user_id'])
    )

    conn.commit()
    cursor.close()
    conn.close()

    flash("Address deleted successfully!", "success")
    return redirect('/add-address')


# ================= CONTINUE TO PAYMENT =================
@app.route('/continue-payment/<int:address_id>')
def continue_payment(address_id):

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    session['selected_address_id'] = address_id
    session.modified = True

    return redirect('/user/pay')


# ------------------------------
# Route: Verify Payment and Store Order
# ------------------------------
@app.route('/verify-payment', methods=['POST'])
def verify_payment():

    if 'user_id' not in session:
        flash("Please login to complete the payment.", "danger")
        return redirect('/user-login')

    razorpay_payment_id = request.form.get('razorpay_payment_id')
    razorpay_order_id = request.form.get('razorpay_order_id')
    razorpay_signature = request.form.get('razorpay_signature')

    if not (razorpay_payment_id and razorpay_order_id and razorpay_signature):
        flash("Payment verification failed (missing data).", "danger")
        return redirect('/user/cart')

    payload = {
        'razorpay_order_id': razorpay_order_id,
        'razorpay_payment_id': razorpay_payment_id,
        'razorpay_signature': razorpay_signature
    }

    try:
        razorpay_client.utility.verify_payment_signature(payload)
    except Exception as e:
        app.logger.error("Razorpay signature verification failed: %s", str(e))
        flash("Payment verification failed. Please contact support.", "danger")
        return redirect('/user/cart')

    user_id = session['user_id']
    address_id = session.get('selected_address_id')

    cart = session.get('selected_cart', {})

    if not cart:
        flash("Selected cart is empty. Cannot create order.", "danger")
        return redirect('/user/cart')

    total_amount = sum(
        float(item['price']) * int(item['quantity'])
        for item in cart.values()
    )

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO orders 
            (user_id, address_id, razorpay_order_id, razorpay_payment_id, amount, payment_status)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            address_id,
            razorpay_order_id,
            razorpay_payment_id,
            total_amount,
            'paid'
        ))

        order_db_id = cursor.lastrowid

        for pid_str, item in cart.items():
            product_id = int(pid_str)
            quantity = int(item['quantity'])
            price = float(item['price'])
            item_total = price * quantity

            cursor.execute("""
                INSERT INTO order_items 
                (order_id, product_id, product_name, quantity, price, total)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                order_db_id,
                product_id,
                item['name'],
                quantity,
                price,
                item_total
            ))

        conn.commit()

        main_cart = session.get('cart', {})
        for pid in cart.keys():
            main_cart.pop(str(pid), None)

        session['cart'] = main_cart

        session.pop('selected_cart', None)
        session.pop('selected_products', None)
        session.pop('razorpay_order_id', None)
        session.pop('selected_address_id', None)
        session.modified = True

        flash("Payment successful and order placed!", "success")
        return redirect(f"/user/order-success/{order_db_id}")

    except Exception as e:
        conn.rollback()
        app.logger.error("Order storage failed: %s\n%s", str(e), traceback.format_exc())
        flash("There was an error saving your order. Contact support.", "danger")
        return redirect('/user/cart')

    finally:
        cursor.close()
        conn.close()

#================================================================
# Orders Success
#===============================================================

@app.route('/user/order-success/<int:order_db_id>')
def order_success(order_db_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()   # ✅ SQLite lo pymysql.cursors.DictCursor use cheyyakudadhu

    cursor.execute(
        "SELECT * FROM orders WHERE order_id=? AND user_id=?",
        (order_db_id, session['user_id'])
    )
    order = cursor.fetchone()

    if not order:
        cursor.close()
        conn.close()
        flash("Order not found.", "danger")
        return redirect('/user/products')

    cursor.execute(
        "SELECT * FROM order_items WHERE order_id=?",
        (order_db_id,)
    )
    items = cursor.fetchall()

    address = None

    if order['address_id']:
        cursor.execute(
            "SELECT * FROM addresses WHERE id=? AND user_id=?",
            (order['address_id'], session['user_id'])
        )
        address = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template(
        "user/order_success.html",
        order=order,
        items=items,
        address=address
    )
#==========================================================
@app.route('/user/my-orders')
def User_my_orders():
    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT 
            order_id,
            razorpay_order_id,
            amount,
            payment_status,
            created_at
        FROM orders
        WHERE user_id = ?
        ORDER BY order_id DESC
    """, (session['user_id'],))

    orders = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('user/my_orders.html', orders=orders)


@app.route("/user/download-invoice/<int:order_id>")
def download_invoice(order_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM orders WHERE order_id=? AND user_id=?",
        (order_id, session['user_id'])
    )
    order = cursor.fetchone()

    if not order:
        cursor.close()
        conn.close()
        flash("Order not found.", "danger")
        return redirect('/user/my-orders')

    cursor.execute(
        "SELECT * FROM order_items WHERE order_id=?",
        (order_id,)
    )
    items = cursor.fetchall()

    address = None

    try:
        cursor.execute(
            "SELECT * FROM addresses WHERE id=? AND user_id=?",
            (order['address_id'], session['user_id'])
        )
        address = cursor.fetchone()
    except Exception as e:
        print("ADDRESS FETCH ERROR:", e)

    cursor.close()
    conn.close()

    html = render_template(
        "user/invoice.html",
        order=order,
        items=items,
        address=address
    )

    pdf = generate_pdf(html) 

    if not pdf:
        flash("Error generating PDF", "danger")
        return redirect('/user/my-orders')

    response = make_response(pdf.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f"attachment; filename=invoice_{order_id}.pdf"

    return response


@app.route('/admin/orders')
def admin_orders():

    if 'admin_id' not in session:
        flash("Please login as admin!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT o.order_id, o.user_id, o.amount, 
               o.payment_status, o.order_status, o.created_at,
               u.name AS username
        FROM orders o
        LEFT JOIN users u ON o.user_id = u.user_id
        ORDER BY o.created_at DESC
    """)

    orders = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("admin/order_list.html", orders=orders)


# ADMIN: VIEW ORDER DETAILS
# ================================================================
@app.route('/admin/order/<int:order_id>')
def admin_order_details(order_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM orders WHERE order_id=?", (order_id,))
    order = cursor.fetchone()

    cursor.execute("SELECT * FROM order_items WHERE order_id=?", (order_id,))
    items = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("admin/order_details.html", order=order, items=items)


@app.route("/admin/update-order-status/<int:order_id>", methods=['POST'])
def update_order_status(order_id):
    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    new_status = request.form.get('status')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE orders SET order_status=? WHERE order_id=?",
        (new_status, order_id)
    )

    conn.commit()
    cursor.close()
    conn.close()

    flash("Order status updated successfully!", "success")
    return redirect(f"/admin/order/{order_id}")


@app.route('/about')
def about():
    return render_template("user/about.html")


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']

        sender_email = config.MAIL_USERNAME
        sender_password = config.MAIL_PASSWORD
        receiver_email = "bhanutejabo241@gmail.com"

        body = f"""
Name: {name}
Email: {email}

Message:
{message}
"""

        msg = MIMEText(body)
        msg['Subject'] = "SmartCart Contact Query"
        msg['From'] = sender_email
        msg['To'] = receiver_email

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, receiver_email, msg.as_string())
        server.quit()

        flash("Your message sent successfully!")
        return redirect('/contact')

    return render_template("user/contact.html")


if __name__ == "__main__":
    app.run(debug=True)