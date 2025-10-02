import os, stripe, json
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, flash, request, abort, jsonify

from flask_bootstrap import Bootstrap
from .forms import LoginForm, RegisterForm
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, current_user, login_required, logout_user
from .db_models import db, User, Item, Order, Ordered_item, Cart   # ⬅️ tambahkan
from itsdangerous import URLSafeTimedSerializer
from .funcs import mail, send_confirmation_email, fulfill_order
from dotenv import load_dotenv
from .admin.routes import admin


load_dotenv()
app = Flask(__name__)
app.register_blueprint(admin, url_prefix="/admin")


app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ["DB_URI"]
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_USERNAME'] = os.environ["EMAIL"]
app.config['MAIL_PASSWORD'] = os.environ["PASSWORD"]
app.config['MAIL_SERVER'] = "smtp.googlemail.com"
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_PORT'] = 587
stripe.api_key = os.environ["STRIPE_PRIVATE"]

Bootstrap(app)
db.init_app(app)
mail.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)

with app.app_context():
	db.create_all()

@app.context_processor
def inject_now():
	""" sends datetime to templates as 'now' """
	return {'now': datetime.utcnow()}

@login_manager.user_loader
def load_user(user_id):
	return User.query.get(user_id)

@app.route("/")
def home():
    # semua produk (kalau masih mau ditampilkan di bawah)
    items = Item.query.all()

    # 3 produk paling baru (urut id terbesar)
    new_arrivals = Item.query.order_by(Item.id.desc()).limit(3).all()

    return render_template("home.html", items=items, new_arrivals=new_arrivals)


@app.route("/login", methods=['POST', 'GET'])
def login():
	if current_user.is_authenticated:
		return redirect(url_for('home'))
	form = LoginForm()
	if form.validate_on_submit():
		email = form.email.data
		user = User.query.filter_by(email=email).first()
		if user == None:
			flash(f'User with email {email} doesn\'t exist!<br> <a href={url_for("register")}>Register now!</a>', 'error')
			return redirect(url_for('login'))
		elif check_password_hash(user.password, form.password.data):
			login_user(user)
			return redirect(url_for('home'))
		else:
			flash("Email and password incorrect!!", "error")
			return redirect(url_for('login'))
	return render_template("login.html", form=form)

@app.route("/register", methods=['POST', 'GET'])
def register():
	if current_user.is_authenticated:
		return redirect(url_for('home'))
	form = RegisterForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		if user:
			flash(f"User with email {user.email} already exists!!<br> <a href={url_for('login')}>Login now!</a>", "error")
			return redirect(url_for('register'))
		new_user = User(name=form.name.data,
						email=form.email.data,
						password=generate_password_hash(
									form.password.data,
									method='pbkdf2:sha256',
									salt_length=8),
						phone=form.phone.data)
		db.session.add(new_user)
		db.session.commit()
		# send_confirmation_email(new_user.email)
		flash('Thanks for registering! You may login now.', 'success')
		return redirect(url_for('login'))
	return render_template("register.html", form=form)

@app.route('/confirm/<token>')
def confirm_email(token):
	try:
		confirm_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
		email = confirm_serializer.loads(token, salt='email-confirmation-salt', max_age=3600)
	except:
		flash('The confirmation link is invalid or has expired.', 'error')
		return redirect(url_for('login'))
	user = User.query.filter_by(email=email).first()
	if user.email_confirmed:
		flash(f'Account already confirmed. Please login.', 'success')
	else:
		user.email_confirmed = True
		db.session.add(user)
		db.session.commit()
		flash('Email address successfully confirmed!', 'success')
	return redirect(url_for('login'))

@app.route("/logout")
@login_required
def logout():
	logout_user()
	return redirect(url_for('login'))

@app.route("/resend")
@login_required
def resend():
	send_confirmation_email(current_user.email)
	logout_user()
	flash('Confirmation email sent successfully.', 'success')
	return redirect(url_for('login'))

@app.route("/add/<id>", methods=['POST'])
def add_to_cart(id):
	if not current_user.is_authenticated:
		flash(f'You must login first!<br> <a href={url_for("login")}>Login now!</a>', 'error')
		return redirect(url_for('login'))

	item = Item.query.get(id)
	if request.method == "POST":
		quantity = request.form["quantity"]
		current_user.add_to_cart(id, quantity)
		flash(f'''{item.name} successfully added to the <a href=cart>cart</a>.<br> <a href={url_for("cart")}>view cart!</a>''','success')
		return redirect(url_for('home'))

@app.route("/cart")
@login_required
def cart():
	price = 0
	price_ids = []
	items = []
	quantity = []
	for cart in current_user.cart:
		items.append(cart.item)
		quantity.append(cart.quantity)
		price_id_dict = {
			"price": cart.item.price_id,
			"quantity": cart.quantity,
			}
		price_ids.append(price_id_dict)
		price += cart.item.price*cart.quantity
	return render_template('cart.html', items=items, price=price, price_ids=price_ids, quantity=quantity)

@app.route('/orders')
@login_required
def orders():
	return render_template('orders.html', orders=current_user.orders)

@app.route("/remove/<id>/<quantity>")
@login_required
def remove(id, quantity):
	current_user.remove_from_cart(id, quantity)
	return redirect(url_for('cart'))

@app.route('/item/<int:id>')
def item(id):
	item = Item.query.get(id)
	return render_template('item.html', item=item)

@app.route('/search')
def search():
	query = request.args['query']
	search = "%{}%".format(query)
	items = Item.query.filter(Item.name.like(search)).all()
	return render_template('home.html', items=items, search=True, query=query)

# stripe stuffs
@app.route('/payment_success')
def payment_success():
	return render_template('success.html')

@app.route('/payment_failure')
def payment_failure():
	return render_template('failure.html')

@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    data = json.loads(request.form['price_ids'].replace("'", '"'))
    try:
        checkout_session = stripe.checkout.Session.create(
            client_reference_id=current_user.id,  # optional
            line_items=data,
            payment_method_types=['card'],
            mode='payment',
            success_url=url_for('payment_success', _external=True),
            cancel_url=url_for('payment_failure', _external=True),
            metadata={   # ⬅️ ini tambahan penting
                "user_id": current_user.id
            }
        )
    except Exception as e:
        return str(e)
    return redirect(checkout_session.url, code=303)


@app.route('/stripe-webhook', methods=['POST'])
def stripe_webhook():
    # --- verifikasi signature dari Stripe CLI ---
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    endpoint_secret = os.environ.get("ENDPOINT_SECRET")  # dari .env
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
    except ValueError:
        # JSON invalid
        return "Invalid payload", 400
    except stripe.error.SignatureVerificationError:
        # Signature salah / ENDPOINT_SECRET beda
        return "Invalid signature", 400

    # --- proses event sukses checkout ---
    if event.get('type') == 'checkout.session.completed':
        session = event['data']['object']

        # ambil user id dari metadata (yang kita set saat buat Session)
        uid = None
        md = session.get("metadata") or {}
        if "user_id" in md:
            uid = md["user_id"]
        elif session.get("client_reference_id"):  # fallback kalau metadata tidak ada
            uid = session["client_reference_id"]

        if not uid:
            # tidak bisa map ke user → abaikan dengan 200 agar Stripe tidak retry
            print("⚠️  No user_id/client_reference_id in session; skipping order creation.")
            return jsonify(success=True), 200

        try:
            uid = int(uid)
        except Exception:
            print(f"⚠️  Invalid uid in session metadata: {uid}")
            return jsonify(success=True), 200

        # buat order
        new_order = Order(
            uid=uid,
            date=datetime.utcnow(),
            status="Paid"
        )
        db.session.add(new_order)
        db.session.commit()  # perlu commit dulu untuk dapat new_order.id

        # pindahkan semua item dari cart user → ordered_items
        cart_items = Cart.query.filter_by(uid=uid).all()
        for ci in cart_items:
            oi = Ordered_item(
                oid=new_order.id,
                itemid=ci.itemid,
                quantity=ci.quantity
            )
            db.session.add(oi)
            db.session.delete(ci)  # kosongkan cart

        db.session.commit()
        print(f"✅ Order #{new_order.id} created for uid={uid} with {len(cart_items)} items.")

    return jsonify(success=True), 200