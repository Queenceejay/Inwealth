from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
import os
import re
import requests
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer  # Token generation for password reset
from flask_mail import Mail, Message  # Email sending

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')  # Load SECRET_KEY from .env file
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///inwealth.db'  # Replace with PostgreSQL in production
app.config['UPLOAD_FOLDER'] = 'static/profile_pics'
app.config['MAX_CONTENT_LENGTH'] = 3 * 1024 * 1024  # 3 MB limit for uploads

# Email Configuration (Set up properly in .env)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

# Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)
mail = Mail(app)

# Initialize Token Generator
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(60), nullable=False)
    profile_picture = db.Column(db.String(150), nullable=True)
    litecoin_address = db.Column(db.String(120), nullable=True)
    usdt_address = db.Column(db.String(120), nullable=True)
    wallet_balance = db.Column(db.Float, default=0.0)
    referral_code = db.Column(db.String(10), unique=True, nullable=True)
    referred_by = db.Column(db.String(10), nullable=True)
    role = db.Column(db.String(20), default='user')
    reset_token = db.Column(db.String(255), nullable=True)  # Token for password reset

class WithdrawalRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    method = db.Column(db.String(20), nullable=False)  # 'litecoin' or 'usdt'
    wallet_address = db.Column(db.String(120), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')  # 'pending', 'approved', 'rejected'

# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Admin check
def is_admin():
    return current_user.role == 'admin'  # Check user role for admin status

# Email validation (Regex)
def is_valid_email(email):
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_regex, email)

# Routes
@app.route('/')
def index():
    return render_template('index.html')  # Render homepage

@app.route('/register', methods=['POST'])
def register():
    data = request.json

    # Check if email is valid
    if not is_valid_email(data['email']):
        return {'message': 'Invalid email format. Please provide a valid email address.'}, 400

    # Check if email or username already exists
    existing_user = User.query.filter_by(email=data['email']).first()
    if existing_user:
        return {'message': 'Email already in use. Please use a different email.'}, 400

    existing_username = User.query.filter_by(username=data['username']).first()
    if existing_username:
        return {'message': 'Username already taken. Please choose a different username.'}, 400

    # Check if password is at least 6 characters
    if len(data['password']) < 6:
        return {'message': 'Password must be at least 6 characters.'}, 400

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], email=data['email'], password=hashed_password)

    # Handle referral system
    if data.get('referred_by'):
        referrer = User.query.filter_by(referral_code=data['referred_by']).first()
        if not referrer:
            return {'message': 'Invalid referral code'}, 400  # Handle invalid referral code
        new_user.referred_by = referrer.referral_code

    # Generate referral code
    new_user.referral_code = os.urandom(4).hex()  # Random referral code
    db.session.add(new_user)
    db.session.commit()
    return {'message': 'User registered successfully'}

@app.route('/referrals', methods=['GET'])
def get_referrals():
    if not current_user.is_authenticated:
        return redirect(url_for('signin'))

    referrals = User.query.filter_by(referred_by=current_user.referral_code).all()
    
    referral_list = [{'username': r.username, 'email': r.email} for r in referrals]
    return jsonify({'referrals': referral_list})

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        data = request.get_json()  # Ensure JSON data is received
        if not data:
            return {'message': 'Invalid request data'}, 400

        user = User.query.filter_by(email=data.get('email')).first()

        if user and bcrypt.check_password_hash(user.password, data.get('password')):
            login_user(user)
            return {'success': True}  # JS will handle redirection

        return {'message': 'Invalid credentials'}, 401  # Error for incorrect login

    return render_template('signin.html')  # Render sign-in page for GET request

@app.route('/logout', methods=['GET','POST'])
def logout():
    return render_template('logout.html')
    logout_user()
    return {'message': 'Logged out successfully'}

@app.route('/upload', methods=['POST'])
def upload_profile_picture():
    if 'profile_picture' in request.files:
        file = request.files['profile_picture']
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        # Check MIME type for image
        if file.content_type not in ['image/jpeg', 'image/png', 'image/gif']:
            return {'message': 'Invalid file type'}, 400  # Handle invalid file type

        file.save(filepath)
        current_user.profile_picture = filename
        db.session.commit()
        return {'message': 'Profile picture updated successfully'}

    return {'message': 'No file uploaded'}, 400

@app.route('/update-profile', methods=['POST'])
def update_profile():
    data = request.json
    current_user.username = data.get('username', current_user.username)
    current_user.email = data.get('email', current_user.email)
    current_user.litecoin_address = data.get('litecoin_address', current_user.litecoin_address)
    current_user.usdt_address = data.get('usdt_address', current_user.usdt_address)
    db.session.commit()
    return {'message': 'Profile updated successfully'}

@app.route('/withdraw', methods=['POST'])
def withdraw():
    data = request.json
    if data['amount'] < 3:
        return {'message': 'Minimum withdrawal is 3 USD.'}, 400  # Ensure minimum withdrawal of 3 USD

    # Check password
    if bcrypt.check_password_hash(current_user.password, data['password']):
        new_request = WithdrawalRequest(
            user_id=current_user.id,
            method=data['method'],
            wallet_address=data['wallet_address'],
            amount=data['amount']
        )
        db.session.add(new_request)
        db.session.commit()
        return {'message': 'Withdrawal request sent'}
    return {'message': 'Incorrect password'}, 401

@app.route('/wallet', methods=['GET'])
def wallet():
    return render_template('wallet.html')
    def get_market_price(crypto):
        url = f"https://api.coingecko.com/api/v3/simple/price?ids={crypto}&vs_currencies=usd"
        response = requests.get(url)
        return response.json()[crypto]['usd']

    litecoin_price = get_market_price('litecoin')
    usdt_price = get_market_price('tether')
    return {
        'wallet_balance': current_user.wallet_balance,
        'litecoin_price': litecoin_price,
        'usdt_price': usdt_price
    }

@app.route('/admin/withdrawals', methods=['GET'])
@login_required
def view_withdrawal_requests():
    if not is_admin():  # Check if the current user is admin
        return {'message': 'Access denied.'}, 403

    withdrawals = WithdrawalRequest.query.all()
    return render_template('admin_dashboard.html', withdrawals=withdrawals)

@app.route('/admin/withdrawal/<int:id>/approve', methods=['POST'])
@login_required
def approve_withdrawal(id):
    if not is_admin():  # Check if the current user is admin
        return {'message': 'Access denied.'}, 403

    request = WithdrawalRequest.query.get_or_404(id)
    request.status = 'approved'
    db.session.commit()
    return {'message': 'Withdrawal request approved'}

@app.route('/admin/withdrawal/<int:id>/reject', methods=['POST'])
@login_required
def reject_withdrawal(id):
    if not is_admin():  # Check if the current user is admin
        return {'message': 'Access denied.'}, 403

    request = WithdrawalRequest.query.get_or_404(id)
    request.status = 'rejected'
    db.session.commit()
    return {'message': 'Withdrawal request rejected'}

@app.errorhandler(413)
def file_too_large(e):
    return {'message': 'File is too large. Max file size is 3 MB.'}, 413

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message

s = URLSafeTimedSerializer("SECRET_KEY")

from flask import request, render_template, url_for, jsonify
import uuid

@app.route('/forgot-password', methods=['GET','POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')

    user = User.query.filter_by(email=email).first()
    if user:
        token = generate_reset_token(user)  # Generate and store token
        reset_link = url_for('reset_password', token=token, _external=True)

        # Send reset link via email
        msg = Message("Password Reset Request", recipients=[user.email])
        msg.body = f"Click the link below to reset your password:\n{reset_link}\n\nIf you did not request this, ignore this email."
        mail.send(msg)

        return jsonify({"message": "A password reset link has been sent to your email."}), 200
    else:
        return jsonify({"message": "No account found with this email."}), 404

from werkzeug.security import generate_password_hash

@app.route('/reset-password/<token>', methods=['POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=3600)  # Expires in 1 hour
    except:
        return jsonify({"message": "Invalid or expired token"}), 400

    data = request.json 
    new_password = data['password']

    # Hash the new password
    hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')

    # Update user password
    user = User.query.filter_by(email=email).first()
    if user:
        user.password = hashed_password
        db.session.commit()
        return jsonify({"message": "Password successfully reset"}), 200
    else:
        return jsonify({"message": "User not found"}), 404

# Rendering other templates
@app.route('/profile')
def profile():
    return render_template('profile.html')

@app.route('/terms-of-service')
def terms_of_service():
    return render_template('terms-of-service.html')

@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy-policy.html')

@app.route('/reset-password/<token>', methods=['GET'])
def reset_password_page(token):
    return render_template('reset_password.html', token=token)

@app.route('/deactivate', methods=['GET', 'POST'])
def deactivate():
    if request.method == 'POST':
        return redirect(url_for('account_deactivated'))  # Redirect after form submission
    
    return render_template('confirm_deactivation.html')  # Show confirmation page for GET requests

@app.route('/confirm-deactivation')
def confirm_deactivation():
    return render_template('confirm_deactivation.html')

@app.route('/withdraw')
def withdraw_page():
    return render_template('withdraw.html')

@app.route('/logout-page')
def logout_page():
    return render_template('logout.html')

@app.route('/signup', methods=['GET'])
def signup():
    if request.method == 'POST':
        return redirect(url_for('dashboard'))
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')  # Render the dashboard template

if __name__ == '__main__':
    app.run(debug=True)
