from flask import Flask, Response, request, jsonify, render_template, url_for
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager
from flask_sqlalchemy import SQLAlchemy
from argon2 import PasswordHasher
from flask_mail import Mail, Message
from datetime import timedelta, datetime
from werkzeug.utils import secure_filename
import os
import secrets
import functools
import base64

# BACKEND FLASK
# Inisialisasi Flask
app = Flask(__name__)

# Konfigurasi MySQL
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:@127.0.0.1/myflask"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# Setup the Flask-JWT-Extended extension
app.config["JWT_SECRET_KEY"] = "super-secret"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=1)
jwt = JWTManager(app)

# Konfigurasi Email
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'myproject.myapp@gmail.com'
app.config['MAIL_PASSWORD'] = 'gckr vsxy ghwh pdhj'
mail = Mail(app)

# Inisialisasi PasswordHasher
ph = PasswordHasher()

# Model pengguna
class User(db.Model):
    __tablename__ = 'users' # Nama tabel di database MySQL

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    avatar = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(200), nullable=True)
    reset_token = db.Column(db.String(200), nullable=True)
    reset_token_expiry = db.Column(db.DateTime, nullable=True)


class ApiKey(db.Model):
    __tablename__ = 'api_key'  # Nama tabel di database MySQL

    id = db.Column(db.Integer, primary_key=True)
    api_key = db.Column(db.String(150), unique=True)


# JWT user lookup
@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.get(identity)

# Dekorator API Key
def api_key_required(func):
    @functools.wraps(func)
    def check_api_key(*args, **kwargs):
        api_key = request.headers.get('x-api-key')
        if ApiKey.query.filter_by(api_key=api_key).first():
            return func(*args, **kwargs)
        else:
            return {"message": "Harap berikan API key yang benar!"}, 400
    return check_api_key

# Endpoint Index
@app.route('/')
def index():
    return "Hello World!"

# Endpoint Signup
@app.post('/signup')
@api_key_required
def signup():
    data = request.form
    email, name, password = data.get("email"), data.get("name"), data.get("password")

    if not email:
        return jsonify(message="Email wajib diisi!"), 400

    if User.query.filter_by(email=email).first():
        return jsonify(error=True, message="Email sudah terdaftar. Harap gunakan email lain!"), 400

    hashed_password = ph.hash(password)
    verification_token = secrets.token_urlsafe(32)
    
    new_user = User(
        email=email,
        name=name,
        password=hashed_password,
        verification_token=verification_token
    )

    db.session.add(new_user)
    db.session.commit()

    confirmation_url = url_for('confirm_email', token=verification_token, _external=True)
    msg = Message(subject="Verifikasi Alamat Email", sender="MallVisTrack App <noreply@app.com>", recipients=[email])
    msg.html = render_template("verify-email.html", confirmation_url=confirmation_url)

    mail.send(msg)

    return jsonify(message="Pendaftaran berhasil. Harap cek email Anda untuk konfirmasi!", error=False), 201

# Endpoint Konfirmasi Email
@app.route('/confirm_email/<token>')
def confirm_email(token):
    user = User.query.filter_by(verification_token=token).first_or_404()
    if user.is_verified:
        return jsonify(message="Akun sudah terverifikasi."), 200
    user.is_verified = True
    user.verification_token = None
    user.updated_at = datetime.utcnow()
    db.session.commit()
    return render_template('verify-success.html', message="Email berhasil diverifikasi."), 200

# Fungsi Kirim Email
def send_email(to, subject, body):
    msg = Message(subject, recipients=[to], body=body)
    mail.send(msg)

# Endpoint Login
@app.post("/login")
@api_key_required
def login():
    base64Str = request.headers.get('Authorization')
    if not base64Str:
        return jsonify({"message": "Header otorisasi tidak ada!"}), 400

    base64Str = base64Str[6:]  # Untuk menghapus "Basic " prefix
    base64Bytes = base64Str.encode('ascii')
    messageBytes = base64.b64decode(base64Bytes)
    pair = messageBytes.decode('ascii')
    email, password = pair.split(":")
    
    user = User.query.filter_by(email=email).first()
    
    if not user:
        return jsonify({"message": "Email atau kata sandi salah!"}), 400

    try:
        ph.verify(user.password, password)
    except:
        return jsonify({"message": "Email atau kata sandi salah!"}), 400
    
    if not user.is_verified:
        return jsonify({"message": "Harap verifikasi email Anda sebelum masuk!"}), 403
    
    access_token = create_access_token(identity=user.id)
    
    return jsonify({"access_token": access_token}), 200

# Endpoint Lupa Kata Sandi
@app.route('/forgot_password', methods=['POST'])
@api_key_required
def forgot_password():
    data = request.form
    email = data.get('email')
    
    user = User.query.filter_by(email=email).first()
    
    if not user:
        return jsonify({"message": "Email tidak ditemukan!"}), 404
    
    reset_token = secrets.token_urlsafe(32)
    reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
    user.reset_token = reset_token
    user.reset_token_expiry = reset_token_expiry
    db.session.commit()
    
    reset_url = url_for('reset_password', token=reset_token, _external=True)
    msg = Message(subject="Atur Ulang Kata Sandi", sender="MallVisTrack App <noreply@app.com>", recipients=[email])
    msg.html = render_template("reset-password.html", reset_url=reset_url)
    mail.send(msg)
    
    return jsonify({"message": "Tautan untuk mengatur ulang kata sandi telah dikirimkan ke alamat email Anda."}), 200

# Endpoint Reset Kata Sandi
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    
    if not user or user.reset_token_expiry < datetime.utcnow():
        return jsonify({"message": "Token tidak valid atau sudah kadaluarsa."}), 400
    
    if request.method == 'GET':
        return render_template('reset-password-form.html', token=token)
    
    if request.method == 'POST':
        data = request.form
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')
        
        if new_password != confirm_password:
            return jsonify({"message": "Kata sandi tidak cocok!"}), 400
        
        hashed_password = ph.hash(new_password)
        
        user.password = hashed_password
        user.reset_token = None
        user.reset_token_expiry = None
        user.updated_at = datetime.utcnow()
        db.session.commit()
        
        return render_template('verify-success.html', message="Kata sandi berhasil diatur ulang."), 200

# Endpoint Protected (Proteksi)
@app.get('/protected')
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({"message": "Pengguna tidak ditemukan!"}), 404
    
    return jsonify(name=user.name, email=user.email, avatar=user.avatar), 200

# Konfigurasi Upload File
UPLOAD_FOLDER = 'static/uploads/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Endpoint Ubah Kata Sandi
@app.route('/change_password', methods=['PUT'])
@api_key_required
@jwt_required()
def change_password():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({"message": "Pengguna tidak ditemukan!"}), 404
    
    current_password = request.form.get("current_password")
    new_password = request.form.get("new_password")
    
    if not current_password or not new_password:
        return jsonify({"message": "Kata sandi saat ini dan baru wajib diisi!"}), 400
    
    try:
        ph.verify(user.password, current_password)
    except:
        return jsonify({"message": "Kata sandi saat ini salah!"}), 400
    
    hashed_new_password = ph.hash(new_password)
    user.password = hashed_new_password
    user.updated_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({"message": "Kata sandi berhasil diubah."}), 200

# Endpoint Edit Profil
@app.route('/edit_profile', methods=['PUT'])
@api_key_required
@jwt_required()
def edit_profile():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({"message": "Pengguna tidak ditemukan!"}), 404
    
    data = request.form
    
    email_changed = False
    if 'email' in data:
        if user.email != data['email']:
            email_changed = True
            user.email = data['email']
            user.is_verified = False
            user.verification_token = secrets.token_urlsafe(32)
    
    if 'name' in data:
        user.name = data['name']
    
    if 'file' in request.files:
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            user.avatar = url_for('static', filename='uploads/' + filename, _external=True)

    user.updated_at = datetime.utcnow()
    
    db.session.commit()
    
    if email_changed:
        confirmation_url = url_for('confirm_email', token=user.verification_token, _external=True)
        msg = Message(subject="Konfirmasi Perubahan Email", sender="MallVisTrack App <noreply@app.com>", recipients=[user.email])
        msg.html = render_template("confirm-change-email.html", confirmation_url=confirmation_url)
        mail.send(msg)

    return jsonify({
        "message": "Profil berhasil diperbarui!",
        "emailRequiresConfirmation": email_changed
    }), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)