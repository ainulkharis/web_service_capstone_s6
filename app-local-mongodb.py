from flask import Flask, Response, request, jsonify, render_template, url_for
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager
from flask_pymongo import PyMongo
from argon2 import PasswordHasher
from flask_mail import Mail, Message
from datetime import timedelta, datetime
from bson.objectid import ObjectId
from werkzeug.utils import secure_filename
from ultralytics import YOLO
from ultralytics.solutions import object_counter
from shapely.geometry import Point
import cv2
import datetime
import os
import secrets
import functools
import base64

# BACKEND FLASK
# Inisialisasi Flask
app = Flask(__name__)

# Konfigurasi MongoDB
app.config["MONGO_URI"] ="mongodb://localhost:27017/supermarket"
mongo = PyMongo(app)
# Mengakses koleksi
users_collection = mongo.db.users
api_key_collection = mongo.db.api_key
detections_collection = mongo.db.detections

# Konfigurasi JWT
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

# User Lookup JWT
@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return users_collection.find_one({"_id": ObjectId(identity)})

# Dekorator API Key
def api_key_required(func):
    @functools.wraps(func)
    def check_api_key(*args, **kwargs):
        api_key = request.headers.get('x-api-key')
        api_key_doc = api_key_collection.find_one({"api_key": api_key})
        if api_key_doc:
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

    if users_collection.find_one({"email": email}):
        return jsonify(error=True, message="Email sudah terdaftar. Harap gunakan email lain!"), 400

    hashed_password = ph.hash(password)
    verification_token = secrets.token_urlsafe(32)
    
    created_at = datetime.utcnow().isoformat()
    updated_at = created_at
    
    new_user = {
        "email": email,
        "name": name,
        "password": hashed_password,
        "avatar": None,
        "created_at": created_at,
        "updated_at": updated_at,
        "is_verified": False,
        "verification_token": verification_token,
        "reset_token": None,
        "reset_token_expiry": None
    }

    users_collection.insert_one(new_user)

    confirmation_url = url_for('confirm_email', token=verification_token, _external=True)
    msg = Message(subject="Verifikasi Alamat Email", sender="MallVisTrack App <noreply@app.com>", recipients=[email])
    msg.html = render_template("verify-email.html", confirmation_url=confirmation_url)

    mail.send(msg)

    return jsonify(message="Pendaftaran berhasil. Harap cek email Anda untuk konfirmasi!", error=False), 201

# Endpoint Konfirmasi Email
@app.route('/confirm_email/<token>')
def confirm_email(token):
    user = users_collection.find_one({"verification_token": token})
    if not user:
        return jsonify(message="Token tidak valid atau sudah kadaluarsa."), 404
    
    if user["is_verified"]:
        return jsonify(message="Akun sudah terverifikasi."), 200
    
    users_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"is_verified": True, "verification_token": None, "updated_at": datetime.utcnow().isoformat()}}
    )
    
    return render_template('verify-success.html', message="Email berhasil diverifikasi."), 200

# Fungsi Kirim Email
def send_email(to, subject, body):
    msg = Message(subject, recipients=[to], body=body)
    mail.send(msg)

# Endpoint Login
@app.post("/login")
@api_key_required
def login():
    # Mengambil header Authorization
    base64Str = request.headers.get('Authorization')
    if not base64Str:
        return jsonify({"message": "Header otorisasi tidak ada!"}), 400
    
    # Decode base64
    base64Str = base64Str[6:] # Untuk menghapus "Basic " prefix
    base64Bytes = base64Str.encode('ascii')
    messageBytes = base64.b64decode(base64Bytes)
    pair = messageBytes.decode('ascii')
    email, password = pair.split(":")
    
    user = users_collection.find_one({"email": email})
    
    if not user:
        return jsonify({"message": "Email atau kata sandi salah!"}), 400

    try:
        ph.verify(user["password"], password)
    except:
        return jsonify({"message": "Email atau kata sandi salah!"}), 400
    
    if not user["is_verified"]:
        return jsonify({"message": "Harap verifikasi email Anda sebelum masuk!"}), 403
    
    access_token = create_access_token(identity=str(user["_id"]))
    
    return jsonify({"access_token": access_token}), 200

# Endpoint Lupa Kata Sandi
@app.route('/forgot_password', methods=['POST'])
@api_key_required
def forgot_password():
    data = request.form
    email = data.get('email')
    
    user = users_collection.find_one({"email": email})
    
    if not user:
        return jsonify({"message": "Email tidak ditemukan!"}), 404
    
    reset_token = secrets.token_urlsafe(32)
    reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
    
    users_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"reset_token": reset_token, "reset_token_expiry": reset_token_expiry.isoformat()}}
    )
    
    reset_url = url_for('reset_password', token=reset_token, _external=True)
    msg = Message(subject="Atur Ulang Kata Sandi", sender="MallVisTrack App <noreply@app.com>", recipients=[email])
    msg.html = render_template("reset-password.html", reset_url=reset_url)
    mail.send(msg)
    
    return jsonify({"message": "Tautan untuk mengatur ulang kata sandi telah dikirimkan ke alamat email Anda."}), 200

# Endpoint Reset Kata Sandi
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = users_collection.find_one({"reset_token": token})
    
    if not user or datetime.fromisoformat(user["reset_token_expiry"]) < datetime.utcnow():
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
        
        users_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {
                "password": hashed_password,
                "reset_token": None,
                "reset_token_expiry": None,
                "updated_at": datetime.utcnow().isoformat()
            }}
        )
        
        return render_template('verify-success.html', message="Kata sandi berhasil diatur ulang."), 200

# Endpoint Protected (Proteksi)
@app.get('/protected')
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()
    user = users_collection.find_one({"_id": ObjectId(current_user_id)})
    
    if not user:
        return jsonify({"message": "Pengguna tidak ditemukan!"}), 404
    
    return jsonify(name=user["name"], email=user["email"], avatar=user.get("avatar")), 200

# Konfigurasi Upload File
UPLOAD_FOLDER = 'static/uploads/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Endpoint Ubah Kata Sandi
@app.route('/change_password', methods=['PUT'])
@api_key_required
@jwt_required()
def change_password():
    current_user_id = get_jwt_identity()
    user = users_collection.find_one({"_id": ObjectId(current_user_id)})
    
    if not user:
        return jsonify({"message": "Pengguna tidak ditemukan!"}), 404
    
    current_password = request.form.get("current_password")
    new_password = request.form.get("new_password")
    
    if not current_password or not new_password:
        return jsonify({"message": "Kata sandi saat ini dan baru wajib diisi!"}), 400
    
    try:
        ph.verify(user["password"], current_password)
    except:
        return jsonify({"message": "Kata sandi saat ini salah!"}), 400
    
    hashed_password = ph.hash(new_password)
    
    users_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"password": hashed_password, "updated_at": datetime.now().isoformat()}}
    )
    
    return jsonify({"message": "Kata sandi berhasil diperbarui!"}), 200

# Endpoint Edit Profil
@app.route('/edit_profile', methods=['PUT'])
@api_key_required
@jwt_required()
def edit_profile():
    current_user_id = get_jwt_identity()
    user = users_collection.find_one({"_id": ObjectId(current_user_id)})
    
    if not user:
        return jsonify({"message": "Pengguna tidak ditemukan!"}), 404
    
    data = request.form
    
    email_changed = False
    if 'email' in data:
        if user["email"] != data['email']:
            email_changed = True
            user["email"] = data['email']
            user["is_verified"] = False
            user["verification_token"] = secrets.token_urlsafe(32)
    
    if 'name' in data:
        user["name"] = data['name']
    
    if 'file' in request.files:
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            user["avatar"] = url_for('static', filename='uploads/' + filename, _external=True)

    user["updated_at"] = datetime.now().isoformat()
    
    users_collection.update_one(
        {"_id": user["_id"]},
        {"$set": user}
    )
    
    if email_changed:
        confirmation_url = url_for('confirm_email', token=user["verification_token"], _external=True)
        msg = Message(subject="Konfirmasi Perubahan Email", sender="MallVisTrack App <noreply@app.com>", recipients=[user["email"]])
        msg.html = render_template("confirm-change-email.html", confirmation_url=confirmation_url)
        mail.send(msg)

    return jsonify({
        "message": "Profil berhasil diperbarui!",
        "emailRequiresConfirmation": email_changed
    }), 200


# DETECTION
model = YOLO("model/best.pt")
region_of_interest = [(300, 20), (302, 680), (280, 680), (280, 20)]
counter = object_counter.ObjectCounter(view_img=True, reg_pts=region_of_interest, classes_names=model.names, draw_tracks=True)

def count_object():
    cap = cv2.VideoCapture('data/dataset.mp4') # Ganti 0 jika ingin menggunakan kamera laptop
    assert cap.isOpened()
    tracked_ids = set()
    male_count = 0
    female_count = 0
    
    while True:
        success, im0 = cap.read()
        if not success:
            break
        tracks = model.track(im0, persist=True, show=False)
        im0 = counter.start_counting(im0, tracks)
        
        # Process tracks and save to MongoDB if crossing the ROI
        if tracks[0].boxes.id is not None:
            boxes = tracks[0].boxes.xyxy.cpu()
            clss = tracks[0].boxes.cls.cpu().tolist()
            track_ids = tracks[0].boxes.id.int().cpu().tolist()

            for box, track_id, cls in zip(boxes, track_ids, clss):
                if track_id not in tracked_ids:
                    prev_position = counter.track_history[track_id][-2] if len(counter.track_history[track_id]) > 1 else None
                    current_position = (float((box[0] + box[2]) / 2), float((box[1] + box[3]) / 2))
                    
                    if len(region_of_interest) >= 3:
                        is_inside = counter.counting_region.contains(Point(current_position))
                        if prev_position and is_inside:
                            tracked_ids.add(track_id)
                            direction = "IN" if (box[0] - prev_position[0]) * (counter.counting_region.centroid.x - prev_position[0]) > 0 else "OUT"
                            
                            if cls == 0:
                                female_count += 1
                            elif cls == 1:
                                male_count += 1
                            
                            detection = {
                                'gender': f"Female: {female_count}, Male: {male_count}",
                                'days': datetime.datetime.now().strftime('%A'),
                                'date': datetime.datetime.now().date().isoformat(),
                                'total': male_count + female_count
                            }
                            detections_collection.insert_one(detection)

        ret, buffer = cv2.imencode('.jpg', im0)
        frame = buffer.tobytes()
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')

    cap.release()
    cv2.destroyAllWindows()

@app.route('/realtime')
def realtime():
    return render_template('index.html')

@app.route('/video_feed')
def video_feed():
    return Response(count_object(), mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/data', methods=['GET'])
def get_data():
    try:
        # Mengambil semua data dari koleksi
        data = list(detections_collection.find({}))  # Menggunakan find() tanpa argumen untuk mengambil semua data
        
        # Konversi ObjectId ke string untuk setiap dokumen
        for item in data:
            item['_id'] = str(item['_id'])
        
        return jsonify(data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)