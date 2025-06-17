from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import os 
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib
from flask_login import login_user, UserMixin, LoginManager, login_required, current_user
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///securechat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

print("Database path:", os.path.abspath('securechat.db'))

# Model User
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_active = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Model Room
class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    # Relasi ke pesan
    messages = db.relationship('ChatMessage', backref='room', lazy=True)

# Model RoomMember untuk relasi user dengan room
class RoomMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    joined_at = db.Column(db.DateTime, server_default=db.func.now())
    user = db.relationship('User', backref=db.backref('room_memberships', lazy=True))
    room = db.relationship('Room', backref=db.backref('members', lazy=True))

# Model ChatMessage
class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # nullable untuk mode room
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=True)  # nullable agar chat lama tetap bisa diakses
    algorithm = db.Column(db.String(16), nullable=False)
    encrypted = db.Column(db.Text, nullable=False)
    decrypted = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())
    sender = db.relationship('User', foreign_keys=[sender_id], backref=db.backref('sent_messages', lazy=True))
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref=db.backref('received_messages', lazy=True))

# Fungsi untuk mengenkripsi pesan dengan AES
def encrypt_message_aes(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

# Fungsi untuk mendekripsi pesan dengan AES
def decrypt_message_aes(encrypted_message, key):
    try:
        data = base64.b64decode(encrypted_message.encode())
        nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()
    except Exception as e:
        return f"[DECRYPTION FAILED: {e}]"

# Fungsi hash sederhana untuk warna avatar konsisten per user
AVATAR_COLOR_COUNT = 6

def get_avatar_color_idx(username):
    return abs(hash(username)) % AVATAR_COLOR_COUNT

# Halaman utama
@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('chat'))
    return render_template('login.html')

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(username=email).first()
        if user and user.check_password(password):
            login_user(user)
            session['username'] = user.username
            session['user_id'] = user.id
            return redirect(url_for('rooms'))
        else:
            error = 'Email atau kata sandi tidak valid.'
            return render_template('login.html', error=error)
    return render_template('login.html')

# Halaman chat
@app.route('/chat', defaults={'receiver_id': None}, methods=['GET', 'POST'])
@app.route('/chat/<int:receiver_id>', methods=['GET', 'POST'])
@login_required
def chat(receiver_id):
    AES_GLOBAL_KEY = os.getenv('AES_KEY', 'SixteenByteKey16').encode() # 16-byte key

    # Fitur clear chat (POST agar lebih aman)
    if request.method == 'POST' and request.form.get('clear_chat') == '1':
        if receiver_id:
            # Clear chat for a specific receiver
            ChatMessage.query.filter(
                ((ChatMessage.sender_id == current_user.id) & (ChatMessage.receiver_id == receiver_id)) |
                ((ChatMessage.sender_id == receiver_id) & (ChatMessage.receiver_id == current_user.id))
            ).delete(synchronize_session=False)
            db.session.commit()
            # If clear chat is successful, return a success JSON response if it's an AJAX request
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': 'Chat history cleared successfully.'})
            return redirect(url_for('chat', receiver_id=receiver_id))
        else:
            # Handle case where no receiver is selected for clear chat
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'error': 'No receiver selected to clear chat history.'}), 400
            # Optional: redirect to chat page without receiver selected
            return redirect(url_for('chat'))

    encrypted_message = None
    decrypted_message = None
    receiver_username = None
    selected_receiver_user = None

    # Jika ada receiver_id yang dipilih, ambil username-nya
    if receiver_id:
        # Tambahan: Cegah chat dengan diri sendiri
        if receiver_id == current_user.id:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'error': 'Tidak bisa chat dengan diri sendiri.'}), 400
            receiver_id = None
        else:
            selected_receiver_user = User.query.get(receiver_id)
            if selected_receiver_user:
                receiver_username = selected_receiver_user.username
            else:
                # Jika receiver_id tidak valid, reset ke None
                receiver_id = None
                # Optionally, return an error if it's an AJAX request to load chat history
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'error': 'ID penerima tidak valid.'}), 400

    if request.method == 'POST' and request.form.get('clear_chat') != '1':
        # Menggunakan request.get_json() karena frontend mengirim sebagai application/json
        data = request.get_json()
        message = data.get('message')
        # Pastikan receiver_id diambil dari data JSON, yang harusnya cocok dengan yang aktif di frontend
        posted_receiver_id = data.get('receiver_id')

        if not message or message.strip() == '':
            return jsonify({'error': 'Pesan tidak boleh kosong. Silakan isi pesan.'}), 400

        if not posted_receiver_id:
            return jsonify({'error': 'Pilih penerima terlebih dahulu.'}), 400

        try:
            posted_receiver_id = int(posted_receiver_id) # Pastikan receiver_id adalah integer
            # Validasi bahwa posted_receiver_id adalah user yang valid
            if not User.query.get(posted_receiver_id):
                raise ValueError("Invalid receiver ID")
        except (ValueError, TypeError):
            return jsonify({'error': 'ID penerima tidak valid atau tidak ada.'}), 400

        # Gunakan posted_receiver_id untuk menyimpan pesan
        target_receiver_id = posted_receiver_id

        encrypted_message = encrypt_message_aes(message, AES_GLOBAL_KEY)

        # Simpan ke database
        chat_msg = ChatMessage(
            sender_id=current_user.id,
            receiver_id=target_receiver_id,
            algorithm='AES',
            encrypted=encrypted_message,
            decrypted=None
        )
        db.session.add(chat_msg)
        db.session.commit()

        # Ambil kembali data receiver_user untuk respon JSON
        response_receiver_user = User.query.get(target_receiver_id)
        response_receiver_username = response_receiver_user.username if response_receiver_user else "Unknown User"
        
        # Untuk tampilan instan di frontend, kirim pesan asli sebagai "original"
        return jsonify({
            'sender': current_user.username,
            'receiver': response_receiver_username,
            'algorithm': 'AES',
            'original': message, # Mengirim pesan asli
            'encrypted': encrypted_message,
            'timestamp': datetime.now().isoformat()
        })

    # Ambil pesan yang relevan untuk user saat ini DAN receiver yang dipilih
    chat_history_raw = []
    if receiver_id:
        chat_history_raw = ChatMessage.query.filter(
            ((ChatMessage.sender_id == current_user.id) & (ChatMessage.receiver_id == receiver_id)) |
            ((ChatMessage.sender_id == receiver_id) & (ChatMessage.receiver_id == current_user.id))
        ).order_by(ChatMessage.timestamp.asc()).all()

    chat_history_data = []
    for c in chat_history_raw:
        try:
            sender_user = User.query.get(c.sender_id)
            receiver_user_msg = User.query.get(c.receiver_id) 
            sender_username = sender_user.username if sender_user else "Unknown User"
            receiver_username_msg = receiver_user_msg.username if receiver_user_msg else "Unknown User"

            # Dekripsi ulang dengan kunci global untuk tampilan jika perlu (saat mengambil histori)
            current_decrypted_for_display = decrypt_message_aes(c.encrypted, AES_GLOBAL_KEY)

            chat_history_data.append({
                'sender': sender_username,
                'receiver': receiver_username_msg,
                'algorithm': 'AES',
                'original': c.original, 
                'encrypted': c.encrypted,
                'decrypted': current_decrypted_for_display, # Ini adalah pesan yang didekripsi untuk tampilan
                'timestamp': c.timestamp.isoformat()
            })
        except Exception as e:
            app.logger.error(f'Error processing chat message: {e}')
            continue  # skip this message

    return render_template('chat.html',
                           available_users=User.query.filter(User.id != current_user.id).all(),
                           selected_receiver_id=receiver_id,
                           selected_receiver_username=receiver_username,
                           chat_history=chat_history_data,
                           current_user=current_user,
                           selected_algorithm='AES')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    session.pop('algorithm', None)
    return redirect(url_for('index'))

def init_db():
    with app.app_context():
        db.create_all()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            error = 'Nama pengguna sudah terdaftar.'
            return render_template('register.html', error=error)
        
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    # Placeholder for forgot password functionality
    return render_template('forgot_password.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    # Placeholder for reset password functionality
    return render_template('reset_password.html')

@app.route('/rooms', methods=['GET', 'POST'])
@login_required
def rooms():
    if request.method == 'POST':
        room_name = request.form.get('room_name')
        if room_name:
            # Cek jika room sudah ada
            existing_room = Room.query.filter_by(name=room_name).first()
            if existing_room:
                # Tambahkan user ke RoomMember jika belum ada
                if not RoomMember.query.filter_by(user_id=current_user.id, room_id=existing_room.id).first():
                    db.session.add(RoomMember(user_id=current_user.id, room_id=existing_room.id))
                    db.session.commit()
                return redirect(url_for('room_chat', room_id=existing_room.id))
            # Buat room baru
            new_room = Room(name=room_name)
            db.session.add(new_room)
            db.session.commit()
            db.session.add(RoomMember(user_id=current_user.id, room_id=new_room.id))
            db.session.commit()
            return redirect(url_for('room_chat', room_id=new_room.id))
    all_rooms = Room.query.order_by(Room.created_at.desc()).all()
    # Ambil daftar room yang diikuti user
    my_room_ids = [rm.room_id for rm in RoomMember.query.filter_by(user_id=current_user.id).all()]
    return render_template('rooms.html', rooms=all_rooms, my_room_ids=my_room_ids)

@app.route('/room/<int:room_id>', methods=['GET', 'POST'])
@login_required
def room_chat(room_id):
    room = Room.query.get_or_404(room_id)
    # Cek apakah user anggota room, jika belum tambahkan
    membership = RoomMember.query.filter_by(user_id=current_user.id, room_id=room.id).first()
    if not membership:
        db.session.add(RoomMember(user_id=current_user.id, room_id=room.id))
        db.session.commit()
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        message = data.get('message')
        # Algoritma default (misal AES)
        algorithm = 'AES'
        if not message or message.strip() == '':
            return jsonify({'error': 'Pesan tidak boleh kosong.'}), 400
        # Kunci global
        AES_GLOBAL_KEY = os.getenv('AES_KEY', 'SixteenByteKey16').encode()
        encrypted_message = encrypt_message_aes(message, AES_GLOBAL_KEY)
        chat_msg = ChatMessage(
            sender_id=current_user.id,
            receiver_id=None,
            room_id=room.id,
            algorithm=algorithm,
            encrypted=encrypted_message,
            decrypted=None
        )
        db.session.add(chat_msg)
        db.session.commit()
        # Kirim hasil dekripsi ke frontend, sertakan avatar_color_idx
        return jsonify({
            'sender': current_user.username,
            'decrypted': message,
            'avatar_color_idx': get_avatar_color_idx(current_user.username),
            'timestamp': datetime.now().isoformat()
        })
    # Ambil semua pesan di room, lakukan dekripsi
    AES_GLOBAL_KEY = os.getenv('AES_KEY', 'SixteenByteKey16').encode()
    chat_history_raw = ChatMessage.query.filter_by(room_id=room.id).order_by(ChatMessage.timestamp.asc()).all()
    chat_history_data = []
    for c in chat_history_raw:
        sender_user = User.query.get(c.sender_id)
        sender_username = sender_user.username if sender_user else "Unknown User"
        # Dekripsi pesan
        if c.algorithm == 'AES':
            decrypted = decrypt_message_aes(c.encrypted, AES_GLOBAL_KEY)
        else:
            decrypted = "[Unsupported Algorithm]"
        chat_history_data.append({
            'sender': sender_username,
            'decrypted': decrypted,
            'avatar_color_idx': get_avatar_color_idx(sender_username),
            'timestamp': c.timestamp.isoformat()
        })
    return render_template('room_chat.html', room=room, chat_history=chat_history_data, current_user=current_user)

@app.route('/room/<int:room_id>/messages', methods=['GET'])
@login_required
def room_messages(room_id):
    room = Room.query.get_or_404(room_id)
    AES_GLOBAL_KEY = os.getenv('AES_KEY', 'SixteenByteKey16').encode()
    chat_history_raw = ChatMessage.query.filter_by(room_id=room.id).order_by(ChatMessage.timestamp.asc()).all()
    chat_history_data = []
    for c in chat_history_raw:
        sender_user = User.query.get(c.sender_id)
        sender_username = sender_user.username if sender_user else "Unknown User"
        chat_history_data.append({
            'sender': sender_username,
            'decrypted': decrypt_message_aes(c.encrypted, AES_GLOBAL_KEY) if c.algorithm == 'AES' else "[Unsupported Algorithm]",
            'avatar_color_idx': get_avatar_color_idx(sender_username),
            'timestamp': c.timestamp.isoformat()
        })
    return jsonify(chat_history_data)

@app.route('/delete_room/<int:room_id>', methods=['POST'])
@login_required
def delete_room(room_id):
    room = Room.query.get_or_404(room_id)
    # Hanya user yang tergabung di room yang bisa hapus
    membership = RoomMember.query.filter_by(user_id=current_user.id, room_id=room.id).first()
    if not membership:
        return redirect(url_for('rooms'))
    # Hapus semua pesan di room
    ChatMessage.query.filter_by(room_id=room.id).delete()
    # Hapus semua membership di room
    RoomMember.query.filter_by(room_id=room.id).delete()
    # Hapus room
    db.session.delete(room)
    db.session.commit()
    return redirect(url_for('rooms'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Ensure tables are created when app starts
    app.run(debug=True)
