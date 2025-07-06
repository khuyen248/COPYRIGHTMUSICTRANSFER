import os
import logging
import uuid
import time
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, send_file
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
import json
import base64
from threading import Lock
from crypto_utils import CryptoManager
from secure_protocol import SecureProtocol
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives import serialization
import tempfile

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'mp3'}
MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB max file size

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///music_transfer.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# Define models
class Host(db.Model):
    __tablename__ = 'hosts'
    host_id = db.Column(db.String(64), primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    ip_address = db.Column(db.String(64), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    private_key = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.Float, default=time.time)
    transfers = db.relationship('Transfer', backref='host', lazy=True)

class Sender(db.Model):
    __tablename__ = 'senders'
    sender_id = db.Column(db.String(64), primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    ip_address = db.Column(db.String(64), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    private_key = db.Column(db.Text, nullable=False)
    transfers = db.relationship('Transfer', backref='sender', lazy=True)

class Transfer(db.Model):
    __tablename__ = 'transfers'
    transfer_id = db.Column(db.String(64), primary_key=True)
    host_id = db.Column(db.String(64), db.ForeignKey('hosts.host_id'), nullable=False)
    sender_id = db.Column(db.String(64), db.ForeignKey('senders.sender_id'), nullable=False)
    session_key_enc = db.Column(db.LargeBinary, nullable=False)
    iv = db.Column(db.LargeBinary, nullable=False)
    file_hash = db.Column(db.String(128), nullable=False)
    metadata_enc = db.Column(db.LargeBinary, nullable=False)
    signature = db.Column(db.LargeBinary, nullable=False)
    ciphertext = db.Column(db.LargeBinary, nullable=True)  # Now nullable, since we store file on disk
    integrity_status = db.Column(db.String(32), default='pending')
    signature_status = db.Column(db.String(32), default='pending')
    timestamp = db.Column(db.Float, default=time.time)
    files = db.relationship('File', backref='transfer', lazy=True)

class File(db.Model):
    __tablename__ = 'files'
    file_id = db.Column(db.String(64), primary_key=True)
    transfer_id = db.Column(db.String(64), db.ForeignKey('transfers.transfer_id'), nullable=False)
    original_name = db.Column(db.String(256), nullable=False)
    stored_name = db.Column(db.String(256), nullable=False)
    copyright_info = db.Column(db.Text)
    file_size = db.Column(db.Integer)
    received_at = db.Column(db.Float, default=time.time)
    status = db.Column(db.String(32), default='pending')

class HandshakeRequest(db.Model):
    __tablename__ = 'handshake_requests'
    id = db.Column(db.String(64), primary_key=True)
    sender_id = db.Column(db.String(64), db.ForeignKey('senders.sender_id'), nullable=False)
    host_id = db.Column(db.String(64), db.ForeignKey('hosts.host_id'), nullable=False)
    ip_address = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(32), default='pending')
    timestamp = db.Column(db.Float, default=time.time)

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

decoded_files_cache = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/receiver')
def receiver():
    ip_address = request.remote_addr or '127.0.0.1'
    print(f"Receiver IP Address: {ip_address}")
    host = Host.query.filter_by(ip_address=ip_address).first()
    if not host:
        return redirect(url_for('create_host'))
    session['host_id'] = host.host_id
    return redirect(url_for('manage_files'))

@app.route('/sender')
def sender():
    ip_address = request.remote_addr or '127.0.0.1'
    sender_id = session.get('sender_id')
    sender = None
    if sender_id:
        sender = Sender.query.filter_by(sender_id=sender_id).first()
    if not sender:
        sender = Sender.query.filter_by(ip_address=ip_address).first()
    if not sender:
        crypto = CryptoManager()
        public_key = crypto.get_public_key_pem()
        private_key = crypto.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        sender_id = str(uuid.uuid4())
        sender = Sender(
            sender_id=sender_id,
            name=f"Sender-{sender_id[:8]}",
            ip_address=ip_address,
            public_key=public_key,
            private_key=private_key
        )
        db.session.add(sender)
        db.session.commit()
        session['sender_id'] = sender_id
    else:
        session['sender_id'] = sender.sender_id
    print(f"Sender ID: {session['sender_id']}, IP Address: {ip_address}")
    return redirect(url_for('choose_host'))

@app.route('/choose_host', methods=['GET', 'POST'])
def choose_host():
    if request.method == 'POST':
        host_id = request.form.get('host_id')
        if not host_id:
            flash('Please select a host', 'error')
            return render_template('choose_host.html', hosts=hosts_with_handshake)
        session['host_id'] = host_id
        return redirect(url_for('send_file_get'))
    else:
        ip_address = request.remote_addr or '127.0.0.1'
        sender_id = session.get('sender_id')
        sender = None
        if sender_id:
            sender = Sender.query.filter_by(sender_id=sender_id).first()
        if not sender:
            sender = Sender.query.filter_by(ip_address=ip_address).first()
        if not sender:
            crypto = CryptoManager()
            public_key = crypto.get_public_key_pem()
            private_key = crypto.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            sender_id = str(uuid.uuid4())
            sender = Sender(
                sender_id=sender_id,
                name=f"Sender-{sender_id[:8]}",
                ip_address=ip_address,
                public_key=public_key,
                private_key=private_key
            )
            db.session.add(sender)
            db.session.commit()
            session['sender_id'] = sender.sender_id
        hosts = Host.query.all()
        hosts_with_handshake = []
        for host in hosts:
            handshake = None
            if sender_id:
                handshake_obj = HandshakeRequest.query.filter_by(host_id=host.host_id, sender_id=session['sender_id']).order_by(HandshakeRequest.timestamp.desc()).first()
                if handshake_obj:
                    handshake = {
                        'status': handshake_obj.status
                    }
            hosts_with_handshake.append({
                'id': host.host_id,
                'name': host.name,
                'ip_address': host.ip_address,
                'handshake': handshake
            })
        print(f"Sender ID: {session.get('sender_id')}, Hosts: {hosts_with_handshake}")
    return render_template('choose_host.html', hosts=hosts_with_handshake)

@app.route('/send_file', methods=['GET'])
def send_file_get():
    host_id = request.args.get('host_id')
    sender_ip = request.remote_addr or '127.0.0.1'
    sender = Sender.query.filter_by(ip_address=sender_ip).first()
    if not sender:
        flash('Sender not found. Please complete handshake first.', 'error')
        return redirect(url_for('choose_host'))
    sender_id = sender.sender_id
    if not host_id or not sender_id:
        return redirect(url_for('choose_host'))
    handshake = HandshakeRequest.query.filter_by(host_id=host_id, sender_id=sender_id, status='accepted').order_by(HandshakeRequest.timestamp.desc()).first()
    if not handshake:
        pending_handshake = HandshakeRequest.query.filter_by(host_id=host_id, sender_id=sender_id, status='pending').order_by(HandshakeRequest.timestamp.desc()).first()
        if pending_handshake:
            flash('You must wait for host confirmation before sending files.', 'warning')
        else:
            flash('You must complete handshake and wait for host confirmation before sending files.', 'warning')
        return redirect(url_for('choose_host'))
    host = Host.query.filter_by(host_id=host_id).first()
    connected_host = host if host else 'Not connected'
    return render_template('send_file.html', connected_host=connected_host, handshake_accepted=True)

@app.route('/send_file', methods=['POST'])
def send_file_post():
    host_ip = request.form.get('hostIp')
    sender_ip = request.remote_addr or '127.0.0.1'
    sender = Sender.query.filter_by(ip_address=sender_ip).first()
    if not sender:
        flash('Sender not found. Please complete handshake first.', 'error')
        return redirect(url_for('choose_host'))
    sender_id = sender.sender_id
    print(f"Sender ID: {sender_id}, Host ID: {host_ip}")
    if not host_ip or not sender_id:
        return redirect(url_for('choose_host'))

    if 'musicFile' not in request.files:
        flash('No file selected', 'error')
        return redirect(request.url)
    file = request.files['musicFile']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(request.url)
    if not allowed_file(file.filename):
        flash('Invalid file type. Only MP3 files are allowed.', 'error')
        return redirect(request.url)
    
    title = request.form.get('title')
    artist = request.form.get('artist')
    album = request.form.get('album')
    year = request.form.get('year')
    if not title or not artist:
        flash('Title and Artist are required in metadata.', 'error')
        return redirect(request.url)
    try:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        file_id = str(uuid.uuid4())
        metadata = {
            'filename': filename,
            'title': title,
            'artist': artist,
            'album': album,
            'year': year
        }
        host = Host.query.filter_by(ip_address=host_ip).first()
        receiver_public_key_pem = host.public_key if host else None
        if not receiver_public_key_pem:
            flash('Receiver public key not found.', 'error')
            return redirect(request.url)
        with open(file_path, 'rb') as f:
            file_bytes = f.read()
        sender_crypto = CryptoManager()
        sender_crypto.private_key = serialization.load_pem_private_key(
            sender.private_key.encode('utf-8'), password=None
        )
        sender_crypto.public_key = sender_crypto.private_key.public_key()
        protocol = SecureProtocol(sender_crypto)
        package = protocol.create_secure_package(file_bytes, metadata, receiver_public_key_pem)
        cipher_bytes = base64.b64decode(package['cipher'])
        enc_filename = f"enc_{file_id}.mp3"
        enc_file_path = os.path.join(app.config['UPLOAD_FOLDER'], enc_filename)
        with open(enc_file_path, 'wb') as ef:
            ef.write(cipher_bytes)
        transfer_id = str(uuid.uuid4())
        new_transfer = Transfer(
            transfer_id=transfer_id,
            host_id=host.host_id,
            sender_id=sender_id,
            session_key_enc=base64.b64decode(package['key']),
            iv=base64.b64decode(package['iv']),
            file_hash=package['hash'],
            metadata_enc=base64.b64decode(package['meta']),
            signature=base64.b64decode(package['sig']),
            ciphertext=None,
            integrity_status='pending',
            signature_status='pending',
            timestamp=time.time()
        )
        db.session.add(new_transfer)
        new_file = File(
            file_id=file_id,
            transfer_id=transfer_id,
            original_name=filename,
            stored_name=enc_filename,
            copyright_info=None,
            file_size=len(cipher_bytes),
            status='pending'
        )
        db.session.add(new_file)
        db.session.commit()
        if os.path.exists(file_path):
            os.remove(file_path)
        flash('File securely encrypted, signed, and sent!', 'success')
        return redirect(url_for('sent_files'))
    except Exception as e:
        logging.error(f"Error in send_file: {str(e)}")
        flash('Error uploading or encrypting file', 'error')
        return redirect(request.url)

@app.route('/sent_files')
def sent_files():
    sender_id = session.get('sender_id')
    sent_files = []
    if sender_id:
        transfers = Transfer.query.filter_by(sender_id=sender_id).all()
        for transfer in transfers:
            for file in transfer.files:
                print(f'File ID: {file.file_id}, Original Name: {file.original_name}, Status: {file.status}')
                sent_files.append({
                    'id': file.file_id,
                    'name': file.original_name,
                    'host': transfer.host.name if transfer.host else 'Unknown',
                    'date': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(file.received_at)),
                    'status': file.status,
                    'status_color': {
                        'received': 'success',
                        'pending': 'warning',
                        'error': 'danger'
                    }.get(file.status, 'info')
                })
    else:
        ip_address = request.remote_addr or '127.0.0.1'
        crypto = CryptoManager()
        public_key = crypto.get_public_key_pem()
        private_key = crypto.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        sender_id = str(uuid.uuid4())
        sender = Sender(
            sender_id=sender_id,
            name=f"Sender-{sender_id[:8]}",
            ip_address=ip_address,
            public_key=public_key,
            private_key=private_key
        )
        db.session.add(sender)
        db.session.commit()
        session['sender_id'] = sender_id
    return render_template('sent_files.html', files=sent_files)

@app.route('/create_host', methods=['GET', 'POST'])
def create_host():
    ip_address = request.remote_addr or '127.0.0.1'
    if request.method == 'POST':
        existing_host = Host.query.filter_by(ip_address=ip_address).first()
        if existing_host:
            flash('A host for this machine already exists.', 'error')
            return redirect(url_for('manage_files'))
        host_id = str(uuid.uuid4())
        name = request.form.get('hostName')
        crypto = CryptoManager()
        public_key = crypto.get_public_key_pem()
        private_key = crypto.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        if not name:
            flash('Host name is required', 'error')
            return redirect(url_for('create_host'))
        host = Host(
            host_id=host_id,
            name=name,
            ip_address=ip_address,
            public_key=public_key,
            private_key=private_key,
            created_at=time.time()
        )
        db.session.add(host)
        db.session.commit()
        session['host_id'] = host_id
        flash(f'Host {name} created successfully', 'success')
        return redirect(url_for('manage_files'))
    else:
        existing_hosts = Host.query.filter_by(ip_address=ip_address).first()
        if existing_hosts:
            flash('A host already exists. Please manage files or create a new host.', 'info')
            return redirect(url_for('manage_files'))
        return render_template('create_host.html', ip_address=ip_address)

@app.route('/manage_files')
def manage_files():
    ip_address = request.remote_addr or '127.0.0.1'
    host = Host.query.filter_by(ip_address=ip_address).first()
    if not host:
        flash('You do not have permission to view these files.', 'error')
        return redirect(url_for('create_host'))
    host_id = host.host_id
    files = []
    verified_files = list(decoded_files_cache.keys())
    transfers = Transfer.query.filter_by(host_id=host_id).all()
    for transfer in transfers:
        for file in transfer.files:
            files.append({
                'id': file.file_id,
                'name': file.original_name,
                'date': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(file.received_at)),
                'status': file.status,
                'sender_id': transfer.sender_id,
                'status_color': {
                    'received': 'success',
                    'pending': 'warning',
                    'error': 'danger'
                }.get(file.status, 'info')
            })
    return render_template('manage_files.html', files=files, verified_files=verified_files)

@app.route('/handle_handshake')
def handle_handshake():
    ip_address = request.remote_addr or '127.0.0.1'
    host = Host.query.filter_by(ip_address=ip_address).first()
    if not host:
        flash('You do not have permission to view handshake requests.', 'error')
        return redirect(url_for('create_host'))
    host_id = host.host_id
    handshake_requests = []
    db_requests = HandshakeRequest.query.filter_by(host_id=host_id).order_by(HandshakeRequest.timestamp.desc()).all()
    for req in db_requests:
        handshake_requests.append({
            'id': req.id,
            'sender_id': req.sender_id,
            'ip_address': req.ip_address,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(req.timestamp)),
            'status': req.status,
            'status_color': {
                'pending': 'warning',
                'accepted': 'success',
                'rejected': 'danger'
            }.get(req.status, 'info')
        })
    return render_template('handle_handshake.html', handshake_requests=handshake_requests)

@app.route('/api/handshake/respond', methods=['POST'])
def respond_to_handshake():
    """Host xác nhận hoặc từ chối handshake request của sender."""
    try:
        data = request.get_json()
        request_id = data.get('request_id')
        action = data.get('action')
        if not request_id or not action:
            return jsonify({'error': 'Missing required parameters'}), 400
        handshake = HandshakeRequest.query.filter_by(id=request_id).first()
        if not handshake:
            return jsonify({'error': 'Handshake request not found'}), 404
        handshake.status = 'accepted' if action == 'accept' else 'rejected'
        db.session.commit()
        new_handshake = HandshakeRequest.query.filter_by(id=request_id).first()
        print(f"New Handshake request {request_id} updated to {new_handshake.status}")
        return jsonify({'message': f'Handshake {action}ed successfully'})
    except Exception as e:
        logging.error(f"Error in respond_to_handshake: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/sender/handshake', methods=['POST'])
def sender_handshake():
    """Sender gửi handshake (Hello!) đến host, lưu trạng thái pending, trả về public key host nếu host xác nhận."""
    try:
        data = request.get_json()
        host_id = data.get('host_id')
        if not host_id:
            return jsonify({'error': 'No host selected'}), 400
        host = Host.query.filter_by(host_id=host_id).first()
        if not host:
            return jsonify({'error': 'Host not found'}), 404
        
        sender_ip = request.remote_addr or '127.0.0.1'
        sender = Sender.query.filter_by(ip_address=sender_ip).first()
        if not sender:
            flash('Sender not found. Please complete handshake first.', 'error')
            return jsonify({'error': 'Sender not found'}), 404
        sender_id = sender.sender_id
        print(f"Sender ID: {sender_id}, Host ID: {host_id}")
        # Gửi handshake request (pending)
        handshake_id = str(uuid.uuid4())
        handshake = HandshakeRequest(
            id=handshake_id,
            sender_id=sender_id,
            host_id=host_id,
            ip_address=request.remote_addr or '127.0.0.1',
            status='pending',
            timestamp=time.time()
        )
        print(f"Creating handshake request: {handshake_id} from sender {sender_id} to host {host_id}")
        db.session.add(handshake)
        db.session.commit()
        return jsonify({
            'message': 'Handshake request sent',
            'handshake_id': handshake_id,
            'sender_id': sender_id
        })
    except Exception as e:
        logging.error(f"Error in sender_handshake: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/decrypt_file/<file_id>', methods=['GET'])
def decrypt_file(file_id):
    ip_address = request.remote_addr or '127.0.0.1'
    host = Host.query.filter_by(ip_address=ip_address).first()
    if not host:
        flash('You do not have permission to decrypt this file.', 'error')
        return redirect(url_for('manage_files'))
    file = File.query.filter_by(file_id=file_id).first()
    if not file:
        flash('File not found.', 'error')
        return redirect(url_for('manage_files'))
    transfer = Transfer.query.filter_by(transfer_id=file.transfer_id, host_id=host.host_id).first()
    if not transfer:
        flash('Transfer not found or you do not have permission.', 'error')
        return redirect(url_for('manage_files'))
    enc_file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.stored_name)
    if not os.path.exists(enc_file_path):
        flash('Encrypted file not found on disk.', 'error')
        return redirect(url_for('manage_files'))
    with open(enc_file_path, 'rb') as ef:
        cipher_bytes = ef.read()
    cipher_b64 = base64.b64encode(cipher_bytes).decode()
    package = {
        'iv': base64.b64encode(transfer.iv).decode(),
        'cipher': cipher_b64,
        'meta': base64.b64encode(transfer.metadata_enc).decode(),
        'hash': transfer.file_hash,
        'sig': base64.b64encode(transfer.signature).decode(),
        'key': base64.b64encode(transfer.session_key_enc).decode()
    }
    receiver_crypto = CryptoManager()
    receiver_crypto.private_key = serialization.load_pem_private_key(
        host.private_key.encode('utf-8'), password=None
    )
    receiver_crypto.public_key = receiver_crypto.private_key.public_key()
    protocol = SecureProtocol(receiver_crypto)
    # Fetch sender from DB to get public key
    sender = Sender.query.filter_by(sender_id=transfer.sender_id).first()
    sender_public_key = sender.public_key if sender else None
    try:
        file_bytes, meta_dict = protocol.verify_and_decrypt_package(package, sender_public_key=sender_public_key)
        decoded_files_cache[file.file_id] = file_bytes
        result = {
            'success': True,
            'meta': meta_dict,
            'message': 'File decrypted and signature verified successfully!'
        }
        transfer.status = 'received'
        transfer.integrity_status = 'verified'
        transfer.signature_status = 'verified'
        file.status = 'received'
        db.session.commit()
    except Exception as e:
        result = {
            'success': False,
            'meta': None,
            'message': f'Error: {str(e)}'
        }
        transfer.status = 'error'
        transfer.integrity_status = 'error'
        transfer.signature_status = 'error'
        file.status = 'error'
        db.session.commit()
    return render_template('decrypt_result.html', file=file, result=result)

@app.route('/download_file/<file_id>', methods=['GET'])
def download_file(file_id):
    ip_address = request.remote_addr or '127.0.0.1'
    host = Host.query.filter_by(ip_address=ip_address).first()
    if not host:
        flash('You do not have permission to download this file.', 'error')
        return redirect(url_for('manage_files'))
    file = File.query.filter_by(file_id=file_id).first()
    if not file:
        flash('File not found.', 'error')
        return redirect(url_for('manage_files'))
    transfer = Transfer.query.filter_by(transfer_id=file.transfer_id, host_id=host.host_id).first()
    if not transfer:
        flash('Transfer not found or you do not have permission.', 'error')
        return redirect(url_for('manage_files'))
    import tempfile
    if file_id in decoded_files_cache:
        file_bytes = decoded_files_cache[file_id]
        temp = tempfile.NamedTemporaryFile(delete=False, suffix='.mp3')
        temp.write(file_bytes)
        temp.flush()
        temp.seek(0)
        try:
            response = send_file(temp.name, download_name=file.original_name or 'decrypted_file.mp3', as_attachment=True)
        except TypeError:
            response = send_file(temp.name, attachment_filename=file.original_name or 'decrypted_file.mp3', as_attachment=True)
        return response
    import os
    enc_file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.stored_name)
    if not os.path.exists(enc_file_path):
        flash('Encrypted file not found on disk.', 'error')
        return redirect(url_for('manage_files'))
    return send_file(enc_file_path, download_name=file.stored_name or 'encrypted_file.mp3', as_attachment=True)

@app.route('/api/file_details/<file_id>')
def api_file_details(file_id):
    try:
        file = File.query.filter_by(file_id=file_id).first()
        if not file:
            return jsonify({'error': 'File not found'}), 404
        transfer = Transfer.query.filter_by(transfer_id=file.transfer_id).first()
        if not transfer:
            return jsonify({'error': 'Transfer not found'}), 404
        return jsonify({
            'session_key': base64.b64encode(transfer.session_key_enc).decode(),
            'iv': base64.b64encode(transfer.iv).decode(),
            'hash': transfer.file_hash,
            'signature': base64.b64encode(transfer.signature).decode(),
            'metadata_enc': base64.b64encode(transfer.metadata_enc).decode()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/decrypted_file_details/<file_id>')
def api_decrypted_file_details(file_id):
    try:
        file = File.query.filter_by(file_id=file_id).first()
        if not file:
            return jsonify({'error': 'File not found'}), 404
        transfer = Transfer.query.filter_by(transfer_id=file.transfer_id).first()
        if not transfer:
            return jsonify({'error': 'Transfer not found'}), 404
        host = Host.query.filter_by(host_id=transfer.host_id).first()
        if not host:
            return jsonify({'error': 'Host not found'}), 404
        import os, base64
        enc_file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.stored_name)
        if not os.path.exists(enc_file_path):
            return jsonify({'error': 'Encrypted file not found on disk'}), 404
        with open(enc_file_path, 'rb') as ef:
            cipher_bytes = ef.read()
        cipher_b64 = base64.b64encode(cipher_bytes).decode()
        package = {
            'iv': base64.b64encode(transfer.iv).decode(),
            'cipher': cipher_b64,
            'meta': base64.b64encode(transfer.metadata_enc).decode(),
            'hash': transfer.file_hash,
            'sig': base64.b64encode(transfer.signature).decode(),
            'key': base64.b64encode(transfer.session_key_enc).decode()
        }
        receiver_crypto = CryptoManager()
        receiver_crypto.private_key = serialization.load_pem_private_key(
            host.private_key.encode('utf-8'), password=None
        )
        receiver_crypto.public_key = receiver_crypto.private_key.public_key()
        protocol = SecureProtocol(receiver_crypto)
        sender = Sender.query.filter_by(sender_id=transfer.sender_id).first()
        sender_public_key = sender.public_key if sender else None
        try:
            file_bytes, meta_dict = protocol.verify_and_decrypt_package(package, sender_public_key=sender_public_key)
            signature_verified = True
            message = 'File decrypted and signature verified successfully!'
        except Exception as e:
            meta_dict = None
            signature_verified = False
            message = f'Error: {str(e)}'
        return jsonify({
            'meta': meta_dict,
            'signature_verified': signature_verified,
            'message': message
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500