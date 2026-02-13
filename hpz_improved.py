import os
import random
import json
import time
import uuid
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
from functools import wraps
from werkzeug.utils import secure_filename
from sqlalchemy import or_, and_, func

# ========== INITIALIZE APP ==========
app = Flask(__name__)
app.secret_key = 'hpz_messenger_secure_key_2024' 
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'hpz_database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 3600,
}
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'static', 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'avi', 'webm', 'mp3', 'wav', 'ogg', 'pdf', 'doc', 'docx', 'txt'}
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Enable CORS for development
CORS(app, supports_credentials=True)

db = SQLAlchemy(app)

# Initialize SocketIO with better configuration
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    logger=True,
    engineio_logger=False,
    async_mode='threading',
    ping_timeout=60,
    ping_interval=25,
    manage_session=False  # Let Flask handle sessions
)

# ========== DATABASE MODELS ==========

class User(db.Model):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=True, index=True)
    phone = db.Column(db.String(20), unique=True, nullable=True, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class UserProfile(db.Model):
    __tablename__ = 'user_profile'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False, index=True)
    bio = db.Column(db.String(500))
    avatar_url = db.Column(db.String(500))
    status = db.Column(db.String(100), default='Available')
    last_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    privacy_settings = db.Column(db.Text, default='{"last_seen": "everyone", "profile_photo": "everyone", "status": "everyone"}')
    theme = db.Column(db.String(20), default='light')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    user = db.relationship('User', backref='profile', uselist=False)

class ChatMessage(db.Model):
    __tablename__ = 'chat_message'
    
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.String(100), nullable=False, index=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    message_type = db.Column(db.String(20), default='text')
    content = db.Column(db.Text, nullable=False)
    filename = db.Column(db.String(200))
    file_size = db.Column(db.Integer)
    file_url = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    read_at = db.Column(db.DateTime)
    delivered_at = db.Column(db.DateTime)
    is_edited = db.Column(db.Boolean, default=False)
    is_deleted = db.Column(db.Boolean, default=False)
    reply_to_id = db.Column(db.Integer, db.ForeignKey('chat_message.id'))
    sender = db.relationship('User', backref='messages')
    replies = db.relationship('ChatMessage', backref='parent', remote_side=[id])

class Friendship(db.Model):
    __tablename__ = 'friendship'
    
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    user2_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    __table_args__ = (db.UniqueConstraint('user1_id', 'user2_id', name='unique_friendship'),)

class FriendRequest(db.Model):
    __tablename__ = 'friend_request'
    
    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    to_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    status = db.Column(db.String(20), default='pending', index=True)  # pending, accepted, rejected, cancelled
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    from_user = db.relationship('User', foreign_keys=[from_user_id], backref='sent_requests')
    to_user = db.relationship('User', foreign_keys=[to_user_id], backref='received_requests')

class BlockedUser(db.Model):
    __tablename__ = 'blocked_user'
    
    id = db.Column(db.Integer, primary_key=True)
    blocker_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    blocked_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    reason = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    __table_args__ = (db.UniqueConstraint('blocker_id', 'blocked_id', name='unique_block'),)

# ========== HELPER FUNCTIONS ==========

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def save_uploaded_file(file, folder):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], folder)
        os.makedirs(upload_path, exist_ok=True)
        file.save(os.path.join(upload_path, unique_filename))
        
        # Get file size
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        return f"/static/uploads/{folder}/{unique_filename}", filename, file_size
    return None, None, None

def get_time_ago(dt):
    if not dt:
        return "Never"
    now = datetime.now(timezone.utc)
    diff = now - dt
    
    if diff.total_seconds() < 60:
        return "Just now"
    elif diff.total_seconds() < 3600:
        return f"{int(diff.total_seconds() / 60)}m ago"
    elif diff.total_seconds() < 86400:
        return f"{int(diff.total_seconds() / 3600)}h ago"
    elif diff.total_seconds() < 604800:
        return f"{int(diff.total_seconds() / 86400)}d ago"
    elif diff.total_seconds() < 2592000:
        return f"{int(diff.total_seconds() / 604800)}w ago"
    else:
        return dt.strftime("%b %d, %Y")

# ========== AUTHENTICATION ROUTES ==========

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/chat')
@login_required
def chat_page():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    
    if not user:
        session.clear()
        return redirect(url_for('index'))
    
    profile = UserProfile.query.filter_by(user_id=user_id).first()
    if not profile:
        profile = UserProfile(user_id=user_id)
        db.session.add(profile)
        db.session.commit()
    
    return render_template('chat.html', 
                          user=user,
                          profile=profile,
                          user_id=user.id,
                          username=user.username)

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    identifier = data.get('identifier', '').strip()
    password = data.get('password', '')
    
    if not identifier or not password:
        return jsonify({'success': False, 'error': 'Please provide credentials'}), 400
    
    # Find user by username, email, or phone
    user = User.query.filter(
        (User.username == identifier) |
        (User.email == identifier) |
        (User.phone == identifier)
    ).first()
    
    if user and user.check_password(password):
        session.permanent = True
        session['user_id'] = user.id
        session['username'] = user.username
        
        # Update last seen
        profile = UserProfile.query.filter_by(user_id=user.id).first()
        if profile:
            profile.last_seen = datetime.now(timezone.utc)
            db.session.commit()
        
        return jsonify({
            'success': True,
            'redirect': '/chat',
            'user': {'id': user.id, 'username': user.username}
        })
    
    return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

@app.route('/register_user', methods=['POST'])
def register_user():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    email = data.get('email', '').strip()
    phone = data.get('phone', '').strip()
    
    if not username or not password:
        return jsonify({'success': False, 'error': 'Username and password required'}), 400
    
    # Check if username exists
    if User.query.filter_by(username=username).first():
        return jsonify({'success': False, 'error': 'Username already exists'}), 400
    
    # Check if email exists
    if email and User.query.filter_by(email=email).first():
        return jsonify({'success': False, 'error': 'Email already registered'}), 400
    
    # Check if phone exists
    if phone and User.query.filter_by(phone=phone).first():
        return jsonify({'success': False, 'error': 'Phone number already registered'}), 400
    
    try:
        user = User(username=username, email=email if email else None, phone=phone if phone else None)
        user.set_password(password)
        db.session.add(user)
        db.session.flush()
        
        profile = UserProfile(user_id=user.id, status="Available")
        db.session.add(profile)
        db.session.commit()
        
        # Auto-login
        session.permanent = True
        session['user_id'] = user.id
        session['username'] = user.username
        
        return jsonify({
            'success': True,
            'redirect': '/chat',
            'user': {'id': user.id, 'username': user.username}
        })
    except Exception as e:
        db.session.rollback()
        print(f"Registration error: {e}")
        return jsonify({'success': False, 'error': 'Registration failed'}), 500

@app.route('/api/auth/logout', methods=['POST'])
@login_required
def logout():
    user_id = session.get('user_id')
    if user_id:
        profile = UserProfile.query.filter_by(user_id=user_id).first()
        if profile:
            profile.last_seen = datetime.now(timezone.utc)
            db.session.commit()
        
        # Notify others
        socketio.emit('user_offline', {
            'userId': user_id,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }, room='hpz_global')
    
    session.clear()
    return jsonify({'success': True})

# ========== 🔥 FIXED: TELEGRAM-STYLE USER SEARCH ==========

@app.route('/api/users/search', methods=['GET'])
@login_required
def search_users():
    """TELEGRAM STYLE - INSTANT SEARCH FOR ALL USERS"""
    current_user_id = session.get('user_id')
    query = request.args.get('q', '').strip()
    
    print(f"🔍 SEARCH: User {current_user_id} searching for '{query}'")
    
    # 🚨 CRITICAL FIX: Allow 1 character search (like Telegram)
    if not query or len(query) < 1:
        return jsonify({
            'success': True,
            'results': [],
            'count': 0,
            'query': query
        })
    
    try:
        # ========== GET ALL RELATIONSHIP DATA IN BULK ==========
        
        # 1. Get friends
        friendships = Friendship.query.filter(
            (Friendship.user1_id == current_user_id) | 
            (Friendship.user2_id == current_user_id)
        ).all()
        
        friend_ids = set()
        for f in friendships:
            friend_id = f.user2_id if f.user1_id == current_user_id else f.user1_id
            friend_ids.add(friend_id)
        
        # 2. Get pending friend requests (sent and received)
        sent_requests = FriendRequest.query.filter_by(
            from_user_id=current_user_id, 
            status='pending'
        ).all()
        sent_request_ids = {r.to_user_id for r in sent_requests}
        
        received_requests = FriendRequest.query.filter_by(
            to_user_id=current_user_id, 
            status='pending'
        ).all()
        received_request_ids = {r.from_user_id for r in received_requests}
        
        # 3. Get blocked users
        blocked = BlockedUser.query.filter_by(blocker_id=current_user_id).all()
        blocked_ids = {b.blocked_id for b in blocked}
        
        # 4. Users blocked by others (they won't see you)
        blocked_by = BlockedUser.query.filter_by(blocked_id=current_user_id).all()
        blocked_by_ids = {b.blocker_id for b in blocked_by}
        
        # ========== PERFORM SEARCH ==========
        
        # Create search pattern
        search_pattern = f'%{query}%'
        
        # Build search filters
        filters = [
            User.username.ilike(search_pattern),
            User.email.ilike(search_pattern)
        ]
        
        # Add phone search if phone column exists
        if User.phone is not None:
            filters.append(User.phone.ilike(search_pattern))
        
        # Search for users - EXCLUDE yourself only!
        users = User.query.filter(
            or_(*filters),
            User.id != current_user_id  # Only exclude yourself
        ).limit(30).all()  # Limit to 30 results for performance
        
        print(f"📊 Found {len(users)} users matching '{query}'")
        
        # ========== BUILD RESPONSE ==========
        results = []
        for user in users:
            profile = UserProfile.query.filter_by(user_id=user.id).first()
            
            # Check if this user should be visible to you
            if user.id in blocked_by_ids:
                # They blocked you - don't show them
                continue
            
            # Determine relationship status
            if user.id in friend_ids:
                relationship = 'friend'
                action_type = 'message'
                action_text = 'Message'
                action_icon = '💬'
            elif user.id in sent_request_ids:
                relationship = 'request_sent'
                action_type = 'pending'
                action_text = 'Pending'
                action_icon = '⏳'
            elif user.id in received_request_ids:
                relationship = 'request_received'
                action_type = 'accept'
                action_text = 'Accept'
                action_icon = '✅'
            else:
                relationship = 'none'
                action_type = 'add'
                action_text = 'Add Friend'
                action_icon = '➕'
            
            # Check online status
            is_online = False
            last_seen_text = "Offline"
            online_status = "offline"
            
            if profile and profile.last_seen:
                diff = datetime.now(timezone.utc) - profile.last_seen
                if diff.total_seconds() < 300:  # 5 minutes
                    is_online = True
                    last_seen_text = "Online"
                    online_status = "online"
                else:
                    last_seen_text = get_time_ago(profile.last_seen)
                    online_status = "offline"
            
            # Get avatar URL
            avatar_url = profile.avatar_url if profile and profile.avatar_url else None
            
            # Generate default avatar if none
            if not avatar_url:
                avatar_url = f"https://ui-avatars.com/api/?name={user.username}&background=5865F2&color=fff&size=100"
            
            # Get user status/bio
            status_text = profile.status if profile and profile.status else "Hey there! I'm using HPZ Messenger"
            
            results.append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'avatar': avatar_url,
                'avatar_url': avatar_url,  # Keep both for compatibility
                'status': status_text,
                'bio': profile.bio if profile else None,
                'is_online': is_online,
                'online_status': online_status,
                'last_seen': last_seen_text,
                'last_seen_raw': profile.last_seen.isoformat() if profile and profile.last_seen else None,
                'relationship': relationship,
                'relationship_status': relationship,  # Keep both for compatibility
                'action_type': action_type,
                'action_text': action_text,
                'action_icon': action_icon,
                'is_friend': relationship == 'friend',
                'has_pending_request': relationship in ['request_sent', 'request_received'],
                'is_blocked': user.id in blocked_ids
            })
        
        # Sort results: online first, then by username
        results.sort(key=lambda x: (not x['is_online'], x['username'].lower()))
        
        response = {
            'success': True,
            'query': query,
            'results': results,
            'count': len(results),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        print(f"✅ Returning {len(results)} results for '{query}'")
        return jsonify(response)
        
    except Exception as e:
        print(f"❌ SEARCH ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False, 
            'error': 'Search failed. Please try again.',
            'details': str(e) if app.debug else None
        }), 500

# ========== ENHANCED: GET USER BY ID ==========

@app.route('/api/users/<int:user_id>', methods=['GET'])
@login_required
def get_user_by_id(user_id):
    """Get user details by ID (for opening chats)"""
    current_user_id = session.get('user_id')
    
    if user_id == current_user_id:
        return jsonify({'success': False, 'error': 'Cannot view yourself'}), 400
    
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        profile = UserProfile.query.filter_by(user_id=user.id).first()
        
        # Check if blocked
        is_blocked = BlockedUser.query.filter_by(
            blocker_id=current_user_id, blocked_id=user_id
        ).first() is not None
        
        is_blocked_by = BlockedUser.query.filter_by(
            blocker_id=user_id, blocked_id=current_user_id
        ).first() is not None
        
        # Check friendship
        is_friend = Friendship.query.filter(
            ((Friendship.user1_id == current_user_id) & (Friendship.user2_id == user_id)) |
            ((Friendship.user1_id == user_id) & (Friendship.user2_id == current_user_id))
        ).first() is not None
        
        # Check pending requests
        sent_request = FriendRequest.query.filter_by(
            from_user_id=current_user_id, to_user_id=user_id, status='pending'
        ).first()
        
        received_request = FriendRequest.query.filter_by(
            from_user_id=user_id, to_user_id=current_user_id, status='pending'
        ).first()
        
        # Online status
        is_online = False
        last_seen_text = "Offline"
        if profile and profile.last_seen:
            diff = datetime.now(timezone.utc) - profile.last_seen
            is_online = diff.total_seconds() < 300
            last_seen_text = "Online" if is_online else get_time_ago(profile.last_seen)
        
        return jsonify({
            'success': True,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'avatar': profile.avatar_url if profile else None,
                'status': profile.status if profile else None,
                'bio': profile.bio if profile else None,
                'is_online': is_online,
                'last_seen': last_seen_text,
                'is_friend': is_friend,
                'is_blocked': is_blocked,
                'is_blocked_by': is_blocked_by,
                'has_pending_sent': sent_request is not None,
                'has_pending_received': received_request is not None
            }
        })
        
    except Exception as e:
        print(f"Error getting user: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ========== CHAT & MESSAGE ROUTES ==========

@app.route('/api/messages/<chat_id>', methods=['GET'])
@login_required
def get_messages(chat_id):
    """Get message history with pagination"""
    user_id = session.get('user_id')
    
    try:
        limit = request.args.get('limit', 50, type=int)
        before = request.args.get('before')
        
        query = ChatMessage.query.filter_by(chat_id=chat_id)
        
        if before:
            before_date = datetime.fromisoformat(before)
            query = query.filter(ChatMessage.created_at < before_date)
        
        messages = query.order_by(
            ChatMessage.created_at.desc()
        ).limit(limit).all()
        
        messages.reverse()
        
        result = []
        for msg in messages:
            sender = User.query.get(msg.sender_id)
            result.append({
                'id': msg.id,
                'chatId': msg.chat_id,
                'senderId': msg.sender_id,
                'sender': sender.username if sender else 'Unknown',
                'senderAvatar': UserProfile.query.filter_by(user_id=msg.sender_id).first().avatar_url if sender else None,
                'content': msg.content,
                'type': msg.message_type,
                'filename': msg.filename,
                'fileUrl': msg.file_url,
                'fileSize': msg.file_size,
                'timestamp': msg.created_at.isoformat(),
                'readAt': msg.read_at.isoformat() if msg.read_at else None,
                'deliveredAt': msg.delivered_at.isoformat() if msg.delivered_at else None,
                'isEdited': msg.is_edited,
                'isDeleted': msg.is_deleted,
                'replyToId': msg.reply_to_id
            })
        
        # Mark messages as delivered
        if chat_id != 'global':
            ChatMessage.query.filter_by(
                chat_id=chat_id
            ).filter(
                ChatMessage.sender_id != user_id,
                ChatMessage.delivered_at.is_(None)
            ).update({
                'delivered_at': datetime.now(timezone.utc)
            })
            db.session.commit()
        
        return jsonify({'success': True, 'messages': result})
    except Exception as e:
        print(f"Error getting messages: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ========== CONTACTS ==========

@app.route('/api/contacts', methods=['GET'])
@login_required
def get_contacts():
    """Get friends list with online status and last message"""
    user_id = session.get('user_id')
    
    try:
        friendships = Friendship.query.filter(
            (Friendship.user1_id == user_id) | (Friendship.user2_id == user_id)
        ).all()
        
        contacts = []
        for friendship in friendships:
            friend_id = friendship.user2_id if friendship.user1_id == user_id else friendship.user1_id
            friend = User.query.get(friend_id)
            
            if not friend:
                continue
                
            profile = UserProfile.query.filter_by(user_id=friend_id).first()
            
            # Get last message
            chat_id = f"{min(user_id, friend_id)}-{max(user_id, friend_id)}"
            last_message = ChatMessage.query.filter_by(chat_id=chat_id).order_by(
                ChatMessage.created_at.desc()
            ).first()
            
            # Get unread count
            unread_count = ChatMessage.query.filter_by(
                chat_id=chat_id
            ).filter(
                ChatMessage.sender_id == friend_id,
                ChatMessage.read_at.is_(None)
            ).count()
            
            # Online status
            is_online = False
            last_seen_text = "Offline"
            if profile and profile.last_seen:
                diff = datetime.now(timezone.utc) - profile.last_seen
                is_online = diff.total_seconds() < 300
                last_seen_text = "Online" if is_online else get_time_ago(profile.last_seen)
            
            contacts.append({
                'id': friend.id,
                'username': friend.username,
                'avatarUrl': profile.avatar_url if profile else None,
                'status': profile.status if profile else None,
                'lastSeen': last_seen_text,
                'isOnline': is_online,
                'lastMessage': {
                    'content': last_message.content if last_message else None,
                    'timestamp': last_message.created_at.isoformat() if last_message else None,
                    'senderId': last_message.sender_id if last_message else None
                } if last_message else None,
                'unreadCount': unread_count,
                'chatId': chat_id
            })
        
        # Sort by online status, then by last message time
        contacts.sort(key=lambda x: (
            not x['isOnline'],
            x['lastMessage']['timestamp'] if x['lastMessage'] else '0'
        ), reverse=True)
        
        return jsonify({'success': True, 'contacts': contacts})
    except Exception as e:
        print(f"Error getting contacts: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ========== FRIEND MANAGEMENT ==========

@app.route('/api/friends/request', methods=['POST'])
@login_required
def send_friend_request():
    """Send a friend request"""
    user_id = session['user_id']
    to_user_id = request.json.get('to_user_id')
    
    if not to_user_id or user_id == to_user_id:
        return jsonify({'success': False, 'error': 'Invalid user'}), 400
    
    # Check if user exists
    target_user = User.query.get(to_user_id)
    if not target_user:
        return jsonify({'success': False, 'error': 'User not found'}), 404
    
    # Check if already friends
    existing_friend = Friendship.query.filter(
        ((Friendship.user1_id == user_id) & (Friendship.user2_id == to_user_id)) |
        ((Friendship.user1_id == to_user_id) & (Friendship.user2_id == user_id))
    ).first()
    
    if existing_friend:
        return jsonify({'success': False, 'error': 'Already friends'}), 400
    
    # Check if request already exists
    existing_request = FriendRequest.query.filter(
        ((FriendRequest.from_user_id == user_id) & (FriendRequest.to_user_id == to_user_id)) |
        ((FriendRequest.from_user_id == to_user_id) & (FriendRequest.to_user_id == user_id)),
        FriendRequest.status == 'pending'
    ).first()
    
    if existing_request:
        if existing_request.from_user_id == user_id:
            return jsonify({'success': False, 'error': 'Request already sent'}), 400
        else:
            # Auto-accept if they already sent you a request
            existing_request.status = 'accepted'
            user1 = min(user_id, to_user_id)
            user2 = max(user_id, to_user_id)
            friendship = Friendship(user1_id=user1, user2_id=user2)
            db.session.add(friendship)
            db.session.commit()
            
            # Notify both users
            socketio.emit('friend_added', {
                'friend_id': to_user_id,
                'friend_username': target_user.username
            }, room=f'user_{user_id}')
            
            socketio.emit('friend_added', {
                'friend_id': user_id,
                'friend_username': session.get('username')
            }, room=f'user_{to_user_id}')
            
            return jsonify({'success': True, 'auto_accepted': True})
    
    # Create new request
    friend_req = FriendRequest(from_user_id=user_id, to_user_id=to_user_id)
    db.session.add(friend_req)
    db.session.commit()
    
    # Notify recipient
    socketio.emit('friend_request_received', {
        'request_id': friend_req.id,
        'from_user_id': user_id,
        'from_username': session.get('username')
    }, room=f'user_{to_user_id}')
    
    return jsonify({'success': True})

@app.route('/api/friends/pending', methods=['GET'])
@login_required
def get_pending_requests():
    """Get pending friend requests"""
    user_id = session['user_id']
    
    sent = FriendRequest.query.filter_by(
        from_user_id=user_id, 
        status='pending'
    ).order_by(FriendRequest.created_at.desc()).all()
    
    received = FriendRequest.query.filter_by(
        to_user_id=user_id, 
        status='pending'
    ).order_by(FriendRequest.created_at.desc()).all()
    
    sent_list = []
    for req in sent:
        user = User.query.get(req.to_user_id)
        if user:
            profile = UserProfile.query.filter_by(user_id=user.id).first()
            sent_list.append({
                'id': req.id,
                'user_id': user.id,
                'username': user.username,
                'avatar_url': profile.avatar_url if profile else None,
                'created_at': req.created_at.isoformat(),
                'time_ago': get_time_ago(req.created_at)
            })
    
    received_list = []
    for req in received:
        user = User.query.get(req.from_user_id)
        if user:
            profile = UserProfile.query.filter_by(user_id=user.id).first()
            received_list.append({
                'request_id': req.id,
                'user_id': user.id,
                'username': user.username,
                'avatar_url': profile.avatar_url if profile else None,
                'created_at': req.created_at.isoformat(),
                'time_ago': get_time_ago(req.created_at)
            })
    
    return jsonify({
        'success': True, 
        'sent': sent_list, 
        'received': received_list,
        'total': len(sent_list) + len(received_list)
    })

@app.route('/api/friends/accept', methods=['POST'])
@login_required
def accept_friend_request():
    """Accept a friend request"""
    user_id = session['user_id']
    request_id = request.json.get('request_id')
    
    friend_req = FriendRequest.query.filter_by(
        id=request_id, 
        to_user_id=user_id, 
        status='pending'
    ).first()
    
    if not friend_req:
        return jsonify({'success': False, 'error': 'Request not found'}), 404
    
    friend_req.status = 'accepted'
    friend_req.updated_at = datetime.now(timezone.utc)
    
    # Create friendship
    user1 = min(friend_req.from_user_id, user_id)
    user2 = max(friend_req.from_user_id, user_id)
    
    friendship = Friendship(user1_id=user1, user2_id=user2)
    db.session.add(friendship)
    db.session.commit()
    
    # Notify both users
    from_user = User.query.get(friend_req.from_user_id)
    to_user = User.query.get(user_id)
    
    socketio.emit('friend_request_accepted', {
        'friend_id': friend_req.from_user_id,
        'friend_username': from_user.username
    }, room=f'user_{user_id}')
    
    socketio.emit('friend_added', {
        'friend_id': user_id,
        'friend_username': to_user.username
    }, room=f'user_{friend_req.from_user_id}')
    
    return jsonify({'success': True})

@app.route('/api/friends/reject', methods=['POST'])
@login_required
def reject_friend_request():
    """Reject a friend request"""
    user_id = session['user_id']
    request_id = request.json.get('request_id')
    
    friend_req = FriendRequest.query.filter_by(
        id=request_id, 
        to_user_id=user_id, 
        status='pending'
    ).first()
    
    if not friend_req:
        return jsonify({'success': False, 'error': 'Request not found'}), 404
    
    friend_req.status = 'rejected'
    friend_req.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/api/friends/cancel', methods=['POST'])
@login_required
def cancel_friend_request():
    """Cancel a sent friend request"""
    user_id = session['user_id']
    request_id = request.json.get('request_id')
    
    friend_req = FriendRequest.query.filter_by(
        id=request_id, 
        from_user_id=user_id, 
        status='pending'
    ).first()
    
    if not friend_req:
        return jsonify({'success': False, 'error': 'Request not found'}), 404
    
    friend_req.status = 'cancelled'
    friend_req.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/api/friends/remove', methods=['POST'])
@login_required
def remove_friend():
    """Remove a friend"""
    user_id = session['user_id']
    friend_id = request.json.get('friend_id')
    
    if not friend_id:
        return jsonify({'success': False, 'error': 'Friend ID required'}), 400
    
    friendship = Friendship.query.filter(
        ((Friendship.user1_id == user_id) & (Friendship.user2_id == friend_id)) |
        ((Friendship.user1_id == friend_id) & (Friendship.user2_id == user_id))
    ).first()
    
    if not friendship:
        return jsonify({'success': False, 'error': 'Friendship not found'}), 404
    
    db.session.delete(friendship)
    db.session.commit()
    
    return jsonify({'success': True})

# ========== PROFILE ROUTES ==========

@app.route('/api/profile', methods=['GET'])
@login_required
def get_profile():
    """Get current user's profile"""
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    profile = UserProfile.query.filter_by(user_id=user_id).first()
    
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 404
    
    if not profile:
        profile = UserProfile(user_id=user_id)
        db.session.add(profile)
        db.session.commit()
    
    return jsonify({
        'success': True,
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'phone': user.phone,
            'bio': profile.bio,
            'avatarUrl': profile.avatar_url,
            'status': profile.status,
            'theme': profile.theme,
            'lastSeen': profile.last_seen.isoformat() if profile.last_seen else None,
            'privacySettings': json.loads(profile.privacy_settings) if profile.privacy_settings else {}
        }
    })

@app.route('/api/profile', methods=['PUT'])
@login_required
def update_profile():
    """Update user profile"""
    user_id = session.get('user_id')
    data = request.json
    
    user = User.query.get(user_id)
    profile = UserProfile.query.filter_by(user_id=user_id).first()
    
    if not profile:
        profile = UserProfile(user_id=user_id)
        db.session.add(profile)
    
    if 'username' in data and data['username'] != user.username:
        # Check if username is taken
        existing = User.query.filter_by(username=data['username']).first()
        if existing and existing.id != user_id:
            return jsonify({'success': False, 'error': 'Username already taken'}), 400
        user.username = data['username']
        session['username'] = data['username']
    
    if 'email' in data and data['email'] != user.email:
        if data['email']:
            existing = User.query.filter_by(email=data['email']).first()
            if existing and existing.id != user_id:
                return jsonify({'success': False, 'error': 'Email already registered'}), 400
        user.email = data['email'] if data['email'] else None
    
    if 'phone' in data and data['phone'] != user.phone:
        if data['phone']:
            existing = User.query.filter_by(phone=data['phone']).first()
            if existing and existing.id != user_id:
                return jsonify({'success': False, 'error': 'Phone already registered'}), 400
        user.phone = data['phone'] if data['phone'] else None
    
    if 'bio' in data:
        profile.bio = data['bio']
    
    if 'status' in data:
        profile.status = data['status']
    
    if 'theme' in data:
        profile.theme = data['theme']
    
    if 'privacy' in data:
        profile.privacy_settings = json.dumps(data['privacy'])
    
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/api/upload-avatar', methods=['POST'])
@login_required
def upload_avatar():
    """Upload profile avatar"""
    user_id = session.get('user_id')
    
    if 'avatar' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'}), 400
    
    file = request.files['avatar']
    url, filename, size = save_uploaded_file(file, 'avatars')
    
    if not url:
        return jsonify({'success': False, 'error': 'Invalid file type'}), 400
    
    profile = UserProfile.query.filter_by(user_id=user_id).first()
    if not profile:
        profile = UserProfile(user_id=user_id)
        db.session.add(profile)
    
    profile.avatar_url = url
    db.session.commit()
    
    return jsonify({'success': True, 'url': url})

# ========== FILE UPLOAD ==========

@app.route('/api/upload-file', methods=['POST'])
@login_required
def upload_file():
    """Handle file uploads"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file'}), 400
    
    file = request.files['file']
    if not file.filename:
        return jsonify({'success': False, 'error': 'No file selected'}), 400
    
    ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
    
    if ext in ['png', 'jpg', 'jpeg', 'gif', 'webp']:
        folder = 'images'
        file_type = 'image'
    elif ext in ['mp4', 'mov', 'avi', 'webm']:
        folder = 'videos'
        file_type = 'video'
    elif ext in ['mp3', 'wav', 'ogg', 'm4a']:
        folder = 'audio'
        file_type = 'audio'
    else:
        folder = 'files'
        file_type = 'file'
    
    url, filename, size = save_uploaded_file(file, folder)
    
    if url:
        return jsonify({
            'success': True, 
            'url': url, 
            'filename': filename,
            'size': size,
            'type': file_type
        })
    
    return jsonify({'success': False, 'error': 'Upload failed'}), 500

# ========== SOCKETIO EVENTS ==========

active_users = {}
user_sockets = {}  # Map user_id -> list of socket ids

@socketio.on('connect')
def handle_connect():
    user_id = session.get('user_id')
    username = session.get('username')
    
    if user_id and username:
        socket_id = request.sid
        
        # Store in active users
        active_users[socket_id] = {
            'user_id': user_id,
            'username': username,
            'connected_at': datetime.now(timezone.utc).isoformat()
        }
        
        # Track user's sockets
        if user_id not in user_sockets:
            user_sockets[user_id] = []
        if socket_id not in user_sockets[user_id]:
            user_sockets[user_id].append(socket_id)
        
        # Join rooms
        join_room('hpz_global')
        join_room(f'user_{user_id}')
        
        # Update last seen
        profile = UserProfile.query.filter_by(user_id=user_id).first()
        if profile:
            profile.last_seen = datetime.now(timezone.utc)
            db.session.commit()
        
        # Notify others
        emit('user_online', {
            'userId': user_id,
            'username': username,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }, room='hpz_global', include_self=False, broadcast=True)
        
        print(f"✅ Connected: {username} (ID: {user_id}, SID: {socket_id})")

@socketio.on('disconnect')
def handle_disconnect():
    socket_id = request.sid
    
    if socket_id in active_users:
        user_data = active_users[socket_id]
        user_id = user_data['user_id']
        username = user_data['username']
        
        # Remove from user_sockets
        if user_id in user_sockets:
            if socket_id in user_sockets[user_id]:
                user_sockets[user_id].remove(socket_id)
            if not user_sockets[user_id]:
                del user_sockets[user_id]
        
        # Only update last_seen and notify if this was their last connection
        if user_id not in user_sockets or not user_sockets.get(user_id):
            profile = UserProfile.query.filter_by(user_id=user_id).first()
            if profile:
                profile.last_seen = datetime.now(timezone.utc)
                db.session.commit()
            
            emit('user_offline', {
                'userId': user_id,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }, room='hpz_global', broadcast=True)
            
            print(f"❌ Disconnected (last connection): {username}")
        else:
            print(f"🔌 Disconnected (other connections remain): {username}")
        
        # Remove from active_users
        del active_users[socket_id]

@socketio.on('join')
def handle_join(data):
    chat_id = data.get('chatId', 'global')
    user_id = session.get('user_id')
    username = session.get('username')
    
    if chat_id != 'global':
        room = f'chat_{chat_id}'
        join_room(room)
        print(f"👥 {username} joined room: {room}")

@socketio.on('leave')
def handle_leave(data):
    chat_id = data.get('chatId', 'global')
    user_id = session.get('user_id')
    username = session.get('username')
    
    if chat_id != 'global':
        room = f'chat_{chat_id}'
        leave_room(room)
        print(f"👋 {username} left room: {room}")

@socketio.on('send_msg')
def handle_send_message(data):
    user_id = session.get('user_id')
    username = session.get('username')
    
    if not user_id or not username:
        return
    
    try:
        chat_id = data.get('chatId', 'global')
        message_type = data.get('type', 'text')
        content = data.get('content', '')
        filename = data.get('filename')
        file_url = data.get('fileUrl')
        file_size = data.get('fileSize')
        reply_to_id = data.get('replyToId')
        
        # Save to database
        message = ChatMessage(
            chat_id=chat_id,
            sender_id=user_id,
            message_type=message_type,
            content=content,
            filename=filename,
            file_url=file_url,
            file_size=file_size,
            reply_to_id=reply_to_id
        )
        db.session.add(message)
        db.session.commit()
        
        # Prepare message data
        message_data = {
            'id': message.id,
            'chatId': chat_id,
            'senderId': user_id,
            'sender': username,
            'senderAvatar': UserProfile.query.filter_by(user_id=user_id).first().avatar_url,
            'content': content,
            'type': message_type,
            'filename': filename,
            'fileUrl': file_url,
            'fileSize': file_size,
            'timestamp': message.created_at.isoformat(),
            'replyToId': reply_to_id
        }
        
        # Broadcast to appropriate room
        if chat_id == 'global':
            emit('receive_msg', message_data, room='hpz_global', broadcast=True)
        else:
            # Send to chat room and to both users' personal rooms
            emit('receive_msg', message_data, room=f'chat_{chat_id}', broadcast=True)
            
            # Also send to personal rooms for notifications
            if '-' in chat_id:
                # This is a 1-on-1 chat
                user_ids = chat_id.split('-')
                for uid in user_ids:
                    if int(uid) != user_id:
                        emit('receive_msg', message_data, room=f'user_{uid}')
            
            # Mark as delivered
            if chat_id != 'global':
                message.delivered_at = datetime.now(timezone.utc)
                db.session.commit()
        
        print(f"📨 Message sent by {username} in {chat_id}")
        
    except Exception as e:
        print(f"❌ Error sending message: {e}")
        import traceback
        traceback.print_exc()
        emit('error', {'message': 'Failed to send message'}, room=f'user_{user_id}')

@socketio.on('mark_read')
def handle_mark_read(data):
    """Mark messages as read"""
    user_id = session.get('user_id')
    chat_id = data.get('chatId')
    message_ids = data.get('messageIds', [])
    
    if not chat_id or not user_id:
        return
    
    try:
        # Mark specific messages as read
        if message_ids:
            ChatMessage.query.filter(
                ChatMessage.id.in_(message_ids),
                ChatMessage.chat_id == chat_id,
                ChatMessage.sender_id != user_id
            ).update({
                'read_at': datetime.now(timezone.utc)
            })
        else:
            # Mark all messages in chat as read
            ChatMessage.query.filter_by(
                chat_id=chat_id
            ).filter(
                ChatMessage.sender_id != user_id,
                ChatMessage.read_at.is_(None)
            ).update({
                'read_at': datetime.now(timezone.utc)
            })
        
        db.session.commit()
        
        # Notify sender that messages were read
        emit('messages_read', {
            'chatId': chat_id,
            'readerId': user_id,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }, room=f'chat_{chat_id}', broadcast=True)
        
    except Exception as e:
        print(f"Error marking read: {e}")

@socketio.on('typing_start')
def handle_typing_start(data):
    username = session.get('username')
    chat_id = data.get('chatId', 'global')
    
    typing_data = {
        'username': username, 
        'chatId': chat_id,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }
    
    if chat_id == 'global':
        emit('typing_start', typing_data, room='hpz_global', include_self=False, broadcast=True)
    else:
        emit('typing_start', typing_data, room=f'chat_{chat_id}', include_self=False, broadcast=True)

@socketio.on('typing_stop')
def handle_typing_stop(data):
    username = session.get('username')
    chat_id = data.get('chatId', 'global')
    
    typing_data = {
        'username': username, 
        'chatId': chat_id,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }
    
    if chat_id == 'global':
        emit('typing_stop', typing_data, room='hpz_global', include_self=False, broadcast=True)
    else:
        emit('typing_stop', typing_data, room=f'chat_{chat_id}', include_self=False, broadcast=True)

# ========== INITIALIZATION ==========

def create_folders():
    folders = ['images', 'videos', 'audio', 'files', 'avatars']
    for folder in folders:
        folder_path = os.path.join(basedir, 'static', 'uploads', folder)
        os.makedirs(folder_path, exist_ok=True)
        print(f"📁 Created folder: {folder_path}")

def init_database():
    with app.app_context():
        try:
            db.create_all()
            print("✅ Database tables created")
            
            # Create indexes for performance
            print("📊 Creating indexes...")
            
            # Check if test users exist
            if not User.query.first():
                print("👤 Creating test users...")
                
                test_users = [
                    {'username': 'admin', 'email': 'admin@hpz.com', 'password': 'admin123', 'status': 'Admin'},
                    {'username': 'alice', 'email': 'alice@example.com', 'password': 'password123', 'status': '🌸 Busy coding'},
                    {'username': 'bob', 'email': 'bob@example.com', 'password': 'password123', 'status': '🎮 Gaming'},
                    {'username': 'charlie', 'email': 'charlie@example.com', 'password': 'password123', 'status': '📚 Reading'},
                    {'username': 'diana', 'email': 'diana@example.com', 'password': 'password123', 'status': '🎵 Music lover'},
                    {'username': 'eve', 'email': 'eve@example.com', 'password': 'password123', 'status': '✈️ Traveler'}
                ]
                
                for u in test_users:
                    user = User(username=u['username'], email=u['email'])
                    user.set_password(u['password'])
                    db.session.add(user)
                    db.session.flush()
                    profile = UserProfile(user_id=user.id, status=u['status'])
                    db.session.add(profile)
                
                db.session.commit()
                print("✅ Test users created:")
                for u in test_users:
                    print(f"   • {u['username']} / {u['password']}")
            else:
                print(f"👥 Found {User.query.count()} existing users")
                
        except Exception as e:
            print(f"❌ Database initialization error: {e}")
            db.session.rollback()

# ========== DEBUG ROUTES ==========

@app.route('/debug/users', methods=['GET'])
def debug_users():
    """Debug route to see all users"""
    users = User.query.all()
    user_list = []
    for user in users:
        profile = UserProfile.query.filter_by(user_id=user.id).first()
        user_list.append({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'has_profile': profile is not None,
            'last_seen': profile.last_seen.isoformat() if profile and profile.last_seen else None
        })
    
    return jsonify({
        'success': True,
        'total_users': len(users),
        'users': user_list,
        'session': dict(session) if session else None
    })

@app.route('/debug/search/<query>', methods=['GET'])
def debug_search(query):
    """Debug route to test search"""
    with app.app_context():
        users = User.query.filter(
            User.username.ilike(f'%{query}%')
        ).all()
        
        return jsonify({
            'query': query,
            'count': len(users),
            'users': [{'id': u.id, 'username': u.username} for u in users]
        })

# ========== MAIN ==========

if __name__ == '__main__':
    create_folders()
    init_database()
    
 
    
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)