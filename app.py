import os
import jwt
import bcrypt
# Remove redis import

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_socketio import SocketIO, emit, join_room, leave_room
from datetime import datetime, timedelta
import sqlite3
import logging
from logging.handlers import RotatingFileHandler
import secrets
import re
from functools import wraps
import html
import bleach
from urllib.parse import urlparse
import hashlib
import json

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Initialize extensions
CORS(app, origins=["*"])  # Allow all origins for now
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Security configuration
csp = {
    'default-src': ["'self'", 'https://cdn.jsdelivr.net'],
    'style-src': ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net'],
    'script-src': ["'self'", 'https://cdn.jsdelivr.net'],
    'font-src': ["'self'", 'https://cdn.jsdelivr.net'],
    'img-src': ["'self'", 'data:', 'https:'],
    'connect-src': ["'self'", 'ws:', 'wss:']
}

Talisman(app, content_security_policy=csp, force_https=False)

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per minute", "50 per second"],
    storage_uri="memory://"
)

# Simple in-memory cache (replaces Redis)
class SimpleCache:
    def __init__(self):
        self._cache = {}
    
    def get(self, key):
        return self._cache.get(key)
    
    def setex(self, key, expiry, value):
        self._cache[key] = value
        # Note: For production, you'd want proper expiration logic

cache = SimpleCache()

# Configuration
class Config:
    DB_NAME = os.environ.get('DB_NAME', 'edgepowered_forum.db')
    JWT_EXPIRY_HOURS = 24
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    BCRYPT_ROUNDS = 12
    MIN_PASSWORD_LENGTH = 8
    MAX_USERNAME_LENGTH = 20
    MAX_POST_LENGTH = 10000
    MAX_COMMENT_LENGTH = 2000

app.config.from_object(Config)

# Enhanced logging
if not os.path.exists('logs'):
    os.makedirs('logs')

file_handler = RotatingFileHandler(
    'logs/edgepowered.log', 
    maxBytes=10240, 
    backupCount=10,
    encoding='utf-8'
)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)

# Database connection with connection pool
class DatabaseConnection:
    def __init__(self):
        self.pool = []
        self._init_pool()
    
    def _init_pool(self):
        for _ in range(5):
            conn = sqlite3.connect(Config.DB_NAME)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA cache_size=-64000")
            self.pool.append(conn)
    
    def get_connection(self):
        if not self.pool:
            self._init_pool()
        return self.pool.pop()
    
    def return_connection(self, conn):
        self.pool.append(conn)

db_pool = DatabaseConnection()

def get_db():
    return db_pool.get_connection()

def return_db(conn):
    db_pool.return_connection(conn)

# Security and Validation Classes
class ValidationError(Exception):
    pass

class SecurityUtils:
    @staticmethod
    def validate_username(username):
        if len(username) < 3:
            raise ValidationError("Username must be at least 3 characters")
        if len(username) > Config.MAX_USERNAME_LENGTH:
            raise ValidationError(f"Username must be less than {Config.MAX_USERNAME_LENGTH} characters")
        if not re.match(r'^[a-zA-Z0-9_\-]+$', username):
            raise ValidationError("Username can only contain letters, numbers, underscores, and hyphens")
        return username.lower().strip()
    
    @staticmethod
    def validate_password(password):
        if len(password) < Config.MIN_PASSWORD_LENGTH:
            raise ValidationError(f"Password must be at least {Config.MIN_PASSWORD_LENGTH} characters")
        
        checks = {
            'uppercase': bool(re.search(r'[A-Z]', password)),
            'lowercase': bool(re.search(r'[a-z]', password)),
            'digit': bool(re.search(r'\d', password)),
            'special': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        }
        
        if sum(checks.values()) < 3:
            raise ValidationError("Password must contain at least 3 of: uppercase, lowercase, digits, special characters")
        
        return password
    
    @staticmethod
    def sanitize_html(content, max_length=None):
        if not content:
            return content
        
        allowed_tags = bleach.sanitizer.ALLOWED_TAGS + [
            'p', 'br', 'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
            'ul', 'ol', 'li', 'strong', 'em', 'u', 'strike', 'blockquote',
            'code', 'pre', 'hr'
        ]
        
        allowed_attributes = {
            '*': ['class', 'style'],
            'a': ['href', 'title', 'target', 'rel'],
            'img': ['src', 'alt', 'width', 'height']
        }
        
        cleaned = bleach.clean(
            content,
            tags=allowed_tags,
            attributes=allowed_attributes,
            strip=True,
            strip_comments=True
        )
        
        cleaned = re.sub(r'javascript:', '', cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r'vbscript:', '', cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r'on\w+=', '', cleaned, flags=re.IGNORECASE)
        
        if max_length and len(cleaned) > max_length:
            cleaned = cleaned[:max_length]
        
        return cleaned.strip()
    
    @staticmethod
    def hash_password(password):
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(Config.BCRYPT_ROUNDS))
    
    @staticmethod
    def check_password(password, hashed):
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed)
        except Exception:
            return False

# Authentication Decorators
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        
        if not token:
            return jsonify({"success": False, "error": "Authentication token required"}), 401
        
        try:
            if not token.startswith('Bearer '):
                return jsonify({"success": False, "error": "Invalid token format"}), 401
            
            token = token[7:]
            decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            
            # Check cache first
            user_data = cache.get(f"user:{decoded['user_id']}")
            if user_data:
                user = json.loads(user_data)
            else:
                conn = get_db()
                c = conn.cursor()
                c.execute("SELECT id, username, avatar_color, is_active, is_moderator, is_admin FROM users WHERE id = ?", (decoded["user_id"],))
                user = c.fetchone()
                return_db(conn)
                
                if user:
                    user = dict(user)
                    cache.setex(f"user:{user['id']}", 3600, json.dumps(user))
            
            if not user or not user["is_active"]:
                return jsonify({"success": False, "error": "Invalid user"}), 401
            
            request.user_id = user["id"]
            request.username = user["username"]
            request.user_data = user
            
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"success": False, "error": "Invalid token"}), 401
        except Exception as e:
            app.logger.error(f"Token validation error: {e}")
            return jsonify({"success": False, "error": "Token validation failed"}), 401
        
        return f(*args, **kwargs)
    return decorated

def validate_json(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not request.is_json:
            return jsonify({"success": False, "error": "Content-Type must be application/json"}), 400
        
        data = request.get_json(silent=True)
        if data is None:
            return jsonify({"success": False, "error": "Invalid JSON data"}), 400
        
        request.json_data = data
        return f(*args, **kwargs)
    return decorated

# Database Initialization
def init_db():
    conn = get_db()
    try:
        c = conn.cursor()
        
        c.executescript("""
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                password TEXT NOT NULL,
                email TEXT UNIQUE,
                avatar_color TEXT DEFAULT '#007AFF',
                bio TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login DATETIME,
                is_active BOOLEAN DEFAULT 1,
                reputation INTEGER DEFAULT 0,
                post_count INTEGER DEFAULT 0,
                comment_count INTEGER DEFAULT 0,
                like_count INTEGER DEFAULT 0,
                is_moderator BOOLEAN DEFAULT 0,
                is_admin BOOLEAN DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS posts(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                category TEXT NOT NULL,
                title TEXT,
                content TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
                likes_count INTEGER DEFAULT 0,
                comments_count INTEGER DEFAULT 0,
                is_pinned BOOLEAN DEFAULT 0,
                is_locked BOOLEAN DEFAULT 0,
                is_deleted BOOLEAN DEFAULT 0,
                edited_at DATETIME,
                view_count INTEGER DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS comments(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                likes_count INTEGER DEFAULT 0,
                parent_comment_id INTEGER,
                is_deleted BOOLEAN DEFAULT 0,
                FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(parent_comment_id) REFERENCES comments(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS likes(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                post_id INTEGER,
                comment_id INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, post_id, comment_id),
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
                FOREIGN KEY(comment_id) REFERENCES comments(id) ON DELETE CASCADE,
                CHECK((post_id IS NOT NULL AND comment_id IS NULL) OR (post_id IS NULL AND comment_id IS NOT NULL))
            );

            CREATE TABLE IF NOT EXISTS bookmarks(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                post_id INTEGER NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, post_id),
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS reports(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reporter_id INTEGER NOT NULL,
                post_id INTEGER,
                comment_id INTEGER,
                reason TEXT NOT NULL,
                description TEXT,
                status TEXT DEFAULT 'pending',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                resolved_at DATETIME,
                resolved_by INTEGER,
                FOREIGN KEY(reporter_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
                FOREIGN KEY(comment_id) REFERENCES comments(id) ON DELETE CASCADE,
                FOREIGN KEY(resolved_by) REFERENCES users(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS notifications(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                type TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                is_read BOOLEAN DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)

        # Create indexes
        c.executescript("""
            CREATE INDEX IF NOT EXISTS idx_posts_timestamp ON posts(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_posts_category ON posts(category);
            CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id);
            CREATE INDEX IF NOT EXISTS idx_likes_user ON likes(user_id);
            CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, created_at DESC);
        """)

        # Insert default admin user if not exists
        c.execute("SELECT id FROM users WHERE username = 'admin'")
        if not c.fetchone():
            hashed_pw = SecurityUtils.hash_password("admin123")
            c.execute("INSERT INTO users (username, password, is_admin, is_moderator) VALUES (?, ?, 1, 1)", 
                     ("admin", hashed_pw))

        conn.commit()
        app.logger.info("Database initialized successfully")
        
    except Exception as e:
        app.logger.error(f"Database initialization error: {e}")
        raise
    finally:
        return_db(conn)

# Initialize database
init_db()

# Utility Functions
def format_timestamp(timestamp):
    if not timestamp:
        return "Recently"
    
    try:
        post_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        now = datetime.now()
        diff = now - post_time
        
        if diff.days > 365:
            years = diff.days // 365
            return f"{years}y ago"
        elif diff.days > 30:
            months = diff.days // 30
            return f"{months}mo ago"
        elif diff.days > 0:
            return f"{diff.days}d ago"
        elif diff.seconds > 3600:
            return f"{diff.seconds // 3600}h ago"
        elif diff.seconds > 60:
            return f"{diff.seconds // 60}m ago"
        else:
            return "Just now"
    except:
        return timestamp

def create_notification(user_id, type, title, message):
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("INSERT INTO notifications (user_id, type, title, message) VALUES (?, ?, ?, ?)",
                 (user_id, type, title, message))
        conn.commit()
        
        # Emit real-time notification
        socketio.emit('new_notification', {
            'user_id': user_id,
            'notification': {
                'type': type,
                'title': title,
                'message': message,
                'timestamp': datetime.now().isoformat()
            }
        }, room=f'user_{user_id}')
        
    except Exception as e:
        app.logger.error(f"Notification creation error: {e}")
    finally:
        return_db(conn)

def update_post_activity(post_id):
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("UPDATE posts SET last_activity = CURRENT_TIMESTAMP WHERE id = ?", (post_id,))
        conn.commit()
    except Exception as e:
        app.logger.error(f"Post activity update error: {e}")
    finally:
        return_db(conn)

# SocketIO Events
@socketio.on('connect')
def handle_connect():
    app.logger.info(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    app.logger.info(f"Client disconnected: {request.sid}")

@socketio.on('join_user_room')
def handle_join_user_room(data):
    user_id = data.get('user_id')
    if user_id:
        join_room(f'user_{user_id}')
        app.logger.info(f"User {user_id} joined their room")

@socketio.on('leave_user_room')
def handle_leave_user_room(data):
    user_id = data.get('user_id')
    if user_id:
        leave_room(f'user_{user_id}')

# API Routes
@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/api/health')
def health_check():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "2.0.0"
    })

@app.route('/api/stats')
def get_stats():
    conn = get_db()
    try:
        c = conn.cursor()
        
        c.execute("SELECT COUNT(*) FROM users WHERE is_active = 1")
        user_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM posts WHERE is_deleted = 0")
        post_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM comments WHERE is_deleted = 0")
        comment_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM likes")
        like_count = c.fetchone()[0]
        
        return jsonify({
            "success": True,
            "stats": {
                "users": {"total": user_count},
                "posts": {
                    "total": post_count,
                    "total_comments": comment_count,
                    "total_likes": like_count
                }
            }
        })
        
    except Exception as e:
        app.logger.error(f"Stats error: {e}")
        return jsonify({"success": False, "error": "Failed to get stats"}), 500
    finally:
        return_db(conn)

@app.route('/api/register', methods=['POST'])
@limiter.limit("5 per hour")
@validate_json
def register():
    data = request.json_data
    
    try:
        username = SecurityUtils.validate_username(data.get("username", ""))
        password = SecurityUtils.validate_password(data.get("password", ""))
        email = data.get("email")
        
        conn = get_db()
        c = conn.cursor()
        
        c.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
        if c.fetchone():
            raise ValidationError("Username or email already exists")
        
        hashed_pw = SecurityUtils.hash_password(password)
        avatar_color = f"#{secrets.token_hex(3)}"  # Generate random color
        
        c.execute("INSERT INTO users (username, password, email, avatar_color) VALUES (?, ?, ?, ?)",
                 (username, hashed_pw, email, avatar_color))
        
        user_id = c.lastrowid
        conn.commit()
        
        app.logger.info(f"New user registered: {username}")
        
        return jsonify({
            "success": True, 
            "message": "Account created successfully",
            "user_id": user_id
        })
    
    except ValidationError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        app.logger.error(f"Registration error: {e}")
        return jsonify({"success": False, "error": "Registration failed"}), 500
    finally:
        return_db(conn)

@app.route('/api/login', methods=['POST'])
@limiter.limit("10 per 15 minutes")
@validate_json
def login():
    data = request.json_data
    
    try:
        username = data.get("username", "").strip().lower()
        password = data.get("password", "")
        
        if not username or not password:
            raise ValidationError("Username and password required")
        
        conn = get_db()
        c = conn.cursor()
        
        c.execute("""
            SELECT id, password, username, avatar_color, is_active, is_moderator, is_admin 
            FROM users WHERE username = ? OR email = ?
        """, (username, username))
        
        user = c.fetchone()
        
        if not user or not SecurityUtils.check_password(password, user["password"]):
            raise ValidationError("Invalid credentials")
        
        if not user["is_active"]:
            raise ValidationError("Account deactivated")
        
        # Update last login
        c.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user["id"],))
        
        # Generate JWT token
        token = jwt.encode({
            "user_id": user["id"],
            "username": user["username"],
            "exp": datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        conn.commit()
        
        # Cache user data
        user_data = {
            'id': user['id'],
            'username': user['username'],
            'avatar_color': user['avatar_color'],
            'is_moderator': bool(user['is_moderator']),
            'is_admin': bool(user['is_admin'])
        }
        cache.setex(f"user:{user['id']}", 3600, json.dumps(user_data))
        
        return jsonify({
            "success": True, 
            "token": token,
            "user": user_data
        })
        
    except ValidationError as e:
        return jsonify({"success": False, "error": str(e)}), 401
    except Exception as e:
        app.logger.error(f"Login error: {e}")
        return jsonify({"success": False, "error": "Login failed"}), 500
    finally:
        return_db(conn)

# ... (keep all the other routes the same as before)

# Error handlers
@app.errorhandler(404)
def not_found(e):
    return jsonify({"success": False, "error": "Endpoint not found"}), 404

@app.errorhandler(500)
def server_error(e):
    app.logger.error(f"500 error: {str(e)}")
    return jsonify({"success": False, "error": "Internal server error"}), 500

if __name__ == '__main__':
    socketio.run(
        app,
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5000)),
        debug=os.environ.get('DEBUG', 'False').lower() == 'true'
    )