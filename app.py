import os
import jwt
import bcrypt
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
import bleach
import json

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Initialize extensions
CORS(app, origins=["*"])
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

# Simple in-memory cache
class SimpleCache:
    def __init__(self):
        self._cache = {}
    
    def get(self, key):
        return self._cache.get(key)
    
    def setex(self, key, expiry, value):
        self._cache[key] = value

cache = SimpleCache()

# Configuration
class Config:
    DB_NAME = os.environ.get('DB_NAME', 'edgepowered_forum.db')
    JWT_EXPIRY_HOURS = 24
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
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

# Database connection
def get_db():
    conn = sqlite3.connect(Config.DB_NAME)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

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
                conn.close()
                
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
        
        # Drop all tables to start fresh
        c.executescript("""
            DROP TABLE IF EXISTS notifications;
            DROP TABLE IF EXISTS reports;
            DROP TABLE IF EXISTS bookmarks;
            DROP TABLE IF EXISTS likes;
            DROP TABLE IF EXISTS comments;
            DROP TABLE IF EXISTS posts;
            DROP TABLE IF EXISTS users;
        """)
        
        # Recreate all tables with updated schema
        c.executescript("""
            CREATE TABLE users(
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

            CREATE TABLE posts(
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

            CREATE TABLE comments(
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

            CREATE TABLE likes(
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

            CREATE TABLE bookmarks(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                post_id INTEGER NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, post_id),
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE
            );

            CREATE TABLE reports(
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

            CREATE TABLE notifications(
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

        # Insert default admin user
        hashed_pw = SecurityUtils.hash_password("admin123")
        c.execute("INSERT INTO users (username, password, is_admin, is_moderator) VALUES (?, ?, 1, 1)", 
                 ("admin", hashed_pw))

        conn.commit()
        app.logger.info("Database initialized successfully")
        
    except Exception as e:
        app.logger.error(f"Database initialization error: {e}")
        raise
    finally:
        conn.close()

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
        conn.close()

def update_post_activity(post_id):
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("UPDATE posts SET last_activity = CURRENT_TIMESTAMP WHERE id = ?", (post_id,))
        conn.commit()
    except Exception as e:
        app.logger.error(f"Post activity update error: {e}")
    finally:
        conn.close()

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
        conn.close()

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
        avatar_color = f"#{secrets.token_hex(3)}"
        
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
        conn.close()

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
        conn.close()

@app.route('/api/posts', methods=['GET', 'POST'])
@token_required
def posts():
    if request.method == 'POST':
        return create_post()
    else:
        return get_posts()

def create_post():
    data = request.json_data
    
    try:
        category = SecurityUtils.sanitize_html(data.get("category", "General"), 50)
        content = SecurityUtils.sanitize_html(data.get("content", ""), Config.MAX_POST_LENGTH)
        title = SecurityUtils.sanitize_html(data.get("title", ""), 200)
        
        if len(content.strip()) < 10:
            raise ValidationError("Content must be at least 10 characters")
        
        conn = get_db()
        c = conn.cursor()
        
        c.execute("INSERT INTO posts (user_id, category, title, content) VALUES (?, ?, ?, ?)",
                 (request.user_id, category, title, content))
        
        post_id = c.lastrowid
        
        # Update user post count
        c.execute("UPDATE users SET post_count = post_count + 1 WHERE id = ?", (request.user_id,))
        
        conn.commit()
        
        # Emit real-time update
        socketio.emit('new_post', {
            'post_id': post_id,
            'category': category,
            'username': request.username
        })
        
        return jsonify({
            "success": True, 
            "message": "Post created successfully", 
            "post_id": post_id
        })
        
    except ValidationError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        app.logger.error(f"Post creation error: {e}")
        return jsonify({"success": False, "error": "Failed to create post"}), 500
    finally:
        conn.close()

def get_posts():
    conn = get_db()
    try:
        c = conn.cursor()
        
        page = max(1, request.args.get('page', 1, type=int))
        per_page = min(max(1, request.args.get('per_page', 10, type=int)), 50)
        category = request.args.get('category', '')
        search = request.args.get('search', '')
        sort = request.args.get('sort', 'newest')
        
        offset = (page - 1) * per_page
        
        query = """
            SELECT p.*, u.username, u.avatar_color,
                   (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id AND c.is_deleted = 0) as real_comments_count
            FROM posts p 
            JOIN users u ON p.user_id = u.id 
            WHERE p.is_deleted = 0 AND u.is_active = 1
        """
        
        count_query = "SELECT COUNT(*) FROM posts p JOIN users u ON p.user_id = u.id WHERE p.is_deleted = 0 AND u.is_active = 1"
        params = []
        count_params = []
        
        if category:
            query += " AND p.category = ?"
            count_query += " AND p.category = ?"
            params.append(category)
            count_params.append(category)
        
        if search:
            query += " AND (p.content LIKE ? OR u.username LIKE ? OR p.title LIKE ?)"
            count_query += " AND (p.content LIKE ? OR u.username LIKE ? OR p.title LIKE ?)"
            search_term = f'%{search}%'
            params.extend([search_term, search_term, search_term])
            count_params.extend([search_term, search_term, search_term])
        
        # Apply sorting
        sort_options = {
            'newest': 'p.timestamp DESC',
            'oldest': 'p.timestamp ASC',
            'popular': 'p.likes_count DESC',
            'active': 'p.last_activity DESC'
        }
        
        query += f" ORDER BY {sort_options.get(sort, 'p.timestamp DESC')}"
        query += " LIMIT ? OFFSET ?"
        params.extend([per_page, offset])
        
        # Get total count
        c.execute(count_query, count_params)
        total_count = c.fetchone()[0]
        
        # Get posts
        c.execute(query, params)
        rows = [dict(row) for row in c.fetchall()]
        
        # Check if user liked/bookmarked each post
        for post in rows:
            c.execute("SELECT id FROM likes WHERE user_id = ? AND post_id = ?", 
                     (request.user_id, post['id']))
            post['user_has_liked'] = c.fetchone() is not None
            
            c.execute("SELECT id FROM bookmarks WHERE user_id = ? AND post_id = ?",
                     (request.user_id, post['id']))
            post['user_has_bookmarked'] = c.fetchone() is not None
            
            post['formatted_timestamp'] = format_timestamp(post['timestamp'])
            post['formatted_last_activity'] = format_timestamp(post['last_activity'])
        
        return jsonify({
            "success": True, 
            "data": rows,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total_count,
                "pages": (total_count + per_page - 1) // per_page
            }
        })
        
    except Exception as e:
        app.logger.error(f"Posts retrieval error: {e}")
        return jsonify({"success": False, "error": "Failed to retrieve posts"}), 500
    finally:
        conn.close()

@app.route('/api/posts/<int:post_id>/like', methods=['POST'])
@token_required
def like_post(post_id):
    conn = get_db()
    try:
        c = conn.cursor()
        
        # Check if already liked
        c.execute("SELECT id FROM likes WHERE user_id = ? AND post_id = ?", (request.user_id, post_id))
        existing_like = c.fetchone()
        
        if existing_like:
            # Unlike
            c.execute("DELETE FROM likes WHERE id = ?", (existing_like['id'],))
            c.execute("UPDATE posts SET likes_count = likes_count - 1 WHERE id = ?", (post_id,))
            action = "unliked"
            new_count = c.execute("SELECT likes_count FROM posts WHERE id = ?", (post_id,)).fetchone()['likes_count']
        else:
            # Like
            c.execute("INSERT INTO likes (user_id, post_id) VALUES (?, ?)", (request.user_id, post_id))
            c.execute("UPDATE posts SET likes_count = likes_count + 1 WHERE id = ?", (post_id,))
            action = "liked"
            new_count = c.execute("SELECT likes_count FROM posts WHERE id = ?", (post_id,)).fetchone()['likes_count']
        
        conn.commit()
        
        return jsonify({
            "success": True,
            "action": action,
            "likes_count": new_count
        })
        
    except Exception as e:
        app.logger.error(f"Like error: {e}")
        return jsonify({"success": False, "error": "Failed to like post"}), 500
    finally:
        conn.close()

@app.route('/api/posts/<int:post_id>/bookmark', methods=['POST'])
@token_required
def bookmark_post(post_id):
    conn = get_db()
    try:
        c = conn.cursor()
        
        # Check if already bookmarked
        c.execute("SELECT id FROM bookmarks WHERE user_id = ? AND post_id = ?", (request.user_id, post_id))
        existing_bookmark = c.fetchone()
        
        if existing_bookmark:
            # Remove bookmark
            c.execute("DELETE FROM bookmarks WHERE id = ?", (existing_bookmark['id'],))
            action = "unbookmarked"
        else:
            # Add bookmark
            c.execute("INSERT INTO bookmarks (user_id, post_id) VALUES (?, ?)", (request.user_id, post_id))
            action = "bookmarked"
        
        conn.commit()
        
        return jsonify({
            "success": True,
            "action": action
        })
        
    except Exception as e:
        app.logger.error(f"Bookmark error: {e}")
        return jsonify({"success": False, "error": "Failed to bookmark post"}), 500
    finally:
        conn.close()

@app.route('/api/posts/<int:post_id>/comments', methods=['GET', 'POST'])
@token_required
def post_comments(post_id):
    if request.method == 'POST':
        return create_comment(post_id)
    else:
        return get_comments(post_id)

def create_comment(post_id):
    data = request.json_data
    
    try:
        content = SecurityUtils.sanitize_html(data.get("content", ""), Config.MAX_COMMENT_LENGTH)
        parent_comment_id = data.get("parent_comment_id")
        
        if len(content.strip()) < 1:
            raise ValidationError("Comment cannot be empty")
        
        conn = get_db()
        c = conn.cursor()
        
        # Verify post exists
        c.execute("SELECT id FROM posts WHERE id = ? AND is_deleted = 0", (post_id,))
        if not c.fetchone():
            raise ValidationError("Post not found")
        
        c.execute("INSERT INTO comments (post_id, user_id, content, parent_comment_id) VALUES (?, ?, ?, ?)",
                 (post_id, request.user_id, content, parent_comment_id))
        
        # Update post comment count and activity
        c.execute("UPDATE posts SET comments_count = comments_count + 1, last_activity = CURRENT_TIMESTAMP WHERE id = ?", (post_id,))
        
        # Update user comment count
        c.execute("UPDATE users SET comment_count = comment_count + 1 WHERE id = ?", (request.user_id,))
        
        conn.commit()
        
        # Emit real-time update
        socketio.emit('new_comment', {
            'post_id': post_id,
            'username': request.username
        })
        
        return jsonify({
            "success": True,
            "message": "Comment added successfully"
        })
        
    except ValidationError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        app.logger.error(f"Comment creation error: {e}")
        return jsonify({"success": False, "error": "Failed to add comment"}), 500
    finally:
        conn.close()

def get_comments(post_id):
    conn = get_db()
    try:
        c = conn.cursor()
        
        c.execute("""
            SELECT c.*, u.username, u.avatar_color
            FROM comments c
            JOIN users u ON c.user_id = u.id
            WHERE c.post_id = ? AND c.is_deleted = 0
            ORDER BY c.timestamp ASC
        """, (post_id,))
        
        comments = [dict(row) for row in c.fetchall()]
        
        # Format timestamps and check likes
        for comment in comments:
            comment['formatted_timestamp'] = format_timestamp(comment['timestamp'])
            c.execute("SELECT id FROM likes WHERE user_id = ? AND comment_id = ?", 
                     (request.user_id, comment['id']))
            comment['user_has_liked'] = c.fetchone() is not None
        
        return jsonify({
            "success": True,
            "data": comments
        })
        
    except Exception as e:
        app.logger.error(f"Comments retrieval error: {e}")
        return jsonify({"success": False, "error": "Failed to retrieve comments"}), 500
    finally:
        conn.close()

@app.route('/api/profile')
@token_required
def get_profile():
    conn = get_db()
    try:
        c = conn.cursor()
        
        c.execute("""
            SELECT username, avatar_color, bio, reputation, post_count, 
                   comment_count, like_count, created_at
            FROM users 
            WHERE id = ?
        """, (request.user_id,))
        
        user = c.fetchone()
        
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404
        
        return jsonify({
            "success": True,
            "profile": dict(user)
        })
        
    except Exception as e:
        app.logger.error(f"Profile error: {e}")
        return jsonify({"success": False, "error": "Failed to get profile"}), 500
    finally:
        conn.close()

@app.route('/api/notifications')
@token_required
def get_notifications():
    conn = get_db()
    try:
        c = conn.cursor()
        
        c.execute("""
            SELECT id, type, title, message, is_read, created_at
            FROM notifications 
            WHERE user_id = ? 
            ORDER BY created_at DESC
            LIMIT 50
        """, (request.user_id,))
        
        notifications = [dict(row) for row in c.fetchall()]
        
        # Format timestamps
        for notification in notifications:
            notification['formatted_timestamp'] = format_timestamp(notification['created_at'])
        
        return jsonify({
            "success": True,
            "notifications": notifications
        })
        
    except Exception as e:
        app.logger.error(f"Notifications error: {e}")
        return jsonify({"success": False, "error": "Failed to get notifications"}), 500
    finally:
        conn.close()

@app.route('/api/bookmarks')
@token_required
def get_bookmarks():
    conn = get_db()
    try:
        c = conn.cursor()
        
        c.execute("""
            SELECT p.*, u.username, u.avatar_color
            FROM bookmarks b
            JOIN posts p ON b.post_id = p.id
            JOIN users u ON p.user_id = u.id
            WHERE b.user_id = ? AND p.is_deleted = 0
            ORDER BY b.created_at DESC
        """, (request.user_id,))
        
        bookmarks = [dict(row) for row in c.fetchall()]
        
        for post in bookmarks:
            post['formatted_timestamp'] = format_timestamp(post['timestamp'])
            post['user_has_bookmarked'] = True
        
        return jsonify({
            "success": True,
            "data": bookmarks
        })
        
    except Exception as e:
        app.logger.error(f"Bookmarks error: {e}")
        return jsonify({"success": False, "error": "Failed to get bookmarks"}), 500
    finally:
        conn.close()

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