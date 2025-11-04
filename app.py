from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import sqlite3, os, jwt, bcrypt
from datetime import datetime, timedelta
import random
import re
from functools import wraps
import logging
from logging.handlers import RotatingFileHandler
import html
import asyncio
import aiohttp
import time
from concurrent.futures import ThreadPoolExecutor
import redis
import json
from dataclasses import dataclass
from typing import Optional, List, Dict, Any
import uuid

# Configuration
class Config:
    DB_NAME = "edgepowered_forum.db"
    SECRET_KEY = os.environ.get('SECRET_KEY', 'edgepowered-super-secure-key-2024-v2')
    RATE_LIMIT = int(os.environ.get('RATE_LIMIT', '1000'))  # Increased for better UX
    CACHE_TIMEOUT = 300  # 5 minutes
    MAX_WORKERS = 10
    SOCKET_TIMEOUT = 300

app = Flask(__name__)
app.config.from_object(Config)
CORS(app, origins=["*"], methods=["GET", "POST", "PUT", "DELETE"], allow_headers=["*"])
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Enhanced Redis Cache
try:
    redis_client = redis.Redis(
        host=os.environ.get('REDIS_HOST', 'localhost'),
        port=int(os.environ.get('REDIS_PORT', 6379)),
        password=os.environ.get('REDIS_PASSWORD'),
        decode_responses=True
    )
    redis_client.ping()
    CACHE_ENABLED = True
except:
    CACHE_ENABLED = False
    print("Redis not available, using in-memory cache")

# In-memory cache fallback
memory_cache = {}
request_cache = {}

# Enhanced Logging
if not os.path.exists('logs'):
    os.makedirs('logs')

file_handler = RotatingFileHandler('logs/edgepowered_enhanced.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)

# Thread pool for async operations
thread_pool = ThreadPoolExecutor(max_workers=Config.MAX_WORKERS)

# Rate limiting storage with enhanced algorithm
request_counts = {}

# Data Classes for Type Safety
@dataclass
class User:
    id: int
    username: str
    email: Optional[str]
    avatar_color: str
    bio: Optional[str]
    reputation: int
    created_at: str
    is_active: bool

@dataclass
class Post:
    id: int
    user_id: int
    category: str
    content: str
    timestamp: str
    likes_count: int
    comments_count: int
    username: str
    avatar_color: str
    user_has_liked: bool = False

# Enhanced Database Initialization
def init_db():
    """Initialize database with advanced schema"""
    conn = sqlite3.connect(Config.DB_NAME)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    
    try:
        c = conn.cursor()
        
        # Enable WAL mode for better concurrency
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        c.execute("PRAGMA cache_size=-64000")  # 64MB cache
        c.execute("PRAGMA temp_store=MEMORY")
        
        # Create enhanced tables
        c.executescript("""
            -- Enhanced Users table
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                password TEXT NOT NULL,
                email TEXT,
                full_name TEXT,
                avatar_color TEXT DEFAULT '#007AFF',
                bio TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                last_login TEXT,
                last_activity TEXT,
                is_active BOOLEAN DEFAULT 1,
                reputation INTEGER DEFAULT 100,
                post_count INTEGER DEFAULT 0,
                like_count INTEGER DEFAULT 0,
                is_verified BOOLEAN DEFAULT 0,
                notification_preferences TEXT DEFAULT '{"email": true, "push": true}'
            );
            
            -- Enhanced Posts table with full-text search
            CREATE TABLE IF NOT EXISTS posts(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                category TEXT NOT NULL,
                title TEXT,
                content TEXT NOT NULL,
                content_search TEXT GENERATED ALWAYS AS (lower(content)) VIRTUAL,
                timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                edited_at TEXT,
                likes_count INTEGER DEFAULT 0,
                comments_count INTEGER DEFAULT 0,
                views_count INTEGER DEFAULT 0,
                is_pinned BOOLEAN DEFAULT 0,
                is_locked BOOLEAN DEFAULT 0,
                tags TEXT,
                media_urls TEXT,
                search_tsv TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            
            -- Enhanced Comments table with nested replies
            CREATE TABLE IF NOT EXISTS comments(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                parent_comment_id INTEGER,
                content TEXT NOT NULL,
                timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                edited_at TEXT,
                likes_count INTEGER DEFAULT 0,
                is_deleted BOOLEAN DEFAULT 0,
                depth INTEGER DEFAULT 0,
                path TEXT DEFAULT '',
                FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(parent_comment_id) REFERENCES comments(id) ON DELETE CASCADE
            );
            
            -- Enhanced Interactions table
            CREATE TABLE IF NOT EXISTS interactions(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                post_id INTEGER,
                comment_id INTEGER,
                type TEXT NOT NULL CHECK(type IN ('like', 'bookmark', 'view', 'share')),
                timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                metadata TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
                FOREIGN KEY(comment_id) REFERENCES comments(id) ON DELETE CASCADE,
                UNIQUE(user_id, post_id, type) WHERE comment_id IS NULL,
                UNIQUE(user_id, comment_id, type) WHERE post_id IS NULL
            );
            
            -- User sessions for analytics
            CREATE TABLE IF NOT EXISTS user_sessions(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT UNIQUE NOT NULL,
                session_start TEXT NOT NULL DEFAULT (datetime('now')),
                session_end TEXT,
                user_agent TEXT,
                ip_address TEXT,
                page_views INTEGER DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            
            -- Enhanced notifications table
            CREATE TABLE IF NOT EXISTS notifications(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                type TEXT NOT NULL CHECK(type IN ('like', 'comment', 'reply', 'mention', 'system')),
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                data TEXT,
                is_read BOOLEAN DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                expires_at TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            
            -- Categories table
            CREATE TABLE IF NOT EXISTS categories(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                color TEXT DEFAULT '#007AFF',
                icon TEXT DEFAULT 'bi-chat',
                is_active BOOLEAN DEFAULT 1,
                post_count INTEGER DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            -- User relationships (followers/following)
            CREATE TABLE IF NOT EXISTS user_relationships(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                follower_id INTEGER NOT NULL,
                following_id INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY(follower_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(following_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(follower_id, following_id)
            );

            -- Analytics table
            CREATE TABLE IF NOT EXISTS analytics(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                metric TEXT NOT NULL,
                value INTEGER NOT NULL,
                timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                metadata TEXT
            );
        """)
        
        # Create enhanced indexes
        c.executescript("""
            CREATE INDEX IF NOT EXISTS idx_posts_user_id ON posts(user_id);
            CREATE INDEX IF NOT EXISTS idx_posts_category ON posts(category);
            CREATE INDEX IF NOT EXISTS idx_posts_timestamp ON posts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_posts_likes ON posts(likes_count);
            CREATE INDEX IF NOT EXISTS idx_posts_search ON posts(content_search);
            CREATE INDEX IF NOT EXISTS idx_comments_post_id ON comments(post_id);
            CREATE INDEX IF NOT EXISTS idx_comments_parent ON comments(parent_comment_id);
            CREATE INDEX IF NOT EXISTS idx_comments_path ON comments(path);
            CREATE INDEX IF NOT EXISTS idx_interactions_user ON interactions(user_id, type);
            CREATE INDEX IF NOT EXISTS idx_interactions_post ON interactions(post_id, type);
            CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, is_read, created_at);
            CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
            CREATE INDEX IF NOT EXISTS idx_users_reputation ON users(reputation);
            CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id);
            
            -- Full-text search virtual table
            CREATE VIRTUAL TABLE IF NOT EXISTS posts_fts USING fts5(
                content, 
                title,
                username,
                category,
                tokenize="porter unicode61"
            );
        """)
        
        # Insert default categories
        default_categories = [
            ('Technology', 'Tech discussions and programming', '#007AFF', 'bi-cpu'),
            ('Science', 'Scientific discoveries and research', '#34C759', 'bi-flask'),
            ('Entertainment', 'Movies, games, and media', '#AF52DE', 'bi-controller'),
            ('Sports', 'Sports news and discussions', '#FF3B30', 'bi-trophy'),
            ('Politics', 'Political discussions', '#5856D6', 'bi-building'),
            ('General', 'General discussions', '#FF9500', 'bi-chat'),
            ('Programming', 'Coding and development', '#32D74B', 'bi-code-slash'),
            ('AI & ML', 'Artificial Intelligence topics', '#BF5AF2', 'bi-robot'),
            ('Web Dev', 'Web development', '#FF453A', 'bi-globe'),
            ('Mobile', 'Mobile development', '#FF9F0A', 'bi-phone')
        ]
        
        c.executemany("""
            INSERT OR IGNORE INTO categories (name, description, color, icon) 
            VALUES (?, ?, ?, ?)
        """, default_categories)
        
        # Create admin user
        admin_password = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt())
        c.execute("""
            INSERT OR IGNORE INTO users (username, password, email, is_verified, reputation) 
            VALUES (?, ?, ?, ?, ?)
        """, ("admin", admin_password, "admin@edgepowered.com", 1, 1000))
        
        # Create sample posts for demo
        sample_posts = [
            (1, "Welcome to EdgePowered!", "Welcome to our enhanced community forum! This is a sample post to demonstrate the beautiful interface and powerful features. Feel free to explore and engage with the community! 🚀", "General"),
            (1, "Getting Started Guide", "## Welcome to EdgePowered!\n\nThis is a **modern community forum** with real-time features, advanced search, and beautiful design.\n\n### Key Features:\n- 🚀 Lightning-fast performance\n- 💬 Real-time messaging\n- 🔍 Advanced search\n- 📱 Mobile responsive\n- 🎨 Beautiful UI/UX\n\nStart by creating your account and joining the conversation!", "Technology"),
            (1, "Community Guidelines", "To ensure a great experience for everyone, please follow these guidelines:\n\n1. Be respectful and kind\n2. Stay on topic\n3. No spam or self-promotion\n4. Keep discussions constructive\n5. Help others when you can\n\nLet's build an amazing community together! 💪", "General")
        ]
        
        c.executemany("""
            INSERT OR IGNORE INTO posts (user_id, title, content, category) 
            VALUES (?, ?, ?, ?)
        """, sample_posts)
        
        conn.commit()
        app.logger.info("Enhanced database schema initialized successfully")
        
    except Exception as e:
        app.logger.error(f"Database initialization error: {e}")
        raise
    finally:
        conn.close()

# Initialize database
init_db()

# Enhanced Database Connection with Connection Pooling
class DatabaseManager:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DatabaseManager, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance
    
    def _initialize(self):
        self.connection_pool = []
        self.max_connections = 10
        
    def get_connection(self):
        """Get database connection from pool or create new one"""
        if self.connection_pool:
            return self.connection_pool.pop()
        else:
            conn = sqlite3.connect(Config.DB_NAME)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            return conn
    
    def return_connection(self, conn):
        """Return connection to pool"""
        if len(self.connection_pool) < self.max_connections:
            self.connection_pool.append(conn)
        else:
            conn.close()

db_manager = DatabaseManager()

def get_db():
    return db_manager.get_connection()

# Enhanced Caching System
class EnhancedCache:
    @staticmethod
    def get(key):
        if CACHE_ENABLED:
            try:
                cached = redis_client.get(f"edgepowered:{key}")
                if cached:
                    return json.loads(cached)
            except:
                pass
        return memory_cache.get(key)
    
    @staticmethod
    def set(key, data, timeout=Config.CACHE_TIMEOUT):
        try:
            if CACHE_ENABLED:
                redis_client.setex(f"edgepowered:{key}", timeout, json.dumps(data))
            else:
                memory_cache[key] = data
        except:
            memory_cache[key] = data
    
    @staticmethod
    def delete(pattern):
        try:
            if CACHE_ENABLED:
                keys = redis_client.keys(f"edgepowered:{pattern}*")
                if keys:
                    redis_client.delete(*keys)
            else:
                for key in list(memory_cache.keys()):
                    if key.startswith(pattern):
                        del memory_cache[key]
        except:
            pass

# Enhanced Rate Limiting
class RateLimiter:
    @staticmethod
    def check_limit(identifier, limit=Config.RATE_LIMIT, window=60):
        now = time.time()
        key = f"rate_limit:{identifier}"
        
        if key not in request_counts:
            request_counts[key] = []
        
        # Remove old requests
        request_counts[key] = [req_time for req_time in request_counts[key] if now - req_time < window]
        
        if len(request_counts[key]) >= limit:
            return False
        
        request_counts[key].append(now)
        return True

# Enhanced Authentication & Security
class AuthManager:
    @staticmethod
    def generate_token(user_id, username):
        payload = {
            "user_id": user_id,
            "username": username,
            "exp": datetime.utcnow() + timedelta(days=7),  # Longer token expiry
            "iat": datetime.utcnow()
        }
        return jwt.encode(payload, Config.SECRET_KEY, algorithm="HS256")
    
    @staticmethod
    def verify_token(token):
        try:
            payload = jwt.decode(token, Config.SECRET_KEY, algorithms=["HS256"])
            return payload
        except jwt.ExpiredSignatureError:
            raise Exception("Token expired")
        except jwt.InvalidTokenError:
            raise Exception("Invalid token")
    
    @staticmethod
    def hash_password(password):
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    
    @staticmethod
    def verify_password(password, hashed):
        return bcrypt.checkpw(password.encode(), hashed)

# Enhanced Input Validation
class Validator:
    @staticmethod
    def validate_username(username):
        if len(username) < 3:
            return False, "Username must be at least 3 characters"
        if len(username) > 20:
            return False, "Username must be less than 20 characters"
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            return False, "Username can only contain letters, numbers, and underscores"
        return True, None
    
    @staticmethod
    def validate_password(password):
        if len(password) < 6:
            return False, "Password must be at least 6 characters"
        if len(password) > 100:
            return False, "Password too long"
        return True, None
    
    @staticmethod
    def validate_email(email):
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return False, "Invalid email format"
        return True, None
    
    @staticmethod
    def sanitize_html(content, max_length=10000):
        """Enhanced HTML sanitization for rich content"""
        if not content:
            return content
        
        # Remove dangerous tags and attributes
        content = re.sub(r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>', '', content, flags=re.IGNORECASE)
        content = re.sub(r'on\w+\s*=', '', content, flags=re.IGNORECASE)
        content = re.sub(r'javascript:', '', content, flags=re.IGNORECASE)
        content = re.sub(r'vbscript:', '', content, flags=re.IGNORECASE)
        content = re.sub(r'expression\(', '', content, flags=re.IGNORECASE)
        
        # Allow safe HTML tags for rich text
        allowed_tags = ['p', 'br', 'strong', 'em', 'u', 'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote', 'code', 'pre']
        for tag in allowed_tags:
            content = re.sub(f'<(/)?{tag}>', f'[\\1{tag}]', content)
        
        # Limit length
        if len(content) > max_length:
            content = content[:max_length] + '...'
        
        return content.strip()

# Enhanced Decorators
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token:
            return jsonify({"success": False, "error": "Authentication required"}), 401
        
        try:
            payload = AuthManager.verify_token(token)
            request.user_id = payload["user_id"]
            request.username = payload["username"]
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 401
        
        return f(*args, **kwargs)
    return decorated

def rate_limit(limit=100, window=60):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            identifier = f"{request.endpoint}:{request.remote_addr}"
            if not RateLimiter.check_limit(identifier, limit, window):
                return jsonify({
                    "success": False, 
                    "error": "Rate limit exceeded. Please slow down."
                }), 429
            return f(*args, **kwargs)
        return decorated
    return decorator

def cache_response(timeout=300):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            cache_key = f"response:{request.path}:{hash(frozenset(request.args.items()))}"
            cached = EnhancedCache.get(cache_key)
            if cached:
                return jsonify(cached)
            
            response = f(*args, **kwargs)
            
            # Cache successful responses
            if response[1] == 200:
                try:
                    data = response[0].get_json()
                    EnhancedCache.set(cache_key, data, timeout)
                except:
                    pass
            
            return response
        return decorated
    return decorator

# Enhanced Utility Functions
def format_timestamp(timestamp):
    """Enhanced timestamp formatting"""
    if not timestamp:
        return "Recently"
    
    try:
        post_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        now = datetime.now(post_time.tzinfo) if post_time.tzinfo else datetime.now()
        diff = now - post_time
        
        if diff.days > 365:
            return f"{diff.days // 365}y ago"
        elif diff.days > 30:
            return f"{diff.days // 30}mo ago"
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

def generate_avatar_color():
    colors = ['#007AFF', '#34C759', '#FF9500', '#FF3B30', '#AF52DE', '#5856D6', '#32D74B', '#FF453A', '#FF9F0A', '#BF5AF2']
    return random.choice(colors)

def update_user_activity(user_id):
    """Update user's last activity timestamp"""
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("UPDATE users SET last_activity = datetime('now') WHERE id = ?", (user_id,))
        conn.commit()
    except Exception as e:
        app.logger.error(f"Activity update error: {e}")
    finally:
        db_manager.return_connection(conn)

# Enhanced Routes
@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/api/health')
def health_check():
    """Enhanced health check with system metrics"""
    conn = get_db()
    try:
        # Database health
        c = conn.cursor()
        c.execute("SELECT 1")
        db_status = "healthy"
        
        # System metrics
        c.execute("SELECT COUNT(*) as user_count FROM users WHERE is_active = 1")
        user_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) as post_count FROM posts")
        post_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) as active_today FROM users WHERE last_activity > datetime('now', '-1 day')")
        active_today = c.fetchone()[0]
        
        # Performance metrics
        c.execute("SELECT COUNT(*) as pending_notifications FROM notifications WHERE is_read = 0")
        pending_notifications = c.fetchone()[0]
        
        cache_status = "enabled" if CACHE_ENABLED else "disabled"
        
        return jsonify({
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "version": "2.0.0",
            "metrics": {
                "users": {
                    "total": user_count,
                    "active_today": active_today
                },
                "content": {
                    "posts": post_count,
                    "pending_notifications": pending_notifications
                },
                "performance": {
                    "cache": cache_status,
                    "rate_limiting": "enabled"
                }
            }
        })
        
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e)}), 500
    finally:
        db_manager.return_connection(conn)

@app.route('/api/register', methods=['POST'])
@rate_limit(limit=5, window=300)  # 5 registrations per 5 minutes
def register():
    """Enhanced user registration"""
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "No data provided"}), 400

    # Validate required fields
    required_fields = ["username", "password", "email"]
    for field in required_fields:
        if not data.get(field):
            return jsonify({"success": False, "error": f"Missing field: {field}"}), 400

    # Enhanced validation
    valid_username, username_msg = Validator.validate_username(data["username"])
    if not valid_username:
        return jsonify({"success": False, "error": username_msg}), 400
    
    valid_password, password_msg = Validator.validate_password(data["password"])
    if not valid_password:
        return jsonify({"success": False, "error": password_msg}), 400
    
    valid_email, email_msg = Validator.validate_email(data["email"])
    if not valid_email:
        return jsonify({"success": False, "error": email_msg}), 400

    # Sanitize inputs
    username = data["username"].strip()
    email = data["email"].strip().lower()
    full_name = Validator.sanitize_html(data.get("full_name", ""), 50)
    bio = Validator.sanitize_html(data.get("bio", ""), 200)

    # Hash password
    hashed_pw = AuthManager.hash_password(data["password"])
    avatar_color = generate_avatar_color()

    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("""INSERT INTO users (username, password, email, full_name, avatar_color, bio) 
                    VALUES (?, ?, ?, ?, ?, ?)""",
                 (username, hashed_pw, email, full_name, avatar_color, bio))
        user_id = c.lastrowid
        
        # Create welcome notification
        c.execute("""
            INSERT INTO notifications (user_id, type, title, message) 
            VALUES (?, 'system', 'Welcome to EdgePowered!', 'Thank you for joining our community! Start by creating your first post.')
        """, (user_id,))
        
        conn.commit()
        
        app.logger.info(f"New user registered: {username} (ID: {user_id})")
        
        # Clear relevant caches
        EnhancedCache.delete("users:stats")
        
        return jsonify({
            "success": True, 
            "message": "Account created successfully",
            "user_id": user_id
        })
    
    except sqlite3.IntegrityError as e:
        if "username" in str(e):
            return jsonify({"success": False, "error": "Username already exists"}), 400
        elif "email" in str(e):
            return jsonify({"success": False, "error": "Email already registered"}), 400
        else:
            return jsonify({"success": False, "error": "Registration failed"}), 400
    except Exception as e:
        app.logger.error(f"Registration error: {e}")
        return jsonify({"success": False, "error": "Registration failed"}), 500
    finally:
        db_manager.return_connection(conn)

@app.route('/api/login', methods=['POST'])
@rate_limit(limit=10, window=300)  # 10 login attempts per 5 minutes
def login():
    """Enhanced login with session management"""
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "No data provided"}), 400

    username = data.get("username", "").strip()
    password = data.get("password", "")

    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("""
            SELECT id, password, username, avatar_color, is_active, reputation, email 
            FROM users 
            WHERE username = ? OR email = ?
        """, (username, username))
        user = c.fetchone()

        if not user or not AuthManager.verify_password(password, user["password"]):
            app.logger.warning(f"Failed login attempt: {username}")
            return jsonify({"success": False, "error": "Invalid credentials"}), 401

        if not user["is_active"]:
            return jsonify({"success": False, "error": "Account deactivated"}), 403

        # Generate token
        token = AuthManager.generate_token(user["id"], user["username"])

        # Update user activity and last login
        c.execute("""
            UPDATE users 
            SET last_login = datetime('now'), last_activity = datetime('now') 
            WHERE id = ?
        """, (user["id"],))
        
        # Create session
        session_token = str(uuid.uuid4())
        c.execute("""
            INSERT INTO user_sessions (user_id, session_token, user_agent, ip_address) 
            VALUES (?, ?, ?, ?)
        """, (user["id"], session_token, request.headers.get('User-Agent'), request.remote_addr))
        
        conn.commit()

        app.logger.info(f"User logged in: {user['username']}")

        return jsonify({
            "success": True, 
            "token": token,
            "session_token": session_token,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "avatar_color": user["avatar_color"],
                "reputation": user["reputation"],
                "email": user["email"]
            }
        })
        
    except Exception as e:
        app.logger.error(f"Login error: {e}")
        return jsonify({"success": False, "error": "Login failed"}), 500
    finally:
        db_manager.return_connection(conn)

@app.route('/api/posts', methods=['GET'])
@token_required
@cache_response(timeout=60)  # Cache posts for 1 minute
def get_posts():
    """Enhanced posts retrieval with advanced filtering"""
    conn = get_db()
    try:
        c = conn.cursor()
        
        # Enhanced pagination and filtering
        page = max(1, int(request.args.get('page', 1)))
        per_page = min(50, max(1, int(request.args.get('per_page', 10))))
        category = request.args.get('category', '')
        search = request.args.get('search', '').strip()
        sort = request.args.get('sort', 'newest')
        author = request.args.get('author', '')
        
        offset = (page - 1) * per_page
        
        # Build enhanced query
        base_query = """
            SELECT p.*, u.username, u.avatar_color, u.reputation,
                   EXISTS(SELECT 1 FROM interactions i WHERE i.user_id = ? AND i.post_id = p.id AND i.type = 'like') as user_has_liked,
                   EXISTS(SELECT 1 FROM interactions i WHERE i.user_id = ? AND i.post_id = p.id AND i.type = 'bookmark') as user_has_bookmarked
            FROM posts p 
            JOIN users u ON p.user_id = u.id 
            WHERE u.is_active = 1
        """
        
        count_query = """
            SELECT COUNT(*) 
            FROM posts p 
            JOIN users u ON p.user_id = u.id 
            WHERE u.is_active = 1
        """
        
        params = [request.user_id, request.user_id]
        count_params = []
        
        # Enhanced filtering
        if category:
            base_query += " AND p.category = ?"
            count_query += " AND p.category = ?"
            params.append(category)
            count_params.append(category)
        
        if search:
            # Use FTS for better search
            base_query += " AND p.id IN (SELECT rowid FROM posts_fts WHERE posts_fts MATCH ?)"
            count_query += " AND p.id IN (SELECT rowid FROM posts_fts WHERE posts_fts MATCH ?)"
            search_term = f'"{search}"*'  # Prefix search
            params.append(search_term)
            count_params.append(search_term)
        
        if author:
            base_query += " AND u.username LIKE ?"
            count_query += " AND u.username LIKE ?"
            params.append(f'%{author}%')
            count_params.append(f'%{author}%')
        
        # Enhanced sorting
        sort_options = {
            'newest': 'p.timestamp DESC',
            'oldest': 'p.timestamp ASC',
            'popular': 'p.likes_count DESC, p.views_count DESC',
            'trending': '(p.likes_count + p.comments_count) / (strftime("%s", "now") - strftime("%s", p.timestamp)) DESC',
            'commented': 'p.comments_count DESC'
        }
        order_by = sort_options.get(sort, 'p.timestamp DESC')
        base_query += f" ORDER BY p.is_pinned DESC, {order_by} LIMIT ? OFFSET ?"
        params.extend([per_page, offset])
        
        # Get total count
        c.execute(count_query, count_params)
        total_count = c.fetchone()[0]
        
        # Get posts
        c.execute(base_query, params)
        posts = []
        for row in c.fetchall():
            post = dict(row)
            post['formatted_timestamp'] = format_timestamp(post['timestamp'])
            posts.append(post)
        
        # Update view counts (async)
        thread_pool.submit(update_post_views, [p['id'] for p in posts])
        
        return jsonify({
            "success": True, 
            "data": posts,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total_count,
                "pages": (total_count + per_page - 1) // per_page,
                "has_more": page * per_page < total_count
            },
            "filters": {
                "category": category,
                "search": search,
                "sort": sort
            }
        })
        
    except Exception as e:
        app.logger.error(f"Posts retrieval error: {e}")
        return jsonify({"success": False, "error": "Failed to retrieve posts"}), 500
    finally:
        db_manager.return_connection(conn)

@app.route('/api/posts', methods=['POST'])
@token_required
@rate_limit(limit=20, window=300)  # 20 posts per 5 minutes
def create_post():
    """Enhanced post creation with rich content support"""
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "No data provided"}), 400
        
    required_fields = ["category", "content"]
    for field in required_fields:
        if not data.get(field):
            return jsonify({"success": False, "error": f"Missing field: {field}"}), 400
    
    category = Validator.sanitize_html(data["category"], 50)
    content = Validator.sanitize_html(data["content"], 5000)
    title = Validator.sanitize_html(data.get("title", ""), 200)

    if len(content.strip()) < 10:
        return jsonify({"success": False, "error": "Content must be at least 10 characters"}), 400

    conn = get_db()
    try:
        c = conn.cursor()
        
        # Verify category exists
        c.execute("SELECT name FROM categories WHERE name = ? AND is_active = 1", (category,))
        if not c.fetchone():
            return jsonify({"success": False, "error": "Invalid category"}), 400

        # Create post
        c.execute("""
            INSERT INTO posts (user_id, category, title, content) 
            VALUES (?, ?, ?, ?)
        """, (request.user_id, category, title, content))
        post_id = c.lastrowid
        
        # Update user post count
        c.execute("UPDATE users SET post_count = post_count + 1 WHERE id = ?", (request.user_id,))
        c.execute("UPDATE categories SET post_count = post_count + 1 WHERE name = ?", (category,))
        
        # Add to FTS
        c.execute("""
            INSERT INTO posts_fts (rowid, content, title, username, category) 
            SELECT p.id, p.content, p.title, u.username, p.category 
            FROM posts p JOIN users u ON p.user_id = u.id 
            WHERE p.id = ?
        """, (post_id,))
        
        conn.commit()
        
        # Clear relevant caches
        EnhancedCache.delete("posts:")
        EnhancedCache.delete("users:stats")
        
        # Real-time notification
        socketio.emit('new_post', {
            'post_id': post_id,
            'username': request.username,
            'category': category,
            'title': title,
            'timestamp': datetime.now().isoformat()
        })
        
        app.logger.info(f"New post created by {request.username}: {title}")
        
        return jsonify({
            "success": True, 
            "message": "Post created successfully", 
            "post_id": post_id
        }), 201
        
    except Exception as e:
        app.logger.error(f"Post creation error: {e}")
        return jsonify({"success": False, "error": "Failed to create post"}), 500
    finally:
        db_manager.return_connection(conn)

@app.route('/api/posts/<int:post_id>', methods=['GET'])
@token_required
def get_post(post_id):
    """Enhanced single post retrieval"""
    conn = get_db()
    try:
        c = conn.cursor()
        
        c.execute("""
            SELECT p.*, u.username, u.avatar_color, u.reputation,
                   EXISTS(SELECT 1 FROM interactions i WHERE i.user_id = ? AND i.post_id = p.id AND i.type = 'like') as user_has_liked,
                   EXISTS(SELECT 1 FROM interactions i WHERE i.user_id = ? AND i.post_id = p.id AND i.type = 'bookmark') as user_has_bookmarked
            FROM posts p 
            JOIN users u ON p.user_id = u.id 
            WHERE p.id = ? AND u.is_active = 1
        """, (request.user_id, request.user_id, post_id))
        
        post = c.fetchone()
        if not post:
            return jsonify({"success": False, "error": "Post not found"}), 404
        
        post_dict = dict(post)
        post_dict['formatted_timestamp'] = format_timestamp(post_dict['timestamp'])
        
        # Increment view count
        c.execute("UPDATE posts SET views_count = views_count + 1 WHERE id = ?", (post_id,))
        
        # Record view interaction
        c.execute("""
            INSERT OR IGNORE INTO interactions (user_id, post_id, type) 
            VALUES (?, ?, 'view')
        """, (request.user_id, post_id))
        
        conn.commit()
        
        return jsonify({"success": True, "data": post_dict})
        
    except Exception as e:
        app.logger.error(f"Post retrieval error: {e}")
        return jsonify({"success": False, "error": "Failed to retrieve post"}), 500
    finally:
        db_manager.return_connection(conn)

@app.route('/api/posts/<int:post_id>/like', methods=['POST'])
@token_required
@rate_limit(limit=50, window=60)  # 50 likes per minute
def like_post(post_id):
    """Enhanced like/unlike functionality"""
    conn = get_db()
    try:
        c = conn.cursor()
        
        # Verify post exists
        c.execute("SELECT id, user_id FROM posts WHERE id = ?", (post_id,))
        post = c.fetchone()
        if not post:
            return jsonify({"success": False, "error": "Post not found"}), 404
        
        # Check existing interaction
        c.execute("SELECT id FROM interactions WHERE user_id = ? AND post_id = ? AND type = 'like'", 
                 (request.user_id, post_id))
        existing = c.fetchone()
        
        if existing:
            # Unlike
            c.execute("DELETE FROM interactions WHERE id = ?", (existing["id"],))
            c.execute("UPDATE posts SET likes_count = likes_count - 1 WHERE id = ?", (post_id,))
            action = "unliked"
            
            # Update reputation
            if post["user_id"] != request.user_id:
                c.execute("UPDATE users SET reputation = reputation - 2 WHERE id = ?", (post["user_id"],))
        else:
            # Like
            c.execute("INSERT INTO interactions (user_id, post_id, type) VALUES (?, ?, 'like')",
                     (request.user_id, post_id))
            c.execute("UPDATE posts SET likes_count = likes_count + 1 WHERE id = ?", (post_id,))
            action = "liked"
            
            # Update reputation and create notification
            if post["user_id"] != request.user_id:
                c.execute("UPDATE users SET reputation = reputation + 2 WHERE id = ?", (post["user_id"],))
                
                # Create notification
                c.execute("""
                    INSERT INTO notifications (user_id, type, title, message, data) 
                    VALUES (?, 'like', 'New Like', 'Your post received a like from {}', ?)
                """.format(request.username), (post["user_id"], json.dumps({"post_id": post_id})))
        
        # Get updated like count
        c.execute("SELECT likes_count FROM posts WHERE id = ?", (post_id,))
        likes_count = c.fetchone()["likes_count"]
        
        conn.commit()
        
        # Clear cache
        EnhancedCache.delete(f"posts:{post_id}")
        
        # Real-time update
        socketio.emit('post_updated', {
            'post_id': post_id,
            'likes_count': likes_count,
            'action': action
        })
        
        return jsonify({
            "success": True, 
            "action": action,
            "likes_count": likes_count
        })
        
    except Exception as e:
        app.logger.error(f"Like operation error: {e}")
        return jsonify({"success": False, "error": "Like operation failed"}), 500
    finally:
        db_manager.return_connection(conn)

@app.route('/api/posts/<int:post_id>/bookmark', methods=['POST'])
@token_required
def bookmark_post(post_id):
    """Enhanced bookmark functionality"""
    conn = get_db()
    try:
        c = conn.cursor()
        
        # Verify post exists
        c.execute("SELECT id FROM posts WHERE id = ?", (post_id,))
        if not c.fetchone():
            return jsonify({"success": False, "error": "Post not found"}), 404
        
        # Check existing bookmark
        c.execute("SELECT id FROM interactions WHERE user_id = ? AND post_id = ? AND type = 'bookmark'", 
                 (request.user_id, post_id))
        existing = c.fetchone()
        
        if existing:
            # Remove bookmark
            c.execute("DELETE FROM interactions WHERE id = ?", (existing["id"],))
            action = "unbookmarked"
        else:
            # Add bookmark
            c.execute("INSERT INTO interactions (user_id, post_id, type) VALUES (?, ?, 'bookmark')",
                     (request.user_id, post_id))
            action = "bookmarked"
        
        conn.commit()
        
        return jsonify({
            "success": True, 
            "action": action
        })
        
    except Exception as e:
        app.logger.error(f"Bookmark operation error: {e}")
        return jsonify({"success": False, "error": "Bookmark operation failed"}), 500
    finally:
        db_manager.return_connection(conn)

@app.route('/api/comments', methods=['POST'])
@token_required
@rate_limit(limit=30, window=300)
def create_comment():
    """Enhanced comment creation with nested replies"""
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "No data provided"}), 400
        
    required_fields = ["post_id", "content"]
    for field in required_fields:
        if not data.get(field):
            return jsonify({"success": False, "error": f"Missing field: {field}"}), 400
    
    post_id = data["post_id"]
    content = Validator.sanitize_html(data["content"], 1000)
    parent_comment_id = data.get("parent_comment_id")
    
    if len(content.strip()) < 1:
        return jsonify({"success": False, "error": "Comment cannot be empty"}), 400

    conn = get_db()
    try:
        c = conn.cursor()
        
        # Verify post exists
        c.execute("SELECT id, user_id FROM posts WHERE id = ?", (post_id,))
        post = c.fetchone()
        if not post:
            return jsonify({"success": False, "error": "Post not found"}), 404
        
        # Calculate depth and path for nested comments
        depth = 0
        path = ""
        if parent_comment_id:
            c.execute("SELECT depth, path FROM comments WHERE id = ?", (parent_comment_id,))
            parent = c.fetchone()
            if parent:
                depth = parent["depth"] + 1
                path = f"{parent['path']}{parent_comment_id}/"
        
        # Insert comment
        c.execute("""
            INSERT INTO comments (post_id, user_id, content, parent_comment_id, depth, path) 
            VALUES (?, ?, ?, ?, ?, ?)
        """, (post_id, request.user_id, content, parent_comment_id, depth, path))
        
        # Update post comment count
        c.execute("UPDATE posts SET comments_count = comments_count + 1 WHERE id = ?", (post_id,))
        
        comment_id = c.lastrowid
        
        # Create notification for post owner
        if post["user_id"] != request.user_id:
            c.execute("""
                INSERT INTO notifications (user_id, type, title, message, data) 
                VALUES (?, 'comment', 'New Comment', 'Your post received a comment from {}', ?)
            """.format(request.username), (post["user_id"], json.dumps({"post_id": post_id, "comment_id": comment_id})))
        
        conn.commit()
        
        # Clear cache
        EnhancedCache.delete(f"posts:{post_id}:comments")
        
        # Real-time notification
        socketio.emit('new_comment', {
            'post_id': post_id,
            'comment_id': comment_id,
            'username': request.username,
            'parent_comment_id': parent_comment_id
        })
        
        return jsonify({
            "success": True, 
            "message": "Comment created successfully", 
            "comment_id": comment_id
        }), 201
        
    except Exception as e:
        app.logger.error(f"Comment creation error: {e}")
        return jsonify({"success": False, "error": "Failed to create comment"}), 500
    finally:
        db_manager.return_connection(conn)

@app.route('/api/posts/<int:post_id>/comments')
@token_required
def get_comments(post_id):
    """Enhanced comments retrieval with nested structure"""
    conn = get_db()
    try:
        c = conn.cursor()
        
        # Verify post exists
        c.execute("SELECT id FROM posts WHERE id = ?", (post_id,))
        if not c.fetchone():
            return jsonify({"success": False, "error": "Post not found"}), 404
        
        # Get comments with user info and like status
        c.execute("""
            SELECT c.*, u.username, u.avatar_color,
                   EXISTS(SELECT 1 FROM interactions i WHERE i.user_id = ? AND i.comment_id = c.id AND i.type = 'like') as user_has_liked
            FROM comments c 
            JOIN users u ON c.user_id = u.id 
            WHERE c.post_id = ? AND c.is_deleted = 0 AND u.is_active = 1
            ORDER BY c.path, c.timestamp ASC
        """, (request.user_id, post_id))
        
        comments = []
        for row in c.fetchall():
            comment = dict(row)
            comment['formatted_timestamp'] = format_timestamp(comment['timestamp'])
            comments.append(comment)
        
        # Build comment tree
        comment_dict = {}
        root_comments = []
        
        for comment in comments:
            comment_id = comment['id']
            comment_dict[comment_id] = comment
            comment['replies'] = []
            
            if comment['parent_comment_id'] is None:
                root_comments.append(comment)
            else:
                parent = comment_dict.get(comment['parent_comment_id'])
                if parent:
                    parent['replies'].append(comment)
        
        return jsonify({
            "success": True, 
            "data": root_comments
        })
        
    except Exception as e:
        app.logger.error(f"Comments retrieval error: {e}")
        return jsonify({"success": False, "error": "Failed to retrieve comments"}), 500
    finally:
        db_manager.return_connection(conn)

@app.route('/api/notifications')
@token_required
def get_notifications():
    """Enhanced notifications with pagination"""
    conn = get_db()
    try:
        c = conn.cursor()
        
        page = max(1, int(request.args.get('page', 1)))
        per_page = min(50, max(1, int(request.args.get('per_page', 20))))
        offset = (page - 1) * per_page
        
        # Get notifications
        c.execute("""
            SELECT id, type, title, message, data, is_read, created_at 
            FROM notifications 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT ? OFFSET ?
        """, (request.user_id, per_page, offset))
        
        notifications = [dict(row) for row in c.fetchall()]
        
        # Mark as read (async)
        notification_ids = [n['id'] for n in notifications if not n['is_read']]
        if notification_ids:
            thread_pool.submit(mark_notifications_read, notification_ids)
        
        # Get unread count
        c.execute("SELECT COUNT(*) as unread_count FROM notifications WHERE user_id = ? AND is_read = 0", 
                 (request.user_id,))
        unread_count = c.fetchone()["unread_count"]
        
        return jsonify({
            "success": True,
            "data": notifications,
            "unread_count": unread_count,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "has_more": len(notifications) == per_page
            }
        })
        
    except Exception as e:
        app.logger.error(f"Notifications error: {e}")
        return jsonify({"success": False, "error": "Failed to get notifications"}), 500
    finally:
        db_manager.return_connection(conn)

@app.route('/api/analytics/overview')
@token_required
def get_analytics():
    """Enhanced analytics dashboard"""
    conn = get_db()
    try:
        c = conn.cursor()
        
        # Basic stats
        c.execute("SELECT COUNT(*) as total_users FROM users WHERE is_active = 1")
        total_users = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) as total_posts FROM posts")
        total_posts = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) as total_comments FROM comments WHERE is_deleted = 0")
        total_comments = c.fetchone()[0]
        
        c.execute("SELECT SUM(likes_count) as total_likes FROM posts")
        total_likes = c.fetchone()[0] or 0
        
        # Growth metrics
        c.execute("""
            SELECT COUNT(*) as new_users_week FROM users 
            WHERE created_at > datetime('now', '-7 days') AND is_active = 1
        """)
        new_users_week = c.fetchone()[0]
        
        c.execute("""
            SELECT COUNT(*) as new_posts_week FROM posts 
            WHERE timestamp > datetime('now', '-7 days')
        """)
        new_posts_week = c.fetchone()[0]
        
        # Popular categories
        c.execute("""
            SELECT category, COUNT(*) as count, 
                   (SELECT color FROM categories WHERE name = posts.category) as color
            FROM posts 
            GROUP BY category 
            ORDER BY count DESC 
            LIMIT 10
        """)
        popular_categories = [dict(row) for row in c.fetchall()]
        
        # Top users
        c.execute("""
            SELECT u.username, u.reputation, u.post_count, u.avatar_color,
                   (SELECT COUNT(*) FROM posts p WHERE p.user_id = u.id) as user_posts,
                   (SELECT COUNT(*) FROM interactions i WHERE i.user_id = u.id AND i.type = 'like') as user_likes_given
            FROM users u
            WHERE u.is_active = 1
            ORDER BY u.reputation DESC
            LIMIT 10
        """)
        top_users = [dict(row) for row in c.fetchall()]
        
        # Recent activity
        c.execute("""
            SELECT 'post' as type, timestamp, username, 
                   CASE WHEN LENGTH(content) > 50 THEN SUBSTR(content, 1, 50) || '...' ELSE content END as preview
            FROM posts p 
            JOIN users u ON p.user_id = u.id 
            WHERE u.is_active = 1
            UNION ALL
            SELECT 'comment' as type, c.timestamp, u.username,
                   CASE WHEN LENGTH(c.content) > 50 THEN SUBSTR(c.content, 1, 50) || '...' ELSE c.content END as preview
            FROM comments c 
            JOIN users u ON c.user_id = u.id 
            WHERE u.is_active = 1 AND c.is_deleted = 0
            ORDER BY timestamp DESC 
            LIMIT 20
        """)
        recent_activity = [dict(row) for row in c.fetchall()]
        
        return jsonify({
            "success": True,
            "analytics": {
                "total_users": total_users,
                "total_posts": total_posts,
                "total_comments": total_comments,
                "total_likes": total_likes,
                "growth": {
                    "new_users_week": new_users_week,
                    "new_posts_week": new_posts_week
                },
                "popular_categories": popular_categories,
                "top_users": top_users,
                "recent_activity": recent_activity
            }
        })
        
    except Exception as e:
        app.logger.error(f"Analytics error: {e}")
        return jsonify({"success": False, "error": "Failed to get analytics"}), 500
    finally:
        db_manager.return_connection(conn)

# WebSocket Events
@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    app.logger.info(f"Client connected: {request.sid}")
    emit('connected', {'message': 'Connected to EdgePowered real-time server'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnect"""
    app.logger.info(f"Client disconnected: {request.sid}")

@socketio.on('join_post')
def handle_join_post(data):
    """Join a post room for real-time updates"""
    post_id = data.get('post_id')
    if post_id:
        join_room(f'post_{post_id}')
        emit('joined_post', {'post_id': post_id})

# Background Tasks
def update_post_views(post_ids):
    """Update post views in background"""
    if not post_ids:
        return
        
    conn = get_db()
    try:
        c = conn.cursor()
        placeholders = ','.join('?' * len(post_ids))
        c.execute(f"UPDATE posts SET views_count = views_count + 1 WHERE id IN ({placeholders})", post_ids)
        conn.commit()
    except Exception as e:
        app.logger.error(f"Background view update error: {e}")
    finally:
        db_manager.return_connection(conn)

def mark_notifications_read(notification_ids):
    """Mark notifications as read in background"""
    if not notification_ids:
        return
        
    conn = get_db()
    try:
        c = conn.cursor()
        placeholders = ','.join('?' * len(notification_ids))
        c.execute(f"UPDATE notifications SET is_read = 1 WHERE id IN ({placeholders})", notification_ids)
        conn.commit()
    except Exception as e:
        app.logger.error(f"Background notification update error: {e}")
    finally:
        db_manager.return_connection(conn)

# Error Handlers
@app.errorhandler(404)
def not_found(e):
    return jsonify({"success": False, "error": "Endpoint not found"}), 404

@app.errorhandler(500)
def server_error(e):
    app.logger.error(f"500 error: {str(e)}")
    return jsonify({"success": False, "error": "Internal server error"}), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        "success": False, 
        "error": "Rate limit exceeded. Please slow down."
    }), 429

@app.errorhandler(413)
def too_large(e):
    return jsonify({"success": False, "error": "File too large"}), 413

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)