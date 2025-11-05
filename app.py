from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import sqlite3, os, jwt, bcrypt
from datetime import datetime, timedelta
import random
import re
from functools import wraps
import logging
from logging.handlers import RotatingFileHandler
import html
import bleach
from urllib.parse import urlparse
import secrets
import hashlib

app = Flask(__name__)
CORS(app)

# Enhanced Configuration
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
    DB_NAME = os.environ.get('DB_NAME', 'edgepowered_forum.db')
    RATE_LIMIT_PER_HOUR = int(os.environ.get('RATE_LIMIT_PER_HOUR', '1000'))
    JWT_EXPIRY_HOURS = int(os.environ.get('JWT_EXPIRY_HOURS', '24'))
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 16777216))  # 16MB
    
    # Security settings
    BCRYPT_ROUNDS = 12
    MIN_PASSWORD_LENGTH = 8
    MAX_USERNAME_LENGTH = 20
    MAX_POST_LENGTH = 10000
    MAX_COMMENT_LENGTH = 2000

app.config.from_object(Config)

# Security Headers
csp = {
    'default-src': ['\'self\''],
    'style-src': ['\'self\'', '\'unsafe-inline\'', 'https://cdn.jsdelivr.net'],
    'script-src': ['\'self\'', 'https://cdn.jsdelivr.net'],
    'font-src': ['\'self\'', 'https://cdn.jsdelivr.net']
}

Talisman(app, content_security_policy=csp, force_https=False)

# Enhanced Rate Limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[f"{Config.RATE_LIMIT_PER_HOUR}/hour"]
)

# Enhanced Logging
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

# Database connection pool
class DatabaseConnection:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init_pool()
        return cls._instance
    
    def _init_pool(self):
        self.pool = []
        for _ in range(5):  # Connection pool size
            conn = sqlite3.connect(Config.DB_NAME)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA cache_size=-64000")  # 64MB cache
            self.pool.append(conn)
    
    def get_connection(self):
        if not self.pool:
            self._init_pool()
        return self.pool.pop()
    
    def return_connection(self, conn):
        self.pool.append(conn)

db_pool = DatabaseConnection()

def get_db():
    """Get database connection from pool"""
    return db_pool.get_connection()

def return_db(conn):
    """Return connection to pool"""
    db_pool.return_connection(conn)

# ---------- Enhanced Helper Functions ----------
class ValidationError(Exception):
    pass

class SecurityUtils:
    @staticmethod
    def validate_username(username):
        """Enhanced username validation"""
        if len(username) < 3:
            raise ValidationError("Username must be at least 3 characters")
        if len(username) > Config.MAX_USERNAME_LENGTH:
            raise ValidationError(f"Username must be less than {Config.MAX_USERNAME_LENGTH} characters")
        if not re.match(r'^[a-zA-Z0-9_\-]+$', username):
            raise ValidationError("Username can only contain letters, numbers, underscores, and hyphens")
        if username.lower() in ['admin', 'administrator', 'moderator', 'system']:
            raise ValidationError("Username not allowed")
        return username.lower().strip()
    
    @staticmethod
    def validate_password(password):
        """Enhanced password validation"""
        if len(password) < Config.MIN_PASSWORD_LENGTH:
            raise ValidationError(f"Password must be at least {Config.MIN_PASSWORD_LENGTH} characters")
        
        # Check password strength
        checks = {
            'uppercase': bool(re.search(r'[A-Z]', password)),
            'lowercase': bool(re.search(r'[a-z]', password)),
            'digit': bool(re.search(r'\d', password)),
            'special': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        }
        
        if sum(checks.values()) < 3:
            raise ValidationError("Password must contain at least 3 of: uppercase, lowercase, digits, special characters")
        
        # Check for common passwords
        common_passwords = {'password', '123456', 'qwerty', 'letmein', 'welcome'}
        if password.lower() in common_passwords:
            raise ValidationError("Password is too common")
        
        return password
    
    @staticmethod
    def sanitize_html(content, max_length=None):
        """Enhanced HTML sanitization with bleach"""
        if not content:
            return content
        
        # Define allowed tags and attributes for rich text
        allowed_tags = bleach.sanitizer.ALLOWED_TAGS + [
            'p', 'br', 'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
            'ul', 'ol', 'li', 'strong', 'em', 'u', 'strike', 'blockquote',
            'code', 'pre', 'hr', 'table', 'thead', 'tbody', 'tr', 'th', 'td'
        ]
        
        allowed_attributes = {
            '*': ['class', 'style', 'id'],
            'a': ['href', 'title', 'target', 'rel'],
            'img': ['src', 'alt', 'width', 'height', 'title'],
            'code': ['class'],
            'span': ['style']
        }
        
        # Clean the content
        cleaned = bleach.clean(
            content,
            tags=allowed_tags,
            attributes=allowed_attributes,
            strip=True,
            strip_comments=True
        )
        
        # Additional security checks
        cleaned = re.sub(r'javascript:', '', cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r'vbscript:', '', cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r'on\w+=', '', cleaned, flags=re.IGNORECASE)
        
        # Limit length if specified
        if max_length and len(cleaned) > max_length:
            cleaned = cleaned[:max_length]
        
        return cleaned.strip()
    
    @staticmethod
    def generate_secure_token(length=32):
        """Generate cryptographically secure token"""
        return secrets.token_hex(length)
    
    @staticmethod
    def hash_password(password):
        """Enhanced password hashing"""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(Config.BCRYPT_ROUNDS))
    
    @staticmethod
    def check_password(password, hashed):
        """Verify password against hash"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed)
        except Exception:
            return False

class RateLimitManager:
    _instance = None
    _request_counts = {}
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def check_rate_limit(self, identifier, limit=100, window=3600):
        """Enhanced rate limiting with sliding window"""
        current_time = datetime.now().timestamp()
        window_start = current_time - window
        
        # Clean old entries
        self._request_counts[identifier] = [
            timestamp for timestamp in self._request_counts.get(identifier, [])
            if timestamp > window_start
        ]
        
        # Check if limit exceeded
        if len(self._request_counts[identifier]) >= limit:
            return False
        
        # Add current request
        self._request_counts[identifier].append(current_time)
        return True

rate_limit_manager = RateLimitManager()

def enhanced_rate_limit(limit=100, window=3600):
    """Enhanced rate limit decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            identifier = f"{request.remote_addr}_{f.__name__}"
            
            if not rate_limit_manager.check_rate_limit(identifier, limit, window):
                app.logger.warning(f"Rate limit exceeded for {identifier}")
                return jsonify({
                    "success": False, 
                    "error": "Rate limit exceeded. Please try again later."
                }), 429
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def token_required(f):
    """Enhanced token authentication decorator"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        
        if not token:
            return jsonify({"success": False, "error": "Authentication token required"}), 401
        
        conn = get_db()
        try:
            # Verify token format
            if not token.startswith('Bearer '):
                return jsonify({"success": False, "error": "Invalid token format"}), 401
            
            token = token[7:]  # Remove 'Bearer ' prefix
            
            decoded = jwt.decode(token, Config.SECRET_KEY, algorithms=["HS256"])
            
            # Verify user exists and is active
            c = conn.cursor()
            c.execute("""
                SELECT id, username, is_active, last_login, avatar_color 
                FROM users WHERE id = ?
            """, (decoded["user_id"],))
            user = c.fetchone()
            
            if not user:
                return jsonify({"success": False, "error": "User not found"}), 401
            
            if not user["is_active"]:
                return jsonify({"success": False, "error": "Account deactivated"}), 403
            
            # Check if token was issued before last password change (for future implementation)
            # This would require storing password change timestamp
            
            request.user_id = user["id"]
            request.username = user["username"]
            request.user_data = dict(user)
            
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"success": False, "error": "Invalid token"}), 401
        except Exception as e:
            app.logger.error(f"Token validation error: {e}")
            return jsonify({"success": False, "error": "Token validation failed"}), 401
        finally:
            return_db(conn)
        
        return f(*args, **kwargs)
    return decorated

def validate_json(schema=None):
    """Enhanced JSON validation decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                return jsonify({"success": False, "error": "Content-Type must be application/json"}), 400
            
            data = request.get_json(silent=True)
            if data is None:
                return jsonify({"success": False, "error": "Invalid JSON data"}), 400
            
            # Basic schema validation can be extended with Marshmallow
            if schema:
                # Placeholder for schema validation
                pass
                
            request.json_data = data
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ---------- Enhanced Database Schema ----------
def init_db():
    """Enhanced database initialization"""
    conn = get_db()
    try:
        c = conn.cursor()
        
        # Enhanced tables with better constraints
        c.executescript("""
            -- Enhanced users table
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                password TEXT NOT NULL,
                email TEXT UNIQUE,
                full_name TEXT,
                avatar_color TEXT DEFAULT '#007AFF',
                bio TEXT,
                created_at DATETIME NOT NULL DEFAULT (datetime('now')),
                last_login DATETIME,
                is_active BOOLEAN DEFAULT 1,
                reputation INTEGER DEFAULT 0,
                post_count INTEGER DEFAULT 0,
                comment_count INTEGER DEFAULT 0,
                like_count INTEGER DEFAULT 0,
                is_moderator BOOLEAN DEFAULT 0,
                is_admin BOOLEAN DEFAULT 0,
                email_verified BOOLEAN DEFAULT 0,
                verification_token TEXT,
                reset_token TEXT,
                reset_token_expiry DATETIME,
                last_password_change DATETIME DEFAULT (datetime('now'))
            );
            
            -- Enhanced posts table
            CREATE TABLE IF NOT EXISTS posts(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                category TEXT NOT NULL,
                title TEXT,
                content TEXT NOT NULL,
                content_search TEXT,
                timestamp DATETIME NOT NULL DEFAULT (datetime('now')),
                last_activity DATETIME NOT NULL DEFAULT (datetime('now')),
                likes_count INTEGER DEFAULT 0,
                comments_count INTEGER DEFAULT 0,
                is_pinned BOOLEAN DEFAULT 0,
                is_locked BOOLEAN DEFAULT 0,
                is_deleted BOOLEAN DEFAULT 0,
                tags TEXT,
                edited_at DATETIME,
                edited_by INTEGER,
                view_count INTEGER DEFAULT 0,
                featured_until DATETIME,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(edited_by) REFERENCES users(id) ON DELETE SET NULL
            );
            
            -- Enhanced comments table
            CREATE TABLE IF NOT EXISTS comments(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                timestamp DATETIME NOT NULL DEFAULT (datetime('now')),
                likes_count INTEGER DEFAULT 0,
                edited_at DATETIME,
                edited_by INTEGER,
                parent_comment_id INTEGER,
                is_deleted BOOLEAN DEFAULT 0,
                depth INTEGER DEFAULT 0,
                path TEXT DEFAULT '',
                FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(parent_comment_id) REFERENCES comments(id) ON DELETE CASCADE,
                FOREIGN KEY(edited_by) REFERENCES users(id) ON DELETE SET NULL
            );
            
            -- Enhanced likes table
            CREATE TABLE IF NOT EXISTS likes(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                post_id INTEGER,
                comment_id INTEGER,
                timestamp DATETIME NOT NULL DEFAULT (datetime('now')),
                type TEXT DEFAULT 'like', -- like, love, laugh, etc.
                UNIQUE(user_id, post_id, comment_id),
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
                FOREIGN KEY(comment_id) REFERENCES comments(id) ON DELETE CASCADE,
                CHECK((post_id IS NOT NULL AND comment_id IS NULL) OR (post_id IS NULL AND comment_id IS NOT NULL))
            );
            
            -- User sessions for better security
            CREATE TABLE IF NOT EXISTS user_sessions(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT UNIQUE NOT NULL,
                created_at DATETIME NOT NULL DEFAULT (datetime('now')),
                expires_at DATETIME NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                is_active BOOLEAN DEFAULT 1,
                last_activity DATETIME NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            
            -- Enhanced user activity log
            CREATE TABLE IF NOT EXISTS user_activity(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                user_agent TEXT,
                timestamp DATETIME NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            -- Enhanced categories table
            CREATE TABLE IF NOT EXISTS categories(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                color TEXT DEFAULT '#007AFF',
                is_active BOOLEAN DEFAULT 1,
                created_at DATETIME NOT NULL DEFAULT (datetime('now')),
                post_count INTEGER DEFAULT 0,
                last_post_date DATETIME
            );

            -- Bookmarks table
            CREATE TABLE IF NOT EXISTS bookmarks(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                post_id INTEGER NOT NULL,
                created_at DATETIME NOT NULL DEFAULT (datetime('now')),
                notes TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
                UNIQUE(user_id, post_id)
            );

            -- Reports table for moderation
            CREATE TABLE IF NOT EXISTS reports(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reporter_id INTEGER NOT NULL,
                post_id INTEGER,
                comment_id INTEGER,
                reason TEXT NOT NULL,
                description TEXT,
                status TEXT DEFAULT 'pending',
                created_at DATETIME NOT NULL DEFAULT (datetime('now')),
                resolved_at DATETIME,
                resolved_by INTEGER,
                FOREIGN KEY(reporter_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
                FOREIGN KEY(comment_id) REFERENCES comments(id) ON DELETE CASCADE,
                FOREIGN KEY(resolved_by) REFERENCES users(id) ON DELETE SET NULL
            );

            -- Notifications table
            CREATE TABLE IF NOT EXISTS notifications(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                type TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                data TEXT,
                is_read BOOLEAN DEFAULT 0,
                created_at DATETIME NOT NULL DEFAULT (datetime('now')),
                expires_at DATETIME,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)
        
        # Database migration for existing installations
        # Add missing columns if they don't exist
        migration_columns = [
            ("posts", "last_activity", "DATETIME DEFAULT (datetime('now'))"),
            ("posts", "content_search", "TEXT"),
            ("posts", "is_locked", "BOOLEAN DEFAULT 0"),
            ("posts", "is_deleted", "BOOLEAN DEFAULT 0"),
            ("posts", "featured_until", "DATETIME"),
            ("users", "is_moderator", "BOOLEAN DEFAULT 0"),
            ("users", "is_admin", "BOOLEAN DEFAULT 0"),
            ("users", "email_verified", "BOOLEAN DEFAULT 0"),
            ("users", "verification_token", "TEXT"),
            ("users", "reset_token", "TEXT"),
            ("users", "reset_token_expiry", "DATETIME"),
            ("users", "last_password_change", "DATETIME DEFAULT (datetime('now'))")
        ]
        
        for table, column, definition in migration_columns:
            try:
                c.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
                app.logger.info(f"Added column {table}.{column}")
            except sqlite3.OperationalError as e:
                if "duplicate column name" not in str(e):
                    app.logger.warning(f"Failed to add column {table}.{column}: {e}")
                # Column already exists, ignore
        
        # Enhanced indexes
        c.executescript("""
            CREATE INDEX IF NOT EXISTS idx_posts_user_category ON posts(user_id, category);
            CREATE INDEX IF NOT EXISTS idx_posts_timestamp ON posts(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_posts_last_activity ON posts(last_activity DESC);
            CREATE INDEX IF NOT EXISTS idx_posts_popularity ON posts(likes_count DESC, comments_count DESC);
            CREATE INDEX IF NOT EXISTS idx_posts_search ON posts(content_search);
            CREATE INDEX IF NOT EXISTS idx_comments_post_path ON comments(post_id, path);
            CREATE INDEX IF NOT EXISTS idx_comments_user ON comments(user_id, timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_likes_user ON likes(user_id, timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_users_reputation ON users(reputation DESC);
            CREATE INDEX IF NOT EXISTS idx_users_username ON users(username COLLATE NOCASE);
            CREATE INDEX IF NOT EXISTS idx_activity_user ON user_activity(user_id, timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_sessions_token ON user_sessions(session_token);
            CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id, expires_at);
            CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_bookmarks_user ON bookmarks(user_id, created_at DESC);
        """)
        
        # Insert default categories
        default_categories = [
            ('General', 'General discussions and topics', '#007AFF'),
            ('Technology', 'Tech news, programming, and gadgets', '#34C759'),
            ('Science', 'Scientific discoveries and discussions', '#FF9500'),
            ('Entertainment', 'Movies, games, and entertainment', '#AF52DE'),
            ('Sports', 'Sports news and discussions', '#FF3B30'),
            ('Politics', 'Political discussions and news', '#5856D6')
        ]
        
        c.executemany("""
            INSERT OR IGNORE INTO categories (name, description, color) 
            VALUES (?, ?, ?)
        """, default_categories)
        
        conn.commit()
        app.logger.info("Enhanced database schema initialized successfully")
        
    except Exception as e:
        app.logger.error(f"Database initialization error: {e}")
        raise
    finally:
        return_db(conn)
        
        # Insert default categories
        default_categories = [
            ('General', 'General discussions and topics', '#007AFF'),
            ('Technology', 'Tech news, programming, and gadgets', '#34C759'),
            ('Science', 'Scientific discoveries and discussions', '#FF9500'),
            ('Entertainment', 'Movies, games, and entertainment', '#AF52DE'),
            ('Sports', 'Sports news and discussions', '#FF3B30'),
            ('Politics', 'Political discussions and news', '#5856D6')
        ]
        
        c.executemany("""
            INSERT OR IGNORE INTO categories (name, description, color) 
            VALUES (?, ?, ?)
        """, default_categories)
        
        conn.commit()
        app.logger.info("Enhanced database schema initialized successfully")
        
    except Exception as e:
        app.logger.error(f"Database initialization error: {e}")
        raise
    finally:
        return_db(conn)

# Initialize database on startup
init_db()

# ---------- Enhanced Utility Functions ----------
def log_user_activity(user_id, action, details=None, log_ip=True):
    """Enhanced activity logging"""
    conn = get_db()
    try:
        c = conn.cursor()
        ip_address = request.remote_addr if log_ip else None
        user_agent = request.headers.get('User-Agent') if log_ip else None
        
        c.execute("""INSERT INTO user_activity 
                    (user_id, action, details, ip_address, user_agent) 
                    VALUES (?, ?, ?, ?, ?)""",
                 (user_id, action, str(details) if details else None, ip_address, user_agent))
        conn.commit()
    except Exception as e:
        app.logger.error(f"Activity logging error: {e}")
    finally:
        return_db(conn)

def create_notification(user_id, type, title, message, data=None, expires_hours=24):
    """Create user notification"""
    conn = get_db()
    try:
        c = conn.cursor()
        expires_at = datetime.now() + timedelta(hours=expires_hours) if expires_hours else None
        
        c.execute("""
            INSERT INTO notifications (user_id, type, title, message, data, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_id, type, title, message, data, expires_at))
        
        conn.commit()
        return c.lastrowid
    except Exception as e:
        app.logger.error(f"Notification creation error: {e}")
        return None
    finally:
        return_db(conn)

def update_post_activity(post_id):
    """Update post last activity timestamp"""
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("""
            UPDATE posts SET last_activity = datetime('now') 
            WHERE id = ?
        """, (post_id,))
        conn.commit()
    except Exception as e:
        app.logger.error(f"Post activity update error: {e}")
    finally:
        return_db(conn)

def format_timestamp(timestamp):
    """Enhanced timestamp formatting"""
    if not timestamp:
        return "Recently"
    
    try:
        post_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        now = datetime.now(post_time.tzinfo) if post_time.tzinfo else datetime.now()
        diff = now - post_time
        
        if diff.days > 365:
            years = diff.days // 365
            return f"{years} year{'s' if years > 1 else ''} ago"
        elif diff.days > 30:
            months = diff.days // 30
            return f"{months} month{'s' if months > 1 else ''} ago"
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

# ---------- Enhanced Routes ----------
@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/api/health')
def health_check():
    """Enhanced health check with more metrics"""
    conn = get_db()
    try:
        c = conn.cursor()
        
        # Database health
        c.execute("SELECT 1")
        db_status = "healthy"
        
        # System metrics
        c.execute("SELECT COUNT(*) as user_count FROM users WHERE is_active = 1")
        user_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) as post_count FROM posts WHERE is_deleted = 0")
        post_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) as active_users FROM users WHERE last_login > datetime('now', '-7 days')")
        active_users = c.fetchone()[0]
        
        # Performance metrics
        c.execute("SELECT COUNT(*) as pending_notifications FROM notifications WHERE is_read = 0")
        pending_notifications = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) as active_sessions FROM user_sessions WHERE is_active = 1 AND expires_at > datetime('now')")
        active_sessions = c.fetchone()[0]
        
        return jsonify({
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "version": "2.0.0",
            "database": db_status,
            "metrics": {
                "users": {
                    "total": user_count,
                    "active_week": active_users,
                    "active_sessions": active_sessions
                },
                "content": {
                    "posts": post_count,
                    "pending_notifications": pending_notifications
                }
            }
        })
        
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"
        return jsonify({
            "status": "degraded",
            "database": db_status,
            "error": str(e)
        }), 500
    finally:
        return_db(conn)

@app.route('/api/register', methods=['POST'])
@enhanced_rate_limit(limit=5, window=3600)  # 5 registrations per hour
@validate_json()
def register():
    """Enhanced user registration"""
    data = request.json_data
    
    try:
        # Validate input
        username = SecurityUtils.validate_username(data.get("username", ""))
        password = SecurityUtils.validate_password(data.get("password", ""))
        email = data.get("email")
        
        if email:
            if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
                raise ValidationError("Invalid email format")
        
        # Additional validations
        full_name = SecurityUtils.sanitize_html(data.get("full_name", ""), 50)
        bio = SecurityUtils.sanitize_html(data.get("bio", ""), 200)
        
        # Check if username/email already exists
        conn = get_db()
        c = conn.cursor()
        
        c.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
        if c.fetchone():
            raise ValidationError("Username or email already exists")
        
        # Create user
        hashed_pw = SecurityUtils.hash_password(password)
        avatar_color = generate_avatar_color()
        verification_token = SecurityUtils.generate_secure_token() if email else None
        
        c.execute("""INSERT INTO users 
                    (username, password, email, full_name, avatar_color, bio, verification_token) 
                    VALUES (?, ?, ?, ?, ?, ?, ?)""",
                 (username, hashed_pw, email, full_name, avatar_color, bio, verification_token))
        
        user_id = c.lastrowid
        conn.commit()
        
        # Log activity
        log_user_activity(user_id, "user_registered", {"email_provided": bool(email)})
        
        app.logger.info(f"New user registered: {username} (ID: {user_id})")
        
        return jsonify({
            "success": True, 
            "message": "Account created successfully",
            "user_id": user_id,
            "requires_verification": bool(email)
        })
    
    except ValidationError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "error": "Username or email already exists"}), 400
    except Exception as e:
        app.logger.error(f"Registration error: {e}")
        return jsonify({"success": False, "error": "Registration failed"}), 500
    finally:
        return_db(conn)

@app.route('/api/login', methods=['POST'])
@enhanced_rate_limit(limit=10, window=900)  # 10 attempts per 15 minutes
@validate_json()
def login():
    """Enhanced login with session management"""
    data = request.json_data
    
    try:
        username = data.get("username", "").strip().lower()
        password = data.get("password", "")
        remember_me = data.get("remember_me", False)
        
        if not username or not password:
            raise ValidationError("Username and password required")
        
        conn = get_db()
        c = conn.cursor()
        
        c.execute("""
            SELECT id, password, username, avatar_color, is_active, email_verified 
            FROM users WHERE username = ? OR email = ?
        """, (username, username))
        
        user = c.fetchone()
        
        if not user or not SecurityUtils.check_password(password, user["password"]):
            log_user_activity(None, "failed_login", {"username": username}, log_ip=True)
            raise ValidationError("Invalid credentials")
        
        if not user["is_active"]:
            raise ValidationError("Account deactivated")
        
        # Update last login
        c.execute("UPDATE users SET last_login = datetime('now') WHERE id = ?", (user["id"],))
        
        # Generate JWT token
        token_expiry = timedelta(hours=24) if remember_me else timedelta(hours=6)
        token = jwt.encode({
            "user_id": user["id"],
            "username": user["username"],
            "exp": datetime.utcnow() + token_expiry
        }, Config.SECRET_KEY, algorithm="HS256")
        
        # Create session record
        session_token = SecurityUtils.generate_secure_token()
        expires_at = datetime.now() + token_expiry
        
        c.execute("""
            INSERT INTO user_sessions 
            (user_id, session_token, expires_at, ip_address, user_agent) 
            VALUES (?, ?, ?, ?, ?)
        """, (user["id"], session_token, expires_at, request.remote_addr, request.headers.get('User-Agent')))
        
        conn.commit()
        
        # Log successful login
        log_user_activity(user["id"], "login_success")
        
        return jsonify({
            "success": True, 
            "token": token,
            "session_token": session_token,
            "expires_in": int(token_expiry.total_seconds()),
            "user": {
                "id": user["id"],
                "username": user["username"],
                "avatar_color": user["avatar_color"],
                "email_verified": user["email_verified"]
            }
        })
        
    except ValidationError as e:
        return jsonify({"success": False, "error": str(e)}), 401
    except Exception as e:
        app.logger.error(f"Login error: {e}")
        return jsonify({"success": False, "error": "Login failed"}), 500
    finally:
        return_db(conn)

@app.route('/api/logout', methods=['POST'])
@token_required
def logout():
    """Enhanced logout with session management"""
    session_token = request.headers.get('X-Session-Token')
    
    conn = get_db()
    try:
        c = conn.cursor()
        
        if session_token:
            c.execute("""
                UPDATE user_sessions SET is_active = 0 
                WHERE session_token = ? AND user_id = ?
            """, (session_token, request.user_id))
        
        log_user_activity(request.user_id, "logout")
        
        conn.commit()
        return jsonify({"success": True, "message": "Logged out successfully"})
        
    except Exception as e:
        app.logger.error(f"Logout error: {e}")
        return jsonify({"success": False, "error": "Logout failed"}), 500
    finally:
        return_db(conn)

# Enhanced posts endpoint with better performance
@app.route('/api/posts', methods=['GET', 'POST'])
@token_required
@enhanced_rate_limit(limit=100, window=3600)
def posts():
    if request.method == 'POST':
        return create_post()
    else:
        return get_posts()

def create_post():
    """Enhanced post creation"""
    data = request.json_data
    
    try:
        category = SecurityUtils.sanitize_html(data.get("category", ""), 50)
        content = SecurityUtils.sanitize_html(data.get("content", ""), Config.MAX_POST_LENGTH)
        title = SecurityUtils.sanitize_html(data.get("title", ""), 200)
        
        if len(content.strip()) < 10:
            raise ValidationError("Content must be at least 10 characters")
        
        # Validate category
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT name FROM categories WHERE name = ? AND is_active = 1", (category,))
        if not c.fetchone():
            raise ValidationError("Invalid category")
        
        # Create post
        c.execute("""
            INSERT INTO posts (user_id, category, title, content) 
            VALUES (?, ?, ?, ?)
        """, (request.user_id, category, title, content))
        
        post_id = c.lastrowid
        
        # Update user post count
        c.execute("UPDATE users SET post_count = post_count + 1 WHERE id = ?", (request.user_id,))
        
        # Update category post count
        c.execute("""
            UPDATE categories SET 
            post_count = post_count + 1,
            last_post_date = datetime('now')
            WHERE name = ?
        """, (category,))
        
        conn.commit()
        
        # Create notification for followers (future feature)
        log_user_activity(request.user_id, "post_created", {"post_id": post_id, "category": category})
        
        return jsonify({
            "success": True, 
            "message": "Post created successfully", 
            "post_id": post_id
        }), 201
        
    except ValidationError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        app.logger.error(f"Post creation error: {e}")
        return jsonify({"success": False, "error": "Failed to create post"}), 500
    finally:
        return_db(conn)

def get_posts():
    """Enhanced posts retrieval with better performance"""
    conn = get_db()
    try:
        c = conn.cursor()
        
        # Parse query parameters
        page = max(1, request.args.get('page', 1, type=int))
        per_page = min(max(1, request.args.get('per_page', 10, type=int)), 50)
        category = request.args.get('category', '')
        search = SecurityUtils.sanitize_html(request.args.get('search', ''), 100)
        sort = request.args.get('sort', 'newest')
        user_id = request.args.get('user_id', type=int)
        
        offset = (page - 1) * per_page
        
        # Build query based on parameters
        query = """
            SELECT p.*, u.username, u.avatar_color, u.reputation,
                   (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id AND c.is_deleted = 0) as real_comments_count
            FROM posts p 
            JOIN users u ON p.user_id = u.id 
            WHERE p.is_deleted = 0 AND u.is_active = 1
        """
        
        count_query = """
            SELECT COUNT(*) 
            FROM posts p 
            JOIN users u ON p.user_id = u.id 
            WHERE p.is_deleted = 0 AND u.is_active = 1
        """
        
        params = []
        
        # Apply filters
        if category:
            query += " AND p.category = ?"
            count_query += " AND p.category = ?"
            params.append(category)
        
        if search:
            query += " AND (p.content_search LIKE ? OR u.username LIKE ? OR p.title LIKE ?)"
            count_query += " AND (p.content_search LIKE ? OR u.username LIKE ? OR p.title LIKE ?)"
            search_term = f'%{search.lower()}%'
            params.extend([search_term, search_term, search_term])
        
        if user_id:
            query += " AND p.user_id = ?"
            count_query += " AND p.user_id = ?"
            params.append(user_id)
        
        # Apply sorting
        sort_options = {
            'newest': 'p.timestamp DESC',
            'oldest': 'p.timestamp ASC',
            'popular': 'p.likes_count DESC, p.comments_count DESC',
            'active': 'p.last_activity DESC',
            'trending': '(p.likes_count + p.comments_count * 0.5) / (1 + (julianday("now") - julianday(p.timestamp))) DESC'
        }
        
        query += f" ORDER BY {sort_options.get(sort, 'p.timestamp DESC')}"
        query += " LIMIT ? OFFSET ?"
        
        count_params = params.copy()
        params.extend([per_page, offset])
        
        # Get total count
        c.execute(count_query, count_params)
        total_count = c.fetchone()[0]
        
        # Get posts
        c.execute(query, params)
        rows = [dict(row) for row in c.fetchall()]
        
        # Check if user liked each post
        for post in rows:
            c.execute("SELECT id FROM likes WHERE user_id = ? AND post_id = ?", 
                     (request.user_id, post['id']))
            post['user_has_liked'] = c.fetchone() is not None
            
            # Check if bookmarked
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
        return_db(conn)

# Enhanced analytics endpoint
@app.route('/api/analytics/overview')
@token_required
@enhanced_rate_limit(limit=60, window=3600)
def get_analytics():
    """Enhanced analytics with more insights"""
    conn = get_db()
    try:
        c = conn.cursor()
        
        # Basic stats with caching potential
        stats = {}
        
        # User analytics
        c.execute("""
            SELECT 
                COUNT(*) as total_users,
                COUNT(CASE WHEN last_login > datetime('now', '-7 days') THEN 1 END) as active_week,
                COUNT(CASE WHEN last_login > datetime('now', '-1 day') THEN 1 END) as active_today,
                COUNT(CASE WHEN created_at > datetime('now', '-7 days') THEN 1 END) as new_users_week,
                AVG(reputation) as avg_reputation
            FROM users 
            WHERE is_active = 1
        """)
        stats['users'] = dict(c.fetchone())
        
        # Post analytics
        c.execute("""
            SELECT 
                COUNT(*) as total_posts,
                COUNT(CASE WHEN timestamp > datetime('now', '-7 days') THEN 1 END) as posts_week,
                COUNT(CASE WHEN timestamp > datetime('now', '-1 day') THEN 1 END) as posts_today,
                AVG(likes_count) as avg_likes,
                AVG(comments_count) as avg_comments,
                SUM(view_count) as total_views
            FROM posts
            WHERE is_deleted = 0
        """)
        stats['posts'] = dict(c.fetchone())
        
        # Engagement metrics
        c.execute("""
            SELECT
                COUNT(*) as total_likes,
                COUNT(*) as total_comments,
                COUNT(DISTINCT user_id) as active_posters,
                COUNT(DISTINCT (SELECT user_id FROM likes WHERE timestamp > datetime('now', '-7 days'))) as active_likers
            FROM posts p
            WHERE p.is_deleted = 0
        """)
        stats['engagement'] = dict(c.fetchone())
        
        # Popular categories with growth
        c.execute("""
            SELECT 
                c.name as category,
                c.post_count,
                c.color,
                COUNT(CASE WHEN p.timestamp > datetime('now', '-7 days') THEN 1 END) as posts_week,
                AVG(p.likes_count) as avg_likes,
                AVG(p.comments_count) as avg_comments
            FROM categories c
            LEFT JOIN posts p ON c.name = p.category AND p.is_deleted = 0
            WHERE c.is_active = 1
            GROUP BY c.id
            ORDER BY c.post_count DESC
            LIMIT 10
        """)
        stats['popular_categories'] = [dict(row) for row in c.fetchall()]
        
        # Top contributors
        c.execute("""
            SELECT 
                u.username,
                u.avatar_color,
                u.reputation,
                u.post_count,
                u.comment_count,
                u.like_count,
                (SELECT COUNT(*) FROM posts p2 WHERE p2.user_id = u.id AND p2.timestamp > datetime('now', '-7 days')) as posts_week,
                (SELECT SUM(p3.likes_count) FROM posts p3 WHERE p3.user_id = u.id) as total_likes_received
            FROM users u
            WHERE u.is_active = 1
            ORDER BY u.reputation DESC, u.post_count DESC
            LIMIT 10
        """)
        stats['top_contributors'] = [dict(row) for row in c.fetchall()]
        
        # Recent growth trends (last 30 days)
        c.execute("""
            SELECT 
                date(p.timestamp) as date,
                COUNT(*) as post_count,
                COUNT(DISTINCT p.user_id) as unique_posters,
                SUM(p.likes_count) as total_likes,
                SUM(p.comments_count) as total_comments
            FROM posts p
            WHERE p.timestamp > datetime('now', '-30 days') AND p.is_deleted = 0
            GROUP BY date(p.timestamp)
            ORDER BY date DESC
            LIMIT 30
        """)
        stats['recent_trends'] = [dict(row) for row in c.fetchall()]
        
        return jsonify({
            "success": True,
            "analytics": stats,
            "generated_at": datetime.now().isoformat()
        })
        
    except Exception as e:
        app.logger.error(f"Analytics error: {e}")
        return jsonify({"success": False, "error": "Failed to get analytics"}), 500
    finally:
        return_db(conn)

# New moderation endpoints
@app.route('/api/moderation/reports', methods=['GET', 'POST'])
@token_required
def moderation_reports():
    """Report management for moderators"""
    if request.method == 'POST':
        return create_report()
    else:
        return get_reports()

def create_report():
    """Create a new report"""
    data = request.json_data
    
    try:
        post_id = data.get('post_id')
        comment_id = data.get('comment_id')
        reason = SecurityUtils.sanitize_html(data.get('reason', ''), 200)
        description = SecurityUtils.sanitize_html(data.get('description', ''), 1000)
        
        if not reason:
            raise ValidationError("Report reason is required")
        
        if not post_id and not comment_id:
            raise ValidationError("Must report either a post or comment")
        
        conn = get_db()
        c = conn.cursor()
        
        # Verify the reported content exists
        if post_id:
            c.execute("SELECT id FROM posts WHERE id = ? AND is_deleted = 0", (post_id,))
            if not c.fetchone():
                raise ValidationError("Post not found")
        
        if comment_id:
            c.execute("SELECT id FROM comments WHERE id = ? AND is_deleted = 0", (comment_id,))
            if not c.fetchone():
                raise ValidationError("Comment not found")
        
        # Create report
        c.execute("""
            INSERT INTO reports (reporter_id, post_id, comment_id, reason, description)
            VALUES (?, ?, ?, ?, ?)
        """, (request.user_id, post_id, comment_id, reason, description))
        
        report_id = c.lastrowid
        conn.commit()
        
        # Notify moderators (simplified - in production, this would be more sophisticated)
        c.execute("SELECT id FROM users WHERE is_moderator = 1 OR is_admin = 1")
        moderators = c.fetchall()
        
        for mod in moderators:
            create_notification(
                mod['id'],
                'new_report',
                'New Content Report',
                f'New report submitted requiring review',
                f'{{"report_id": {report_id}}}'
            )
        
        log_user_activity(request.user_id, "report_created", {"report_id": report_id})
        
        return jsonify({
            "success": True,
            "message": "Report submitted successfully",
            "report_id": report_id
        })
        
    except ValidationError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        app.logger.error(f"Report creation error: {e}")
        return jsonify({"success": False, "error": "Failed to create report"}), 500
    finally:
        return_db(conn)

def get_reports():
    """Get reports (moderators only)"""
    conn = get_db()
    try:
        # Check if user is moderator
        c = conn.cursor()
        c.execute("SELECT is_moderator, is_admin FROM users WHERE id = ?", (request.user_id,))
        user = c.fetchone()
        
        if not user['is_moderator'] and not user['is_admin']:
            return jsonify({"success": False, "error": "Insufficient permissions"}), 403
        
        status = request.args.get('status', 'pending')
        page = max(1, request.args.get('page', 1, type=int))
        per_page = min(max(1, request.args.get('per_page', 20, type=int)), 50)
        offset = (page - 1) * per_page
        
        query = """
            SELECT r.*, 
                   u.username as reporter_username,
                   p.content as post_content,
                   c.content as comment_content,
                   pu.username as post_username,
                   cu.username as comment_username
            FROM reports r
            JOIN users u ON r.reporter_id = u.id
            LEFT JOIN posts p ON r.post_id = p.id
            LEFT JOIN users pu ON p.user_id = pu.id
            LEFT JOIN comments c ON r.comment_id = c.id
            LEFT JOIN users cu ON c.user_id = cu.id
            WHERE r.status = ?
            ORDER BY r.created_at DESC
            LIMIT ? OFFSET ?
        """
        
        c.execute(query, (status, per_page, offset))
        reports = [dict(row) for row in c.fetchall()]
        
        return jsonify({
            "success": True,
            "data": reports,
            "pagination": {
                "page": page,
                "per_page": per_page
            }
        })
        
    except Exception as e:
        app.logger.error(f"Reports retrieval error: {e}")
        return jsonify({"success": False, "error": "Failed to retrieve reports"}), 500
    finally:
        return_db(conn)

# Enhanced error handlers
@app.errorhandler(404)
def not_found(e): 
    return jsonify({"success": False, "error": "Endpoint not found"}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"success": False, "error": "Method not allowed"}), 405

@app.errorhandler(500)
def server_error(e): 
    app.logger.error(f"500 error: {str(e)}")
    return jsonify({"success": False, "error": "Internal server error"}), 500

@app.errorhandler(413)
def too_large(e):
    return jsonify({"success": False, "error": "Request body too large"}), 413

# Request logging middleware
@app.before_request
def log_request_info():
    """Log request information for security and debugging"""
    if request.endpoint and request.endpoint != 'static':
        app.logger.info(f"{request.method} {request.path} - IP: {request.remote_addr}")

@app.after_request
def after_request(response):
    """Add security headers and log response"""
    # Security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Log response status for monitoring
    if request.endpoint and request.endpoint != 'static':
        app.logger.info(f"{request.method} {request.path} - Status: {response.status_code}")
    
    return response

# Utility function
def generate_avatar_color():
    colors = ['#007AFF', '#34C759', '#FF9500', '#FF3B30', '#AF52DE', '#5856D6', '#FF2D55', '#32D74B']
    return random.choice(colors)

if __name__ == '__main__':
    # Production configuration
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5000)),
        debug=os.environ.get('DEBUG', 'False').lower() == 'true',
        threaded=True
    )