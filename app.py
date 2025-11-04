from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sqlite3, os, jwt, bcrypt, uuid
from datetime import datetime, timedelta
import random
import re
from functools import wraps
import logging
from logging.handlers import RotatingFileHandler
import atexit
import threading

app = Flask(__name__)
CORS(app)

# Enhanced Configuration
DB_NAME = "edgepowered_forum.db"
SECRET_KEY = os.environ.get('SECRET_KEY', 'edgepowered-super-secure-key-2024')
RATE_LIMIT = int(os.environ.get('RATE_LIMIT', '100'))
MAX_DB_CONNECTIONS = int(os.environ.get('MAX_DB_CONNECTIONS', '10'))

# Enhanced Logging
if not os.path.exists('logs'):
    os.makedirs('logs')

file_handler = RotatingFileHandler('logs/edgepowered.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)

# Rate limiting storage
request_counts = {}

# ---------- Professional Database Layer ----------
class DatabaseManager:
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(DatabaseManager, cls).__new__(cls)
                cls._instance._init_db()
            return cls._instance
    
    def _init_db(self):
        self.connections = {}
        self.init_database_schema()
    
    def get_connection(self, thread_id=None):
        if thread_id is None:
            thread_id = threading.get_ident()
        
        if thread_id not in self.connections:
            conn = sqlite3.connect(DB_NAME, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            conn.execute("PRAGMA cache_size = -64000")
            self.connections[thread_id] = conn
        
        return self.connections[thread_id]
    
    def close_connection(self, thread_id=None):
        if thread_id is None:
            thread_id = threading.get_ident()
        
        if thread_id in self.connections:
            self.connections[thread_id].close()
            del self.connections[thread_id]
    
    def close_all_connections(self):
        for conn in self.connections.values():
            conn.close()
        self.connections.clear()
    
    def init_database_schema(self):
        conn = self.get_connection()
        try:
            c = conn.cursor()
            
            # Enable WAL mode for better concurrency
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=NORMAL")
            
            # Create tables with proper constraints
            c.executescript("""
                -- Users table with enhanced constraints
                CREATE TABLE IF NOT EXISTS users(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL CHECK(length(username) >= 3 AND length(username) <= 20),
                    password TEXT NOT NULL CHECK(length(password) >= 6),
                    email TEXT CHECK(email IS NULL OR email LIKE '%_@__%.__%'),
                    full_name TEXT CHECK(full_name IS NULL OR length(full_name) <= 50),
                    avatar_color TEXT DEFAULT '#007AFF' CHECK(length(avatar_color) = 7),
                    bio TEXT CHECK(bio IS NULL OR length(bio) <= 200),
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    last_login TEXT,
                    is_active BOOLEAN DEFAULT 1 CHECK(is_active IN (0, 1)),
                    reputation INTEGER DEFAULT 0
                );
                
                -- Posts table with proper indexing
                CREATE TABLE IF NOT EXISTS posts(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    category TEXT NOT NULL CHECK(length(category) <= 50),
                    title TEXT CHECK(title IS NULL OR length(title) <= 100),
                    content TEXT NOT NULL CHECK(length(content) >= 10 AND length(content) <= 1000),
                    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                    likes_count INTEGER DEFAULT 0 CHECK(likes_count >= 0),
                    comments_count INTEGER DEFAULT 0 CHECK(comments_count >= 0),
                    is_pinned BOOLEAN DEFAULT 0 CHECK(is_pinned IN (0, 1)),
                    tags TEXT CHECK(tags IS NULL OR length(tags) <= 100),
                    edited_at TEXT,
                    view_count INTEGER DEFAULT 0 CHECK(view_count >= 0),
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                
                -- Comments table with hierarchy support
                CREATE TABLE IF NOT EXISTS comments(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    post_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    content TEXT NOT NULL CHECK(length(content) >= 2 AND length(content) <= 500),
                    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                    likes_count INTEGER DEFAULT 0 CHECK(likes_count >= 0),
                    edited_at TEXT,
                    parent_comment_id INTEGER,
                    is_deleted BOOLEAN DEFAULT 0 CHECK(is_deleted IN (0, 1)),
                    FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY(parent_comment_id) REFERENCES comments(id) ON DELETE CASCADE
                );
                
                -- Likes table with unique constraints
                CREATE TABLE IF NOT EXISTS likes(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    post_id INTEGER,
                    comment_id INTEGER,
                    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                    UNIQUE(user_id, post_id) WHERE post_id IS NOT NULL,
                    UNIQUE(user_id, comment_id) WHERE comment_id IS NOT NULL,
                    CHECK((post_id IS NOT NULL AND comment_id IS NULL) OR (post_id IS NULL AND comment_id IS NOT NULL)),
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
                    FOREIGN KEY(comment_id) REFERENCES comments(id) ON DELETE CASCADE
                );
                
                -- User sessions for analytics
                CREATE TABLE IF NOT EXISTS user_sessions(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    session_start TEXT NOT NULL DEFAULT (datetime('now')),
                    session_end TEXT,
                    page_views INTEGER DEFAULT 0 CHECK(page_views >= 0),
                    ip_address TEXT,
                    user_agent TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                
                -- User activity log
                CREATE TABLE IF NOT EXISTS user_activity(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    action TEXT NOT NULL CHECK(length(action) <= 50),
                    details TEXT,
                    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                    ip_address TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                
                -- Create comprehensive indexes for performance
                CREATE INDEX IF NOT EXISTS idx_posts_user_id ON posts(user_id);
                CREATE INDEX IF NOT EXISTS idx_posts_category ON posts(category);
                CREATE INDEX IF NOT EXISTS idx_posts_timestamp ON posts(timestamp);
                CREATE INDEX IF NOT EXISTS idx_posts_likes ON posts(likes_count);
                CREATE INDEX IF NOT EXISTS idx_comments_post_id ON comments(post_id);
                CREATE INDEX IF NOT EXISTS idx_comments_user_id ON comments(user_id);
                CREATE INDEX IF NOT EXISTS idx_likes_user_post ON likes(user_id, post_id);
                CREATE INDEX IF NOT EXISTS idx_likes_user_comment ON likes(user_id, comment_id);
                CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
                CREATE INDEX IF NOT EXISTS idx_users_reputation ON users(reputation);
                CREATE INDEX IF NOT EXISTS idx_user_activity_user_id ON user_activity(user_id);
                CREATE INDEX IF NOT EXISTS idx_user_activity_timestamp ON user_activity(timestamp);
                CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
            """)
            
            conn.commit()
            app.logger.info("Database schema initialized successfully")
            
        except Exception as e:
            app.logger.error(f"Database initialization error: {e}")
            raise
        finally:
            self.close_connection()

# Initialize database manager
db_manager = DatabaseManager()

# Cleanup on exit
atexit.register(db_manager.close_all_connections)

def get_db():
    """Get database connection for current thread"""
    return db_manager.get_connection()

# ---------- Enhanced Helper Functions ----------
def rate_limit(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        client_ip = request.remote_addr
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M")
        key = f"{client_ip}_{current_time}"
        
        if key not in request_counts:
            request_counts[key] = 0
        
        request_counts[key] += 1
        
        if request_counts[key] > RATE_LIMIT:
            return jsonify({
                "success": False, 
                "error": "Rate limit exceeded. Please try again later."
            }), 429
        
        return func(*args, **kwargs)
    return wrapper

def token_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token:
            return jsonify({"success": False, "error": "Missing token"}), 401
        
        conn = get_db()
        try:
            decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            # Verify user exists and is active
            c = conn.cursor()
            c.execute("SELECT id, username, is_active FROM users WHERE id = ?", (decoded["user_id"],))
            user = c.fetchone()
            
            if not user:
                return jsonify({"success": False, "error": "User not found"}), 401
            
            if not user["is_active"]:
                return jsonify({"success": False, "error": "Account deactivated"}), 403
            
            request.user_id = decoded["user_id"]
            request.username = decoded["username"]
            
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "error": "Token expired"}), 401
        except Exception as e:
            app.logger.warning(f"Invalid token attempt: {e}")
            return jsonify({"success": False, "error": "Invalid token"}), 401
        
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

def validate_fields(data, required):
    for field in required:
        if not data.get(field):
            return False, f"Missing field: {field}"
    return True, None

def sanitize_input(text, max_length=1000):
    """Sanitize user input to prevent XSS and other attacks"""
    if not text:
        return text
    
    # Remove potentially dangerous characters and patterns
    text = re.sub(r'<script.*?>.*?</script>', '', text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r'javascript:', '', text, flags=re.IGNORECASE)
    text = re.sub(r'on\w+=', '', text, flags=re.IGNORECASE)
    text = re.sub(r'vbscript:', '', text, flags=re.IGNORECASE)
    text = re.sub(r'expression\(', '', text, flags=re.IGNORECASE)
    
    # Limit length
    if len(text) > max_length:
        text = text[:max_length]
    
    return text.strip()

def validate_username(username):
    """Validate username format"""
    if len(username) < 3:
        return False, "Username must be at least 3 characters"
    if len(username) > 20:
        return False, "Username must be less than 20 characters"
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscores"
    return True, None

def validate_password(password):
    """Validate password strength"""
    if len(password) < 6:
        return False, "Password must be at least 6 characters"
    return True, None

def generate_avatar_color():
    colors = ['#007AFF', '#34C759', '#FF9500', '#FF3B30', '#AF52DE', '#5856D6']
    return random.choice(colors)

def calculate_user_reputation(user_id):
    """Calculate user reputation based on activity"""
    conn = get_db()
    c = conn.cursor()
    try:
        c.execute("""
            SELECT 
                (COUNT(DISTINCT p.id) * 10) + 
                (COUNT(DISTINCT c.id) * 3) + 
                (COUNT(DISTINCT l.id) * 1) as reputation
            FROM users u
            LEFT JOIN posts p ON u.id = p.user_id
            LEFT JOIN comments c ON u.id = c.user_id  
            LEFT JOIN likes l ON u.id = l.user_id
            WHERE u.id = ?
        """, (user_id,))
        result = c.fetchone()
        return result[0] or 0 if result else 0
    except Exception as e:
        app.logger.error(f"Reputation calculation error: {e}")
        return 0

def update_user_reputation(user_id):
    """Update user reputation in database"""
    conn = get_db()
    c = conn.cursor()
    try:
        reputation = calculate_user_reputation(user_id)
        c.execute("UPDATE users SET reputation = ? WHERE id = ?", (reputation, user_id))
        conn.commit()
        return reputation
    except Exception as e:
        app.logger.error(f"Reputation update error: {e}")
        conn.rollback()
        return 0

def log_user_activity(user_id, action, details=None, ip_address=None):
    """Log user activity with error handling"""
    conn = get_db()
    c = conn.cursor()
    try:
        c.execute("""INSERT INTO user_activity 
                    (user_id, action, details, timestamp, ip_address) 
                    VALUES (?, ?, ?, ?, ?)""",
                 (user_id, action, str(details) if details else None, 
                  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                  ip_address or request.remote_addr))
        conn.commit()
    except Exception as e:
        app.logger.error(f"Activity logging error: {e}")
        conn.rollback()

def get_client_info():
    """Get client information for analytics"""
    return {
        'ip_address': request.remote_addr,
        'user_agent': request.headers.get('User-Agent', ''),
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

# ---------- Enhanced Routes ----------
@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/api/health')
def health_check():
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT 1")
        db_status = "healthy"
        
        # Get some basic stats
        c.execute("SELECT COUNT(*) as user_count FROM users")
        user_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) as post_count FROM posts")
        post_count = c.fetchone()[0]
        
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"
        user_count = post_count = 0
    
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "version": "4.0.0",
        "database": db_status,
        "stats": {
            "users": user_count,
            "posts": post_count
        },
        "rate_limit_remaining": RATE_LIMIT - request_counts.get(f"{request.remote_addr}_{datetime.now().strftime('%Y-%m-%d %H:%M')}", 0)
    })

@app.route('/api/debug/db')
def debug_db():
    """Debug endpoint to check database status"""
    conn = get_db()
    c = conn.cursor()
    try:
        # Check if tables exist
        c.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row['name'] for row in c.fetchall()]
        
        # Get table counts
        stats = {}
        for table in tables:
            c.execute(f"SELECT COUNT(*) as count FROM {table}")
            stats[table] = c.fetchone()[0]
        
        return jsonify({
            "success": True,
            "tables": tables,
            "stats": stats,
            "status": "Database connected and healthy"
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# Enhanced registration with validation
@app.route('/api/register', methods=['POST'])
@rate_limit
def register():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "No data provided"}), 400

    valid, msg = validate_fields(data, ["username", "password"])
    if not valid:
        return jsonify({"success": False, "error": msg}), 400

    # Validate username and password
    valid_username, username_msg = validate_username(data["username"])
    if not valid_username:
        return jsonify({"success": False, "error": username_msg}), 400
    
    valid_password, password_msg = validate_password(data["password"])
    if not valid_password:
        return jsonify({"success": False, "error": password_msg}), 400

    # Sanitize inputs
    username = sanitize_input(data["username"], 20)
    email = sanitize_input(data.get("email", ""), 50)
    full_name = sanitize_input(data.get("full_name", ""), 50)
    bio = sanitize_input(data.get("bio", ""), 200)

    hashed_pw = bcrypt.hashpw(data["password"].encode(), bcrypt.gensalt())
    avatar_color = generate_avatar_color()

    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("""INSERT INTO users 
                    (username, password, email, full_name, avatar_color, bio) 
                    VALUES (?, ?, ?, ?, ?, ?)""",
                 (username, hashed_pw, email, full_name, avatar_color, bio))
        conn.commit()
        
        app.logger.info(f"New EdgePowered user registered: {username}")
        return jsonify({"success": True, "message": "EdgePowered account created successfully"})
    
    except sqlite3.IntegrityError as e:
        if "username" in str(e):
            return jsonify({"success": False, "error": "Username already exists"}), 400
        return jsonify({"success": False, "error": "Registration failed"}), 400
    except Exception as e:
        app.logger.error(f"Registration error: {e}")
        conn.rollback()
        return jsonify({"success": False, "error": "Registration failed"}), 500

# Enhanced login with security features
@app.route('/api/login', methods=['POST'])
@rate_limit
def login():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "No data provided"}), 400

    valid, msg = validate_fields(data, ["username", "password"])
    if not valid:
        return jsonify({"success": False, "error": msg}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, password, username, avatar_color, is_active FROM users WHERE username=?", (data["username"],))
    user = c.fetchone()

    if not user or not bcrypt.checkpw(data["password"].encode(), user["password"]):
        app.logger.warning(f"Failed login attempt for username: {data['username']}")
        return jsonify({"success": False, "error": "Invalid credentials"}), 401

    if not user["is_active"]:
        return jsonify({"success": False, "error": "Account deactivated"}), 403

    # Start user session with client info
    client_info = get_client_info()
    try:
        c.execute("""INSERT INTO user_sessions 
                    (user_id, session_start, ip_address, user_agent) 
                    VALUES (?, ?, ?, ?)""",
                 (user["id"], client_info['timestamp'], 
                  client_info['ip_address'], client_info['user_agent']))
        
        # Update last login
        c.execute("UPDATE users SET last_login = ? WHERE id = ?", 
                 (client_info['timestamp'], user["id"]))
        
        conn.commit()

    except Exception as e:
        app.logger.error(f"Session logging error: {e}")
        conn.rollback()

    token = jwt.encode({
        "user_id": user["id"],
        "username": user["username"],
        "exp": datetime.utcnow() + timedelta(hours=24)
    }, SECRET_KEY, algorithm="HS256")

    # Log successful login
    log_user_activity(user["id"], "login", client_info, client_info['ip_address'])

    return jsonify({
        "success": True, 
        "token": token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "avatar_color": user["avatar_color"]
        }
    })

# Enhanced posts with security and performance
@app.route('/api/posts', methods=['GET', 'POST'])
@token_required
@rate_limit
def posts():
    conn = get_db()
    
    if request.method == 'POST':
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
            
        valid, msg = validate_fields(data, ["category", "content"])
        if not valid:
            return jsonify({"success": False, "error": msg}), 400
        
        # Sanitize content
        category = sanitize_input(data["category"], 50)
        title = sanitize_input(data.get("title", ""), 100)
        content = sanitize_input(data["content"], 1000)
        tags = sanitize_input(data.get("tags", ""), 100)
        
        if len(content) < 10:
            return jsonify({"success": False, "error": "Content must be at least 10 characters"}), 400

        try:
            c = conn.cursor()
            c.execute("""INSERT INTO posts 
                        (user_id, category, title, content, tags) 
                        VALUES (?, ?, ?, ?, ?)""",
                     (request.user_id, category, title, content, tags))
            post_id = c.lastrowid
            
            # Update user reputation
            update_user_reputation(request.user_id)
            
            conn.commit()
            
            # Log activity
            log_user_activity(request.user_id, "post_created", 
                            {"post_id": post_id, "category": category})
            
            return jsonify({
                "success": True, 
                "message": "Post added to EdgePowered", 
                "post_id": post_id
            }), 201
            
        except Exception as e:
            app.logger.error(f"Post creation error: {e}")
            conn.rollback()
            return jsonify({"success": False, "error": "Failed to create post"}), 500

    # GET posts with pagination and filtering
    try:
        c = conn.cursor()
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 10, type=int), 50)
        category = request.args.get('category', '')
        search = sanitize_input(request.args.get('search', ''), 50)
        time_filter = request.args.get('time_filter', '')
        sort_by = request.args.get('sort_by', 'newest')
        
        offset = (page - 1) * per_page
        
        query = """SELECT p.*, u.username, u.avatar_color, u.reputation 
                   FROM posts p 
                   JOIN users u ON p.user_id = u.id 
                   WHERE u.is_active = 1"""
        count_query = """SELECT COUNT(*) 
                        FROM posts p 
                        JOIN users u ON p.user_id = u.id 
                        WHERE u.is_active = 1"""
        params = []
        
        conditions = []
        if category:
            conditions.append("p.category = ?")
            params.append(category)
        
        if search:
            conditions.append("(p.content LIKE ? OR p.title LIKE ? OR p.tags LIKE ?)")
            params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])
        
        if time_filter:
            if time_filter == 'today':
                conditions.append("p.timestamp >= date('now')")
            elif time_filter == 'week':
                conditions.append("p.timestamp >= datetime('now', '-7 days')")
            elif time_filter == 'month':
                conditions.append("p.timestamp >= datetime('now', '-30 days')")
        
        if conditions:
            where_clause = " AND " + " AND ".join(conditions)
            query += where_clause
            count_query += where_clause
        
        # Apply sorting
        if sort_by == 'popular':
            query += " ORDER BY p.likes_count DESC, p.comments_count DESC"
        elif sort_by == 'trending':
            query += " ORDER BY (p.likes_count * 0.7 + p.comments_count * 0.3) DESC"
        else:  # newest
            query += " ORDER BY p.is_pinned DESC, p.timestamp DESC"
        
        query += " LIMIT ? OFFSET ?"
        params.extend([per_page, offset])
        
        # Get total count
        c.execute(count_query, params[:-2])
        total_count = c.fetchone()[0]
        
        # Get posts
        c.execute(query, params)
        rows = [dict(row) for row in c.fetchall()]
        
        # Check if user liked each post
        for post in rows:
            c.execute("SELECT id FROM likes WHERE user_id = ? AND post_id = ?", (request.user_id, post['id']))
            post['user_has_liked'] = c.fetchone() is not None
        
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

# Enhanced like system
@app.route('/api/posts/<int:post_id>/like', methods=['POST'])
@token_required
@rate_limit
def like_post(post_id):
    conn = get_db()
    try:
        c = conn.cursor()
        
        # Verify post exists
        c.execute("SELECT id, user_id FROM posts WHERE id = ?", (post_id,))
        post = c.fetchone()
        if not post:
            return jsonify({"success": False, "error": "Post not found"}), 404
        
        # Check if already liked
        c.execute("SELECT id FROM likes WHERE user_id = ? AND post_id = ?", (request.user_id, post_id))
        existing_like = c.fetchone()
        
        if existing_like:
            # Unlike
            c.execute("DELETE FROM likes WHERE id = ?", (existing_like["id"],))
            c.execute("UPDATE posts SET likes_count = likes_count - 1 WHERE id = ?", (post_id,))
            action = "unliked"
        else:
            # Like
            c.execute("INSERT INTO likes (user_id, post_id) VALUES (?, ?)",
                     (request.user_id, post_id))
            c.execute("UPDATE posts SET likes_count = likes_count + 1 WHERE id = ?", (post_id,))
            action = "liked"
        
        # Update reputations
        update_user_reputation(request.user_id)  # Liker's reputation
        update_user_reputation(post["user_id"])  # Post owner's reputation
        
        conn.commit()
        
        # Get updated like count
        c.execute("SELECT likes_count FROM posts WHERE id = ?", (post_id,))
        likes_count = c.fetchone()["likes_count"]
        
        # Log activity
        log_user_activity(request.user_id, f"post_{action}", {"post_id": post_id})
        
        return jsonify({
            "success": True, 
            "action": action,
            "likes_count": likes_count
        })
        
    except Exception as e:
        app.logger.error(f"Like operation error: {e}")
        conn.rollback()
        return jsonify({"success": False, "error": "Like operation failed"}), 500

# [Include all other endpoints from previous version with similar error handling...]
# Comments, analytics, recommendations, search, etc.

# Enhanced error handlers
@app.errorhandler(404)
def not_found(e): 
    app.logger.warning(f"404 error: {request.url}")
    return jsonify({"success": False, "error": "Endpoint not found"}), 404

@app.errorhandler(500)
def server_error(e): 
    app.logger.error(f"500 error: {str(e)}")
    return jsonify({"success": False, "error": "Internal server error"}), 500

@app.errorhandler(413)
def too_large(e):
    return jsonify({"success": False, "error": "File too large"}), 413

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        "success": False, 
        "error": "Rate limit exceeded. Please try again later."
    }), 429

if __name__ == '__main__':
    app.run(debug=True)