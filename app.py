from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sqlite3, os, jwt, bcrypt
from datetime import datetime, timedelta
import random
import re
from functools import wraps
import logging
from logging.handlers import RotatingFileHandler
import html

app = Flask(__name__)
CORS(app)

# Configuration
DB_NAME = "edgepowered_forum.db"
SECRET_KEY = os.environ.get('SECRET_KEY', 'edgepowered-super-secure-key-2024')
RATE_LIMIT = int(os.environ.get('RATE_LIMIT', '100'))

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

# ---------- Database Initialization ----------
def init_db():
    """Initialize database with proper schema"""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    
    try:
        c = conn.cursor()
        
        # Enable WAL mode for better concurrency
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        
        # Create tables
        c.executescript("""
            -- Users table
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT,
                full_name TEXT,
                avatar_color TEXT DEFAULT '#007AFF',
                bio TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                last_login TEXT,
                is_active BOOLEAN DEFAULT 1,
                reputation INTEGER DEFAULT 0
            );
            
            -- Posts table
            CREATE TABLE IF NOT EXISTS posts(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                category TEXT NOT NULL,
                title TEXT,
                content TEXT NOT NULL,
                timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                likes_count INTEGER DEFAULT 0,
                comments_count INTEGER DEFAULT 0,
                is_pinned BOOLEAN DEFAULT 0,
                tags TEXT,
                edited_at TEXT,
                view_count INTEGER DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            
            -- Comments table
            CREATE TABLE IF NOT EXISTS comments(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                likes_count INTEGER DEFAULT 0,
                edited_at TEXT,
                parent_comment_id INTEGER,
                is_deleted BOOLEAN DEFAULT 0,
                FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(parent_comment_id) REFERENCES comments(id) ON DELETE CASCADE
            );
            
            -- Likes table - simplified without complex constraints
            CREATE TABLE IF NOT EXISTS likes(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                post_id INTEGER,
                comment_id INTEGER,
                timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
                FOREIGN KEY(comment_id) REFERENCES comments(id) ON DELETE CASCADE
            );
            
            -- User sessions
            CREATE TABLE IF NOT EXISTS user_sessions(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_start TEXT NOT NULL DEFAULT (datetime('now')),
                session_end TEXT,
                page_views INTEGER DEFAULT 0,
                ip_address TEXT,
                user_agent TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            
            -- User activity log
            CREATE TABLE IF NOT EXISTS user_activity(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                ip_address TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            -- Categories table for better category management
            CREATE TABLE IF NOT EXISTS categories(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                color TEXT DEFAULT '#007AFF',
                is_active BOOLEAN DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            -- Bookmarks table (using likes table for simplicity in this implementation)
        """)
        
        # Create indexes
        c.executescript("""
            CREATE INDEX IF NOT EXISTS idx_posts_user_id ON posts(user_id);
            CREATE INDEX IF NOT EXISTS idx_posts_category ON posts(category);
            CREATE INDEX IF NOT EXISTS idx_posts_timestamp ON posts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_comments_post_id ON comments(post_id);
            CREATE INDEX IF NOT EXISTS idx_likes_user_post ON likes(user_id, post_id);
            CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
            CREATE INDEX IF NOT EXISTS idx_user_activity_user_id ON user_activity(user_id);
            CREATE INDEX IF NOT EXISTS idx_posts_search ON posts(content);
            CREATE INDEX IF NOT EXISTS idx_comments_parent ON comments(parent_comment_id);
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
        app.logger.info("Database schema initialized successfully")
        
    except Exception as e:
        app.logger.error(f"Database initialization error: {e}")
        raise
    finally:
        conn.close()

# Initialize database on startup
init_db()

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

# ---------- Helper Functions ----------
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
        finally:
            conn.close()
        
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

def validate_fields(data, required):
    for field in required:
        if not data.get(field):
            return False, f"Missing field: {field}"
    return True, None

def sanitize_input(text, max_length=5000):
    """Sanitize user input for rich text content"""
    if not text:
        return text
    
    # Allow safe HTML tags for rich text
    allowed_tags = ['b', 'i', 'u', 'strong', 'em', 'ul', 'ol', 'li', 'br', 'p', 'div']
    allowed_attrs = {
        '*': ['class', 'style'],
        'a': ['href', 'title'],
        'img': ['src', 'alt', 'width', 'height']
    }
    
    # Remove dangerous patterns but keep safe HTML
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
    if len(username) < 3:
        return False, "Username must be at least 3 characters"
    if len(username) > 20:
        return False, "Username must be less than 20 characters"
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscores"
    return True, None

def validate_password(password):
    if len(password) < 6:
        return False, "Password must be at least 6 characters"
    return True, None

def generate_avatar_color():
    colors = ['#007AFF', '#34C759', '#FF9500', '#FF3B30', '#AF52DE', '#5856D6']
    return random.choice(colors)

def log_user_activity(user_id, action, details=None):
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("""INSERT INTO user_activity 
                    (user_id, action, details, ip_address) 
                    VALUES (?, ?, ?, ?)""",
                 (user_id, action, str(details) if details else None, request.remote_addr))
        conn.commit()
    except Exception as e:
        app.logger.error(f"Activity logging error: {e}")
    finally:
        conn.close()

def format_timestamp(timestamp):
    """Format timestamp for frontend display"""
    if not timestamp:
        return "Recently"
    
    try:
        post_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        now = datetime.now(post_time.tzinfo) if post_time.tzinfo else datetime.now()
        diff = now - post_time
        
        if diff.days > 0:
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
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT 1")
        db_status = "healthy"
        
        c.execute("SELECT COUNT(*) as user_count FROM users")
        user_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) as post_count FROM posts")
        post_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) as active_users FROM users WHERE last_login > datetime('now', '-7 days')")
        active_users = c.fetchone()[0]
        
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"
        user_count = post_count = active_users = 0
    finally:
        conn.close()
    
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "database": db_status,
        "stats": {
            "users": user_count, 
            "posts": post_count,
            "active_users": active_users
        }
    })

@app.route('/api/stats')
@token_required
def get_stats():
    """Get comprehensive forum statistics"""
    conn = get_db()
    try:
        c = conn.cursor()
        
        # User stats
        c.execute("""
            SELECT 
                COUNT(*) as total_users,
                COUNT(CASE WHEN last_login > datetime('now', '-7 days') THEN 1 END) as active_week,
                COUNT(CASE WHEN last_login > datetime('now', '-1 day') THEN 1 END) as active_today
            FROM users 
            WHERE is_active = 1
        """)
        user_stats = dict(c.fetchone())
        
        # Post stats
        c.execute("""
            SELECT 
                COUNT(*) as total_posts,
                COUNT(CASE WHEN timestamp > datetime('now', '-7 days') THEN 1 END) as posts_week,
                COUNT(CASE WHEN timestamp > datetime('now', '-1 day') THEN 1 END) as posts_today
            FROM posts
        """)
        post_stats = dict(c.fetchone())
        
        # Category stats
        c.execute("""
            SELECT category, COUNT(*) as count 
            FROM posts 
            GROUP BY category 
            ORDER BY count DESC 
            LIMIT 10
        """)
        top_categories = [dict(row) for row in c.fetchall()]
        
        return jsonify({
            "success": True,
            "stats": {
                "users": user_stats,
                "posts": post_stats,
                "top_categories": top_categories
            }
        })
        
    except Exception as e:
        app.logger.error(f"Stats retrieval error: {e}")
        return jsonify({"success": False, "error": "Failed to retrieve stats"}), 500
    finally:
        conn.close()

@app.route('/api/categories')
def get_categories():
    """Get all available categories"""
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT name, description, color FROM categories WHERE is_active = 1 ORDER BY name")
        categories = [dict(row) for row in c.fetchall()]
        
        return jsonify({
            "success": True,
            "categories": categories
        })
        
    except Exception as e:
        app.logger.error(f"Categories retrieval error: {e}")
        return jsonify({"success": False, "error": "Failed to retrieve categories"}), 500
    finally:
        conn.close()

@app.route('/api/notifications')
@token_required
def get_notifications():
    """Get user notifications"""
    conn = get_db()
    try:
        c = conn.cursor()
        
        # Get notifications from user activity (post likes, comments, etc.)
        c.execute("""
            SELECT ua.action, ua.details, ua.timestamp, u.username as trigger_username
            FROM user_activity ua
            LEFT JOIN users u ON ua.details LIKE '%' || u.id || '%'
            WHERE ua.user_id = ? 
            AND ua.action IN ('post_liked', 'comment_created', 'post_created')
            ORDER BY ua.timestamp DESC
            LIMIT 20
        """, (request.user_id,))
        
        notifications = []
        for row in c.fetchall():
            notification = dict(row)
            # Format notification message based on action
            if notification['action'] == 'post_liked':
                notification['message'] = f"{notification['trigger_username']} liked your post"
                notification['type'] = 'like'
            elif notification['action'] == 'comment_created':
                notification['message'] = f"{notification['trigger_username']} commented on your post"
                notification['type'] = 'comment'
            else:
                notification['message'] = "New activity on your post"
                notification['type'] = 'info'
            
            notifications.append(notification)
        
        return jsonify({
            "success": True,
            "notifications": notifications
        })
        
    except Exception as e:
        app.logger.error(f"Notifications error: {e}")
        return jsonify({"success": False, "error": "Failed to get notifications"}), 500
    finally:
        conn.close()

@app.route('/api/users/<int:user_id>/profile')
@token_required
def get_user_profile(user_id):
    """Get comprehensive user profile with activity"""
    conn = get_db()
    try:
        c = conn.cursor()
        
        # Get user basic info
        c.execute("""
            SELECT username, email, full_name, avatar_color, bio, 
                   created_at, reputation, last_login
            FROM users WHERE id = ? AND is_active = 1
        """, (user_id,))
        user = c.fetchone()
        
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404
        
        # Get user stats
        c.execute("SELECT COUNT(*) FROM posts WHERE user_id = ?", (user_id,))
        post_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM likes WHERE user_id = ?", (user_id,))
        like_count = c.fetchone()[0]
        
        c.execute("SELECT SUM(likes_count) FROM posts WHERE user_id = ?", (user_id,))
        total_likes_received = c.fetchone()[0] or 0
        
        # Get recent activity
        c.execute("""
            SELECT action, details, timestamp 
            FROM user_activity 
            WHERE user_id = ? 
            ORDER BY timestamp DESC 
            LIMIT 10
        """, (user_id,))
        recent_activity = [dict(row) for row in c.fetchall()]
        
        return jsonify({
            "success": True,
            "profile": {
                **dict(user),
                "post_count": post_count,
                "like_count": like_count,
                "total_likes_received": total_likes_received,
                "recent_activity": recent_activity
            }
        })
        
    except Exception as e:
        app.logger.error(f"Profile retrieval error: {e}")
        return jsonify({"success": False, "error": "Failed to retrieve profile"}), 500
    finally:
        conn.close()

@app.route('/api/profile')
@token_required
def get_current_user_profile():
    """Get current user's profile"""
    return get_user_profile(request.user_id)

@app.route('/api/register', methods=['POST'])
@rate_limit
def register():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "No data provided"}), 400

    valid, msg = validate_fields(data, ["username", "password"])
    if not valid:
        return jsonify({"success": False, "error": msg}), 400

    valid_username, username_msg = validate_username(data["username"])
    if not valid_username:
        return jsonify({"success": False, "error": username_msg}), 400
    
    valid_password, password_msg = validate_password(data["password"])
    if not valid_password:
        return jsonify({"success": False, "error": password_msg}), 400

    username = sanitize_input(data["username"], 20)
    email = sanitize_input(data.get("email", ""), 50)
    full_name = sanitize_input(data.get("full_name", ""), 50)
    bio = sanitize_input(data.get("bio", ""), 200)

    hashed_pw = bcrypt.hashpw(data["password"].encode(), bcrypt.gensalt())
    avatar_color = generate_avatar_color()

    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("""INSERT INTO users (username, password, email, full_name, avatar_color, bio) 
                    VALUES (?, ?, ?, ?, ?, ?)""",
                 (username, hashed_pw, email, full_name, avatar_color, bio))
        conn.commit()
        
        app.logger.info(f"New user registered: {username}")
        return jsonify({"success": True, "message": "Account created successfully"})
    
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "error": "Username already exists"}), 400
    except Exception as e:
        app.logger.error(f"Registration error: {e}")
        return jsonify({"success": False, "error": "Registration failed"}), 500
    finally:
        conn.close()

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
    conn.close()

    if not user or not bcrypt.checkpw(data["password"].encode(), user["password"]):
        app.logger.warning(f"Failed login attempt: {data['username']}")
        return jsonify({"success": False, "error": "Invalid credentials"}), 401

    if not user["is_active"]:
        return jsonify({"success": False, "error": "Account deactivated"}), 403

    token = jwt.encode({
        "user_id": user["id"],
        "username": user["username"],
        "exp": datetime.utcnow() + timedelta(hours=24)
    }, SECRET_KEY, algorithm="HS256")

    # Update last login
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE users SET last_login = datetime('now') WHERE id = ?", (user["id"],))
    conn.commit()
    conn.close()

    log_user_activity(user["id"], "login")

    return jsonify({
        "success": True, 
        "token": token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "avatar_color": user["avatar_color"]
        }
    })

@app.route('/api/posts', methods=['GET', 'POST'])
@token_required
@rate_limit
def posts():
    if request.method == 'POST':
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
            
        valid, msg = validate_fields(data, ["category", "content"])
        if not valid:
            return jsonify({"success": False, "error": msg}), 400
        
        category = sanitize_input(data["category"], 50)
        content = sanitize_input(data["content"], 5000)  # Increased for rich text
        
        if len(content.strip()) < 10:
            return jsonify({"success": False, "error": "Content must be at least 10 characters"}), 400

        # Validate category exists
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT name FROM categories WHERE name = ? AND is_active = 1", (category,))
        if not c.fetchone():
            return jsonify({"success": False, "error": "Invalid category"}), 400

        try:
            c.execute("""INSERT INTO posts (user_id, category, content) 
                        VALUES (?, ?, ?)""",
                     (request.user_id, category, content))
            post_id = c.lastrowid
            conn.commit()
            
            log_user_activity(request.user_id, "post_created", {"post_id": post_id})
            
            return jsonify({
                "success": True, 
                "message": "Post created successfully", 
                "post_id": post_id
            }), 201
            
        except Exception as e:
            app.logger.error(f"Post creation error: {e}")
            return jsonify({"success": False, "error": "Failed to create post"}), 500
        finally:
            conn.close()

    # GET posts with enhanced filtering and search
    conn = get_db()
    try:
        c = conn.cursor()
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 10, type=int), 50)
        category = request.args.get('category', '')
        search = sanitize_input(request.args.get('search', ''), 100)
        
        offset = (page - 1) * per_page
        
        query = """SELECT p.*, u.username, u.avatar_color 
                   FROM posts p 
                   JOIN users u ON p.user_id = u.id 
                   WHERE u.is_active = 1"""
        count_query = """SELECT COUNT(*) 
                        FROM posts p 
                        JOIN users u ON p.user_id = u.id 
                        WHERE u.is_active = 1"""
        params = []
        
        if category:
            query += " AND p.category = ?"
            count_query += " AND p.category = ?"
            params.append(category)
        
        if search:
            # Enhanced search across multiple fields
            query += " AND (p.content LIKE ? OR u.username LIKE ?)"
            count_query += " AND (p.content LIKE ? OR u.username LIKE ?)"
            search_term = f'%{search}%'
            params.extend([search_term, search_term])
        
        query += " ORDER BY p.is_pinned DESC, p.timestamp DESC LIMIT ? OFFSET ?"
        params.extend([per_page, offset])
        
        # Get total count
        c.execute(count_query, params[:-2])
        total_count = c.fetchone()[0]
        
        # Get posts
        c.execute(query, params)
        rows = [dict(row) for row in c.fetchall()]
        
        # Check if user liked each post and format timestamps
        for post in rows:
            c.execute("SELECT id FROM likes WHERE user_id = ? AND post_id = ?", (request.user_id, post['id']))
            post['user_has_liked'] = c.fetchone() is not None
            post['formatted_timestamp'] = format_timestamp(post['timestamp'])
        
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

@app.route('/api/posts/<int:post_id>', methods=['GET', 'DELETE', 'PUT'])
@token_required
@rate_limit
def single_post(post_id):
    """Get, update or delete a specific post"""
    conn = get_db()
    try:
        c = conn.cursor()
        
        if request.method == 'DELETE':
            # Verify post ownership
            c.execute("SELECT user_id FROM posts WHERE id = ?", (post_id,))
            post = c.fetchone()
            
            if not post:
                return jsonify({"success": False, "error": "Post not found"}), 404
            
            if post["user_id"] != request.user_id:
                return jsonify({"success": False, "error": "Not authorized to delete this post"}), 403
            
            c.execute("DELETE FROM posts WHERE id = ?", (post_id,))
            conn.commit()
            
            log_user_activity(request.user_id, "post_deleted", {"post_id": post_id})
            
            return jsonify({"success": True, "message": "Post deleted successfully"})
        
        elif request.method == 'PUT':
            data = request.get_json()
            if not data:
                return jsonify({"success": False, "error": "No data provided"}), 400
                
            valid, msg = validate_fields(data, ["content"])
            if not valid:
                return jsonify({"success": False, "error": msg}), 400
            
            content = sanitize_input(data["content"], 5000)
            category = sanitize_input(data.get("category", ""), 50)
            
            if len(content) < 10:
                return jsonify({"success": False, "error": "Content must be at least 10 characters"}), 400

            # Verify post exists and user owns it
            c.execute("SELECT user_id FROM posts WHERE id = ?", (post_id,))
            post = c.fetchone()
            
            if not post:
                return jsonify({"success": False, "error": "Post not found"}), 404
                
            if post["user_id"] != request.user_id:
                return jsonify({"success": False, "error": "Not authorized to edit this post"}), 403
            
            # Update post
            c.execute("""
                UPDATE posts 
                SET content = ?, category = ?, edited_at = datetime('now') 
                WHERE id = ?
            """, (content, category, post_id))
            
            conn.commit()
            log_user_activity(request.user_id, "post_edited", {"post_id": post_id})
            
            return jsonify({
                "success": True, 
                "message": "Post updated successfully"
            })
        
        # GET single post
        c.execute("""
            SELECT p.*, u.username, u.avatar_color 
            FROM posts p 
            JOIN users u ON p.user_id = u.id 
            WHERE p.id = ? AND u.is_active = 1
        """, (post_id,))
        
        post = c.fetchone()
        if not post:
            return jsonify({"success": False, "error": "Post not found"}), 404
        
        post_dict = dict(post)
        
        # Check if user liked the post
        c.execute("SELECT id FROM likes WHERE user_id = ? AND post_id = ?", (request.user_id, post_id))
        post_dict['user_has_liked'] = c.fetchone() is not None
        post_dict['formatted_timestamp'] = format_timestamp(post_dict['timestamp'])
        
        # Increment view count
        c.execute("UPDATE posts SET view_count = view_count + 1 WHERE id = ?", (post_id,))
        conn.commit()
        
        return jsonify({"success": True, "data": post_dict})
        
    except Exception as e:
        app.logger.error(f"Single post operation error: {e}")
        return jsonify({"success": False, "error": "Operation failed"}), 500
    finally:
        conn.close()

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
            
            # Update user reputation (simplified)
            if post["user_id"] != request.user_id:
                c.execute("UPDATE users SET reputation = reputation - 1 WHERE id = ?", (post["user_id"],))
        else:
            # Like
            c.execute("INSERT INTO likes (user_id, post_id) VALUES (?, ?)",
                     (request.user_id, post_id))
            c.execute("UPDATE posts SET likes_count = likes_count + 1 WHERE id = ?", (post_id,))
            action = "liked"
            
            # Update user reputation (simplified)
            if post["user_id"] != request.user_id:
                c.execute("UPDATE users SET reputation = reputation + 1 WHERE id = ?", (post["user_id"],))
        
        conn.commit()
        
        # Get updated like count
        c.execute("SELECT likes_count FROM posts WHERE id = ?", (post_id,))
        likes_count = c.fetchone()["likes_count"]
        
        log_user_activity(request.user_id, f"post_{action}", {"post_id": post_id})
        
        return jsonify({
            "success": True, 
            "action": action,
            "likes_count": likes_count
        })
        
    except Exception as e:
        app.logger.error(f"Like operation error: {e}")
        return jsonify({"success": False, "error": "Like operation failed"}), 500
    finally:
        conn.close()

@app.route('/api/posts/<int:post_id>/bookmark', methods=['POST'])
@token_required
@rate_limit
def bookmark_post(post_id):
    """Bookmark or unbookmark a post"""
    conn = get_db()
    try:
        c = conn.cursor()
        
        # Verify post exists
        c.execute("SELECT id FROM posts WHERE id = ?", (post_id,))
        if not c.fetchone():
            return jsonify({"success": False, "error": "Post not found"}), 404
        
        # Check if already bookmarked (using likes table for simplicity)
        c.execute("SELECT id FROM likes WHERE user_id = ? AND post_id = ? AND comment_id IS NULL", 
                 (request.user_id, post_id))
        existing_bookmark = c.fetchone()
        
        if existing_bookmark:
            # Remove bookmark
            c.execute("DELETE FROM likes WHERE id = ?", (existing_bookmark["id"],))
            action = "unbookmarked"
        else:
            # Add bookmark
            c.execute("INSERT INTO likes (user_id, post_id) VALUES (?, ?)",
                     (request.user_id, post_id))
            action = "bookmarked"
        
        conn.commit()
        log_user_activity(request.user_id, f"post_{action}", {"post_id": post_id})
        
        return jsonify({
            "success": True, 
            "action": action
        })
        
    except Exception as e:
        app.logger.error(f"Bookmark operation error: {e}")
        return jsonify({"success": False, "error": "Bookmark operation failed"}), 500
    finally:
        conn.close()

@app.route('/api/bookmarks')
@token_required
@rate_limit
def get_bookmarks():
    """Get user's bookmarked posts"""
    conn = get_db()
    try:
        c = conn.cursor()
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 10, type=int), 50)
        offset = (page - 1) * per_page
        
        # Get bookmarked posts
        c.execute("""
            SELECT p.*, u.username, u.avatar_color 
            FROM posts p 
            JOIN users u ON p.user_id = u.id 
            JOIN likes l ON p.id = l.post_id 
            WHERE l.user_id = ? AND l.comment_id IS NULL
            AND u.is_active = 1
            ORDER BY l.timestamp DESC
            LIMIT ? OFFSET ?
        """, (request.user_id, per_page, offset))
        
        posts = [dict(row) for row in c.fetchall()]
        
        # Check if user liked each post
        for post in posts:
            c.execute("SELECT id FROM likes WHERE user_id = ? AND post_id = ?", 
                     (request.user_id, post['id']))
            post['user_has_liked'] = c.fetchone() is not None
            post['user_has_bookmarked'] = True
            post['formatted_timestamp'] = format_timestamp(post['timestamp'])
        
        # Get total count
        c.execute("""
            SELECT COUNT(*) 
            FROM likes l 
            JOIN posts p ON l.post_id = p.id 
            JOIN users u ON p.user_id = u.id 
            WHERE l.user_id = ? AND l.comment_id IS NULL AND u.is_active = 1
        """, (request.user_id,))
        total_count = c.fetchone()[0]
        
        return jsonify({
            "success": True, 
            "data": posts,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total_count,
                "pages": (total_count + per_page - 1) // per_page
            }
        })
        
    except Exception as e:
        app.logger.error(f"Bookmarks retrieval error: {e}")
        return jsonify({"success": False, "error": "Failed to retrieve bookmarks"}), 500
    finally:
        conn.close()

@app.route('/api/comments', methods=['POST'])
@token_required
@rate_limit
def create_comment():
    """Create a new comment"""
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "No data provided"}), 400
        
    valid, msg = validate_fields(data, ["post_id", "content"])
    if not valid:
        return jsonify({"success": False, "error": msg}), 400
    
    post_id = data["post_id"]
    content = sanitize_input(data["content"], 1000)
    parent_comment_id = data.get("parent_comment_id")
    
    if len(content) < 1:
        return jsonify({"success": False, "error": "Comment cannot be empty"}), 400

    conn = get_db()
    try:
        c = conn.cursor()
        
        # Verify post exists
        c.execute("SELECT id, user_id FROM posts WHERE id = ?", (post_id,))
        post = c.fetchone()
        if not post:
            return jsonify({"success": False, "error": "Post not found"}), 404
        
        # Insert comment
        c.execute("""
            INSERT INTO comments (post_id, user_id, content, parent_comment_id) 
            VALUES (?, ?, ?, ?)
        """, (post_id, request.user_id, content, parent_comment_id))
        
        # Update post comment count
        c.execute("UPDATE posts SET comments_count = comments_count + 1 WHERE id = ?", (post_id,))
        
        comment_id = c.lastrowid
        conn.commit()
        
        # Log activity and create notification for post owner
        log_user_activity(request.user_id, "comment_created", {
            "post_id": post_id, 
            "comment_id": comment_id
        })
        
        if post["user_id"] != request.user_id:
            log_user_activity(post["user_id"], "post_commented", {
                "post_id": post_id, 
                "comment_id": comment_id,
                "commenter_id": request.user_id
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
        conn.close()

@app.route('/api/posts/<int:post_id>/comments', methods=['GET'])
@token_required
@rate_limit
def get_comments(post_id):
    """Get comments for a post"""
    conn = get_db()
    try:
        c = conn.cursor()
        
        # Verify post exists
        c.execute("SELECT id FROM posts WHERE id = ?", (post_id,))
        if not c.fetchone():
            return jsonify({"success": False, "error": "Post not found"}), 404
        
        # Get comments with user info
        c.execute("""
            SELECT c.*, u.username, u.avatar_color 
            FROM comments c 
            JOIN users u ON c.user_id = u.id 
            WHERE c.post_id = ? AND c.is_deleted = 0 AND u.is_active = 1
            ORDER BY c.timestamp ASC
        """, (post_id,))
        
        comments = [dict(row) for row in c.fetchall()]
        
        # Build comment tree for nested comments
        comment_dict = {}
        root_comments = []
        
        for comment in comments:
            comment_id = comment['id']
            parent_id = comment['parent_comment_id']
            comment['replies'] = []
            comment_dict[comment_id] = comment
            
            if parent_id is None:
                root_comments.append(comment)
            else:
                if parent_id in comment_dict:
                    comment_dict[parent_id]['replies'].append(comment)
        
        # Check if user liked each comment
        for comment in comments:
            c.execute("SELECT id FROM likes WHERE user_id = ? AND comment_id = ?", 
                     (request.user_id, comment['id']))
            comment['user_has_liked'] = c.fetchone() is not None
            comment['formatted_timestamp'] = format_timestamp(comment['timestamp'])
        
        return jsonify({
            "success": True, 
            "data": root_comments
        })
        
    except Exception as e:
        app.logger.error(f"Comments retrieval error: {e}")
        return jsonify({"success": False, "error": "Failed to retrieve comments"}), 500
    finally:
        conn.close()

@app.route('/api/search')
@token_required
@rate_limit
def advanced_search():
    """Advanced search with multiple criteria"""
    conn = get_db()
    try:
        c = conn.cursor()
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 10, type=int), 50)
        category = request.args.get('category', '')
        search = sanitize_input(request.args.get('q', ''), 100)
        author = sanitize_input(request.args.get('author', ''), 50)
        sort = request.args.get('sort', 'newest')
        min_likes = request.args.get('min_likes', 0, type=int)
        has_comments = request.args.get('has_comments', 'false') == 'true'
        my_posts = request.args.get('my_posts', 'false') == 'true'
        
        offset = (page - 1) * per_page
        
        query = """SELECT p.*, u.username, u.avatar_color 
                   FROM posts p 
                   JOIN users u ON p.user_id = u.id 
                   WHERE u.is_active = 1"""
        count_query = """SELECT COUNT(*) 
                        FROM posts p 
                        JOIN users u ON p.user_id = u.id 
                        WHERE u.is_active = 1"""
        params = []
        
        # Build query based on filters
        if category:
            query += " AND p.category = ?"
            count_query += " AND p.category = ?"
            params.append(category)
        
        if search:
            query += " AND (p.content LIKE ? OR u.username LIKE ?)"
            count_query += " AND (p.content LIKE ? OR u.username LIKE ?)"
            search_term = f'%{search}%'
            params.extend([search_term, search_term])
        
        if author:
            query += " AND u.username LIKE ?"
            count_query += " AND u.username LIKE ?"
            params.append(f'%{author}%')
        
        if min_likes > 0:
            query += " AND p.likes_count >= ?"
            count_query += " AND p.likes_count >= ?"
            params.append(min_likes)
        
        if has_comments:
            query += " AND p.comments_count > 0"
            count_query += " AND p.comments_count > 0"
        
        if my_posts:
            query += " AND p.user_id = ?"
            count_query += " AND p.user_id = ?"
            params.append(request.user_id)
        
        # Add sorting
        sort_options = {
            'newest': 'p.timestamp DESC',
            'oldest': 'p.timestamp ASC',
            'popular': 'p.likes_count DESC',
            'comments': 'p.comments_count DESC'
        }
        query += f" ORDER BY {sort_options.get(sort, 'p.timestamp DESC')}"
        
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
            c.execute("SELECT id FROM likes WHERE user_id = ? AND post_id = ?", 
                     (request.user_id, post['id']))
            post['user_has_liked'] = c.fetchone() is not None
            post['formatted_timestamp'] = format_timestamp(post['timestamp'])
        
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
        app.logger.error(f"Search error: {e}")
        return jsonify({"success": False, "error": "Search failed"}), 500
    finally:
        conn.close()

@app.route('/api/analytics/overview')
@token_required
@rate_limit
def get_analytics():
    """Get forum analytics and insights"""
    conn = get_db()
    try:
        c = conn.cursor()
        
        # Basic stats
        c.execute("SELECT COUNT(*) FROM users WHERE is_active = 1")
        total_users = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM posts")
        total_posts = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM comments")
        total_comments = c.fetchone()[0]
        
        c.execute("SELECT SUM(likes_count) FROM posts")
        total_likes = c.fetchone()[0] or 0
        
        # Recent growth
        c.execute("""
            SELECT COUNT(*) FROM users 
            WHERE created_at > datetime('now', '-7 days') AND is_active = 1
        """)
        new_users_week = c.fetchone()[0]
        
        c.execute("""
            SELECT COUNT(*) FROM posts 
            WHERE timestamp > datetime('now', '-7 days')
        """)
        new_posts_week = c.fetchone()[0]
        
        # Popular categories
        c.execute("""
            SELECT category, COUNT(*) as count 
            FROM posts 
            GROUP BY category 
            ORDER BY count DESC 
            LIMIT 5
        """)
        popular_categories = [dict(row) for row in c.fetchall()]
        
        # Top users
        c.execute("""
            SELECT u.username, u.reputation, COUNT(p.id) as post_count
            FROM users u
            LEFT JOIN posts p ON u.id = p.user_id
            WHERE u.is_active = 1
            GROUP BY u.id
            ORDER BY u.reputation DESC
            LIMIT 10
        """)
        top_users = [dict(row) for row in c.fetchall()]
        
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
                "top_users": top_users
            }
        })
        
    except Exception as e:
        app.logger.error(f"Analytics error: {e}")
        return jsonify({"success": False, "error": "Failed to get analytics"}), 500
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

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        "success": False, 
        "error": "Rate limit exceeded. Please try again later."
    }), 429

if __name__ == '__main__':
    app.run(debug=True)