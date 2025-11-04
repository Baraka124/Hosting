from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sqlite3, os, jwt, bcrypt
from datetime import datetime, timedelta
import random
import re
from functools import wraps
import logging
from logging.handlers import RotatingFileHandler

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
        """)
        
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

def sanitize_input(text, max_length=1000):
    """Sanitize user input"""
    if not text:
        return text
    
    # Remove dangerous patterns
    text = re.sub(r'<script.*?>.*?</script>', '', text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r'javascript:', '', text, flags=re.IGNORECASE)
    text = re.sub(r'on\w+=', '', text, flags=re.IGNORECASE)
    
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

# ---------- Routes ----------
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
        
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"
        user_count = post_count = 0
    finally:
        conn.close()
    
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "database": db_status,
        "stats": {"users": user_count, "posts": post_count}
    })

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
        content = sanitize_input(data["content"], 1000)
        
        if len(content) < 10:
            return jsonify({"success": False, "error": "Content must be at least 10 characters"}), 400

        conn = get_db()
        try:
            c = conn.cursor()
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

    # GET posts
    conn = get_db()
    try:
        c = conn.cursor()
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 10, type=int), 50)
        category = request.args.get('category', '')
        search = sanitize_input(request.args.get('search', ''), 50)
        
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
            query += " AND (p.content LIKE ? OR p.title LIKE ?)"
            count_query += " AND (p.content LIKE ? OR p.title LIKE ?)"
            params.extend([f'%{search}%', f'%{search}%'])
        
        query += " ORDER BY p.timestamp DESC LIMIT ? OFFSET ?"
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
        c.execute("SELECT id FROM posts WHERE id = ?", (post_id,))
        if not c.fetchone():
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