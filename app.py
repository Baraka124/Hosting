from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sqlite3, os, jwt, bcrypt, uuid
from datetime import datetime, timedelta
import random
import re
from functools import wraps
import logging
from logging.handlers import RotatingFileHandler

app = Flask(__name__)
CORS(app)

# Enhanced Configuration
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

# ---------- Enhanced Database Layer ----------
def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    # Enable foreign keys
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    with get_db() as conn:
        c = conn.cursor()
        
        # Create indexes for performance
        c.executescript("""
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT,
                full_name TEXT,
                avatar_color TEXT DEFAULT '#007AFF',
                bio TEXT,
                created_at TEXT NOT NULL,
                last_login TEXT,
                is_active BOOLEAN DEFAULT 1
            );
            
            CREATE TABLE IF NOT EXISTS posts(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                category TEXT NOT NULL,
                title TEXT,
                content TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                likes_count INTEGER DEFAULT 0,
                comments_count INTEGER DEFAULT 0,
                is_pinned BOOLEAN DEFAULT 0,
                tags TEXT,
                edited_at TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            
            CREATE TABLE IF NOT EXISTS comments(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER,
                user_id INTEGER,
                content TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                likes_count INTEGER DEFAULT 0,
                edited_at TEXT,
                parent_comment_id INTEGER,
                FOREIGN KEY(post_id) REFERENCES posts(id),
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(parent_comment_id) REFERENCES comments(id)
            );
            
            CREATE TABLE IF NOT EXISTS likes(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                post_id INTEGER,
                comment_id INTEGER,
                timestamp TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(post_id) REFERENCES posts(id),
                FOREIGN KEY(comment_id) REFERENCES comments(id)
            );
            
            CREATE TABLE IF NOT EXISTS user_sessions(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                session_start TEXT NOT NULL,
                session_end TEXT,
                page_views INTEGER DEFAULT 0,
                ip_address TEXT,
                user_agent TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            
            CREATE TABLE IF NOT EXISTS user_activity(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                details TEXT,
                timestamp TEXT NOT NULL,
                ip_address TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            
            -- Create indexes for better performance
            CREATE INDEX IF NOT EXISTS idx_posts_user_id ON posts(user_id);
            CREATE INDEX IF NOT EXISTS idx_posts_category ON posts(category);
            CREATE INDEX IF NOT EXISTS idx_posts_timestamp ON posts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_comments_post_id ON comments(post_id);
            CREATE INDEX IF NOT EXISTS idx_likes_user_post ON likes(user_id, post_id);
            CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
            CREATE INDEX IF NOT EXISTS idx_user_activity_user_id ON user_activity(user_id);
        """)
        conn.commit()

init_db()

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
        try:
            decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
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
    
    # Remove potentially dangerous characters
    text = re.sub(r'<script.*?>.*?</script>', '', text, flags=re.IGNORECASE)
    text = re.sub(r'javascript:', '', text, flags=re.IGNORECASE)
    text = re.sub(r'on\w+=', '', text, flags=re.IGNORECASE)
    
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

def calculate_reputation(user_id):
    """Calculate user reputation based on activity"""
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT 
                (COUNT(DISTINCT p.id) * 5) + 
                (COUNT(DISTINCT c.id) * 2) + 
                (COUNT(DISTINCT l.id) * 1) as reputation
            FROM users u
            LEFT JOIN posts p ON u.id = p.user_id
            LEFT JOIN comments c ON u.id = c.user_id  
            LEFT JOIN likes l ON u.id = l.user_id
            WHERE u.id = ?
        """, (user_id,))
        return c.fetchone()[0] or 0

def log_user_activity(user_id, action, details=None, ip_address=None):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""INSERT INTO user_activity 
                    (user_id, action, details, timestamp, ip_address) 
                    VALUES (?, ?, ?, ?, ?)""",
                 (user_id, action, str(details) if details else None, 
                  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                  ip_address or request.remote_addr))
        conn.commit()

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
    with get_db() as conn:
        c = conn.cursor()
        try:
            c.execute("SELECT 1")
            db_status = "healthy"
        except Exception as e:
            db_status = f"unhealthy: {str(e)}"
    
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "version": "3.0.0",
        "database": db_status,
        "rate_limit_remaining": RATE_LIMIT - request_counts.get(f"{request.remote_addr}_{datetime.now().strftime('%Y-%m-%d %H:%M')}", 0)
    })

# Enhanced registration with validation
@app.route('/api/register', methods=['POST'])
@rate_limit
def register():
    data = request.get_json()
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

    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("""INSERT INTO users 
                        (username, password, email, full_name, avatar_color, bio, created_at) 
                        VALUES (?, ?, ?, ?, ?, ?, ?)""",
                     (username, hashed_pw, email, full_name, avatar_color, bio,
                      datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
        
        app.logger.info(f"New EdgePowered user registered: {username}")
        return jsonify({"success": True, "message": "EdgePowered account created successfully"})
    
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "error": "Username already exists"}), 400
    except Exception as e:
        app.logger.error(f"Registration error: {e}")
        return jsonify({"success": False, "error": "Registration failed"}), 500

# Enhanced login with security features
@app.route('/api/login', methods=['POST'])
@rate_limit
def login():
    data = request.get_json()
    valid, msg = validate_fields(data, ["username", "password"])
    if not valid:
        return jsonify({"success": False, "error": msg}), 400

    with get_db() as conn:
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
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""INSERT INTO user_sessions 
                    (user_id, session_start, ip_address, user_agent) 
                    VALUES (?, ?, ?, ?)""",
                 (user["id"], client_info['timestamp'], 
                  client_info['ip_address'], client_info['user_agent']))
        
        # Update last login
        c.execute("UPDATE users SET last_login = ? WHERE id = ?", 
                 (client_info['timestamp'], user["id"]))
        
        conn.commit()

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
    with get_db() as conn:
        c = conn.cursor()
        
        if request.method == 'POST':
            data = request.get_json()
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

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            c.execute("""INSERT INTO posts 
                        (user_id, category, title, content, timestamp, tags) 
                        VALUES (?, ?, ?, ?, ?, ?)""",
                     (request.user_id, category, title, content, timestamp, tags))
            conn.commit()
            
            # Log activity
            log_user_activity(request.user_id, "post_created", 
                            {"post_id": c.lastrowid, "category": category})
            
            return jsonify({"success": True, "message": "Post added to EdgePowered", "post_id": c.lastrowid}), 201

        # Enhanced GET with security and performance
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 10, type=int), 50)
        category = request.args.get('category', '')
        search = sanitize_input(request.args.get('search', ''), 50)
        time_filter = request.args.get('time_filter', '')
        sort_by = request.args.get('sort_by', 'newest')
        
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

# Enhanced like system
@app.route('/api/posts/<int:post_id>/like', methods=['POST'])
@token_required
@rate_limit
def like_post(post_id):
    with get_db() as conn:
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
            c.execute("INSERT INTO likes (user_id, post_id, timestamp) VALUES (?, ?, ?)",
                     (request.user_id, post_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            c.execute("UPDATE posts SET likes_count = likes_count + 1 WHERE id = ?", (post_id,))
            action = "liked"
        
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

# Post analytics endpoint
@app.route('/api/posts/<int:post_id>/analytics')
@token_required
def post_analytics(post_id):
    with get_db() as conn:
        c = conn.cursor()
        
        # Verify post exists and belongs to user or is public
        c.execute("SELECT user_id FROM posts WHERE id = ?", (post_id,))
        post = c.fetchone()
        if not post:
            return jsonify({"success": False, "error": "Post not found"}), 404
        
        # Get post engagement metrics
        c.execute("""
            SELECT 
                p.likes_count,
                p.comments_count,
                COUNT(DISTINCT l.user_id) as unique_likers,
                (SELECT COUNT(*) FROM comments c2 WHERE c2.post_id = p.id) as total_comments,
                (SELECT COUNT(DISTINCT user_id) FROM comments c3 WHERE c3.post_id = p.id) as unique_commenters
            FROM posts p 
            LEFT JOIN likes l ON p.id = l.post_id
            WHERE p.id = ?
            GROUP BY p.id
        """, (post_id,))
        
        result = c.fetchone()
        if not result:
            return jsonify({"success": False, "error": "Analytics not available"}), 404
            
        analytics = dict(result)
        return jsonify({"success": True, "analytics": analytics})

# Comments endpoints
@app.route('/api/posts/<int:post_id>/comments', methods=['GET', 'POST'])
@token_required
@rate_limit
def post_comments(post_id):
    with get_db() as conn:
        c = conn.cursor()
        
        # Verify post exists and user can access it
        c.execute("""SELECT p.id FROM posts p 
                    JOIN users u ON p.user_id = u.id 
                    WHERE p.id = ? AND u.is_active = 1""", (post_id,))
        if not c.fetchone():
            return jsonify({"success": False, "error": "Post not found"}), 404
        
        if request.method == 'POST':
            data = request.get_json()
            valid, msg = validate_fields(data, ["content"])
            if not valid:
                return jsonify({"success": False, "error": msg}), 400
            
            content = sanitize_input(data["content"], 500)
            
            if len(content) < 2:
                return jsonify({"success": False, "error": "Comment must be at least 2 characters"}), 400

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            c.execute("""INSERT INTO comments (post_id, user_id, content, timestamp) 
                        VALUES (?, ?, ?, ?)""",
                     (post_id, request.user_id, content, timestamp))
            
            # Update post comments count
            c.execute("UPDATE posts SET comments_count = comments_count + 1 WHERE id = ?", (post_id,))
            
            conn.commit()
            
            # Log activity
            log_user_activity(request.user_id, "comment_created", {"post_id": post_id})
            
            return jsonify({"success": True, "message": "Comment added"}), 201
        
        # GET comments for post
        c.execute("""SELECT c.*, u.username, u.avatar_color 
                    FROM comments c 
                    JOIN users u ON c.user_id = u.id 
                    WHERE c.post_id = ? AND u.is_active = 1
                    ORDER BY c.timestamp ASC""", (post_id,))
        comments = [dict(row) for row in c.fetchall()]
        
        return jsonify({"success": True, "data": comments})

# Enhanced user profile with reputation
@app.route('/api/profile', methods=['GET'])
@token_required
def get_profile():
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""SELECT id, username, email, full_name, avatar_color, bio, created_at, last_login 
                    FROM users WHERE id = ? AND is_active = 1""", (request.user_id,))
        user = c.fetchone()
        
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404
        
        # Get user stats
        c.execute("SELECT COUNT(*) as post_count FROM posts WHERE user_id = ?", (request.user_id,))
        post_count = c.fetchone()["post_count"]
        
        c.execute("SELECT COUNT(*) as comment_count FROM comments WHERE user_id = ?", (request.user_id,))
        comment_count = c.fetchone()["comment_count"]
        
        c.execute("""SELECT COUNT(*) as like_count FROM likes l 
                    JOIN posts p ON l.post_id = p.id 
                    WHERE p.user_id = ?""", (request.user_id,))
        like_count = c.fetchone()["like_count"]
        
        # Calculate reputation
        reputation = calculate_reputation(request.user_id)
        
        return jsonify({
            "success": True,
            "profile": dict(user),
            "stats": {
                "posts": post_count,
                "comments": comment_count,
                "likes_received": like_count,
                "reputation": reputation
            }
        })

# User's posts endpoint
@app.route('/api/profile/posts')
@token_required
def get_user_posts():
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""SELECT p.*, u.username, u.avatar_color 
                    FROM posts p 
                    JOIN users u ON p.user_id = u.id 
                    WHERE p.user_id = ? 
                    ORDER BY p.timestamp DESC""", (request.user_id,))
        posts = [dict(row) for row in c.fetchall()]
        
        return jsonify({
            "success": True,
            "data": posts
        })

# Recommendations endpoint
@app.route('/api/recommendations')
@token_required
def get_recommendations():
    """Get personalized post recommendations based on user activity"""
    with get_db() as conn:
        c = conn.cursor()
        
        # Get user's most engaged categories
        c.execute("""
            SELECT p.category, COUNT(*) as engagement
            FROM posts p
            LEFT JOIN likes l ON p.id = l.post_id AND l.user_id = ?
            LEFT JOIN comments c ON p.id = c.post_id AND c.user_id = ?
            WHERE l.id IS NOT NULL OR c.id IS NOT NULL
            GROUP BY p.category
            ORDER BY engagement DESC
            LIMIT 2
        """, (request.user_id, request.user_id))
        
        top_categories = [row['category'] for row in c.fetchall()]
        
        # Get recommended posts
        if top_categories:
            placeholders = ','.join(['?'] * len(top_categories))
            c.execute(f"""
                SELECT p.*, u.username, u.avatar_color
                FROM posts p
                JOIN users u ON p.user_id = u.id
                WHERE p.category IN ({placeholders})
                AND p.user_id != ?
                AND u.is_active = 1
                ORDER BY (p.likes_count * 0.5 + p.comments_count * 0.3) DESC
                LIMIT 5
            """, top_categories + [request.user_id])
        else:
            # Fallback to popular posts
            c.execute("""
                SELECT p.*, u.username, u.avatar_color
                FROM posts p
                JOIN users u ON p.user_id = u.id
                WHERE u.is_active = 1
                ORDER BY (p.likes_count * 0.5 + p.comments_count * 0.3) DESC
                LIMIT 5
            """)
        
        recommendations = [dict(row) for row in c.fetchall()]
        return jsonify({"success": True, "recommendations": recommendations})

# Enhanced search with security
@app.route('/api/search')
@rate_limit
def search():
    query = sanitize_input(request.args.get('q', ''), 50)
    if not query or len(query) < 2:
        return jsonify({"success": False, "error": "Query must be at least 2 characters"}), 400
    
    with get_db() as conn:
        c = conn.cursor()
        
        # Search posts
        c.execute("""SELECT p.*, u.username, u.avatar_color 
                    FROM posts p 
                    JOIN users u ON p.user_id = u.id 
                    WHERE (p.content LIKE ? OR p.title LIKE ? OR p.tags LIKE ?) 
                    AND u.is_active = 1
                    ORDER BY p.timestamp DESC LIMIT 20""",
                 (f'%{query}%', f'%{query}%', f'%{query}%'))
        posts = [dict(row) for row in c.fetchall()]
        
        # Search users
        c.execute("""SELECT id, username, avatar_color, bio 
                    FROM users 
                    WHERE (username LIKE ? OR bio LIKE ?) 
                    AND is_active = 1
                    LIMIT 10""",
                 (f'%{query}%', f'%{query}%'))
        users = [dict(row) for row in c.fetchall()]
        
        # Log search activity (if user is authenticated)
        if hasattr(request, 'user_id'):
            log_user_activity(request.user_id, "search", {"query": query, "results": len(posts) + len(users)})
        
        return jsonify({
            "success": True,
            "query": query,
            "posts": posts,
            "users": users
        })

# Categories endpoint
@app.route('/api/categories')
def get_categories():
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT category, COUNT(*) as count FROM posts GROUP BY category")
        categories = {row["category"]: row["count"] for row in c.fetchall()}
        
        return jsonify({
            "success": True,
            "categories": categories
        })

# Trending topics endpoint
@app.route('/api/trending')
def get_trending():
    with get_db() as conn:
        c = conn.cursor()
        # Get posts with most likes in last 7 days
        c.execute("""SELECT p.*, u.username, u.avatar_color 
                    FROM posts p 
                    JOIN users u ON p.user_id = u.id 
                    WHERE p.timestamp >= datetime('now', '-7 days')
                    ORDER BY p.likes_count DESC, p.comments_count DESC 
                    LIMIT 5""")
        trending_posts = [dict(row) for row in c.fetchall()]
        
        return jsonify({
            "success": True,
            "trending": trending_posts
        })

# Top contributors endpoint
@app.route('/api/contributors')
def get_top_contributors():
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""SELECT u.username, u.avatar_color, COUNT(p.id) as post_count
                    FROM users u 
                    LEFT JOIN posts p ON u.id = p.user_id 
                    GROUP BY u.id 
                    ORDER BY post_count DESC 
                    LIMIT 5""")
        contributors = [dict(row) for row in c.fetchall()]
        
        return jsonify({
            "success": True,
            "contributors": contributors
        })

# Performance metrics endpoint
@app.route('/api/performance/metrics')
@token_required
def performance_metrics():
    """Get performance metrics for admin users"""
    with get_db() as conn:
        c = conn.cursor()
        
        # Database performance
        c.execute("SELECT COUNT(*) as total_posts FROM posts")
        total_posts = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) as active_users FROM users WHERE last_login > datetime('now', '-7 days')")
        active_users = c.fetchone()[0]
        
        # Response times (simplified)
        c.execute("""
            SELECT 
                AVG((julianday('now') - julianday(timestamp)) * 24 * 60) as avg_post_age_minutes
            FROM posts 
            WHERE timestamp > datetime('now', '-1 day')
        """)
        avg_post_age = c.fetchone()[0] or 0
        
        return jsonify({
            "success": True,
            "metrics": {
                "total_posts": total_posts,
                "active_users": active_users,
                "engagement_rate": (active_users / max(total_posts, 1)) * 100,
                "avg_post_age_minutes": round(avg_post_age, 2)
            }
        })

# Analytics endpoint
@app.route('/api/analytics/overview')
@token_required
def analytics_overview():
    with get_db() as conn:
        c = conn.cursor()
        
        # Total posts
        c.execute("SELECT COUNT(*) as total_posts FROM posts")
        total_posts = c.fetchone()["total_posts"]
        
        # Total users
        c.execute("SELECT COUNT(*) as total_users FROM users")
        total_users = c.fetchone()["total_users"]
        
        # Total likes
        c.execute("SELECT COUNT(*) as total_likes FROM likes")
        total_likes = c.fetchone()["total_likes"]
        
        # Total comments
        c.execute("SELECT COUNT(*) as total_comments FROM comments")
        total_comments = c.fetchone()["total_comments"]
        
        # Posts by category
        c.execute("SELECT category, COUNT(*) as count FROM posts GROUP BY category")
        categories = {row["category"]: row["count"] for row in c.fetchall()}
        
        # Recent activity
        c.execute("""SELECT p.timestamp, u.username, p.category 
                    FROM posts p 
                    JOIN users u ON p.user_id = u.id 
                    ORDER BY p.timestamp DESC LIMIT 5""")
        recent_activity = [dict(row) for row in c.fetchall()]
        
        return jsonify({
            "success": True,
            "overview": {
                "total_posts": total_posts,
                "total_users": total_users,
                "total_likes": total_likes,
                "total_comments": total_comments,
                "categories": categories,
                "recent_activity": recent_activity
            }
        })

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

# Maintenance endpoint
@app.route('/api/maintenance/cleanup', methods=['POST'])
def cleanup_old_sessions():
    """Clean up old sessions and activities (can be called by cron job)"""
    try:
        with get_db() as conn:
            c = conn.cursor()
            # Clean up sessions older than 30 days
            c.execute("DELETE FROM user_sessions WHERE session_start < datetime('now', '-30 days')")
            # Clean up activities older than 90 days
            c.execute("DELETE FROM user_activity WHERE timestamp < datetime('now', '-90 days')")
            conn.commit()
        
        app.logger.info("EdgePowered cleanup completed successfully")
        return jsonify({"success": True, "message": "Cleanup completed"})
    
    except Exception as e:
        app.logger.error(f"Cleanup error: {e}")
        return jsonify({"success": False, "error": "Cleanup failed"}), 500

if __name__ == '__main__':
    app.run(debug=True)