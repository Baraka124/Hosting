from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sqlite3, os, jwt, bcrypt, uuid
from datetime import datetime, timedelta
import random

app = Flask(__name__)
CORS(app)

DB_NAME = "konekt_advanced.db"
SECRET_KEY = "supersecret-jwt-key-advanced"

# ---------- Database Layer ----------
def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        c = conn.cursor()
        
        # Enhanced users table with profile info
        c.execute("""CREATE TABLE IF NOT EXISTS users(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL,
                        email TEXT,
                        full_name TEXT,
                        avatar_color TEXT DEFAULT '#007AFF',
                        bio TEXT,
                        created_at TEXT NOT NULL
                    )""")
        
        # Enhanced posts table with engagement metrics
        c.execute("""CREATE TABLE IF NOT EXISTS posts(
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
                        FOREIGN KEY(user_id) REFERENCES users(id)
                    )""")
        
        # Comments table
        c.execute("""CREATE TABLE IF NOT EXISTS comments(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        post_id INTEGER,
                        user_id INTEGER,
                        content TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        likes_count INTEGER DEFAULT 0,
                        FOREIGN KEY(post_id) REFERENCES posts(id),
                        FOREIGN KEY(user_id) REFERENCES users(id)
                    )""")
        
        # Likes table for posts and comments
        c.execute("""CREATE TABLE IF NOT EXISTS likes(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER,
                        post_id INTEGER,
                        comment_id INTEGER,
                        timestamp TEXT NOT NULL,
                        FOREIGN KEY(user_id) REFERENCES users(id),
                        FOREIGN KEY(post_id) REFERENCES posts(id),
                        FOREIGN KEY(comment_id) REFERENCES comments(id)
                    )""")
        
        # User sessions for analytics
        c.execute("""CREATE TABLE IF NOT EXISTS user_sessions(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER,
                        session_start TEXT NOT NULL,
                        session_end TEXT,
                        page_views INTEGER DEFAULT 0,
                        FOREIGN KEY(user_id) REFERENCES users(id)
                    )""")
        
        # User activity log
        c.execute("""CREATE TABLE IF NOT EXISTS user_activity(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER,
                        action TEXT NOT NULL,
                        details TEXT,
                        timestamp TEXT NOT NULL,
                        FOREIGN KEY(user_id) REFERENCES users(id)
                    )""")
        
        conn.commit()

init_db()

# ---------- Helper Functions ----------
def token_required(func):
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
            return jsonify({"success": False, "error": "Invalid token"}), 401
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

def validate_fields(data, required):
    for field in required:
        if not data.get(field):
            return False, f"Missing field: {field}"
    return True, None

def generate_avatar_color():
    colors = ['#007AFF', '#34C759', '#FF9500', '#FF3B30', '#AF52DE', '#5856D6']
    return random.choice(colors)

def log_user_activity(user_id, action, details=None):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("INSERT INTO user_activity (user_id, action, details, timestamp) VALUES (?, ?, ?, ?)",
                 (user_id, action, str(details) if details else None, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()

# ---------- Routes ----------
@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/api/health')
def health_check():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "version": "2.0.0"
    })

# Enhanced registration with profile
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    valid, msg = validate_fields(data, ["username", "password"])
    if not valid:
        return jsonify({"success": False, "error": msg}), 400

    hashed_pw = bcrypt.hashpw(data["password"].encode(), bcrypt.gensalt())
    avatar_color = generate_avatar_color()

    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("""INSERT INTO users 
                        (username, password, email, full_name, avatar_color, bio, created_at) 
                        VALUES (?, ?, ?, ?, ?, ?, ?)""",
                     (data["username"], hashed_pw, 
                      data.get("email"), data.get("full_name"), 
                      avatar_color, data.get("bio"),
                      datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
        return jsonify({"success": True, "message": "User registered successfully"})
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "error": "Username already exists"}), 400

# Enhanced login with session tracking
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    valid, msg = validate_fields(data, ["username", "password"])
    if not valid:
        return jsonify({"success": False, "error": msg}), 400

    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT id, password, username, avatar_color FROM users WHERE username=?", (data["username"],))
        user = c.fetchone()

    if not user or not bcrypt.checkpw(data["password"].encode(), user["password"]):
        return jsonify({"success": False, "error": "Invalid credentials"}), 401

    # Start user session
    with get_db() as conn:
        c = conn.cursor()
        c.execute("INSERT INTO user_sessions (user_id, session_start) VALUES (?, ?)",
                 (user["id"], datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()

    token = jwt.encode({
        "user_id": user["id"],
        "username": user["username"],
        "exp": datetime.utcnow() + timedelta(hours=24)
    }, SECRET_KEY, algorithm="HS256")

    return jsonify({
        "success": True, 
        "token": token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "avatar_color": user["avatar_color"]
        }
    })

# Enhanced posts with pagination and filtering
@app.route('/api/posts', methods=['GET', 'POST'])
@token_required
def posts():
    with get_db() as conn:
        c = conn.cursor()
        
        if request.method == 'POST':
            data = request.get_json()
            valid, msg = validate_fields(data, ["category", "content"])
            if not valid:
                return jsonify({"success": False, "error": msg}), 400
            
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            c.execute("""INSERT INTO posts 
                        (user_id, category, title, content, timestamp, tags) 
                        VALUES (?, ?, ?, ?, ?, ?)""",
                     (request.user_id, data["category"], data.get("title"), 
                      data["content"], timestamp, data.get("tags")))
            conn.commit()
            
            # Log activity
            log_user_activity(request.user_id, "post_created", {"post_id": c.lastrowid})
            
            return jsonify({"success": True, "message": "Post added", "post_id": c.lastrowid}), 201

        # GET with pagination and filtering
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        category = request.args.get('category', '')
        search = request.args.get('search', '')
        
        offset = (page - 1) * per_page
        
        query = """SELECT p.*, u.username, u.avatar_color 
                   FROM posts p 
                   JOIN users u ON p.user_id = u.id"""
        count_query = "SELECT COUNT(*) FROM posts p JOIN users u ON p.user_id = u.id"
        params = []
        
        conditions = []
        if category:
            conditions.append("p.category = ?")
            params.append(category)
        
        if search:
            conditions.append("(p.content LIKE ? OR p.title LIKE ?)")
            params.extend([f'%{search}%', f'%{search}%'])
        
        if conditions:
            where_clause = " WHERE " + " AND ".join(conditions)
            query += where_clause
            count_query += where_clause
        
        query += " ORDER BY p.is_pinned DESC, p.timestamp DESC LIMIT ? OFFSET ?"
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

# Comments endpoints
@app.route('/api/posts/<int:post_id>/comments', methods=['GET', 'POST'])
@token_required
def post_comments(post_id):
    with get_db() as conn:
        c = conn.cursor()
        
        if request.method == 'POST':
            data = request.get_json()
            valid, msg = validate_fields(data, ["content"])
            if not valid:
                return jsonify({"success": False, "error": msg}), 400
            
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            c.execute("""INSERT INTO comments (post_id, user_id, content, timestamp) 
                        VALUES (?, ?, ?, ?)""",
                     (post_id, request.user_id, data["content"], timestamp))
            
            # Update post comments count
            c.execute("UPDATE posts SET comments_count = comments_count + 1 WHERE id = ?", (post_id,))
            
            conn.commit()
            return jsonify({"success": True, "message": "Comment added"}), 201
        
        # GET comments for post
        c.execute("""SELECT c.*, u.username, u.avatar_color 
                    FROM comments c 
                    JOIN users u ON c.user_id = u.id 
                    WHERE c.post_id = ? 
                    ORDER BY c.timestamp ASC""", (post_id,))
        comments = [dict(row) for row in c.fetchall()]
        
        return jsonify({"success": True, "data": comments})

# Like/unlike endpoints
@app.route('/api/posts/<int:post_id>/like', methods=['POST'])
@token_required
def like_post(post_id):
    with get_db() as conn:
        c = conn.cursor()
        
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
        
        return jsonify({
            "success": True, 
            "action": action,
            "likes_count": likes_count
        })

# User profile endpoints
@app.route('/api/profile', methods=['GET'])
@token_required
def get_profile():
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""SELECT id, username, email, full_name, avatar_color, bio, created_at 
                    FROM users WHERE id = ?""", (request.user_id,))
        user = c.fetchone()
        
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404
        
        # Get user stats
        c.execute("SELECT COUNT(*) as post_count FROM posts WHERE user_id = ?", (request.user_id,))
        post_count = c.fetchone()["post_count"]
        
        c.execute("SELECT COUNT(*) as like_count FROM likes WHERE user_id = ?", (request.user_id,))
        like_count = c.fetchone()["like_count"]
        
        return jsonify({
            "success": True,
            "profile": dict(user),
            "stats": {
                "posts": post_count,
                "likes_received": like_count
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

# Search endpoint
@app.route('/api/search')
def search():
    query = request.args.get('q', '')
    if not query or len(query) < 2:
        return jsonify({"success": False, "error": "Query too short"}), 400
    
    with get_db() as conn:
        c = conn.cursor()
        
        # Search posts
        c.execute("""SELECT p.*, u.username, u.avatar_color 
                    FROM posts p 
                    JOIN users u ON p.user_id = u.id 
                    WHERE p.content LIKE ? OR p.title LIKE ? 
                    ORDER BY p.timestamp DESC LIMIT 20""",
                 (f'%{query}%', f'%{query}%'))
        posts = [dict(row) for row in c.fetchall()]
        
        # Search users
        c.execute("""SELECT id, username, avatar_color, bio 
                    FROM users 
                    WHERE username LIKE ? OR bio LIKE ? 
                    LIMIT 10""",
                 (f'%{query}%', f'%{query}%'))
        users = [dict(row) for row in c.fetchall()]
        
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

# Error handlers
@app.errorhandler(404)
def not_found(e): 
    return jsonify({"success": False, "error": "Endpoint not found"}), 404

@app.errorhandler(500)
def server_error(e): 
    return jsonify({"success": False, "error": "Internal server error"}), 500

@app.errorhandler(413)
def too_large(e):
    return jsonify({"success": False, "error": "File too large"}), 413

if __name__ == '__main__':
    app.run(debug=True)