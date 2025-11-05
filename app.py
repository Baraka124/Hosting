import os
import jwt
import bcrypt
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from datetime import datetime, timedelta
import sqlite3
import logging
import secrets
import re
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-123')

CORS(app)

# Setup logging
logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

def get_db():
    conn = sqlite3.connect('forum.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    try:
        c = conn.cursor()
        
        # Drop all tables and recreate
        c.executescript('''
            DROP TABLE IF EXISTS users;
            DROP TABLE IF EXISTS posts;
            DROP TABLE IF EXISTS comments;
            DROP TABLE IF EXISTS likes;
            DROP TABLE IF EXISTS bookmarks;

            CREATE TABLE users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT,
                avatar_color TEXT DEFAULT '#007AFF',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1
            );

            CREATE TABLE posts(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                category TEXT NOT NULL,
                title TEXT,
                content TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                likes_count INTEGER DEFAULT 0,
                comments_count INTEGER DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE comments(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(post_id) REFERENCES posts(id),
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE likes(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                post_id INTEGER,
                comment_id INTEGER,
                UNIQUE(user_id, post_id, comment_id)
            );

            CREATE TABLE bookmarks(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                post_id INTEGER NOT NULL,
                UNIQUE(user_id, post_id)
            );
        ''')
        
        # Add default admin user
        hashed_pw = bcrypt.hashpw(b"admin123", bcrypt.gensalt())
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                 ("admin", hashed_pw))
        
        conn.commit()
        app.logger.info("Database initialized successfully")
    except Exception as e:
        app.logger.error(f"Database error: {e}")
        conn.rollback()
    finally:
        conn.close()

# Initialize database
init_db()

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('.', path)

@app.route('/api/health')
def health():
    return jsonify({"status": "healthy"})

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        email = data.get('email')
        
        if len(username) < 3:
            return jsonify({"success": False, "error": "Username too short"}), 400
        
        if len(password) < 8:
            return jsonify({"success": False, "error": "Password too short"}), 400
        
        conn = get_db()
        c = conn.cursor()
        
        # Check if user exists
        c.execute("SELECT id FROM users WHERE username = ?", (username,))
        if c.fetchone():
            return jsonify({"success": False, "error": "Username exists"}), 400
        
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        avatar_color = f"#{secrets.token_hex(3)}"
        
        c.execute("INSERT INTO users (username, password, email, avatar_color) VALUES (?, ?, ?, ?)",
                 (username, hashed_pw, email, avatar_color))
        
        conn.commit()
        return jsonify({"success": True, "message": "User created"})
        
    except Exception as e:
        app.logger.error(f"Register error: {e}")
        return jsonify({"success": False, "error": "Registration failed"}), 500
    finally:
        conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        conn = get_db()
        c = conn.cursor()
        
        c.execute("SELECT id, password, username, avatar_color FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        
        if not user:
            return jsonify({"success": False, "error": "Invalid credentials"}), 401
        
        if not bcrypt.checkpw(password.encode('utf-8'), user["password"]):
            return jsonify({"success": False, "error": "Invalid credentials"}), 401
        
        token = jwt.encode({
            "user_id": user["id"],
            "username": user["username"],
            "exp": datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        return jsonify({
            "success": True,
            "token": token,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "avatar_color": user["avatar_color"]
            }
        })
        
    except Exception as e:
        app.logger.error(f"Login error: {e}")
        return jsonify({"success": False, "error": "Login failed"}), 500
    finally:
        conn.close()

@app.route('/api/debug/reset-db')
def reset_db():
    init_db()
    return jsonify({"success": True, "message": "Database reset"})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)