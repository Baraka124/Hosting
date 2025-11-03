from flask import Flask, request, jsonify, send_from_directory
import sqlite3, os, jwt
from datetime import datetime, timedelta

app = Flask(__name__)
DB_NAME = "konekt.db"
SECRET_KEY = "supersecret-jwt-key"

# ---------- Database Layer ----------
def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL
                )""")
    c.execute("""CREATE TABLE IF NOT EXISTS posts(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    category TEXT NOT NULL,
                    content TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )""")
    conn.commit()
    conn.close()

init_db()

# ---------- Helper Functions ----------
def token_required(func):
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token:
            return jsonify({"error": "Missing token"}), 401
        try:
            decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user_id = decoded["user_id"]
        except Exception as e:
            return jsonify({"error": "Invalid token"}), 401
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

def validate_fields(data, required):
    for field in required:
        if not data.get(field):
            return False, f"Missing field: {field}"
    return True, None

# ---------- Routes ----------
@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

# Register new user
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    valid, msg = validate_fields(data, ["username", "password"])
    if not valid:
        return jsonify({"error": msg}), 400

    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                  (data["username"], data["password"]))
        conn.commit()
        return jsonify({"message": "User registered successfully"})
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 400
    finally:
        conn.close()

# Login
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    valid, msg = validate_fields(data, ["username", "password"])
    if not valid:
        return jsonify({"error": msg}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username=? AND password=?",
              (data["username"], data["password"]))
    user = c.fetchone()
    conn.close()

    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    token = jwt.encode({
        "user_id": user["id"],
        "exp": datetime.utcnow() + timedelta(hours=2)
    }, SECRET_KEY, algorithm="HS256")
    return jsonify({"token": token})

# Post creation and listing
@app.route('/api/posts', methods=['GET', 'POST'])
@token_required
def posts():
    conn = get_db()
    c = conn.cursor()

    if request.method == 'POST':
        data = request.get_json()
        valid, msg = validate_fields(data, ["category", "content"])
        if not valid:
            return jsonify({"error": msg}), 400
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("INSERT INTO posts (user_id, category, content, timestamp) VALUES (?, ?, ?, ?)",
                  (request.user_id, data["category"], data["content"], timestamp))
        conn.commit()
        conn.close()
        return jsonify({"message": "Post added"}), 201

    c.execute("""SELECT p.id, u.username, p.category, p.content, p.timestamp
                 FROM posts p JOIN users u ON p.user_id=u.id
                 ORDER BY p.id DESC""")
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(rows)

# ---------- Error Handling ----------
@app.errorhandler(404)
def not_found(e): return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def server_error(e): return jsonify({"error": "Server error"}), 500

if __name__ == '__main__':
    app.run(debug=True)
