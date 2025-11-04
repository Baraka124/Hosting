from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sqlite3, os, jwt, bcrypt
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)

DB_NAME = "konekt.db"
SECRET_KEY = "supersecret-jwt-key"

# ---------- Database Layer ----------
def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
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
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "error": "Token expired"}), 401
        except Exception:
            return jsonify({"success": False, "error": "Invalid token"}), 401
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

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    valid, msg = validate_fields(data, ["username", "password"])
    if not valid:
        return jsonify({"success": False, "error": msg}), 400

    hashed_pw = bcrypt.hashpw(data["password"].encode(), bcrypt.gensalt())

    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                      (data["username"], hashed_pw))
            conn.commit()
        return jsonify({"success": True, "message": "User registered successfully"})
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "error": "Username already exists"}), 400

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    valid, msg = validate_fields(data, ["username", "password"])
    if not valid:
        return jsonify({"success": False, "error": msg}), 400

    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT id, password FROM users WHERE username=?", (data["username"],))
        user = c.fetchone()

    if not user or not bcrypt.checkpw(data["password"].encode(), user["password"]):
        return jsonify({"success": False, "error": "Invalid credentials"}), 401

    token = jwt.encode({
        "user_id": user["id"],
        "exp": datetime.utcnow() + timedelta(hours=4)
    }, SECRET_KEY, algorithm="HS256")

    return jsonify({"success": True, "token": token})

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
            c.execute("INSERT INTO posts (user_id, category, content, timestamp) VALUES (?, ?, ?, ?)",
                      (request.user_id, data["category"], data["content"], timestamp))
            conn.commit()
            return jsonify({"success": True, "message": "Post added"}), 201

        c.execute("""SELECT p.id, u.username, p.category, p.content, p.timestamp
                     FROM posts p JOIN users u ON p.user_id=u.id
                     ORDER BY p.id DESC""")
        rows = [dict(row) for row in c.fetchall()]
    return jsonify({"success": True, "data": rows})

@app.errorhandler(404)
def not_found(e): return jsonify({"success": False, "error": "Not found"}), 404

@app.errorhandler(500)
def server_error(e): return jsonify({"success": False, "error": "Server error"}), 500

if __name__ == '__main__':
    app.run(debug=True)
