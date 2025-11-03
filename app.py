from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
from datetime import datetime

app = Flask(__name__)
CORS(app)  # Allow requests from frontend (e.g., Vercel)

DB_FILE = "database.db"


# ------------------------------
# Database Helpers
# ------------------------------
def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cur = conn.cursor()

    # Create patients table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS patients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            age INTEGER,
            gender TEXT,
            diagnosis_date TEXT
        )
    """)

    # Create vitals table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS vitals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER,
            timestamp TEXT,
            oxygen_sat REAL,
            resp_rate REAL,
            heart_rate REAL,
            lung_capacity REAL,
            treatment_stage TEXT,
            FOREIGN KEY(patient_id) REFERENCES patients(id)
        )
    """)

    conn.commit()
    conn.close()


# Initialize the database
init_db()


# ------------------------------
# Routes
# ------------------------------

@app.route('/')
def index():
    return jsonify({"message": "COPD Digital Tracing API active"}), 200


# --- PATIENTS ---

@app.route('/api/patients', methods=['GET'])
def get_patients():
    conn = get_db_connection()
    patients = conn.execute('SELECT * FROM patients').fetchall()
    conn.close()
    return jsonify([dict(p) for p in patients])


@app.route('/api/patients', methods=['POST'])
def add_patient():
    data = request.json
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO patients (name, age, gender, diagnosis_date) VALUES (?, ?, ?, ?)',
        (data['name'], data.get('age'), data.get('gender'), data.get('diagnosis_date', datetime.now().strftime('%Y-%m-%d')))
    )
    conn.commit()
    conn.close()
    return jsonify({"message": "Patient added successfully"}), 201


# --- VITALS ---

@app.route('/api/vitals/<int:patient_id>', methods=['GET'])
def get_vitals(patient_id):
    conn = get_db_connection()
    vitals = conn.execute('SELECT * FROM vitals WHERE patient_id = ?', (patient_id,)).fetchall()
    conn.close()
    return jsonify([dict(v) for v in vitals])


@app.route('/api/vitals', methods=['POST'])
def add_vitals():
    data = request.json
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO vitals (patient_id, timestamp, oxygen_sat, resp_rate, heart_rate, lung_capacity, treatment_stage) VALUES (?, ?, ?, ?, ?, ?, ?)',
        (
            data['patient_id'],
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            data.get('oxygen_sat'),
            data.get('resp_rate'),
            data.get('heart_rate'),
            data.get('lung_capacity'),
            data.get('treatment_stage', 'unknown')
        )
    )
    conn.commit()
    conn.close()
    return jsonify({"message": "Vitals recorded successfully"}), 201


# --- SIMULATED DATA (optional) ---
@app.route('/api/simulate/<int:patient_id>', methods=['POST'])
def simulate_vitals(patient_id):
    import random
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO vitals (patient_id, timestamp, oxygen_sat, resp_rate, heart_rate, lung_capacity, treatment_stage) VALUES (?, ?, ?, ?, ?, ?, ?)',
        (
            patient_id,
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            random.uniform(88, 99),
            random.uniform(12, 25),
            random.uniform(60, 110),
            random.uniform(2.0, 5.5),
            random.choice(['pre-treatment', 'post-treatment'])
        )
    )
    conn.commit()
    conn.close()
    return jsonify({"message": "Simulated vital added"}), 201


# ------------------------------
# Main Entry
# ------------------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
