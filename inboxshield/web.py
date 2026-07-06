import os
import sqlite3
from flask import Flask, jsonify, render_template, request
from .database import get_db_connection

def create_app(db_path: str):
    app = Flask(__name__, static_folder='static', template_folder='templates')
    
    @app.route('/')
    def index():
        return render_template('index.html')
    
    @app.route('/api/metrics')
    def get_metrics():
        try:
            with get_db_connection(db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT verdict, COUNT(*) as count FROM emails GROUP BY verdict")
                rows = cursor.fetchall()
                
                metrics = {
                    "total": 0,
                    "safe": 0,
                    "suspicious": 0,
                    "phishing": 0
                }
                
                for row in rows:
                    verdict = row["verdict"].lower() if row["verdict"] else "unknown"
                    count = row["count"]
                    metrics["total"] += count
                    if verdict == "safe":
                        metrics["safe"] = count
                    elif verdict == "suspicious":
                        metrics["suspicious"] = count
                    elif verdict == "phishing":
                        metrics["phishing"] = count
                        
                return jsonify(metrics)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route('/api/emails')
    def get_emails():
        try:
            with get_db_connection(db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id, message_id, sender, subject, verdict, threat_score, processed_at FROM emails ORDER BY processed_at DESC LIMIT 50")
                rows = cursor.fetchall()
                return jsonify([dict(row) for row in rows])
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route('/api/emails/<int:email_id>')
    def get_email_details(email_id):
        try:
            with get_db_connection(db_path) as conn:
                cursor = conn.cursor()
                
                # Fetch email
                cursor.execute("SELECT * FROM emails WHERE id = ?", (email_id,))
                email_row = cursor.fetchone()
                if not email_row:
                    return jsonify({"error": "Email not found"}), 404
                    
                email_data = dict(email_row)
                
                # Fetch URLs
                cursor.execute("SELECT * FROM urls_analyzed WHERE email_id = ?", (email_id,))
                urls = [dict(row) for row in cursor.fetchall()]
                
                # Fetch Logs
                cursor.execute("SELECT * FROM analysis_logs WHERE email_id = ? ORDER BY timestamp ASC", (email_id,))
                logs = [dict(row) for row in cursor.fetchall()]
                
                return jsonify({
                    "email": email_data,
                    "urls": urls,
                    "logs": logs
                })
        except Exception as e:
            return jsonify({"error": str(e)}), 500
            
    return app

def run_server(db_path: str, host="0.0.0.0", port=5000):
    app = create_app(db_path)
    print(f"[*] Starting InboxShield Web Dashboard on http://{host}:{port}")
    app.run(host=host, port=port, debug=False)
