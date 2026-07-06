import sqlite3
import logging
from contextlib import contextmanager
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

@contextmanager
def get_db_connection(db_path: str):
    """Context manager for SQLite database connections."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    # Enable foreign keys
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
    finally:
        conn.close()

def init_db(db_path: str):
    """Initialize the SQLite database schema if tables do not exist."""
    logger.info(f"Initializing database at: {db_path}")
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        
        # Create emails table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT UNIQUE,
                sender TEXT,
                recipient TEXT,
                subject TEXT,
                date_received TEXT,
                body_preview TEXT,
                verdict TEXT,
                threat_score INTEGER,
                analysis_summary TEXT,
                processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # Create urls_analyzed table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS urls_analyzed (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_id INTEGER,
                original_url TEXT,
                final_url TEXT,
                domain TEXT,
                whois_created_date TEXT,
                whois_registrar TEXT,
                vt_malicious_count INTEGER,
                vt_harmless_count INTEGER,
                verdict TEXT,
                FOREIGN KEY (email_id) REFERENCES emails (id) ON DELETE CASCADE
            );
        """)
        
        # Create analysis_logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_id INTEGER,
                agent_name TEXT,
                log_message TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (email_id) REFERENCES emails (id) ON DELETE CASCADE
            );
        """)
        
        conn.commit()
    logger.info("Database initialized successfully.")

def save_email_analysis(
    db_path: str,
    email_meta: Dict[str, Any],
    verdict: str,
    threat_score: int,
    analysis_summary: str,
    urls_details: List[Dict[str, Any]],
    agent_logs: List[Dict[str, Any]]
) -> int:
    """
    Save the complete results of an email analysis pipeline.
    
    Args:
        db_path: Path to the SQLite db file.
        email_meta: Dict with keys message_id, sender, recipient, subject, date_received, body_preview
        verdict: 'Safe', 'Suspicious', or 'Phishing'
        threat_score: Int score 0-100
        analysis_summary: Markdown or plain text synthesis of the threat
        urls_details: List of dicts representing analyzed URLs
        agent_logs: List of dicts representing steps/logs of the multi-agent system
    
    Returns:
        The database ID of the inserted email record.
    """
    logger.info(f"Saving analysis result for Message-ID: {email_meta.get('message_id')}")
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        
        try:
            # Insert email record (use INSERT OR REPLACE to allow re-runs of same email)
            cursor.execute("""
                INSERT OR REPLACE INTO emails (
                    message_id, sender, recipient, subject, date_received, body_preview, verdict, threat_score, analysis_summary
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                email_meta.get("message_id"),
                email_meta.get("sender"),
                email_meta.get("recipient"),
                email_meta.get("subject"),
                email_meta.get("date_received"),
                email_meta.get("body_preview", "")[:500],  # Preview limit
                verdict,
                threat_score,
                analysis_summary
            ))
            
            email_id = cursor.lastrowid
            
            # If message was replaced, fetch its ID (since lastrowid might be unexpected in some versions)
            if not email_id or email_id == 0:
                cursor.execute("SELECT id FROM emails WHERE message_id = ?", (email_meta.get("message_id"),))
                row = cursor.fetchone()
                if row:
                    email_id = row["id"]
            
            # Clean up old URLs / Logs for this email if we are overwriting
            cursor.execute("DELETE FROM urls_analyzed WHERE email_id = ?", (email_id,))
            cursor.execute("DELETE FROM analysis_logs WHERE email_id = ?", (email_id,))
            
            # Insert URL details
            for url in urls_details:
                cursor.execute("""
                    INSERT INTO urls_analyzed (
                        email_id, original_url, final_url, domain, whois_created_date, whois_registrar, vt_malicious_count, vt_harmless_count, verdict
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    email_id,
                    url.get("original_url"),
                    url.get("final_url"),
                    url.get("domain"),
                    url.get("whois_created_date"),
                    url.get("whois_registrar"),
                    url.get("vt_malicious_count", 0),
                    url.get("vt_harmless_count", 0),
                    url.get("verdict")
                ))
            
            # Insert Agent Logs
            for log in agent_logs:
                cursor.execute("""
                    INSERT INTO analysis_logs (
                        email_id, agent_name, log_message
                    ) VALUES (?, ?, ?)
                """, (
                    email_id,
                    log.get("agent_name"),
                    log.get("log_message")
                ))
                
            conn.commit()
            return email_id
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to save email analysis: {e}")
            raise

def get_email_verdict(db_path: str, message_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve existing verdict for a message_id if it exists."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM emails WHERE message_id = ?", (message_id,))
        row = cursor.fetchone()
        if row:
            return dict(row)
    return None
