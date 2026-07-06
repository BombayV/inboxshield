import unittest
import os
import sqlite3
from pathlib import Path

from inboxshield.tools.whois_lookup import extract_domain, lookup_whois
from inboxshield.tools.redirect_follow import trace_redirects
from inboxshield.tools.virustotal import scan_url_virustotal
from inboxshield.email_fetcher import parse_raw_email
from inboxshield.database import init_db, save_email_analysis, get_email_verdict

class TestInboxShieldComponents(unittest.TestCase):
    
    def test_domain_extraction(self):
        self.assertEqual(extract_domain("https://www.google.com/search?q=test"), "google.com")
        self.assertEqual(extract_domain("http://github.com/settings/keys"), "github.com")
        self.assertEqual(extract_domain("netflix-security-alert.com/login"), "netflix-security-alert.com")
        
    def test_whois_lookup_fallback(self):
        # Should complete without crashing even for invalid domains
        res = lookup_whois("invalid-domain-name-that-does-not-exist-12345.xyz")
        self.assertIsNotNone(res)
        self.assertEqual(res["domain"], "invalid-domain-name-that-does-not-exist-12345.xyz")
        
    def test_email_parsing(self):
        sample_eml = Path(__file__).parent / "samples" / "safe_email.eml"
        with open(sample_eml, "rb") as f:
            raw_bytes = f.read()
            
        data = parse_raw_email(raw_bytes)
        self.assertEqual(data["subject"], "[GitHub] Security Alert: New SSH key added to your account")
        self.assertEqual(data["sender"], "GitHub <noreply@github.com>")
        self.assertIn("https://github.com/settings/keys", data["links"])
        
    def test_database_operations(self):
        db_path = "test_inboxshield.db"
        if os.path.exists(db_path):
            os.remove(db_path)
            
        try:
            # Init
            init_db(db_path)
            
            # Save dummy
            email_meta = {
                "message_id": "test-msg-123@test.com",
                "sender": "Spammer <spammer@bad.com>",
                "recipient": "victim@example.com",
                "subject": "Win Money!",
                "date_received": "Mon, 06 Jul 2026 12:00:00 -0400",
                "body_preview": "Click this link to win money!"
            }
            
            urls = [{
                "original_url": "http://bad.com/win",
                "final_url": "http://bad.com/win",
                "domain": "bad.com",
                "whois_created_date": "Created 5 days ago",
                "whois_registrar": "Namecheap",
                "vt_malicious_count": 5,
                "vt_harmless_count": 10,
                "verdict": "Malicious"
            }]
            
            logs = [
                {"agent_name": "TriageAgent", "log_message": "Flagged spam keywords"},
                {"agent_name": "URLAnalystAgent", "log_message": "Flagged domain bad.com"}
            ]
            
            email_id = save_email_analysis(
                db_path=db_path,
                email_meta=email_meta,
                verdict="Phishing",
                threat_score=95,
                analysis_summary="Urgent tone and malicious link detected",
                urls_details=urls,
                agent_logs=logs
            )
            
            self.assertTrue(email_id > 0)
            
            # Fetch verdict
            retrieved = get_email_verdict(db_path, "test-msg-123@test.com")
            self.assertIsNotNone(retrieved)
            self.assertEqual(retrieved["verdict"], "Phishing")
            self.assertEqual(retrieved["threat_score"], 95)
            
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)

if __name__ == "__main__":
    unittest.main()
