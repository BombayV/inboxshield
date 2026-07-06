import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env if present
env_path = Path(__file__).resolve().parents[1] / ".env"
load_dotenv(dotenv_path=env_path)

class Config:
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    
    IMAP_SERVER = os.getenv("IMAP_SERVER", "imap.gmail.com")
    IMAP_PORT = int(os.getenv("IMAP_PORT", "993"))
    EMAIL_USER = os.getenv("EMAIL_USER", "")
    EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "")
    
    MONITOR_FOLDER = os.getenv("MONITOR_FOLDER", "INBOX")
    ISOLATE_FOLDER = os.getenv("ISOLATE_FOLDER", "InboxShield-Isolate")
    
    DB_PATH = os.getenv("DB_PATH", "inboxshield.db")
    POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "60"))

    @classmethod
    def validate(cls) -> list[str]:
        """Validate config parameters and return a list of warnings or issues."""
        warnings = []
        if not cls.GEMINI_API_KEY:
            warnings.append("GEMINI_API_KEY is not set. Multi-agent analysis will fail.")
        if not cls.EMAIL_USER or not cls.EMAIL_PASSWORD:
            warnings.append("EMAIL_USER or EMAIL_PASSWORD is not set. IMAP operations will fail.")
        if not cls.VIRUSTOTAL_API_KEY:
            warnings.append("VIRUSTOTAL_API_KEY is not set. VirusTotal URL scans will fall back to local mock reports.")
        return warnings
