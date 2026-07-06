# InboxShield - Automated Email Security & Phishing Isolation

InboxShield is an automated email security application designed to intercept, analyze, and isolate phishing threats before they reach an end-user’s inbox. By evaluating inbound email metadata, verifying domain authenticity, and deeply inspecting embedded URLs for hidden redirects or IP logging scripts, the system provides real-time defense against modern digital social engineering tactics.

---

## Key Features
- **IMAP Monitoring**: Automatically polls any IMAP-compliant email provider (e.g. Gmail) for unread messages.
- **BeautifulSoup Parsing**: Parses text and HTML email parts to extract all hyperlinks safely.
- **Diagnostic Engine**:
  - **WHOIS Checker**: Extracts domain age, creation date, and registrar data.
  - **VirusTotal API Integration**: Automatically gathers malicious indicator counts for all URLs.
  - **Redirect Chain Tracker**: Follows HTTP/HTTPS redirects to identify hidden jumps, meta-refreshes, or IP logger sites.
- **Structured Multi-Agent System**:
  - Powered by **Google GenAI SDK (Gemini 2.5 Flash)**.
  - **Triage Agent**: Analyzes urgency language, sender display misalignment, and text anomalies.
  - **URL Analyst Agent**: Evaluates diagnostic metrics for links (WHOIS age, VT status, redirect hops).
  - **Security Director Agent**: Consolidates reports to yield a unified threat rating and action.
- **Automated Isolation**: Phishing emails are moved out of the inbox to an isolation folder (e.g. `InboxShield-Isolate`) and deleted from the main inbox.
- **Audit Persistence**: Stores final verdicts, threat scores, URL statistics, and multi-agent reasoning logs inside SQLite.

---

## File Structure

```
inboxshield/
├── README.md                 # Project README with documentation
├── requirements.txt          # Python dependencies
├── .env.example              # Sample environment configuration file
├── main.py                   # Entry point CLI runner
├── tests/
│   ├── samples/
│   │   ├── safe_email.eml     # Sample clean email for offline testing
│   │   └── phishing_email.eml # Sample phishing email for offline testing
│   └── test_components.py    # Unit tests for core libraries & helpers
└── inboxshield/
    ├── __init__.py           # Package initializer
    ├── config.py             # Environment configuration manager
    ├── database.py           # SQLite schema and persistent queries
    ├── email_fetcher.py      # IMAP connector and parser
    ├── tools/
    │   ├── __init__.py
    │   ├── whois_lookup.py   # WHOIS query wrapper with age calculator
    │   ├── virustotal.py     # VirusTotal v3 API implementation
    │   └── redirect_follow.py# Redirect path and meta-refresh tracer
    └── agents/
        ├── __init__.py
        ├── schemas.py        # Pydantic structured output structures
        └── orchestrator.py   # Multi-agent workflow coordination
```

---

## Installation & Setup

### 1. Clone & Set Up Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure Environment Variables
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

Open `.env` and fill in your keys:
- **`GEMINI_API_KEY`**: Obtain from Google AI Studio.
- **`VIRUSTOTAL_API_KEY`** (Optional): Obtain from VirusTotal Community portal.
- **`EMAIL_USER` / `EMAIL_PASSWORD`**:
  - For **Gmail**, you cannot use your regular account password due to Multi-Factor Authentication. You **must** generate an **App Password**. Go to: Google Account > Security > 2-Step Verification > App Passwords.

---

## Running the Application

### A. Run Once
To fetch all unseen messages, run them through the analysis pipeline, execute isolation if needed, and exit immediately:
```bash
python3 main.py --run-once
```

### B. Run as a Background Daemon
To run in a continuous polling loop checking for new emails (polls every `POLL_INTERVAL` configured in `.env`):
```bash
python3 main.py --daemon
```

### C. Run Local Offline Tests (No IMAP Required)
You can test the multi-agent detection capability locally by feeding raw `.eml` files. This is very useful for debugging or dry-running without messing up an active mailbox:
```bash
# Test a known safe email
python3 main.py --test-email tests/samples/safe_email.eml

# Test a known phishing email
python3 main.py --test-email tests/samples/phishing_email.eml
```
*(Note: If `GEMINI_API_KEY` is not provided in your `.env`, the system automatically falls back to a deterministic Mock Analysis mode).*

### D. Run the Web Dashboard
You can visualize the analysis results stored in the SQLite database by running the web dashboard:
```bash
python3 main.py --dashboard
```
Navigate to `http://127.0.0.1:5000` in your browser to view the beautiful, glassmorphism UI showing global metrics, recent emails, threat scores, and detailed agent analysis logs.

---

## Database Architecture
Results are persisted inside the `inboxshield.db` SQLite database with the following tables:
1. **`emails`**: Message metadata, final verdict (`Safe`, `Suspicious`, `Phishing`), threat score (0-100), and security reasoning summary.
2. **`urls_analyzed`**: Track details of all extracted links, redirect chains, registrar data, domain age, and VirusTotal flags.
3. **`analysis_logs`**: Chronological trace of actions, tool invocations, and decisions made by individual agents (Triage, URL Analyst, Security Director).

To inspect the SQLite records:
```bash
sqlite3 inboxshield.db "SELECT subject, verdict, threat_score FROM emails;"
```

## Running Unit Tests
To verify all internal libraries, database routines, and mock tools function properly on your system:
```bash
python3 -m unittest tests/test_components.py
```
