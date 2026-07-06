#!/usr/bin/env python3
import os
import sys
import time
import argparse
import logging
from pathlib import Path
from typing import Dict, Any, List

from inboxshield.config import Config
from inboxshield.database import init_db, save_email_analysis
from inboxshield.email_fetcher import IMAPConnection, parse_raw_email
from inboxshield.agents.orchestrator import AgentOrchestrator

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("inboxshield")

def run_pipeline_for_email(
    email_data: Dict[str, Any], 
    orchestrator: AgentOrchestrator, 
    db_path: str,
    imap_conn: IMAPConnection = None,
    uid_str: str = None
) -> Dict[str, Any]:
    """Process a single parsed email through the multi-agent analysis and action pipeline."""
    logger.info("=" * 60)
    logger.info(f"Analyzing Email: {email_data.get('subject')}")
    logger.info(f"From: {email_data.get('sender')}")
    logger.info(f"Message-ID: {email_data.get('message_id')}")
    logger.info(f"Extracted Links count: {len(email_data.get('links', []))}")
    logger.info("=" * 60)
    
    # 1. Run multi-agent pipeline
    analysis = orchestrator.analyze_email(email_data)
    
    triage = analysis["triage_analysis"]
    url_results = analysis["url_analyst_output"]
    director = analysis["director_output"]
    logs = analysis["logs"]
    
    # Format URLs list for database
    urls_db_payload = []
    for item in url_results.analyzed_urls:
        urls_db_payload.append({
            "original_url": item.url,
            "final_url": item.final_url,
            "domain": item.domain,
            "whois_created_date": item.domain_age_days, # Or string date if needed
            "whois_registrar": item.domain_registrar,
            "vt_malicious_count": item.virustotal_malicious_count,
            "vt_harmless_count": item.virustotal_harmless_count,
            "verdict": item.verdict
        })
        
    # Convert whois age to string if available
    for item, db_item in zip(url_results.analyzed_urls, urls_db_payload):
        db_item["whois_created_date"] = (
            f"Created {item.domain_age_days} days ago" 
            if item.domain_age_days is not None else "Unknown"
        )
        
    # 2. Save analysis to Database
    email_id = save_email_analysis(
        db_path=db_path,
        email_meta=email_data,
        verdict=director.verdict,
        threat_score=director.threat_score,
        analysis_summary=director.reasoning_summary,
        urls_details=urls_db_payload,
        agent_logs=logs
    )
    
    logger.info(f"Saved analysis to database (ID: {email_id}) with Verdict: {director.verdict}")
    
    # 3. Take security action
    if director.verdict == "Phishing" and imap_conn and uid_str:
        logger.warning(f"ACTION REQUIRED: Moving phishing email UID {uid_str} to isolation folder.")
        try:
            imap_conn.isolate_email(
                uid_str=uid_str,
                source_folder=Config.MONITOR_FOLDER,
                target_folder=Config.ISOLATE_FOLDER
            )
        except Exception as e:
            logger.error(f"Failed to isolate email UID {uid_str}: {e}")
    elif director.verdict == "Suspicious":
        logger.warning("Email marked as Suspicious. Saving to database; no IMAP move action taken.")
    else:
        logger.info("Email marked as Safe. No action taken.")
        
    return analysis

def monitor_inbox(orchestrator: AgentOrchestrator):
    """Connect to IMAP server, poll for unseen emails, analyze them."""
    imap = IMAPConnection()
    try:
        imap.connect()
        unseen = imap.fetch_unseen_emails(Config.MONITOR_FOLDER)
        if unseen:
            logger.info(f"Retrieved {len(unseen)} unseen email(s) for analysis.")
            for uid, email_data in unseen:
                try:
                    run_pipeline_for_email(
                        email_data=email_data,
                        orchestrator=orchestrator,
                        db_path=Config.DB_PATH,
                        imap_conn=imap,
                        uid_str=uid
                    )
                except Exception as e:
                    logger.error(f"Error processing email UID {uid}: {e}")
        else:
            logger.info("No new emails found.")
    except Exception as e:
        logger.error(f"IMAP Error in polling cycle: {e}")
    finally:
        imap.disconnect()

def main():
    parser = argparse.ArgumentParser(
        description="InboxShield - Automated Email Security & Phishing Isolation"
    )
    
    # Mode arguments
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--run-once", 
        action="store_true", 
        help="Connect to IMAP, process all unseen emails once, and exit"
    )
    group.add_argument(
        "--daemon", 
        action="store_true", 
        help="Run in continuous polling mode"
    )
    group.add_argument(
        "--test-email", 
        type=str, 
        help="Path to a raw RFC822 email file (.eml or text) to run analysis offline"
    )
    group.add_argument(
        "--dashboard", 
        action="store_true", 
        help="Launch the web dashboard to view analyzed emails"
    )
    
    parser.add_argument(
        "--verbose", 
        action="store_true", 
        help="Enable debug logging"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled.")
        
    # Check config validity
    warnings = Config.validate()
    if warnings:
        logger.warning("Configuration alerts:")
        for w in warnings:
            logger.warning(f" - {w}")
            
    # Initialize SQLite database
    init_db(Config.DB_PATH)
    
    # Initialize Multi-Agent Orchestrator
    orchestrator = AgentOrchestrator()
    
    if args.test_email:
        logger.info(f"Running in offline test mode using raw file: {args.test_email}")
        email_file = Path(args.test_email)
        if not email_file.exists():
            logger.error(f"File not found: {args.test_email}")
            sys.exit(1)
            
        try:
            with open(email_file, "rb") as f:
                raw_bytes = f.read()
                
            email_data = parse_raw_email(raw_bytes)
            analysis = run_pipeline_for_email(
                email_data=email_data,
                orchestrator=orchestrator,
                db_path=Config.DB_PATH
            )
            
            # Print analysis results nicely in console
            director = analysis["director_output"]
            print("\n" + "=" * 50)
            print("SECURITY ANALYSIS REPORT (OFFLINE)")
            print("=" * 50)
            print(f"VERDICT:      {director.verdict}")
            print(f"THREAT SCORE: {director.threat_score}/100")
            print(f"ACTION:       {director.action_required}")
            print("-" * 50)
            print("SUMMARY REASONING:")
            print(director.reasoning_summary)
            print("=" * 50 + "\n")
            
        except Exception as e:
            logger.exception(f"Failed to process test email file: {e}")
            sys.exit(1)
            
    elif args.dashboard:
        logger.info("Starting Web Dashboard...")
        from inboxshield.web import run_server
        run_server(Config.DB_PATH, host="0.0.0.0", port=5000)

    elif args.run_once:
        logger.info("Starting single-run monitoring cycle...")
        if not Config.EMAIL_USER or not Config.EMAIL_PASSWORD:
            logger.error("IMAP credentials missing in configuration. Cannot connect.")
            sys.exit(1)
        monitor_inbox(orchestrator)
        logger.info("Single-run completed.")
        
    elif args.daemon:
        logger.info(f"Starting daemon mode. Polling every {Config.POLL_INTERVAL} seconds. Press Ctrl+C to stop.")
        if not Config.EMAIL_USER or not Config.EMAIL_PASSWORD:
            logger.error("IMAP credentials missing in configuration. Cannot connect.")
            sys.exit(1)
            
        try:
            while True:
                monitor_inbox(orchestrator)
                logger.info(f"Sleeping for {Config.POLL_INTERVAL} seconds...")
                time.sleep(Config.POLL_INTERVAL)
        except KeyboardInterrupt:
            logger.info("Daemon stopped by user. Exiting.")

if __name__ == "__main__":
    main()
