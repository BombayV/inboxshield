import imaplib
import email
from email.header import decode_header
import logging
from bs4 import BeautifulSoup
from typing import Dict, Any, List, Tuple, Optional
from inboxshield.config import Config

logger = logging.getLogger(__name__)

def decode_mime_header(header_value: str) -> str:
    """Decode encoded MIME header values (e.g. UTF-8 subjects)."""
    if not header_value:
        return ""
    try:
        decoded_parts = decode_header(header_value)
        header_text = ""
        for part, encoding in decoded_parts:
            if isinstance(part, bytes):
                header_text += part.decode(encoding or "utf-8", errors="replace")
            else:
                header_text += part
        return header_text
    except Exception as e:
        logger.debug(f"Failed to decode header: {e}")
        return str(header_value)

def extract_body_and_links(msg: email.message.Message) -> Tuple[str, str, List[str]]:
    """
    Extract plaintext body, HTML body, and unique HTTP/HTTPS hyperlinks from an email.
    """
    text_content = ""
    html_content = ""
    links = []
    
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            
            # Skip attachments
            if "attachment" in content_disposition:
                continue
                
            try:
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                charset = part.get_content_charset() or "utf-8"
                decoded_payload = payload.decode(charset, errors="replace")
                
                if content_type == "text/plain":
                    text_content += decoded_payload + "\n"
                elif content_type == "text/html":
                    html_content += decoded_payload + "\n"
            except Exception as e:
                logger.warning(f"Error parsing email body part: {e}")
    else:
        content_type = msg.get_content_type()
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                decoded = payload.decode(charset, errors="replace")
                if content_type == "text/html":
                    html_content = decoded
                else:
                    text_content = decoded
        except Exception as e:
            logger.warning(f"Error parsing single-part email body: {e}")
            
    # Extract links from HTML using BeautifulSoup
    if html_content:
        try:
            soup = BeautifulSoup(html_content, "html.parser")
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"].strip()
                # Only analyze HTTP/HTTPS links
                if href.lower().startswith(("http://", "https://")):
                    links.append(href)
        except Exception as e:
            logger.error(f"Error parsing hyperlinks with BeautifulSoup: {e}")
            
    # Clean and deduplicate links while preserving order
    unique_links = []
    for link in links:
        if link not in unique_links:
            unique_links.append(link)
            
    return text_content.strip(), html_content.strip(), unique_links

def parse_raw_email(raw_bytes: bytes) -> Dict[str, Any]:
    """Parse raw RFC822 email bytes into a structured dict representation."""
    msg = email.message_from_bytes(raw_bytes)
    
    subject = decode_mime_header(msg.get("Subject", "(No Subject)"))
    sender = decode_mime_header(msg.get("From", ""))
    recipient = decode_mime_header(msg.get("To", ""))
    date_received = decode_mime_header(msg.get("Date", ""))
    message_id = msg.get("Message-ID", "")
    
    # Generate a fallback message ID if missing
    if not message_id:
        import uuid
        message_id = f"fallback-{uuid.uuid4()}@inboxshield.local"
        
    text_body, html_body, links = extract_body_and_links(msg)
    
    # Body preview (first 400 chars of plain text or HTML text content)
    body_preview = text_body[:400]
    if not body_preview and html_body:
        try:
            soup = BeautifulSoup(html_body, "html.parser")
            body_preview = soup.get_text()[:400].strip()
        except:
            pass
            
    return {
        "message_id": message_id,
        "subject": subject,
        "sender": sender,
        "recipient": recipient,
        "date_received": date_received,
        "text_body": text_body,
        "html_body": html_body,
        "body_preview": body_preview,
        "links": links
    }

class IMAPConnection:
    """Wrapper class for SSL-based IMAP interactions."""
    def __init__(self):
        self.server = Config.IMAP_SERVER
        self.port = Config.IMAP_PORT
        self.user = Config.EMAIL_USER
        self.password = Config.EMAIL_PASSWORD
        self.conn: Optional[imaplib.IMAP4_SSL] = None
        
    def connect(self) -> imaplib.IMAP4_SSL:
        """Establish SSL connection and log in."""
        logger.info(f"Connecting to IMAP server {self.server}:{self.port}...")
        self.conn = imaplib.IMAP4_SSL(self.server, self.port)
        logger.info(f"Logging in as {self.user}...")
        self.conn.login(self.user, self.password)
        logger.info("IMAP Login successful.")
        return self.conn

    def disconnect(self):
        """Clean up connection."""
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass
            try:
                self.conn.logout()
            except Exception:
                pass
            self.conn = None
            logger.info("IMAP Connection closed.")

    def fetch_unseen_emails(self, folder: str = "INBOX") -> List[Tuple[str, Dict[str, Any]]]:
        """
        Fetch all UNSEEN emails in the specified folder.
        
        Returns:
            A list of tuples: (imap_uid_str, parsed_email_dict)
        """
        if not self.conn:
            raise RuntimeError("Not connected. Call connect() first.")
            
        logger.info(f"Selecting folder: {folder}")
        self.conn.select(folder)
        
        # Search for unseen messages
        status, data = self.conn.uid("search", None, "UNSEEN")
        if status != "OK":
            logger.error(f"Search failed in folder {folder}: {status}")
            return []
            
        uids = data[0].split()
        if not uids:
            logger.info(f"No new emails found in {folder}.")
            return []
            
        logger.info(f"Found {len(uids)} unseen email(s). Fetching...")
        results = []
        
        for uid in uids:
            uid_str = uid.decode("utf-8")
            logger.info(f"Fetching email UID: {uid_str}")
            
            # Fetch message parts
            status, fetch_data = self.conn.uid("fetch", uid, "(RFC822)")
            if status != "OK" or not fetch_data:
                logger.error(f"Failed to fetch email UID: {uid_str}")
                continue
                
            # fetch_data[0] is a tuple of (header info, body bytes)
            raw_bytes = None
            for response_part in fetch_data:
                if isinstance(response_part, tuple):
                    raw_bytes = response_part[1]
                    break
                    
            if raw_bytes:
                parsed_email = parse_raw_email(raw_bytes)
                results.append((uid_str, parsed_email))
                
        return results

    def isolate_email(self, uid_str: str, source_folder: str, target_folder: str):
        """
        Move a flagged email by copying it to target_folder and marking it deleted in source_folder.
        """
        if not self.conn:
            raise RuntimeError("Not connected. Call connect() first.")
            
        logger.info(f"Isolating email UID {uid_str} from {source_folder} to {target_folder}...")
        
        # Create target folder if it does not exist
        # IMAP CREATE returns OK or NO (if already exists, which we ignore)
        try:
            self.conn.create(target_folder)
        except Exception:
            pass # Ignore folder creation error if already exists
            
        # Select source folder
        self.conn.select(source_folder)
        
        # Copy to isolate folder
        copy_status, copy_data = self.conn.uid("COPY", uid_str, target_folder)
        if copy_status != "OK":
            logger.error(f"Failed to copy email UID {uid_str} to {target_folder}: {copy_status}")
            return
            
        # Delete from original inbox
        delete_status, delete_data = self.conn.uid("STORE", uid_str, "+FLAGS", "\\Deleted")
        if delete_status != "OK":
            logger.error(f"Failed to flag email UID {uid_str} as deleted: {delete_status}")
            return
            
        # Permanent purge
        self.conn.expunge()
        logger.info(f"Email UID {uid_str} isolated successfully.")
