import logging
import whois
from urllib.parse import urlparse
from datetime import datetime
from typing import Dict, Any, Optional, Union, List

logger = logging.getLogger(__name__)

def extract_domain(url: str) -> str:
    """Extract domain from a given URL."""
    try:
        parsed = urlparse(url)
        # Handle cases where URL doesn't have scheme
        if not parsed.scheme:
            parsed = urlparse("http://" + url)
        domain = parsed.netloc
        if not domain:
            domain = parsed.path
        # Strip port if any
        if ":" in domain:
            domain = domain.split(":")[0]
        # Strip www.
        if domain.startswith("www."):
            domain = domain[4:]
        return domain
    except Exception as e:
        logger.error(f"Error parsing URL {url}: {e}")
        return ""

def parse_date(date_val: Any) -> Optional[str]:
    """Parse dates from WHOIS, handling lists and raw datetimes."""
    if not date_val:
        return None
    if isinstance(date_val, list):
        # Use the first date if it's a list
        return parse_date(date_val[0])
    if isinstance(date_val, datetime):
        return date_val.isoformat()
    if isinstance(date_val, str):
        # Clean up string
        return date_val.strip()
    return str(date_val)

def lookup_whois(domain_or_url: str) -> Dict[str, Any]:
    """
    Perform a WHOIS query on the domain.
    
    Returns:
        A dictionary containing:
        - domain: Domain checked
        - registrar: Registrar name
        - creation_date: ISO creation date or string
        - expiration_date: ISO expiration date or string
        - organization: Registrant organization
        - age_days: Age in days (if creation date available)
        - error: Error message if lookup failed
    """
    domain = extract_domain(domain_or_url)
    result = {
        "domain": domain,
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "organization": None,
        "age_days": None,
        "error": None
    }
    
    if not domain:
        result["error"] = "Invalid domain extracted"
        return result

    try:
        logger.info(f"Performing WHOIS lookup for domain: {domain}")
        w = whois.whois(domain)
        
        result["registrar"] = w.get("registrar")
        result["organization"] = w.get("org") or w.get("organization")
        
        created = w.get("creation_date")
        expired = w.get("expiration_date")
        
        created_str = parse_date(created)
        expired_str = parse_date(expired)
        
        result["creation_date"] = created_str
        result["expiration_date"] = expired_str
        
        # Calculate domain age in days
        if created:
            first_created = created[0] if isinstance(created, list) else created
            if isinstance(first_created, datetime):
                # Ensure timezone-naive comparison to avoid TypeError
                first_created_naive = first_created.replace(tzinfo=None)
                age = datetime.now() - first_created_naive
                result["age_days"] = age.days
            elif isinstance(first_created, str):
                # Try parsing common formats if python-whois returned it as string
                for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%d-%b-%Y", "%Y.%m.%d"):
                    try:
                        dt = datetime.strptime(first_created.strip()[:10], fmt[:8])
                        age = datetime.now() - dt
                        result["age_days"] = age.days
                        break
                    except ValueError:
                        continue
                        
    except Exception as e:
        logger.warning(f"WHOIS lookup failed for {domain}: {e}")
        result["error"] = str(e)
        
    return result
