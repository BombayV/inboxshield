import base64
import logging
import requests
from typing import Dict, Any

logger = logging.getLogger(__name__)

def encode_url_for_vt(url: str) -> str:
    """Encode URL to VirusTotal url identifier format (base64 urlsafe, stripped padding)."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").strip("=")

def scan_url_virustotal(url: str, api_key: str) -> Dict[str, Any]:
    """
    Look up a URL in VirusTotal v3 API. If the URL has not been analyzed, submit it.
    
    Args:
        url: The URL string to inspect.
        api_key: VirusTotal API v3 key.
        
    Returns:
        Dictionary with:
        - malicious_count: number of vendors flagging it as malicious
        - harmless_count: number of vendors flagging it as harmless
        - suspicious_count: number of vendors flagging it as suspicious
        - total_scans: total number of vendors
        - last_analysis_stats: dictionary of stats (malicious, harmless, suspicious, undetected, timeout)
        - reputation: VirusTotal reputation score
        - scan_status: "found", "submitted", "error", or "no_key"
        - error_message: optional error detail
    """
    result = {
        "malicious_count": 0,
        "harmless_count": 0,
        "suspicious_count": 0,
        "total_scans": 0,
        "last_analysis_stats": {},
        "reputation": 0,
        "scan_status": "error",
        "error_message": None
    }
    
    if not api_key:
        logger.warning("VirusTotal API Key is missing. Returning default mock results.")
        result["scan_status"] = "no_key"
        # Mock logic based on keywords for offline testing/validation
        lower_url = url.lower()
        if "phish" in lower_url or "login-security" in lower_url or "update-password" in lower_url or "verify-account" in lower_url:
            result["malicious_count"] = 8
            result["suspicious_count"] = 2
            result["harmless_count"] = 65
            result["reputation"] = -10
            result["scan_status"] = "mocked_suspicious"
        else:
            result["harmless_count"] = 75
            result["scan_status"] = "mocked_safe"
        return result

    try:
        url_id = encode_url_for_vt(url)
        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }
        
        logger.info(f"Checking URL on VirusTotal: {url} (ID: {url_id})")
        response = requests.get(vt_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            result["last_analysis_stats"] = stats
            result["malicious_count"] = stats.get("malicious", 0)
            result["harmless_count"] = stats.get("harmless", 0)
            result["suspicious_count"] = stats.get("suspicious", 0)
            result["reputation"] = attributes.get("reputation", 0)
            
            total = sum(stats.values())
            result["total_scans"] = total
            result["scan_status"] = "found"
            
        elif response.status_code == 404:
            # URL not found in database, request scanning
            logger.info(f"URL not found in VirusTotal. Submitting for scan: {url}")
            submit_url = "https://www.virustotal.com/api/v3/urls"
            payload = {"url": url}
            submit_headers = {
                "accept": "application/json",
                "x-apikey": api_key,
                "content-type": "application/x-www-form-urlencoded"
            }
            
            submit_response = requests.post(submit_url, data=payload, headers=submit_headers, timeout=10)
            
            if submit_response.status_code == 200:
                result["scan_status"] = "submitted"
            else:
                result["scan_status"] = "error"
                result["error_message"] = f"Failed to submit: {submit_response.text}"
                
        else:
            result["scan_status"] = "error"
            result["error_message"] = f"HTTP {response.status_code}: {response.text}"
            
    except Exception as e:
        logger.error(f"VirusTotal scan error: {e}")
        result["scan_status"] = "error"
        result["error_message"] = str(e)
        
    return result
