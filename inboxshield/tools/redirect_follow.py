import logging
import requests
from bs4 import BeautifulSoup
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

# Known IP logger and link tracker domains or keywords
SUSPICIOUS_DOMAINS_KEYWORDS = [
    "iplogger", "grabify", "blasze", "yip.su", "yip.su/logger", "ps3cf", 
    "url-shortener", "tinyurl", "bit.ly", "cutt.ly", "rebrand.ly", "t.co"
]

def trace_redirects(url: str, timeout: int = 8) -> Dict[str, Any]:
    """
    Traces the redirect path of a given URL and analyzes each hop.
    
    Args:
        url: The URL to inspect.
        timeout: Request timeout in seconds.
        
    Returns:
        Dictionary containing:
        - original_url: The input URL
        - final_url: The destination URL after redirects
        - hop_count: Total redirects followed
        - chain: List of hops, each with {url, status_code, location}
        - is_redirected: Boolean indicating if redirects occurred
        - suspicious_redirects: True if any redirection appears suspicious (e.g., IP logger or multi-hop)
        - page_title: Title of final HTML page (if fetched)
        - meta_refresh_url: Meta refresh redirect URL (if found in HTML)
        - error: Error string if request failed
    """
    result = {
        "original_url": url,
        "final_url": url,
        "hop_count": 0,
        "chain": [],
        "is_redirected": False,
        "suspicious_redirects": False,
        "page_title": None,
        "meta_refresh_url": None,
        "error": None
    }
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5"
    }
    
    # Ensure scheme is present
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "http://" + url
        result["original_url"] = url
        result["final_url"] = url

    try:
        logger.info(f"Tracing redirects for: {url}")
        # Perform request with standard requests library.
        # We use GET because we want to inspect HTML meta refreshes too, but we limit output/size.
        response = requests.get(
            url, 
            headers=headers, 
            allow_redirects=True, 
            timeout=timeout,
            stream=True # stream response to prevent downloading massive files
        )
        
        # Parse standard redirect history
        if response.history:
            result["is_redirected"] = True
            result["hop_count"] = len(response.history)
            
            for hop in response.history:
                hop_info = {
                    "url": hop.url,
                    "status_code": hop.status_code,
                    "location": hop.headers.get("Location")
                }
                result["chain"].append(hop_info)
                
                # Check for suspicious domains in the chain
                for kw in SUSPICIOUS_DOMAINS_KEYWORDS:
                    if kw in hop.url.lower() or (hop_info["location"] and kw in hop_info["location"].lower()):
                        result["suspicious_redirects"] = True
                        
        result["final_url"] = response.url
        
        # Check if final URL itself is suspicious
        for kw in SUSPICIOUS_DOMAINS_KEYWORDS:
            if kw in response.url.lower():
                result["suspicious_redirects"] = True

        # Process the HTML (limit to first 100KB to prevent memory issues)
        content_bytes = b""
        for chunk in response.iter_content(chunk_size=1024):
            content_bytes += chunk
            if len(content_bytes) > 100 * 1024:
                break
                
        # Parse HTML to find title and look for meta-refresh redirects
        try:
            html = content_bytes.decode(response.encoding or "utf-8", errors="replace")
            soup = BeautifulSoup(html, "html.parser")
            
            if soup.title:
                result["page_title"] = soup.title.string.strip() if soup.title.string else None
                
            # Search for meta refresh tag: <meta http-equiv="refresh" content="5;url=http://example.com" />
            meta_refresh = soup.find("meta", attrs={"http-equiv": lambda x: x and x.lower() == "refresh"})
            if meta_refresh:
                content = meta_refresh.get("content", "")
                if "url=" in content.lower():
                    # Extract URL from content attribute
                    parts = content.lower().split("url=")
                    if len(parts) > 1:
                        raw_refresh_url = content[len(parts[0]) + 4:].strip()
                        # Clean quotes
                        if raw_refresh_url.startswith(("'", '"')):
                            raw_refresh_url = raw_refresh_url[1:-1]
                        result["meta_refresh_url"] = raw_refresh_url
                        result["suspicious_redirects"] = True # Meta refresh redirects are suspicious
        except Exception as html_err:
            logger.debug(f"Failed to parse HTML for refresh/title on {response.url}: {html_err}")

    except requests.exceptions.Timeout:
        logger.warning(f"Redirect tracing timed out for {url}")
        result["error"] = "Timeout"
    except Exception as e:
        logger.warning(f"Redirect tracing failed for {url}: {e}")
        result["error"] = str(e)
        
    return result
