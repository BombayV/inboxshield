from pydantic import BaseModel, Field
from typing import List, Optional

class TriageAnalysis(BaseModel):
    sender_authenticity_check: str = Field(
        description="Analysis of the sender's display name vs actual email address domain, noting anomalies."
    )
    content_urgency_check: str = Field(
        description="Assessment of urgency, threats, emotional pressure, or requests for credentials/financial info."
    )
    suspicious_indicators: List[str] = Field(
        description="Key phishing signals noticed in the email text or headers."
    )
    confidence_score: float = Field(
        description="Confidence of triage assessment from 0.0 (low threat) to 1.0 (certain phishing)."
    )

class URLAnalysisResult(BaseModel):
    url: str = Field(description="The original URL extracted from the email.")
    final_url: str = Field(description="The final URL after following redirect chains.")
    domain: str = Field(description="The domain name extracted from the URL.")
    domain_age_days: Optional[int] = Field(None, description="Age of the domain in days (from WHOIS).")
    domain_registrar: Optional[str] = Field(None, description="Domain registrar name (from WHOIS).")
    virustotal_malicious_count: int = Field(description="Number of malicious votes on VirusTotal.")
    virustotal_harmless_count: int = Field(description="Number of harmless/undetected votes on VirusTotal.")
    redirect_hops_count: int = Field(description="Total number of redirect hops followed.")
    is_ip_logger_or_redirect_suspicious: bool = Field(
        description="Whether the URL redirect chain uses known IP loggers, trackers, or suspicious redirects."
    )
    verdict: str = Field(description="Verdict for this URL: 'Safe', 'Suspicious', or 'Malicious'.")
    reasoning: str = Field(description="Short reasoning explaining the verdict.")

class URLAnalystOutput(BaseModel):
    analyzed_urls: List[URLAnalysisResult] = Field(
        description="List of detailed analysis results for each URL."
    )
    overall_url_threat_summary: str = Field(
        description="Summary of the URL findings and threat levels."
    )

class SecurityDirectorOutput(BaseModel):
    verdict: str = Field(
        description="Final email verdict. MUST be one of: 'Safe', 'Suspicious', or 'Phishing'."
    )
    threat_score: int = Field(
        description="Integer score from 0 (completely safe) to 100 (confirmed threat)."
    )
    reasoning_summary: str = Field(
        description="A synthesized summary explaining the decision, citing sender checks, headers, and URL findings."
    )
    action_required: str = Field(
        description="Required security action. MUST be one of: 'Allow' (for Safe), 'Flag' (for Suspicious), or 'Isolate' (for Phishing)."
    )
