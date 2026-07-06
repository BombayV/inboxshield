import logging
from google import genai
from google.genai import types
from typing import Dict, Any, List, Tuple
from inboxshield.config import Config
from inboxshield.agents.schemas import TriageAnalysis, URLAnalystOutput, SecurityDirectorOutput, URLAnalysisResult
from inboxshield.tools.whois_lookup import lookup_whois
from inboxshield.tools.virustotal import scan_url_virustotal
from inboxshield.tools.redirect_follow import trace_redirects

logger = logging.getLogger(__name__)

class AgentOrchestrator:
    def __init__(self):
        self.api_key = Config.GEMINI_API_KEY
        self.client = None
        if self.api_key:
            self.client = genai.Client(api_key=self.api_key)
        else:
            logger.warning("GEMINI_API_KEY is not set. Orchestrator will run in MOCK mode.")
            
    def run_triage(self, email_data: Dict[str, Any]) -> Tuple[TriageAnalysis, List[Dict[str, Any]]]:
        """Run the Triage Agent to analyze email body and headers."""
        logs = []
        log_msg = "Triage Agent started analyzing email headers and content."
        logger.info(log_msg)
        logs.append({"agent_name": "TriageAgent", "log_message": log_msg})
        
        prompt = f"""
        You are a Triage Agent specializing in analyzing email headers and email body text for phishing indicators, 
        sender/domain misalignment, and social engineering pressure.
        
        Analyze the following email metadata and content:
        Sender: {email_data.get('sender')}
        Recipient: {email_data.get('recipient')}
        Subject: {email_data.get('subject')}
        Date: {email_data.get('date_received')}
        Body Preview: {email_data.get('body_preview')}
        Full Text Body:
        {email_data.get('text_body')}
        
        Examine:
        1. Sender authenticity: Does the sender's domain align with their display name or claim (e.g. sender says "Netflix Support" but domain is "netflix-security-alert-392.com")?
        2. Content urgency: Is there emotional manipulation, threats of account deletion, request for credentials, or billing issues requiring immediate click?
        3. General language & syntax irregularities.
        
        Provide your assessment structured exactly according to the schema.
        """
        
        if not self.client:
            # Mock triage fallback
            log_msg = "Running Triage in Mock Mode because GEMINI_API_KEY is missing."
            logger.warning(log_msg)
            logs.append({"agent_name": "TriageAgent", "log_message": log_msg})
            
            # Simple heuristic
            is_suspicious = any(kw in email_data.get("subject", "").lower() or kw in email_data.get("text_body", "").lower()
                                for kw in ["urgent", "verify", "suspend", "action required", "login"])
            
            mock_triage = TriageAnalysis(
                sender_authenticity_check="Sender check completed (Mocked: No real validation done).",
                content_urgency_check="Checked for urgency signals (Mocked).",
                suspicious_indicators=["Mock alert: Contains urgent keywords"] if is_suspicious else [],
                confidence_score=0.75 if is_suspicious else 0.1
            )
            return mock_triage, logs
            
        try:
            response = self.client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt,
                config={
                    "response_mime_type": "application/json",
                    "response_schema": TriageAnalysis,
                    "temperature": 0.1
                }
            )
            triage_result = response.parsed
            
            log_msg = f"Triage Agent assessment completed. Confidence score: {triage_result.confidence_score}. Suspicious indicators: {', '.join(triage_result.suspicious_indicators) if triage_result.suspicious_indicators else 'None'}."
            logger.info(log_msg)
            logs.append({"agent_name": "TriageAgent", "log_message": log_msg})
            return triage_result, logs
            
        except Exception as e:
            logger.error(f"Triage Agent execution failed: {e}")
            raise

    def run_url_analysis(self, urls: List[str]) -> Tuple[URLAnalystOutput, List[Dict[str, Any]]]:
        """Run diagnostic tools on the URLs, then pass results to URL Analyst Agent."""
        logs = []
        log_msg = f"URL Analyst Agent started processing {len(urls)} URLs."
        logger.info(log_msg)
        logs.append({"agent_name": "URLAnalystAgent", "log_message": log_msg})
        
        if not urls:
            log_msg = "No URLs to analyze in the email."
            logger.info(log_msg)
            logs.append({"agent_name": "URLAnalystAgent", "log_message": log_msg})
            return URLAnalystOutput(analyzed_urls=[], overall_url_threat_summary="No links found in the email."), logs
            
        # 1. Run local diagnostic tools on each URL
        diagnostic_reports = []
        for url in urls:
            log_msg = f"Running diagnostics for URL: {url}"
            logger.info(log_msg)
            logs.append({"agent_name": "URLAnalystAgent", "log_message": log_msg})
            
            # Follow redirects
            redirect_report = trace_redirects(url)
            final_url = redirect_report["final_url"]
            
            # Whois lookup
            whois_report = lookup_whois(final_url)
            
            # VirusTotal check
            vt_report = scan_url_virustotal(final_url, Config.VIRUSTOTAL_API_KEY)
            
            report_str = f"""
            URL: {url}
            Redirect Path: {" -> ".join([h["url"] for h in redirect_report["chain"]]) + " -> " + final_url if redirect_report["is_redirected"] else "No redirects"}
            Final URL: {final_url}
            Domain: {whois_report['domain']}
            WHOIS Registrar: {whois_report['registrar']}
            WHOIS Domain Age: {whois_report['age_days']} days (Created: {whois_report['creation_date']})
            VirusTotal Verdict: Malicious={vt_report.get('malicious_count', 0)}, Harmless={vt_report.get('harmless_count', 0)}, Suspicious={vt_report.get('suspicious_count', 0)}
            Suspicious redirects detected: {redirect_report['suspicious_redirects']}
            """
            
            diagnostic_reports.append({
                "url": url,
                "final_url": final_url,
                "domain": whois_report['domain'],
                "age_days": whois_report['age_days'],
                "registrar": whois_report['registrar'],
                "vt_malicious": vt_report.get('malicious_count', 0),
                "vt_harmless": vt_report.get('harmless_count', 0),
                "redirect_hops": redirect_report['hop_count'],
                "suspicious_redirect": redirect_report['suspicious_redirects'],
                "report_str": report_str
            })
            
        # 2. Call the Gemini URL Analyst Agent with diagnostic reports
        prompt = """
        You are a URL Analyst Agent. Your job is to review diagnostic information for multiple URLs extracted from an email and evaluate their threat status.
        
        Below are the diagnostic reports for each URL:
        """
        for r in diagnostic_reports:
            prompt += f"\n--- DIAGNOSTIC REPORT ---\n{r['report_str']}\n"
            
        prompt += """
        For each URL, evaluate whether it is:
        - 'Safe': Normal domains, no malicious signals, no suspicious redirects, mature age.
        - 'Suspicious': Low reputation, very newly registered domain (<30 days), generic URL shorteners, or multi-hop redirect chains.
        - 'Malicious': Explicitly flagged by VirusTotal (malicious count > 0) or using known IP-logging endpoints.
        
        Construct your final analysis matching the expected JSON output format.
        """
        
        if not self.client:
            # Mock fallback
            log_msg = "Running URL Analyst in Mock Mode because GEMINI_API_KEY is missing."
            logger.warning(log_msg)
            logs.append({"agent_name": "URLAnalystAgent", "log_message": log_msg})
            
            analyzed = []
            for r in diagnostic_reports:
                is_malicious = r["vt_malicious"] > 0 or r["suspicious_redirect"]
                analyzed.append(URLAnalysisResult(
                    url=r["url"],
                    final_url=r["final_url"],
                    domain=r["domain"],
                    domain_age_days=r["age_days"],
                    domain_registrar=r["registrar"],
                    virustotal_malicious_count=r["vt_malicious"],
                    virustotal_harmless_count=r["vt_harmless"],
                    redirect_hops_count=r["redirect_hops"],
                    is_ip_logger_or_redirect_suspicious=r["suspicious_redirect"],
                    verdict="Malicious" if is_malicious else "Safe",
                    reasoning="Checked with local tools (Mocked details)."
                ))
            
            mock_url_analyst = URLAnalystOutput(
                analyzed_urls=analyzed,
                overall_url_threat_summary="URLs analyzed using mock agent logic."
            )
            return mock_url_analyst, logs

        try:
            response = self.client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt,
                config={
                    "response_mime_type": "application/json",
                    "response_schema": URLAnalystOutput,
                    "temperature": 0.1
                }
            )
            url_result = response.parsed
            
            # Add logs
            for item in url_result.analyzed_urls:
                log_msg = f"URL Analyzed: {item.url} -> Verdict: {item.verdict}. VT malicious: {item.virustotal_malicious_count}. Domain age: {item.domain_age_days}."
                logger.info(log_msg)
                logs.append({"agent_name": "URLAnalystAgent", "log_message": log_msg})
                
            return url_result, logs
            
        except Exception as e:
            logger.error(f"URL Analyst Agent execution failed: {e}")
            raise

    def run_director(self, email_data: Dict[str, Any], triage: TriageAnalysis, url_analysis: URLAnalystOutput) -> Tuple[SecurityDirectorOutput, List[Dict[str, Any]]]:
        """Run the Security Director Agent to synthesize findings and make a final verdict."""
        logs = []
        log_msg = "Security Director Agent reviewing findings and finalizing verdict."
        logger.info(log_msg)
        logs.append({"agent_name": "SecurityDirectorAgent", "log_message": log_msg})
        
        prompt = f"""
        You are the Security Director Agent. Your job is to review the findings from the Triage Agent and the URL Analyst Agent, and make a final unified assessment.
        
        --- Email Details ---
        Sender: {email_data.get('sender')}
        Subject: {email_data.get('subject')}
        
        --- Triage Agent Assessment ---
        Sender Authenticity Check: {triage.sender_authenticity_check}
        Content Urgency Check: {triage.content_urgency_check}
        Suspicious Indicators: {triage.suspicious_indicators}
        Triage Confidence Score: {triage.confidence_score}
        
        --- URL Analyst Agent Assessment ---
        Summary: {url_analysis.overall_url_threat_summary}
        """
        
        for u in url_analysis.analyzed_urls:
            prompt += f"\n- URL: {u.url}\n  Verdict: {u.verdict}\n  Reason: {u.reasoning}\n"
            
        prompt += """
        Synthesize these findings:
        - Determine the final verdict: 'Safe', 'Suspicious', or 'Phishing'.
        - If any URLs are Malicious, the overall verdict MUST be 'Phishing'.
        - If the Triage confidence is very high (e.g., > 0.8) and urgency is severe, mark as 'Phishing' or 'Suspicious'.
        - Assign a Threat Score from 0 (harmless) to 100 (absolute phishing).
        - Choose the action: 'Isolate' (for Phishing), 'Flag' (for Suspicious), or 'Allow' (for Safe).
        - Write a detailed reasoning summary.
        
        Provide the response structured exactly according to the schema.
        """
        
        if not self.client:
            # Mock director fallback
            log_msg = "Running Security Director in Mock Mode because GEMINI_API_KEY is missing."
            logger.warning(log_msg)
            logs.append({"agent_name": "SecurityDirectorAgent", "log_message": log_msg})
            
            # Simple heuristic
            has_malicious_urls = any(u.verdict == "Malicious" for u in url_analysis.analyzed_urls)
            is_suspicious_triage = triage.confidence_score > 0.5
            
            verdict = "Phishing" if has_malicious_urls else ("Suspicious" if is_suspicious_triage else "Safe")
            score = 90 if verdict == "Phishing" else (50 if verdict == "Suspicious" else 10)
            action = "Isolate" if verdict == "Phishing" else ("Flag" if verdict == "Suspicious" else "Allow")
            
            mock_director = SecurityDirectorOutput(
                verdict=verdict,
                threat_score=score,
                reasoning_summary=f"Analysis conducted locally. Triage suspicion: {is_suspicious_triage}. Malicious links: {has_malicious_urls}.",
                action_required=action
            )
            return mock_director, logs

        try:
            response = self.client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt,
                config={
                    "response_mime_type": "application/json",
                    "response_schema": SecurityDirectorOutput,
                    "temperature": 0.1
                }
            )
            director_result = response.parsed
            
            log_msg = f"Security Director final decision: {director_result.verdict} (Score: {director_result.threat_score}/100). Action: {director_result.action_required}."
            logger.info(log_msg)
            logs.append({"agent_name": "SecurityDirectorAgent", "log_message": log_msg})
            return director_result, logs
            
        except Exception as e:
            logger.error(f"Security Director Agent execution failed: {e}")
            raise
            
    def analyze_email(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Runs the complete multi-agent pipeline for a single email.
        
        Returns:
            Dict containing:
            - triage_analysis: TriageAnalysis
            - url_analyst_output: URLAnalystOutput
            - director_output: SecurityDirectorOutput
            - logs: List of logging steps
        """
        all_logs = []
        
        # 1. Triage Agent
        triage_analysis, triage_logs = self.run_triage(email_data)
        all_logs.extend(triage_logs)
        
        # 2. URL Analyst Agent
        url_analyst_output, url_logs = self.run_url_analysis(email_data.get("links", []))
        all_logs.extend(url_logs)
        
        # 3. Security Director Agent
        director_output, director_logs = self.run_director(email_data, triage_analysis, url_analyst_output)
        all_logs.extend(director_logs)
        
        return {
            "triage_analysis": triage_analysis,
            "url_analyst_output": url_analyst_output,
            "director_output": director_output,
            "logs": all_logs
        }
