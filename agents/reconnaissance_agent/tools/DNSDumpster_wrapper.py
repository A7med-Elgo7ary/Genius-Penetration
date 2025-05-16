"""
DNSDumpster wrapper for the reconnaissance agent.
"""

import requests
from typing import Dict, Any, List, Optional
import logging
from bs4 import BeautifulSoup
import re
import time
import json
from datetime import datetime
import random
import urllib3
import subprocess
import dns.resolver

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class DNSDumpsterScanner:
    """DNSDumpster scanner implementation with enhanced features."""
    
    def __init__(self):
        """Initialize the DNSDumpster scanner."""
        self.logger = logging.getLogger(__name__)
        self.base_url = "https://dnsdumpster.com"
        self.session = requests.Session()
        
        # Rotate user agents to avoid detection
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36'
        ]
        
        self.session.headers.update({
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })

    def _try_alternative_dns_lookup(self, target: str) -> Dict[str, Any]:
        """
        Use standard DNS tools to get basic information when DNSDumpster fails.
        
        Args:
            target: Target domain to scan
            
        Returns:
            Dict containing basic DNS information
        """
        results = {
            "domain": target,
            "scan_date": datetime.utcnow().isoformat(),
            "status": "partial",
            "dns_records": {
                "a": [],
                "aaaa": [],
                "mx": [],
                "ns": [],
                "txt": []
            },
            "subdomains": [],
            "error": "Used fallback DNS lookup due to DNSDumpster failure"
        }
        
        try:
            # Initialize DNS resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 10
            
            # Query common record types
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
            for record_type in record_types:
                try:
                    answers = resolver.resolve(target, record_type)
                    for answer in answers:
                        if record_type == 'A':
                            results["dns_records"]["a"].append({"ip": str(answer)})
                        elif record_type == 'AAAA':
                            results["dns_records"]["aaaa"].append({"ip": str(answer)})
                        elif record_type == 'MX':
                            results["dns_records"]["mx"].append({
                                "host": str(answer.exchange),
                                "preference": answer.preference
                            })
                        elif record_type == 'NS':
                            results["dns_records"]["ns"].append({"nameserver": str(answer)})
                        elif record_type == 'TXT':
                            results["dns_records"]["txt"].append({"text": str(answer)})
                except Exception as e:
                    self.logger.debug(f"No {record_type} records found: {str(e)}")
                    
            # Try to get basic subdomain information using common prefixes
            common_prefixes = ['www', 'mail', 'ftp', 'smtp', 'pop', 'ns1', 'ns2', 'webmail', 'admin']
            for prefix in common_prefixes:
                try:
                    subdomain = f"{prefix}.{target}"
                    answers = resolver.resolve(subdomain, 'A')
                    results["subdomains"].append({
                        "hostname": subdomain,
                        "ips": [str(answer) for answer in answers]
                    })
                except Exception:
                    pass
                    
            return results
            
        except Exception as e:
            self.logger.error(f"Error in alternative DNS lookup: {str(e)}")
            results["status"] = "error"
            results["error"] = f"Alternative DNS lookup failed: {str(e)}"
            return results
            
    def _get_csrf_token(self) -> str:
        """Get CSRF token from DNSDumpster homepage with enhanced error handling."""
        try:
            # First, get the homepage to set cookies
            response = self.session.get(
                self.base_url,
                timeout=10,
                verify=False,
                allow_redirects=True
            )
            response.raise_for_status()
            
            # Update headers with referer
            self.session.headers.update({
                'Referer': self.base_url
            })
            
            # Try multiple methods to find the CSRF token
            csrf_token = None
            
            # Method 1: Look for csrfmiddlewaretoken in form
            soup = BeautifulSoup(response.text, 'html.parser')
            csrf_input = soup.find('input', {'name': 'csrfmiddlewaretoken'})
            if csrf_input and csrf_input.get('value'):
                csrf_token = csrf_input['value']
                self.logger.debug("Found CSRF token in form input")
                
            # Method 2: Look for csrf token in cookies
            if not csrf_token and 'csrftoken' in self.session.cookies:
                csrf_token = self.session.cookies['csrftoken']
                self.logger.debug("Found CSRF token in cookies")
                
            # Method 3: Look for token in page content
            if not csrf_token:
                csrf_pattern = r"name=['\"]csrfmiddlewaretoken['\"] value=['\"]([^'\"]+)['\"]"
                csrf_match = re.search(csrf_pattern, response.text)
                if csrf_match:
                    csrf_token = csrf_match.group(1)
                    self.logger.debug("Found CSRF token in page content")
                    
            if not csrf_token:
                raise ValueError("Could not find CSRF token using any method")
                
            # Update session headers with the token
            self.session.headers.update({
                'X-CSRFToken': csrf_token
            })
            
            return csrf_token
            
        except requests.RequestException as e:
            self.logger.error(f"Failed to get CSRF token: {str(e)}")
            raise RuntimeError(f"Failed to get CSRF token: {str(e)}")
            
    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Perform DNSDumpster scan for the target domain.
        
        Args:
            target: Target domain to scan
            **kwargs: Additional arguments
                - timeout: Request timeout in seconds (default: 30)
                - max_retries: Maximum number of retries (default: 3)
                - verify_ssl: Verify SSL certificates (default: False)
                - use_alternative: Use alternative DNS lookup on failure (default: True)
                
        Returns:
            Dict containing DNSDumpster scan results
        """
        try:
            self.logger.info(f"Starting DNSDumpster scan for {target}")
            
            # Get scan parameters
            timeout = kwargs.get('timeout', 30)
            max_retries = kwargs.get('max_retries', 3)
            verify_ssl = kwargs.get('verify_ssl', False)
            use_alternative = kwargs.get('use_alternative', True)
            
            # Get CSRF token with retries
            retry_delay = 2
            csrf_token = None
            
            for attempt in range(max_retries):
                try:
                    csrf_token = self._get_csrf_token()
                    if csrf_token:
                        break
                except Exception as e:
                    if attempt == max_retries - 1:
                        if use_alternative:
                            self.logger.warning("Falling back to alternative DNS lookup")
                            return self._try_alternative_dns_lookup(target)
                        raise
                    self.logger.warning(f"CSRF token attempt {attempt + 1} failed: {str(e)}")
                    time.sleep(retry_delay)
                    retry_delay *= 2
                    # Rotate user agent on retry
                    self.session.headers.update({
                        'User-Agent': random.choice(self.user_agents)
                    })
            
            if not csrf_token:
                if use_alternative:
                    return self._try_alternative_dns_lookup(target)
                raise ValueError("Failed to obtain CSRF token after all retries")
            
            # Prepare data for the scan
            data = {
                'csrfmiddlewaretoken': csrf_token,
                'targetip': target,
                'user': 'free'
            }
            
            # Submit the scan request
            response = self.session.post(
                self.base_url,
                data=data,
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=True
            )
            response.raise_for_status()
            
            # Check if the response contains actual results
            if 'There was an error getting results' in response.text:
                if use_alternative:
                    return self._try_alternative_dns_lookup(target)
                raise ValueError("DNSDumpster returned an error in the results page")
            
            # Parse the results
            soup = BeautifulSoup(response.text, 'html.parser')
            
            results = {
                "domain": target,
                "scan_date": datetime.utcnow().isoformat(),
                "status": "success",
                "dns_records": self._parse_dns_records(soup),
                "subdomains": self._parse_subdomains(soup),
                "mx_records": self._extract_mx_records(soup),
                "txt_records": self._extract_txt_records(soup),
                "host_records": self._extract_host_records(soup)
            }
            
            # Add analysis of the results
            analysis = self._analyze_results(results)
            results.update(analysis)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error in DNSDumpster scan: {str(e)}")
            if use_alternative:
                return self._try_alternative_dns_lookup(target)
                
            error_info = {
                "domain": target,
                "scan_date": datetime.utcnow().isoformat(),
                "status": "error",
                "error": str(e),
                "dns_records": {},
                "subdomains": [],
                "mx_records": [],
                "txt_records": [],
                "host_records": [],
                "key_findings": [
                    {
                        "finding": f"DNSDumpster scan failed for the target domain {target}.",
                        "significance": "Unable to gather DNS information and potential attack surface data."
                    }
                ],
                "potential_risks": [
                    "Missing critical DNS reconnaissance data",
                    "Unable to identify potential security misconfigurations",
                    "Cannot map the target's infrastructure"
                ],
                "recommendations": [
                    "Retry the scan with different parameters",
                    "Use alternative DNS reconnaissance tools",
                    "Consider manual DNS enumeration methods",
                    f"Perform `whois {target}` for registration information"
                ]
            }
            return error_info

    def _parse_dns_records(self, soup: BeautifulSoup) -> Dict[str, list]:
        """Parse DNS records from the response."""
        dns_records = {
            "a": [],
            "aaaa": [],
            "ns": [],
            "mx": [],
            "txt": [],
            "soa": [],
            "ptr": []
        }
        
        # Find DNS records tables
        tables = soup.find_all('table', {'class': 'table'})
        for table in tables:
            header = table.find_previous('h4')
            if not header:
                continue
                
            header_text = header.text.lower()
            if 'dns record' in header_text or 'a record' in header_text:
                for row in table.find_all('tr')[1:]:  # Skip header row
                    cols = row.find_all('td')
                    if len(cols) >= 2:
                        ip = self._extract_ip(cols[1].text)
                        if ip:
                            dns_records["a"].append({"ip": ip})
                            
            elif 'ns record' in header_text:
                for row in table.find_all('tr')[1:]:
                    cols = row.find_all('td')
                    if len(cols) >= 1:
                        ns = cols[0].text.strip()
                        if ns:
                            dns_records["ns"].append({"nameserver": ns})
                            
        return dns_records
        
    def _parse_subdomains(self, soup: BeautifulSoup) -> List[Dict[str, Any]]:
        """Parse subdomains from the response."""
        subdomains = []
        
        # Find host records table
        tables = soup.find_all('table', {'class': 'table'})
        for table in tables:
            header = table.find_previous('h4')
            if header and 'host record' in header.text.lower():
                for row in table.find_all('tr')[1:]:
                    cols = row.find_all('td')
                    if len(cols) >= 2:
                        hostname = cols[0].text.strip()
                        ip = self._extract_ip(cols[1].text)
                        if hostname and hostname not in [s["hostname"] for s in subdomains]:
                            subdomain = {
                                "hostname": hostname,
                                "ip": ip,
                                "country": cols[2].text.strip() if len(cols) > 2 else None
                            }
                            subdomains.append(subdomain)
                            
        return subdomains
        
    def _extract_mx_records(self, soup: BeautifulSoup) -> List[Dict[str, Any]]:
        """Extract MX records from the response."""
        mx_records = []
        
        # Find MX records table
        tables = soup.find_all('table', {'class': 'table'})
        for table in tables:
            header = table.find_previous('h4')
            if header and 'mx record' in header.text.lower():
                for row in table.find_all('tr')[1:]:
                    cols = row.find_all('td')
                    if len(cols) >= 2:
                        priority = cols[0].text.strip()
                        hostname = cols[1].text.strip()
                        if hostname:
                            mx_records.append({
                                "priority": int(priority) if priority.isdigit() else 0,
                                "hostname": hostname
                            })
                            
        return mx_records
        
    def _extract_txt_records(self, soup: BeautifulSoup) -> List[Dict[str, Any]]:
        """Extract TXT records from the response."""
        txt_records = []
        
        # Find TXT records table
        tables = soup.find_all('table', {'class': 'table'})
        for table in tables:
            header = table.find_previous('h4')
            if header and 'txt record' in header.text.lower():
                for row in table.find_all('tr')[1:]:
                    cols = row.find_all('td')
                    if len(cols) >= 1:
                        txt = cols[0].text.strip()
                        if txt:
                            record_type = "SPF" if "v=spf1" in txt.lower() else \
                                        "DMARC" if "v=dmarc1" in txt.lower() else \
                                        "DKIM" if "v=dkim1" in txt.lower() else "OTHER"
                            txt_records.append({
                                "text": txt,
                                "type": record_type
                            })
                            
        return txt_records
        
    def _extract_host_records(self, soup: BeautifulSoup) -> List[Dict[str, Any]]:
        """Extract host records from the response."""
        hosts = []
        
        # Find host records table
        tables = soup.find_all('table', {'class': 'table'})
        for table in tables:
            header = table.find_previous('h4')
            if header and 'host record' in header.text.lower():
                for row in table.find_all('tr')[1:]:
                    cols = row.find_all('td')
                    if len(cols) >= 2:
                        hostname = cols[0].text.strip()
                        ip = self._extract_ip(cols[1].text)
                        if hostname and ip:
                            hosts.append({
                                "hostname": hostname,
                                "ip": ip,
                                "country": cols[2].text.strip() if len(cols) > 2 else None
                            })
                            
        return hosts
        
    def _extract_ip(self, text: str) -> Optional[str]:
        """Extract IP address from text."""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        match = re.search(ip_pattern, text)
        return match.group(0) if match else None
        
    def _analyze_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze scan results for security implications."""
        analysis = {
            "key_findings": [],
            "potential_risks": [],
            "recommendations": []
        }
        
        # Check DNS records
        if not results["dns_records"]["ns"]:
            analysis["key_findings"].append({
                "finding": "No NS records found",
                "significance": "DNS configuration issue"
            })
            analysis["potential_risks"].append("Domain may have DNS resolution problems")
            analysis["recommendations"].append("Verify NS records are properly configured")
            
        # Check MX records
        if not results["mx_records"]:
            analysis["key_findings"].append({
                "finding": "No MX records found",
                "significance": "Email delivery issues"
            })
            analysis["potential_risks"].append("Domain may not be able to receive email")
            analysis["recommendations"].append("Configure MX records if email is needed")
            
        # Check TXT records for email security
        spf_found = False
        dmarc_found = False
        for record in results["txt_records"]:
            if record["type"] == "SPF":
                spf_found = True
            elif record["type"] == "DMARC":
                dmarc_found = True
                
        if not spf_found:
            analysis["key_findings"].append({
                "finding": "Missing SPF record",
                "significance": "Email security gap"
            })
            analysis["potential_risks"].append("Domain vulnerable to email spoofing")
            analysis["recommendations"].append("Implement SPF record")
            
        if not dmarc_found:
            analysis["key_findings"].append({
                "finding": "Missing DMARC record",
                "significance": "Email security gap"
            })
            analysis["potential_risks"].append("No email authentication policy")
            analysis["recommendations"].append("Implement DMARC record")
            
        # Check subdomain count
        subdomain_count = len(results["subdomains"])
        if subdomain_count > 50:
            analysis["key_findings"].append({
                "finding": f"Large number of subdomains: {subdomain_count}",
                "significance": "Expanded attack surface"
            })
            analysis["potential_risks"].append("Increased attack surface")
            analysis["recommendations"].append("Review and consolidate subdomains")
            
        # If no findings, add a baseline
        if not analysis["key_findings"]:
            analysis["key_findings"].append({
                "finding": "No significant DNS security issues found",
                "significance": "Basic DNS configuration appears secure"
            })
            analysis["recommendations"].append("Continue monitoring DNS configuration")
            
        return analysis