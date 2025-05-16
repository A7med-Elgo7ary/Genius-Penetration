"""
WHOIS lookup tool for the reconnaissance agent using command line whois.
"""

import subprocess
from typing import Dict, Any, Optional
import logging
import re
from datetime import datetime
import json

class WhoisLookup:
    """WHOIS lookup implementation using command line whois tool."""
    
    def __init__(self):
        """Initialize the WHOIS lookup tool."""
        self.logger = logging.getLogger(__name__)
        
    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Perform WHOIS lookup for the target domain using command line whois.
        
        Args:
            target: Target domain to lookup
            **kwargs: Additional arguments
                - timeout: Timeout in seconds (default: 10)
                - validate_domain: Whether to validate domain format (default: True)
            
        Returns:
            Dict containing WHOIS information
        """
        try:
            self.logger.info(f"Performing WHOIS lookup for {target}")
            
            # Validate domain format if requested
            if kwargs.get("validate_domain", True):
                if not self._validate_domain(target):
                    raise ValueError(f"Invalid domain format: {target}")
            
            # Run whois command
            timeout = kwargs.get("timeout", 10)
            process = subprocess.run(
                ["whois", target],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if process.returncode != 0:
                raise Exception(f"WHOIS command failed: {process.stderr}")
            
            # Process the output
            whois_data = self._parse_whois_output(process.stdout)
            
            # Add analysis
            whois_data.update(self._analyze_whois_data(whois_data))
            
            return whois_data
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"WHOIS lookup timed out for {target}")
            return {
                "error": "Command timed out",
                "domain": target,
                "status": "error",
                "raw_output": ""
            }
        except Exception as e:
            self.logger.error(f"Error in WHOIS lookup: {str(e)}")
            return {
                "error": str(e),
                "domain": target,
                "status": "error",
                "raw_output": ""
            }
            
    def _validate_domain(self, domain: str) -> bool:
        """Validate domain format."""
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, domain))
        
    def _parse_whois_output(self, output: str) -> Dict[str, Any]:
        """Parse WHOIS command output."""
        result = {
            "raw_output": output,
            "status": "success",
            "scan_date": datetime.utcnow().isoformat()
        }
        
        # Common WHOIS field mappings
        field_mappings = {
            "domain name": "domain",
            "registrar": "registrar",
            "creation date": "creation_date",
            "updated date": "last_updated",
            "expiration date": "expiration_date",
            "name server": "name_servers",
            "status": "domain_status",
            "registrant name": "registrant_name",
            "registrant organization": "registrant_org",
            "registrant email": "registrant_email",
            "registrant phone": "registrant_phone",
            "registrant country": "registrant_country",
            "dnssec": "dnssec"
        }
        
        # Initialize fields
        parsed_data = {v: None for v in field_mappings.values()}
        parsed_data["name_servers"] = []
        parsed_data["domain_status"] = []
        
        # Process each line
        for line in output.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
                
            key, value = [x.strip().lower() for x in line.split(":", 1)]
            
            # Skip empty values
            if not value or value in ["not found", "redacted for privacy"]:
                continue
                
            # Map fields
            for whois_key, result_key in field_mappings.items():
                if whois_key in key:
                    if result_key in ["name_servers", "domain_status"]:
                        if value not in parsed_data[result_key]:
                            parsed_data[result_key].append(value)
                    else:
                        parsed_data[result_key] = value
                    break
                    
        # Add parsed data to result
        result.update(parsed_data)
        
        return result
        
    def _analyze_whois_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze WHOIS data for potential security implications."""
        analysis = {
            "key_findings": [],
            "potential_risks": [],
            "recommendations": []
        }
        
        # Check domain age
        if data.get("creation_date"):
            try:
                creation_date = datetime.strptime(data["creation_date"].split()[0], "%Y-%m-%d")
                age_days = (datetime.now() - creation_date).days
                if age_days < 30:
                    analysis["key_findings"].append("Domain is less than 30 days old")
                    analysis["potential_risks"].append("Newly registered domains are often used in malicious campaigns")
            except:
                pass
                
        # Check expiration
        if data.get("expiration_date"):
            try:
                expiry_date = datetime.strptime(data["expiration_date"].split()[0], "%Y-%m-%d")
                days_to_expiry = (expiry_date - datetime.now()).days
                if days_to_expiry < 30:
                    analysis["key_findings"].append("Domain is expiring in less than 30 days")
                    analysis["potential_risks"].append("Expiring domains are at risk of hijacking if not renewed")
            except:
                pass
                
        # Check for privacy protection
        privacy_terms = ["privacy", "redacted", "protected"]
        raw_output = data.get("raw_output", "").lower()
        has_privacy = any(term in raw_output for term in privacy_terms)
        
        if not has_privacy:
            exposed_fields = []
            if data.get("registrant_email"):
                exposed_fields.append("email")
            if data.get("registrant_phone"):
                exposed_fields.append("phone")
            if data.get("registrant_name"):
                exposed_fields.append("name")
                
            if exposed_fields:
                analysis["key_findings"].append(f"Exposed registrant information: {', '.join(exposed_fields)}")
                analysis["potential_risks"].append("Exposed contact information can be targeted for social engineering")
                analysis["recommendations"].append("Enable domain privacy protection")
                
        # Check DNSSEC
        dnssec = data.get("dnssec", "").lower()
        if not dnssec or dnssec in ["unsigned", "none", "no"]:
            analysis["key_findings"].append("DNSSEC is not enabled")
            analysis["potential_risks"].append("Domain is vulnerable to DNS spoofing attacks")
            analysis["recommendations"].append("Enable DNSSEC for additional DNS security")
            
        # Check name servers
        if len(data.get("name_servers", [])) < 2:
            analysis["key_findings"].append("Less than 2 name servers found")
            analysis["potential_risks"].append("Limited DNS redundancy increases risk of service disruption")
            analysis["recommendations"].append("Use at least 2 name servers for redundancy")
            
        return analysis