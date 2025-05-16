"""
DNS Lookup tool for the reconnaissance agent.
"""

import dns.resolver
import dns.zone
import dns.query
import dns.exception
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
import socket
import re
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import json

class DNSLookup:
    """Enhanced DNS Lookup implementation with comprehensive record support and analysis."""
    
    # Standard DNS record types to query
    COMMON_RECORD_TYPES = [
        'A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR',
        'SRV', 'CAA', 'DNSKEY', 'DS', 'NSEC', 'NSEC3'
    ]
    
    def __init__(self):
        """Initialize the DNS Lookup tool."""
        self.logger = logging.getLogger(__name__)
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3.0
        self.resolver.lifetime = 3.0
        
    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Perform comprehensive DNS lookup for the target domain.
        
        Args:
            target: Target domain to scan
            **kwargs: Additional arguments
                - record_types: List of DNS record types to query (default: COMMON_RECORD_TYPES)
                - nameservers: List of nameservers to use (default: system resolvers)
                - timeout: Query timeout in seconds (default: 3.0)
                - concurrent: Enable concurrent queries (default: True)
                - try_zone_transfer: Attempt zone transfer (default: False)
                - validate_dnssec: Check DNSSEC validation (default: True)
                
        Returns:
            Dict containing DNS lookup results and analysis
        """
        try:
            self.logger.info(f"Starting DNS lookup for {target}")
            
            # Validate domain format
            if not self._validate_domain(target):
                raise ValueError(f"Invalid domain format: {target}")
                
            # Set custom nameservers if provided
            if kwargs.get("nameservers"):
                self.resolver.nameservers = kwargs["nameservers"]
                
            # Set custom timeout if provided
            if kwargs.get("timeout"):
                self.resolver.timeout = kwargs["timeout"]
                self.resolver.lifetime = kwargs["timeout"]
                
            # Initialize results dictionary
            results = {
                "domain": target,
                "scan_date": datetime.utcnow().isoformat(),
                "nameservers_used": self.resolver.nameservers,
                "records": {},
                "analysis": {
                    "status": "success",
                    "findings": [],
                    "security_issues": [],
                    "recommendations": []
                }
            }
            
            # Get record types to query
            record_types = kwargs.get("record_types", self.COMMON_RECORD_TYPES)
            
            # Perform DNS queries
            if kwargs.get("concurrent", True):
                results["records"] = self._concurrent_dns_query(target, record_types)
            else:
                results["records"] = self._sequential_dns_query(target, record_types)
                
            # Attempt zone transfer if requested
            if kwargs.get("try_zone_transfer", False):
                zone_transfer_result = self._try_zone_transfer(target)
                if zone_transfer_result:
                    results["zone_transfer"] = zone_transfer_result
                    
            # Validate DNSSEC if requested
            if kwargs.get("validate_dnssec", True):
                dnssec_result = self._validate_dnssec(target)
                results["dnssec"] = dnssec_result
                
            # Analyze results
            self._analyze_results(results)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error in DNS lookup: {str(e)}")
            return {
                "domain": target,
                "scan_date": datetime.utcnow().isoformat(),
                "status": "error",
                "error": str(e)
            }
            
    def _validate_domain(self, domain: str) -> bool:
        """Validate domain format."""
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, domain))
        
    def _concurrent_dns_query(self, target: str, record_types: List[str]) -> Dict[str, Any]:
        """Perform concurrent DNS queries for multiple record types."""
        records = {}
        with ThreadPoolExecutor(max_workers=min(len(record_types), 10)) as executor:
            future_to_type = {
                executor.submit(self._query_record_type, target, record_type): record_type
                for record_type in record_types
            }
            
            for future in as_completed(future_to_type):
                record_type = future_to_type[future]
                try:
                    result = future.result()
                    if result:
                        records[record_type] = result
                except Exception as e:
                    self.logger.debug(f"Error querying {record_type} records: {str(e)}")
                    
        return records
        
    def _sequential_dns_query(self, target: str, record_types: List[str]) -> Dict[str, Any]:
        """Perform sequential DNS queries for multiple record types."""
        records = {}
        for record_type in record_types:
            result = self._query_record_type(target, record_type)
            if result:
                records[record_type] = result
        return records
        
    def _query_record_type(self, target: str, record_type: str) -> Optional[List[Dict[str, Any]]]:
        """Query specific DNS record type and format results."""
        try:
            answers = self.resolver.resolve(target, record_type)
            records = []
            
            for rdata in answers:
                record_data = self._format_record_data(rdata, record_type)
                if record_data:
                    records.append({
                        "value": record_data,
                        "ttl": answers.ttl
                    })
                    
            return records if records else None
            
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return None
        except Exception as e:
            self.logger.debug(f"Error querying {record_type} record: {str(e)}")
            return None
            
    def _format_record_data(self, rdata: Any, record_type: str) -> Optional[Any]:
        """Format DNS record data based on record type."""
        try:
            if record_type == 'A':
                return str(rdata)
            elif record_type == 'AAAA':
                return str(rdata)
            elif record_type == 'MX':
                return {"preference": rdata.preference, "exchange": str(rdata.exchange)}
            elif record_type == 'NS':
                return str(rdata)
            elif record_type == 'TXT':
                return str(rdata).strip('"')
            elif record_type == 'SOA':
                return {
                    "mname": str(rdata.mname),
                    "rname": str(rdata.rname),
                    "serial": rdata.serial,
                    "refresh": rdata.refresh,
                    "retry": rdata.retry,
                    "expire": rdata.expire,
                    "minimum": rdata.minimum
                }
            elif record_type == 'CNAME':
                return str(rdata)
            elif record_type == 'SRV':
                return {
                    "priority": rdata.priority,
                    "weight": rdata.weight,
                    "port": rdata.port,
                    "target": str(rdata.target)
                }
            elif record_type == 'CAA':
                return {
                    "flag": rdata.flags,
                    "tag": str(rdata.tag),
                    "value": str(rdata.value)
                }
            else:
                return str(rdata)
                
        except Exception as e:
            self.logger.debug(f"Error formatting {record_type} record: {str(e)}")
            return None
            
    def _try_zone_transfer(self, target: str) -> Optional[Dict[str, Any]]:
        """Attempt zone transfer from each nameserver."""
        try:
            ns_records = self.resolver.resolve(target, 'NS')
            results = []
            
            for ns in ns_records:
                try:
                    ns_ip = self.resolver.resolve(str(ns), 'A')[0]
                    zone = dns.zone.from_xfr(dns.query.xfr(str(ns_ip), target, lifetime=5))
                    
                    if zone:
                        zone_data = []
                        for name, node in zone.nodes.items():
                            for rdataset in node.rdatasets:
                                zone_data.append({
                                    "name": str(name),
                                    "ttl": rdataset.ttl,
                                    "type": dns.rdatatype.to_text(rdataset.rdtype),
                                    "data": [str(rdata) for rdata in rdataset]
                                })
                                
                        results.append({
                            "nameserver": str(ns),
                            "status": "success",
                            "records": zone_data
                        })
                        
                except Exception as e:
                    results.append({
                        "nameserver": str(ns),
                        "status": "failed",
                        "error": str(e)
                    })
                    
            return {"attempts": results} if results else None
            
        except Exception as e:
            self.logger.debug(f"Error attempting zone transfer: {str(e)}")
            return None
            
    def _validate_dnssec(self, target: str) -> Dict[str, Any]:
        """Validate DNSSEC configuration and chain of trust."""
        try:
            # Check for DNSKEY records
            try:
                dnskey_records = self.resolver.resolve(target, 'DNSKEY')
                has_dnskey = True
            except:
                has_dnskey = False
                
            # Check for DS records
            try:
                ds_records = self.resolver.resolve(target, 'DS')
                has_ds = True
            except:
                has_ds = False
                
            # Check for RRSIG records (signed responses)
            try:
                self.resolver.resolve(target, 'A', want_dnssec=True)
                has_rrsig = True
            except:
                has_rrsig = False
                
            status = "secure" if (has_dnskey and has_ds and has_rrsig) else "partial" if any([has_dnskey, has_ds, has_rrsig]) else "unsigned"
            
            return {
                "status": status,
                "has_dnskey": has_dnskey,
                "has_ds": has_ds,
                "has_rrsig": has_rrsig
            }
            
        except Exception as e:
            self.logger.debug(f"Error validating DNSSEC: {str(e)}")
            return {"status": "error", "error": str(e)}
            
    def _analyze_results(self, results: Dict[str, Any]) -> None:
        """Analyze DNS lookup results for security implications."""
        analysis = results["analysis"]
        records = results.get("records", {})
        
        # Check for missing essential records
        essential_records = ['A', 'MX', 'NS', 'SOA']
        missing_records = [r for r in essential_records if r not in records]
        if missing_records:
            analysis["findings"].append(f"Missing essential DNS records: {', '.join(missing_records)}")
            analysis["security_issues"].append("Incomplete DNS configuration may impact domain functionality")
            
        # Analyze SPF and DMARC records
        txt_records = records.get('TXT', [])
        has_spf = any('v=spf1' in str(r.get('value', '')).lower() for r in txt_records)
        has_dmarc = any('v=dmarc1' in str(r.get('value', '')).lower() for r in txt_records)
        
        if not has_spf:
            analysis["security_issues"].append("Missing SPF record - domain is vulnerable to email spoofing")
            analysis["recommendations"].append("Implement SPF record to prevent email spoofing")
            
        if not has_dmarc:
            analysis["security_issues"].append("Missing DMARC record - email authentication policy not defined")
            analysis["recommendations"].append("Implement DMARC record to enforce email authentication policy")
            
        # Check for DNSSEC
        dnssec_info = results.get("dnssec", {})
        if dnssec_info.get("status") == "unsigned":
            analysis["security_issues"].append("DNSSEC not implemented - vulnerable to DNS spoofing")
            analysis["recommendations"].append("Implement DNSSEC to prevent DNS spoofing attacks")
            
        # Check for zone transfer
        zone_transfer = results.get("zone_transfer", {})
        if zone_transfer and any(a.get("status") == "success" for a in zone_transfer.get("attempts", [])):
            analysis["security_issues"].append("Zone transfer possible - exposing internal DNS information")
            analysis["recommendations"].append("Disable zone transfers or restrict to authorized servers only")
            
        # Analyze NS record distribution
        ns_records = records.get('NS', [])
        if ns_records:
            ns_count = len(ns_records)
            if ns_count < 2:
                analysis["findings"].append("Single name server configuration detected")
                analysis["recommendations"].append("Add secondary name servers for redundancy")
            elif ns_count > 8:
                analysis["findings"].append(f"Unusually high number of name servers ({ns_count})")
                
        # Check for CAA records
        if 'CAA' not in records:
            analysis["findings"].append("No CAA records found")
            analysis["recommendations"].append("Consider implementing CAA records to control SSL/TLS certificate issuance")
            
        # Update status based on security issues
        if analysis["security_issues"]:
            analysis["status"] = "warning"