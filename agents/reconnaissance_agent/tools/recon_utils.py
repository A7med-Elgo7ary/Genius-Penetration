"""
Utility functions for the reconnaissance agent.
This module provides helper functions for data processing and validation.
"""

import re
import socket
from typing import Dict, Any, Union
from urllib.parse import urlparse

def merge_results(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge results from different reconnaissance tools into a unified format.
    
    Args:
        results: Dictionary containing results from different tools
        
    Returns:
        Dict containing merged and normalized results
    """
    merged = {
        "target_info": {},
        "dns_records": {},
        "subdomains": set(),
        "services": {},
        "vulnerabilities": [],
        "metadata": {},
        "raw_data": {}
    }
    
    for tool_name, tool_data in results.items():
        if not isinstance(tool_data, dict):
            continue
            
        # Store raw data
        merged["raw_data"][tool_name] = tool_data
        
        # Extract subdomains from any tool
        if "subdomains" in tool_data:
            if isinstance(tool_data["subdomains"], (list, set)):
                merged["subdomains"].update(tool_data["subdomains"])
            elif isinstance(tool_data["subdomains"], dict):
                merged["subdomains"].update(tool_data["subdomains"].keys())
                
        # Merge DNS records
        if "dns_records" in tool_data:
            if isinstance(tool_data["dns_records"], dict):
                for record_type, records in tool_data["dns_records"].items():
                    if record_type not in merged["dns_records"]:
                        merged["dns_records"][record_type] = set()
                    if isinstance(records, (list, set)):
                        merged["dns_records"][record_type].update(records)
                    elif isinstance(records, str):
                        merged["dns_records"][record_type].add(records)
                        
        # Merge service information
        if "services" in tool_data:
            merged["services"].update(tool_data["services"])
            
        # Collect potential vulnerabilities
        if "vulnerabilities" in tool_data:
            if isinstance(tool_data["vulnerabilities"], list):
                merged["vulnerabilities"].extend(tool_data["vulnerabilities"])
                
        # Merge metadata
        if "metadata" in tool_data:
            merged["metadata"][tool_name] = tool_data["metadata"]
            
    # Convert sets to lists for JSON serialization
    merged["subdomains"] = list(merged["subdomains"])
    for record_type in merged["dns_records"]:
        if isinstance(merged["dns_records"][record_type], set):
            merged["dns_records"][record_type] = list(merged["dns_records"][record_type])
            
    return merged

def validate_target(target: str) -> Union[str, None]:
    """
    Validate and normalize the target input.
    
    Args:
        target: Target domain or IP address
        
    Returns:
        Normalized target string or None if invalid
    """
    # Remove any whitespace and convert to lowercase
    target = target.strip().lower()
    
    # Check if it's an IP address
    try:
        socket.inet_aton(target)
        return target
    except socket.error:
        pass
        
    # Check if it's a domain name
    if target.startswith(('http://', 'https://')):
        parsed = urlparse(target)
        target = parsed.netloc
        
    # Basic domain name validation
    domain_pattern = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
    if re.match(domain_pattern, target):
        return target
        
    return None
