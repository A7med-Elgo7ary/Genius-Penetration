"""
TheHarvester wrapper module for the AI-PenTest Agents project.
This module provides an interface to theHarvester tool for email harvesting,
subdomain enumeration, and more.
"""

import os
import json
import subprocess
import tempfile
import re
from typing import Dict, List, Any, Optional
import logging

class TheHarvesterScanner:
    """Interface for theHarvester tool to gather information about the target."""
    
    def __init__(self):
        """Initialize theHarvester scanner."""
        self.logger = logging.getLogger(__name__)
        # Default sources that are reliable and don't require API keys
        self.default_sources = [
            "baidu",
            "bing",
            "crtsh",
            "dnsdumpster",
            "duckduckgo",
            "hackertarget",
            "rapiddns",
            "subdomaincenter",
            "threatminer",
            "urlscan",
            "yahoo"
        ]
        
    def _parse_console_output(self, output: str) -> Dict[str, List[str]]:
        """
        Parse theHarvester console output for results.
        
        Args:
            output: Console output from theHarvester
            
        Returns:
            Dict containing parsed results
        """
        results = {
            "hosts": [],
            "ips": [],
            "emails": [],
            "urls": []
        }
        
        current_section = None
        
        for line in output.split('\n'):
            line = line.strip()
            
            # Skip empty lines and headers
            if not line or '[*]' in line or '*' * 10 in line:
                continue
                
            # Detect section changes
            if line.startswith('Hosts found:'):
                current_section = "hosts"
                continue
            elif line.startswith('IPs found:'):
                current_section = "ips"
                continue
            elif line.startswith('Emails found:'):
                current_section = "emails"
                continue
            elif line.startswith('URLs found:'):
                current_section = "urls"
                continue
                
            # Add items to current section
            if current_section and line:
                # Clean up the line
                item = line.strip('[]() \t')
                if item and item not in results[current_section]:
                    results[current_section].append(item)
        
        return results
        
    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Perform theHarvester scan for the target domain.
        
        Args:
            target: Target domain to scan
            **kwargs: Additional arguments
                - sources: Data sources to use (default: self.default_sources)
                - limit: Limit the number of results (default: 500)
                - dns_lookup: Perform DNS lookup (default: True)
                - dns_brute: DNS brute force (default: False)
                - use_proxies: Use proxies for requests (default: False)
                - timeout: Scan timeout in seconds (default: 300)
                
        Returns:
            Dict containing theHarvester scan results
        """
        try:
            self.logger.info(f"Starting theHarvester scan for {target}")
            
            # Prepare command arguments
            cmd = ["theHarvester", "-d", target]
            
            # Add data sources
            sources = kwargs.get("sources", self.default_sources)
            if isinstance(sources, list):
                cmd.extend(["-b", ",".join(sources)])
            else:
                cmd.extend(["-b", ",".join(self.default_sources)])
                
            # Add limit
            limit = kwargs.get("limit", 500)
            cmd.extend(["-l", str(limit)])
            
            # DNS options
            if kwargs.get("dns_lookup", True):
                cmd.append("-n")
            if kwargs.get("dns_brute", False):
                cmd.append("-c")
                
            # Use proxies if specified
            if kwargs.get("use_proxies", False):
                cmd.append("-p")
                
            # Create temporary file for results
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp_file:
                output_file = temp_file.name
                cmd.extend(["-f", output_file])
                
                # Run theHarvester with timeout
                timeout = kwargs.get("timeout", 300)
                self.logger.debug(f"Running command: {' '.join(cmd)}")
                
                process = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=timeout
                )
                
                # Initialize results
                results = {
                    "domain": target,
                    "hosts": [],
                    "ips": [],
                    "emails": [],
                    "urls": [],
                    "sources": sources,
                    "success": True,
                    "error": None
                }
                
                # Parse console output first
                console_results = self._parse_console_output(process.stdout)
                results.update(console_results)
                
                # Try to parse JSON output if available
                if os.path.exists(output_file):
                    try:
                        with open(output_file, 'r') as f:
                            json_content = f.read().strip()
                            if json_content:  # Only try to parse if there's content
                                harvester_results = json.loads(json_content)
                                
                                # Merge JSON results with console results
                                for key in ["hosts", "ips", "emails", "urls"]:
                                    if key in harvester_results:
                                        results[key] = list(set(results[key] + harvester_results[key]))
                                
                    except json.JSONDecodeError as e:
                        self.logger.warning(f"Could not parse JSON output: {str(e)}")
                    finally:
                        try:
                            os.unlink(output_file)
                        except Exception as e:
                            self.logger.warning(f"Could not delete temporary file: {str(e)}")
                
                # Check for errors in stderr
                if process.stderr:
                    error_msg = process.stderr.strip()
                    if error_msg and "Error:" in error_msg:
                        results["error"] = error_msg
                        if process.returncode != 0:
                            results["success"] = False
                
                # Remove duplicates and sort
                for key in ["hosts", "ips", "emails", "urls"]:
                    results[key] = sorted(list(set(results[key])))
                
                # Add statistics
                results["statistics"] = {
                    "total_hosts": len(results["hosts"]),
                    "total_ips": len(results["ips"]),
                    "total_emails": len(results["emails"]),
                    "total_urls": len(results["urls"])
                }
                
                return results
                
        except subprocess.TimeoutExpired:
            self.logger.error(f"theHarvester scan timed out after {timeout} seconds")
            return {
                "domain": target,
                "success": False,
                "error": f"Scan timed out after {timeout} seconds",
                "hosts": [],
                "ips": [],
                "emails": [],
                "urls": [],
                "statistics": {
                    "total_hosts": 0,
                    "total_ips": 0,
                    "total_emails": 0,
                    "total_urls": 0
                }
            }
        except Exception as e:
            self.logger.error(f"Error in theHarvester scan: {str(e)}")
            return {
                "domain": target,
                "success": False,
                "error": str(e),
                "hosts": [],
                "ips": [],
                "emails": [],
                "urls": [],
                "statistics": {
                    "total_hosts": 0,
                    "total_ips": 0,
                    "total_emails": 0,
                    "total_urls": 0
                }
            }