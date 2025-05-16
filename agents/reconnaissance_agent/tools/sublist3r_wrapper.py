"""
Sublist3r wrapper for the reconnaissance agent.
"""

import subprocess
from typing import Dict, Any, List, Optional
import logging
import json
import tempfile
import os
import re
from datetime import datetime
import sys

class Sublist3rScanner:
    """Simple Sublist3r scanner implementation."""
    
    def __init__(self):
        """Initialize the Sublist3r scanner."""
        self.logger = logging.getLogger(__name__)
        self.sublist3r_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
                                         "Sublist3r", "sublist3r.py")
        
    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Perform Sublist3r scan for the target domain.
        
        Args:
            target: Target domain to scan
            **kwargs: Additional arguments (ignored for simplicity)
            
        Returns:
            Dict containing Sublist3r scan results
        """
        try:
            self.logger.info(f"Starting Sublist3r scan for {target}")
            
            # Ensure Sublist3r script exists
            if not os.path.exists(self.sublist3r_path):
                raise FileNotFoundError(f"Sublist3r script not found at {self.sublist3r_path}")
            
            # Create temporary file for output
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_file:
                output_file = temp_file.name
                
                # Run Sublist3r command with Python interpreter
                cmd = [
                    sys.executable,
                    self.sublist3r_path,
                    "-d", target,
                    "-o", output_file,
                    "-v"  # Verbose output
                ]
                
                # Add optional arguments
                if kwargs.get("threads"):
                    cmd.extend(["-t", str(kwargs["threads"])])
                if kwargs.get("ports"):
                    cmd.extend(["-p", str(kwargs["ports"])])
                if kwargs.get("engines"):
                    cmd.extend(["-e", ",".join(kwargs["engines"])])
                    
                try:
                    process = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=300,
                        env={"PYTHONPATH": os.path.dirname(self.sublist3r_path)}
                    )
                except subprocess.TimeoutExpired:
                    self.logger.error("Sublist3r scan timed out")
                    if os.path.exists(output_file):
                        os.unlink(output_file)
                    return {
                        "error": "Scan timed out",
                        "domain": target,
                        "status": "error",
                        "scan_date": datetime.utcnow().isoformat()
                    }
                
                subdomains = set()  # Use set to avoid duplicates
                
                # Read from output file if it exists
                if os.path.exists(output_file):
                    try:
                        with open(output_file, 'r') as f:
                            file_subdomains = [line.strip() for line in f if line.strip()]
                            subdomains.update(file_subdomains)
                    except Exception as e:
                        self.logger.error(f"Error reading output file: {str(e)}")
                    finally:
                        os.unlink(output_file)
                    
                # Parse console output for subdomains
                if process.stdout:
                    for line in process.stdout.splitlines():
                        # Skip log lines and empty lines
                        if not line or line.startswith('[-]') or line.startswith('[!]') or line.startswith('[*]'):
                            continue
                        
                        # Clean and validate subdomain
                        subdomain = line.strip()
                        if target in subdomain and self._is_valid_subdomain(subdomain):
                            subdomains.add(subdomain)
                            
                # Convert set to list and sort
                subdomain_list = sorted(list(subdomains))
                
                results = {
                    "domain": target,
                    "scan_date": datetime.utcnow().isoformat(),
                    "subdomains": [{"hostname": s} for s in subdomain_list],
                    "total_found": len(subdomain_list),
                    "status": "success" if process.returncode == 0 and subdomain_list else "error",
                    "command_output": process.stdout,
                    "command_error": process.stderr
                }
                
                # Add analysis
                results.update(self._analyze_results(results))
                
                return results
                
        except Exception as e:
            self.logger.error(f"Error in Sublist3r scan: {str(e)}")
            return {
                "error": str(e),
                "domain": target,
                "status": "error",
                "scan_date": datetime.utcnow().isoformat()
            }
            
    def _is_valid_subdomain(self, subdomain: str) -> bool:
        """Validate subdomain format."""
        try:
            # Basic subdomain validation
            if not subdomain or len(subdomain) > 255:
                return False
                
            # Check each label
            labels = subdomain.split('.')
            for label in labels:
                if not label or len(label) > 63:
                    return False
                if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$', label):
                    return False
                    
            return True
        except:
            return False
            
    def _analyze_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze scan results for security implications."""
        analysis = {
            "key_findings": [],
            "potential_risks": [],
            "recommendations": []
        }
        
        subdomains = results.get("subdomains", [])
        
        if not subdomains:
            analysis["key_findings"].append("No subdomains found")
            analysis["recommendations"].append("Consider using additional enumeration techniques")
            return analysis
            
        # Check for potentially sensitive subdomains
        sensitive_keywords = ["dev", "stage", "test", "admin", "internal", "vpn", "mail", "remote"]
        sensitive_subdomains = []
        
        for subdomain in subdomains:
            hostname = subdomain["hostname"].lower()
            matches = [kw for kw in sensitive_keywords if kw in hostname]
            if matches:
                sensitive_subdomains.append((hostname, matches[0]))
                
        if sensitive_subdomains:
            analysis["key_findings"].append(f"Found {len(sensitive_subdomains)} potentially sensitive subdomains")
            analysis["potential_risks"].append("Sensitive subdomains might expose internal information or development environments")
            analysis["recommendations"].append("Review and secure sensitive subdomains")
            
        # Add general recommendations
        if len(subdomains) > 0:
            analysis["key_findings"].append(f"Found {len(subdomains)} total subdomains")
            analysis["recommendations"].extend([
                "Verify all subdomains are intended to be public",
                "Implement proper access controls on all subdomains",
                "Consider using wildcard SSL certificates for comprehensive coverage"
            ])
            
        return analysis