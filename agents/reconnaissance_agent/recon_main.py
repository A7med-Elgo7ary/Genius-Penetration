#!/usr/bin/env python3
"""
Main script for the Reconnaissance Agent.
"""

import os
import json
import argparse
import logging
from datetime import datetime
from typing import Dict, Any
import sys
from flask import Flask, render_template, request, jsonify, redirect, url_for

# Add the parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from agents.reconnaissance_agent.tools.DNSDumpster_wrapper import DNSDumpsterScanner
from agents.reconnaissance_agent.tools.sublist3r_wrapper import Sublist3rScanner
from agents.reconnaissance_agent.tools.whois_lookup import WhoisLookup
from agents.reconnaissance_agent.tools.dns_lookup import DNSLookup
from agents.reconnaissance_agent.tools.theHarvester_wrapper import TheHarvesterScanner
from agents.reconnaissance_agent.llm_interface import ReconLLMInterface

app = Flask(__name__)

class ReconnaissanceAgent:
    """Reconnaissance Agent for gathering information about the target."""
    
    def __init__(self):
        """Initialize the Reconnaissance Agent."""
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        self.logger = logging.getLogger("reconnaissance_agent")
        
        # Initialize tools
        self.tools = {
            "dnsdumpster": DNSDumpsterScanner(),
            "sublist3r": Sublist3rScanner(),
            "whois": WhoisLookup(),
            "dns": DNSLookup(),
            "harvester": TheHarvesterScanner()
        }
        
        # Initialize LLM interface
        api_key = os.getenv('GEMINI_API_KEY')
        if not api_key:
            self.logger.warning("GEMINI_API_KEY not found in environment. LLM features will be disabled.")
            self.llm = None
        else:
            self.llm = ReconLLMInterface(api_key=api_key, logger=self.logger)
        
        self.output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")
        os.makedirs(self.output_dir, exist_ok=True)
        
    def run(self, target: str) -> Dict[str, Any]:
        """
        Run reconnaissance on the target.
        
        Args:
            target: Target domain to scan
            
        Returns:
            Dict containing reconnaissance results
        """
        self.logger.info(f"Starting reconnaissance on target: {target}")
        
        results = {
            "scan_date": datetime.utcnow().isoformat(),
            "target": target,
            "findings": {},
            "total_findings": 0,
            "emails_found": 0,
            "hosts_found": 0
        }
        
        # If LLM is available, get the reconnaissance strategy
        if self.llm:
            try:
                strategy = self.llm.determine_recon_strategy(
                    target=target,
                    available_tools=list(self.tools.keys())
                )
                self.logger.info(f"LLM Strategy: {json.dumps(strategy, indent=2)}")
                
                # Use the LLM-determined tool order
                tool_order = strategy["tool_order"]
                tool_configs = strategy["tool_configs"]
            except Exception as e:
                self.logger.error(f"Error getting LLM strategy: {str(e)}")
                tool_order = list(self.tools.keys())
                tool_configs = {tool: {} for tool in tool_order}
        else:
            tool_order = list(self.tools.keys())
            tool_configs = {tool: {} for tool in tool_order}
        
        # Run each tool in the determined order
        for tool_name in tool_order:
            tool = self.tools[tool_name]
            try:
                self.logger.info(f"Running {tool_name} scan...")
                
                # If LLM is available, get tool-specific guidance
                if self.llm:
                    try:
                        prompt = self.llm.generate_tool_prompt(
                            tool_name=tool_name,
                            target=target,
                            tool_config=tool_configs.get(tool_name, {})
                        )
                        tool_results = self.llm.execute_tool(
                            tool_name=tool_name,
                            target=target,
                            prompt=prompt,
                            tool_instance=tool
                        )
                    except Exception as e:
                        self.logger.error(f"Error using LLM for {tool_name}: {str(e)}")
                        tool_results = tool.scan(target)
                else:
                    tool_results = tool.scan(target)
                
                results["findings"][tool_name] = tool_results
                
                # Count findings
                if isinstance(tool_results, dict):
                    if "emails" in tool_results:
                        results["emails_found"] += len(tool_results["emails"])
                    if "hosts" in tool_results:
                        results["hosts_found"] += len(tool_results["hosts"])
                    results["total_findings"] += sum(len(v) if isinstance(v, list) else 1 
                                                   for v in tool_results.values())
                
                # If LLM is available, process and analyze the results
                if self.llm:
                    try:
                        analyzed_results = self.llm.process_tool_output(
                            tool_name=tool_name,
                            tool_output=tool_results,
                            target=target
                        )
                        results["findings"][tool_name] = analyzed_results
                    except Exception as e:
                        self.logger.error(f"Error analyzing {tool_name} results with LLM: {str(e)}")
                
                self.logger.info(f"Completed {tool_name} scan")
                
            except Exception as e:
                self.logger.error(f"Error running {tool_name}: {str(e)}")
                results["findings"][tool_name] = {"error": str(e)}
        
        # If LLM is available, perform final analysis of all results
        if self.llm:
            try:
                final_analysis = self.llm.analyze_recon_data(results, target)
                results["llm_analysis"] = final_analysis
            except Exception as e:
                self.logger.error(f"Error performing final LLM analysis: {str(e)}")
        
        # Save results
        output_file = os.path.join(self.output_dir, "recon_data.json")
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
            
        # Log summary
        self.logger.info(f"Reconnaissance complete. Summary:")
        self.logger.info(f"- Emails found: {results['emails_found']}")
        self.logger.info(f"- Hosts found: {results['hosts_found']}")
        self.logger.info(f"- Total findings: {results['total_findings']}")
        self.logger.info(f"Results saved to {output_file}")
        
        return results

@app.route('/')
def index():
    return render_template('recon_page.html')

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form.get('target')
    if not target:
        return render_template('recon_page.html', message="Please provide a target domain.", error=True)

    try:
        agent = ReconnaissanceAgent()
        results = agent.run(target)
        message = f"Reconnaissance completed successfully! Found {results['total_findings']} findings, "
        message += f"{results['emails_found']} emails, and {results['hosts_found']} hosts. "
        if "llm_analysis" in results:
            message += "\n\nLLM Analysis Summary: " + results["llm_analysis"].get("summary", "")
        message += "\n\nResults saved to output/recon_data.json"
        return render_template('recon_page.html', message=message)
    except Exception as e:
        return render_template('recon_page.html', message=f"Error during reconnaissance: {str(e)}", error=True)

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Reconnaissance Agent")
    parser.add_argument("-t", "--target", help="Target domain for reconnaissance")
    parser.add_argument("--web", action="store_true", help="Start web interface")
    args = parser.parse_args()

    if args.web:
        app.run(debug=True, port=5050)
    elif args.target:
        agent = ReconnaissanceAgent()
        results = agent.run(args.target)
        print(json.dumps(results, indent=2))
    else:
        app.run(debug=True, port=5050)

if __name__ == "__main__":
    main()