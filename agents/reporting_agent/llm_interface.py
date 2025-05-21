#!/usr/bin/env python3
# llm_interface.py - Reporting Agent LLM Interface
# Part of AI-PenTest Agents Project

import os
import json
import logging
import google.generativeai as genai
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("reporting_agent.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("reporting_agent.llm_interface")

class ReportingLLMInterface:
    """
    LLM Interface for the Reporting Agent using Google Gemini 2.5 Flash
    Aggregates and summarizes data from all previous agent outputs
    """
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the LLM interface
        
        Args:
            api_key: Google AI API key (optional if set via GOOGLE_API_KEY env var)
        """
        # Use provided API key or get from environment variable
        self.api_key = api_key or os.environ.get("GOOGLE_API_KEY")
        if not self.api_key:
            logger.error("No Google AI API key provided. Set GOOGLE_API_KEY environment variable or pass as parameter.")
            raise ValueError("Google AI API key is required")
        
        # Configure Gemini API
        genai.configure(api_key=self.api_key)
        self.model = genai.GenerativeModel("gemini-2.5-flash")
        logger.info("LLM Interface initialized with Gemini 2.5 Flash model")
        
        # Define paths to agent output files
        self.agent_output_paths = {
            "reconnaissance": "../reconnaissance_agent/output/recon_data.json",
            "vulnerability_scan": "../vulnerability_scanner_agent/output/vuln_scan_results.json",
            "vulnerability_analysis": "../vulnerability_analysis_agent/output/vuln_analysis_report.json",
            "exploitation": "../exploitation_agent/output/exploit_attempts.json",
            "post_exploitation": "../post_exploitation_agent/output/post_exfil_report.json",
            "blue_team": "../blue_team_agent/output/blue_team_alerts.json",
            "coordinator": "../../coordinator_logs.json"  # Assuming coordinator logs are stored in the project root
        }
        
        # Output path for consolidated report
        self.output_path = Path("output")
        self.output_path.mkdir(exist_ok=True)
        
    def load_agent_data(self) -> Dict[str, Any]:
        """
        Load data from all agent output files with error handling
        
        Returns:
            Dict containing data from each agent
        """
        consolidated_data = {}
        
        for agent_name, file_path in self.agent_output_paths.items():
            try:
                # Convert to absolute path if needed
                path = Path(file_path)
                if not path.is_absolute():
                    # Get this file's directory and resolve relative path
                    base_dir = Path(__file__).parent
                    path = (base_dir / path).resolve()
                
                logger.info(f"Loading data from {agent_name} agent: {path}")
                
                if not path.exists():
                    logger.warning(f"File not found for {agent_name} agent: {path}")
                    consolidated_data[agent_name] = {
                        "status": "error",
                        "message": f"Data file not found: {path}",
                        "timestamp": datetime.now().isoformat()
                    }
                    continue
                
                with open(path, 'r') as file:
                    agent_data = json.load(file)
                    consolidated_data[agent_name] = {
                        "status": "success",
                        "data": agent_data,
                        "timestamp": datetime.now().isoformat()
                    }
                    
            except json.JSONDecodeError as e:
                logger.error(f"JSON decode error for {agent_name} agent: {e}")
                consolidated_data[agent_name] = {
                    "status": "error",
                    "message": f"Invalid JSON format: {str(e)}",
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                logger.error(f"Error loading data from {agent_name} agent: {e}")
                consolidated_data[agent_name] = {
                    "status": "error",
                    "message": f"Failed to load data: {str(e)}",
                    "timestamp": datetime.now().isoformat()
                }
        
        return consolidated_data
    
    def generate_llm_prompt(self, consolidated_data: Dict[str, Any]) -> str:
        """
        Generate prompt for Gemini API to summarize pentest data
        
        Args:
            consolidated_data: Dictionary containing data from all agents
            
        Returns:
            String prompt for the LLM
        """
        # Construct a prompt that instructs Gemini how to summarize and analyze the data
        prompt = """
        You are an expert cybersecurity analyst and part of an AI-driven penetration testing system.
        I'm providing you with data from various penetration testing agents that have conducted
        different phases of a security assessment. Please analyze this data and provide:
        
        1. An EXECUTIVE SUMMARY of the overall security posture
        2. For each agent, provide a CONCISE SUMMARY of their findings
        3. A prioritized list of VULNERABILITIES ordered by severity (Critical, High, Medium, Low)
        4. RECOMMENDATIONS for remediation
        5. Identify any CORRELATIONS between findings from different agents
        
        Format your response as a structured JSON document with these sections.
        For any agent data that contains errors or is missing, note this in your summary.
        
        Here is the data from each agent:
        """
        
        # Add each agent's data to the prompt, handling errors
        for agent_name, agent_info in consolidated_data.items():
            prompt += f"\n\n## {agent_name.upper()} AGENT DATA:\n"
            
            if agent_info["status"] == "error":
                prompt += f"ERROR: {agent_info['message']}"
            else:
                # Serialize the JSON data and add it to the prompt
                # Limit data size if needed to avoid token limits
                agent_data_str = json.dumps(agent_info["data"], indent=2)
                if len(agent_data_str) > 10000:  # Arbitrary limit to avoid exceeding token limits
                    prompt += f"{agent_data_str[:10000]}... (truncated)"
                else:
                    prompt += agent_data_str
        
        # Final instructions to format the output
        prompt += """
        
        Your response should be valid JSON with the following structure:
        {
            "executive_summary": "Concise overall assessment of the security posture",
            "agent_summaries": {
                "reconnaissance": {"summary": "...", "key_findings": ["...", "..."]},
                "vulnerability_scan": {"summary": "...", "key_findings": ["...", "..."]},
                "vulnerability_analysis": {"summary": "...", "key_findings": ["...", "..."]},
                "exploitation": {"summary": "...", "key_findings": ["...", "..."]},
                "post_exploitation": {"summary": "...", "key_findings": ["...", "..."]},
                "blue_team": {"summary": "...", "key_findings": ["...", "..."]},
                "coordinator": {"summary": "...", "key_findings": ["...", "..."]}
            },
            "vulnerabilities": [
                {"id": "VULN-001", "name": "Critical SQL Injection", "severity": "Critical", "affected_components": ["..."], "description": "...", "recommendation": "..."},
                // Additional vulnerabilities...
            ],
            "recommendations": [
                {"id": "REC-001", "title": "Patch SQL Injection", "priority": "High", "description": "...", "implementation_steps": ["...", "..."]},
                // Additional recommendations...
            ],
            "correlations": [
                {"finding_1": "VULN-001", "finding_2": "VULN-003", "relationship": "The SQL injection vulnerability (VULN-001) was used to escalate privileges (VULN-003)"}
                // Additional correlations...
            ],
            "metadata": {
                "report_generated": "TIMESTAMP",
                "agents_data_status": {
                    "reconnaissance": "success/error",
                    // Status for other agents...
                }
            }
        }
        
        Ensure your response is properly formatted JSON without any additional text.
        """
        
        return prompt
    
    async def generate_report(self) -> Dict[str, Any]:
        """
        Use Gemini to generate a comprehensive penetration test report
        
        Returns:
            Dictionary containing the structured report data
        """
        # Load data from all agents
        consolidated_data = self.load_agent_data()
        
        # Generate prompt for Gemini
        prompt = self.generate_llm_prompt(consolidated_data)
        
        try:
            logger.info("Sending request to Gemini API")
            # Generate response from Gemini
            response = await self.model.generate_content_async(prompt)
            
            # Extract the text response
            response_text = response.text
            
            # Parse the JSON from the response
            try:
                report_data = json.loads(response_text)
                
                # Add metadata to report
                report_data["metadata"] = {
                    "report_generated": datetime.now().isoformat(),
                    "agents_data_status": {
                        agent: data["status"] for agent, data in consolidated_data.items()
                    }
                }
                
                # Add raw data for reference (optional)
                report_data["raw_data"] = {
                    agent: data.get("data", {"status": "error"}) if data["status"] == "success" else {"error": data["message"]}
                    for agent, data in consolidated_data.items()
                }
                
                # Save the report to a file
                output_file = self.output_path / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                with open(output_file, "w") as f:
                    json.dump(report_data, f, indent=2)
                
                # Also save to a consistent filename for the dashboard to use
                with open(self.output_path / "report.json", "w") as f:
                    json.dump(report_data, f, indent=2)
                
                logger.info(f"Report successfully generated and saved to {output_file}")
                return report_data
                
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse LLM response as JSON: {e}")
                # Create error report
                error_report = {
                    "status": "error",
                    "message": "Failed to generate valid JSON report from LLM",
                    "error": str(e),
                    "raw_response": response_text[:1000] + "..." if len(response_text) > 1000 else response_text,
                    "metadata": {
                        "report_generated": datetime.now().isoformat(),
                        "agents_data_status": {
                            agent: data["status"] for agent, data in consolidated_data.items()
                        }
                    }
                }
                
                # Save the error report
                error_file = self.output_path / f"error_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                with open(error_file, "w") as f:
                    json.dump(error_report, f, indent=2)
                
                # Also save to the consistent filename
                with open(self.output_path / "report.json", "w") as f:
                    json.dump(error_report, f, indent=2)
                
                logger.error(f"Error report saved to {error_file}")
                return error_report
                
        except Exception as e:
            logger.error(f"Error generating report with Gemini API: {e}")
            # Handle API errors
            error_report = {
                "status": "error",
                "message": "Failed to generate report with Gemini API",
                "error": str(e),
                "metadata": {
                    "report_generated": datetime.now().isoformat(),
                    "agents_data_status": {
                        agent: data["status"] for agent, data in consolidated_data.items()
                    }
                }
            }
            
            # Save the error report
            error_file = self.output_path / f"error_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(error_file, "w") as f:
                json.dump(error_report, f, indent=2)
            
            # Also save to the consistent filename
            with open(self.output_path / "report.json", "w") as f:
                json.dump(error_report, f, indent=2)
            
            logger.error(f"Error report saved to {error_file}")
            return error_report
    
    def generate_fallback_report(self, consolidated_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a basic report without using LLM in case of API failure
        
        Args:
            consolidated_data: Dictionary containing data from all agents
            
        Returns:
            Basic report with agent data summaries
        """
        logger.info("Generating fallback report without LLM")
        
        # Create a simplified report structure
        report = {
            "executive_summary": "Fallback report generated due to LLM API failure. Basic data consolidation only.",
            "agent_summaries": {},
            "vulnerabilities": [],
            "recommendations": [
                {"id": "REC-001", "title": "Review raw data", "priority": "High", 
                 "description": "Due to LLM processing failure, manual review of raw agent data is required."}
            ],
            "metadata": {
                "report_generated": datetime.now().isoformat(),
                "report_type": "fallback",
                "agents_data_status": {
                    agent: data["status"] for agent, data in consolidated_data.items()
                }
            },
            "raw_data": {}
        }
        
        # Add basic summaries and extract vulnerabilities
        for agent_name, agent_info in consolidated_data.items():
            # Add basic agent summary
            report["agent_summaries"][agent_name] = {
                "summary": f"Data {'available' if agent_info['status'] == 'success' else 'unavailable'} from {agent_name} agent.",
                "key_findings": []
            }
            
            # Add raw data for reference
            if agent_info["status"] == "success":
                report["raw_data"][agent_name] = agent_info.get("data", {})
                
                # Extract vulnerabilities from vulnerability analysis if available
                if agent_name == "vulnerability_analysis" and "data" in agent_info:
                    try:
                        # Attempt to extract vulnerabilities based on common structure
                        vuln_data = agent_info["data"]
                        if isinstance(vuln_data, dict) and "vulnerabilities" in vuln_data:
                            report["vulnerabilities"] = vuln_data["vulnerabilities"]
                        elif isinstance(vuln_data, list):
                            # Assume list of vulnerabilities
                            report["vulnerabilities"] = vuln_data
                    except Exception as e:
                        logger.error(f"Error extracting vulnerabilities from analysis: {e}")
            else:
                report["raw_data"][agent_name] = {"error": agent_info.get("message", "Unknown error")}
        
        # Save the fallback report
        output_file = self.output_path / f"fallback_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)
        
        # Also save to the consistent filename
        with open(self.output_path / "report.json", "w") as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Fallback report saved to {output_file}")
        return report

# For testing purposes
async def test_interface():
    """Test function to verify the LLM interface works correctly"""
    interface = ReportingLLMInterface()
    report = await interface.generate_report()
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    import asyncio
    asyncio.run(test_interface())
