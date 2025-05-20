"""
LLM Interface for the Reconnaissance Agent.
This module handles all interactions with the Gemini API for reconnaissance tasks.
"""

import os
import json
import time
from typing import Dict, List, Any, Optional, Callable
import logging
import google.generativeai as genai
from google.generativeai.types import GenerationConfig

class ReconLLMInterface:
    """Interface for interacting with the Gemini API for reconnaissance tasks."""
    
    def __init__(self, api_key: str, model: str = "gemini-2.5-flash-preview-04-17", logger=None):
        """
        Initialize the LLM interface with the Gemini API.
        
        Args:
            api_key: Gemini API key
            model: Model name to use
            logger: Logger instance
        """
        self.api_key = api_key
        self.model = model
        self.logger = logger or logging.getLogger(__name__)
        
        # Configure the Gemini API
        genai.configure(api_key=api_key)
        
        # Default generation config
        self.generation_config = GenerationConfig(
            temperature=0.2,
            top_k=40,
            max_output_tokens=8192,
        )
        
        # System prompt for reconnaissance
        self.system_prompt = """
        You are an expert cybersecurity reconnaissance agent running in Kali Linux 2025. 
        You have complete access to various reconnaissance tools in this environment. 
        Your task is to gather detailed information about the target in a systematic and thorough manner.
        
        You can access and utilize the following tools:
        - Sublist3r: For subdomain enumeration
        - WHOIS: For domain registration information
        - DNS lookup tools: For DNS records, zone transfers
        - DNSDumpster: For comprehensive DNS reconnaissance, including subdomains, DNS records, and domain mapping
        - theHarvester: For email addresses, subdomains, hosts, employee names
        
        Be precise in your commands and interpret the results accurately. 
        Format all outputs as structured JSON that can be easily processed by other agents in the pipeline.
        Ensure all information is relevant to the penetration testing process.
        """
    
    def _call_gemini(self, prompt: str, system_prompt: str = None) -> str:
        """
        Make a call to the Gemini API.
        
        Args:
            prompt: User prompt to send to the API
            system_prompt: Optional system prompt override
            
        Returns:
            API response text
        """
        try:
            model = genai.GenerativeModel(
                model_name=self.model,
                generation_config=self.generation_config
            )
            
            # Create the chat session
            chat = model.start_chat(history=[])
            
            # Add the system prompt if provided
            if system_prompt:
                response = chat.send_message(f"System: {system_prompt}\n\nUser: {prompt}")
            else:
                response = chat.send_message(f"System: {self.system_prompt}\n\nUser: {prompt}")
            
            return response.text
            
        except Exception as e:
            self.logger.error(f"Error calling Gemini API: {str(e)}")
            raise
    
    def determine_recon_strategy(self, target: str, available_tools: List[str]) -> Dict[str, Any]:
        """
        Use the LLM to determine the best reconnaissance strategy for the target.
        
        Args:
            target: Target domain or IP address
            available_tools: List of available tools
            
        Returns:
            Dict containing reconnaissance strategy
        """
        prompt = f"""
        I need to perform reconnaissance on the target: {target}
        
        Available tools: {', '.join(available_tools)}
        
        Please help me determine the most effective reconnaissance strategy by:
        1. Deciding the optimal order to run these tools
        2. Providing specific configuration parameters for each tool
        3. Explaining your reasoning for this strategy
        
        Provide your response as a JSON object with the following structure:
        {{
            "target_analysis": "brief analysis of the target",
            "tool_order": ["ordered", "list", "of", "tools"],
            "tool_configs": {{
                "tool1": {{"param1": "value1", "param2": "value2"}},
                "tool2": {{"param1": "value1", "param2": "value2"}}
            }},
            "reasoning": "explanation of your strategy"
        }}
        """
        
        response = self._call_gemini(prompt)
        
        # Parse the JSON response
        try:
            # Extract JSON from the response text if needed
            json_start = response.find("{")
            json_end = response.rfind("}") + 1
            if json_start >= 0 and json_end > json_start:
                json_str = response[json_start:json_end]
                result = json.loads(json_str)
            else:
                self.logger.warning("Could not extract JSON from response, using full response")
                result = json.loads(response)
                
            return result
        except json.JSONDecodeError:
            self.logger.error("Failed to parse LLM response as JSON")
            # Return a basic fallback strategy
            return {
                "target_analysis": f"Basic analysis of {target}",
                "tool_order": available_tools,
                "tool_configs": {tool: {} for tool in available_tools},
                "reasoning": "Default strategy due to LLM parsing failure"
            }
    
    def generate_tool_prompt(self, tool_name: str, target: str, tool_config: Dict[str, Any]) -> str:
        """
        Generate a tool-specific prompt for the LLM.
        
        Args:
            tool_name: Name of the tool
            target: Target domain or IP address
            tool_config: Tool configuration parameters
            
        Returns:
            Tool-specific prompt
        """
        prompt = f"""
        I need to use {tool_name} to gather information about {target}.
        
        Tool configuration parameters: {json.dumps(tool_config)}
        
        Please provide the exact command to run in Kali Linux 2025, including all necessary flags and parameters.
        Also explain what information we're looking for and why this approach is optimal.
        """
        
        response = self._call_gemini(prompt)
        return response
    
    def execute_tool(self, tool_name: str, target: str, prompt: str, tool_instance: Any) -> Dict[str, Any]:
        """
        Execute a reconnaissance tool using the LLM-generated prompt.
        
        Args:
            tool_name: Name of the tool
            target: Target domain or IP address
            prompt: LLM-generated prompt for tool execution
            tool_instance: Instance of the tool class
            
        Returns:
            Dict containing tool execution results
        """
        self.logger.info(f"Executing {tool_name} with LLM guidance")
        
        # Generate the LLM-guided command or parameters
        tool_guidance_prompt = f"""
        Based on the tool execution plan:
        
        {prompt}
        
        Please generate only the exact parameters to use with the {tool_name} Python interface.
        Return these as a JSON object with parameter names and values.
        Do not include any explanations or command-line syntax, just the Python parameters.
        """
        
        parameters_response = self._call_gemini(tool_guidance_prompt)
        
        # Extract the parameters from the response
        try:
            # Find JSON in the response
            json_start = parameters_response.find("{")
            json_end = parameters_response.rfind("}") + 1
            if json_start >= 0 and json_end > json_start:
                json_str = parameters_response[json_start:json_end]
                parameters = json.loads(json_str)
            else:
                self.logger.warning("Could not extract JSON from parameters response, using empty parameters")
                parameters = {}
        except json.JSONDecodeError:
            self.logger.warning(f"Failed to parse parameters for {tool_name}, using defaults")
            parameters = {}
        
        # Execute the tool with the parameters
        if hasattr(tool_instance, 'scan') and callable(getattr(tool_instance, 'scan')):
            # Most tools will have a scan method
            results = tool_instance.scan(target, **parameters)
        elif hasattr(tool_instance, 'lookup') and callable(getattr(tool_instance, 'lookup')):
            # Some tools might have a lookup method
            results = tool_instance.lookup(target, **parameters)
        else:
            # Try to find any method that takes a target parameter
            for attr_name in dir(tool_instance):
                attr = getattr(tool_instance, attr_name)
                if callable(attr) and not attr_name.startswith('_'):
                    try:
                        results = attr(target, **parameters)
                        break
                    except:
                        continue
            else:
                raise ValueError(f"Could not find a suitable method to run in {tool_name}")
        
        return results
    
    def process_tool_output(self, tool_name: str, tool_output: Dict[str, Any], target: str) -> Dict[str, Any]:
        """
        Process and analyze the output from a reconnaissance tool using the LLM.
        
        Args:
            tool_name: Name of the tool
            tool_output: Raw output from the tool
            target: Target domain or IP address
            
        Returns:
            Dict containing processed and analyzed results
        """
        # Create a tool-specific prompt for output analysis
        if tool_name == "dnsdumpster":
            analysis_prompt = f"""
            Analyze the following DNSDumpster results for {target}:
            
            {json.dumps(tool_output, indent=2)}
            
            Please provide:
            1. A summary of key DNS findings
            2. Identified subdomains and their significance
            3. Any potential security implications
            4. Recommendations for further investigation
            
            Format your response as a JSON object with these sections.
            Focus on findings that are relevant for penetration testing.
            """
        else:
            analysis_prompt = f"""
            Analyze the following {tool_name} results for {target}:
            
            {json.dumps(tool_output, indent=2)}
            
            Please provide:
            1. Key findings and their significance
            2. Potential vulnerabilities or security implications
            3. Recommendations for further investigation
            
            Format your response as a JSON object with these sections.
            """
            
        response = self._call_gemini(analysis_prompt)
        
        try:
            # Extract JSON from the response
            json_start = response.find("{")
            json_end = response.rfind("}") + 1
            if json_start >= 0 and json_end > json_start:
                processed_results = json.loads(response[json_start:json_end])
            else:
                processed_results = json.loads(response)
                
            return processed_results
            
        except json.JSONDecodeError:
            self.logger.error(f"Failed to parse LLM analysis for {tool_name}")
            return {
                "error": "Failed to parse LLM analysis",
                "raw_output": tool_output
            }
    
    def analyze_recon_data(self, combined_results: Dict[str, Any], target: str) -> Dict[str, Any]:
        """
        Use the LLM to analyze the complete reconnaissance dataset.
        
        Args:
            combined_results: Combined results from all tools
            target: Target domain or IP address
            
        Returns:
            Dict containing reconnaissance insights
        """
        # Prepare a summary of the data to avoid token limits
        tools_summary = {}
        for tool_name, tool_data in combined_results.items():
            if isinstance(tool_data, dict) and "analysis" in tool_data:
                tools_summary[tool_name] = tool_data["analysis"]
            else:
                tools_summary[tool_name] = {"note": "Data available but not summarized"}
        
        prompt = f"""
        I have completed reconnaissance on target {target} using multiple tools.
        Here is a summary of the findings:
        
        {json.dumps(tools_summary, indent=2)}
        
        Please provide a comprehensive analysis including:
        1. A summary of the most critical findings across all tools
        2. Potential attack vectors identified
        3. Recommended next steps for vulnerability scanning
        4. Any security misconfigurations or concerning exposures
        5. An overall risk assessment of the target based on the reconnaissance data
        
        Format your response as a detailed JSON object with these sections.
        """
        
        response = self._call_gemini(prompt)
        
        # Parse the JSON response
        try:
            # Extract JSON from the response text if needed
            json_start = response.find("{")
            json_end = response.rfind("}") + 1
            if json_start >= 0 and json_end > json_start:
                json_str = response[json_start:json_end]
                insights = json.loads(json_str)
            else:
                self.logger.warning("Could not extract JSON from insights response, using full response")
                insights = {"overall_analysis": response}
                
            return insights
        except json.JSONDecodeError:
            self.logger.error("Failed to parse LLM insights as JSON")
            return {
                "error": "Failed to parse LLM insights",
                "raw_insights": response
            }