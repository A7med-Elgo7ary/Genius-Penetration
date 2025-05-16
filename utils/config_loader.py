"""
Configuration loader utility for the AI-PenTest Agents project.
This module handles loading and validation of configuration files.
"""

import os
import yaml
from typing import Dict, Any, Optional
import logging

# Set up module logger
logger = logging.getLogger(__name__)

def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load and validate configuration from a YAML file.
    
    Args:
        config_path: Path to the configuration file. If None, uses default config.
        
    Returns:
        Dict containing the configuration
        
    Raises:
        FileNotFoundError: If config file doesn't exist
        yaml.YAMLError: If config file is invalid YAML
    """
    # Use default config path if none provided
    if config_path is None:
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "config",
            "config.yaml"
        )
    
    # Ensure config file exists
    if not os.path.exists(config_path):
        logger.error(f"Configuration file not found: {config_path}")
        # Create default config if it doesn't exist
        return create_default_config(config_path)
    
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
            
        if not isinstance(config, dict):
            logger.error("Invalid configuration format")
            return create_default_config(config_path)
            
        # Validate and set defaults for missing values
        config = validate_config(config)
        
        return config
        
    except yaml.YAMLError as e:
        logger.error(f"Error parsing configuration file: {str(e)}")
        return create_default_config(config_path)
    except Exception as e:
        logger.error(f"Unexpected error loading configuration: {str(e)}")
        return create_default_config(config_path)

def create_default_config(config_path: str) -> Dict[str, Any]:
    """
    Create a default configuration file.
    
    Args:
        config_path: Path where to save the default config
        
    Returns:
        Dict containing the default configuration
    """
    default_config = {
        "logging": {
            "level": "INFO",
            "file": "logs/ai_pentest.log",
            "console_output": True
        },
        "llm": {
            "model": "gemini-2.5-flash-preview-04-17",
            "temperature": 0.2,
            "max_tokens": 8192
        },
        "agents": {
            "reconnaissance": {
                "tools": ["dnsdumpster", "sublist3r", "whois", "dns", "harvester"],
                "output_dir": "output/recon",
                "timeout": 300
            },
            "vulnerability_scanner": {
                "tools": ["nmap", "nikto", "wpscan"],
                "output_dir": "output/vulnscan",
                "timeout": 600
            }
        },
        "reporting": {
            "output_format": ["json", "html"],
            "report_dir": "reports"
        }
    }
    
    # Create config directory if it doesn't exist
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    
    # Save default config
    try:
        with open(config_path, 'w') as f:
            yaml.safe_dump(default_config, f, default_flow_style=False)
    except Exception as e:
        logger.error(f"Failed to save default configuration: {str(e)}")
    
    return default_config

def validate_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate configuration and set defaults for missing values.
    
    Args:
        config: Configuration dictionary to validate
        
    Returns:
        Validated configuration dictionary
    """
    # Ensure required top-level sections exist
    required_sections = ["logging", "llm", "agents", "reporting"]
    for section in required_sections:
        if section not in config:
            config[section] = {}
    
    # Validate logging section
    if "logging" in config:
        config["logging"].setdefault("level", "INFO")
        config["logging"].setdefault("file", "logs/ai_pentest.log")
        config["logging"].setdefault("console_output", True)
    
    # Validate LLM section
    if "llm" in config:
        config["llm"].setdefault("model", "gemini-2.5-flash-preview-04-17")
        config["llm"].setdefault("temperature", 0.2)
        config["llm"].setdefault("max_tokens", 8192)
    
    # Validate agents section
    if "agents" in config:
        if "reconnaissance" not in config["agents"]:
            config["agents"]["reconnaissance"] = {}
        config["agents"]["reconnaissance"].setdefault("tools", 
            ["dnsdumpster", "sublist3r", "whois", "dns", "harvester"])
        config["agents"]["reconnaissance"].setdefault("output_dir", "output/recon")
        config["agents"]["reconnaissance"].setdefault("timeout", 300)
    
    # Validate reporting section
    if "reporting" in config:
        config["reporting"].setdefault("output_format", ["json", "html"])
        config["reporting"].setdefault("report_dir", "reports")
    
    return config
