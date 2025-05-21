#!/usr/bin/env python3
"""
Environment variable loader for the Genius-Penetration toolkit.
Loads variables from .env file in the project root.
"""

import os
import logging
from pathlib import Path
from dotenv import load_dotenv

def load_environment_variables():
    """
    Load environment variables from .env file in the project root.
    Returns a dictionary with all environment variables.
    """
    # Get the project root directory (3 levels up from this file)
    project_root = Path(__file__).parent.parent.absolute()
    env_path = project_root / '.env'
    
    # Load variables from .env file
    load_dotenv(env_path)
    
    # Create a dictionary with all environment variables needed for scanners
    env_vars = {
        'GEMINI_API_KEY': os.getenv('GEMINI_API_KEY'),
        'WPSCAN_API_TOKEN': os.getenv('WPSCAN_API_TOKEN'),
        'ZAP_API_KEY': os.getenv('ZAP_API_KEY'),
        'NIKTO_PATH': os.getenv('NIKTO_PATH', '/usr/bin/nikto'),
        'SQLMAP_PATH': os.getenv('SQLMAP_PATH', '/usr/bin/sqlmap'),
        'DIRB_PATH': os.getenv('DIRB_PATH', '/usr/bin/dirb'),
        'GOBUSTER_PATH': os.getenv('GOBUSTER_PATH', '/usr/bin/gobuster'),
        'NUCLEI_PATH': os.getenv('NUCLEI_PATH', '/home/kali/go/bin/nuclei'),
        'MASSCAN_PATH': os.getenv('MASSCAN_PATH', '/usr/bin/masscan'),
        'XSSER_PATH': os.getenv('XSSER_PATH', '/usr/bin/xsser'),
        'ZAP_PATH': os.getenv('ZAP_PATH', '/usr/bin/zap'),
        'SCAN_TIMEOUT': int(os.getenv('SCAN_TIMEOUT', 1800)),
        'DEFAULT_WORDLIST': os.getenv('DEFAULT_WORDLIST', '/usr/share/dirb/wordlists/common.txt')
    }
    
    # Log warnings for missing critical variables
    logger = logging.getLogger('env_loader')
    
    if not env_vars['GEMINI_API_KEY']:
        logger.warning("GEMINI_API_KEY not found in environment. LLM features will be disabled.")
    
    if not env_vars['WPSCAN_API_TOKEN'] or env_vars['WPSCAN_API_TOKEN'] == "YOUR_WPSCAN_API_TOKEN":
        logger.warning("WPSCAN_API_TOKEN not found in environment. Vulnerability data may be outdated or incomplete.")
    
    if not env_vars['ZAP_API_KEY']:
        logger.warning("ZAP_API_KEY not found in environment. ZAP scanner may not function correctly.")
    
    return env_vars
