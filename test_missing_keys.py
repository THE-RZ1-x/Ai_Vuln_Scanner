#!/usr/bin/env python3
"""
Simple test script to verify the vulnerability scanner works with missing API keys.
This script deliberately removes all API keys from the environment and runs a basic scan.
"""

import os
import sys
import asyncio
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('test_missing_keys.log')
    ]
)
logger = logging.getLogger(__name__)

def clear_api_keys():
    """Remove all API keys from environment."""
    api_keys = [
        'VULNERS_API_KEY',
        'SHODAN_API_KEY',
        'GEMINI_API_KEY',
        'OPENAI_API_KEY',
        'NVD_API_KEY',
        'GREYNOISE_API_KEY',
        'URLSCAN_API_KEY',
        'ABUSEIPDB_API_KEY',
        'VIRUSTOTAL_API_KEY'
    ]
    
    # Save original keys
    original_keys = {}
    for key in api_keys:
        if key in os.environ:
            original_keys[key] = os.environ[key]
            del os.environ[key]
    
    logger.info(f"Removed {len(original_keys)} API keys from environment")
    return original_keys

def restore_api_keys(original_keys):
    """Restore original API keys to environment."""
    for key, value in original_keys.items():
        os.environ[key] = value
    logger.info(f"Restored {len(original_keys)} API keys to environment")

async def run_test_scan():
    """Run a test scan with missing API keys."""
    try:
        # Import here to ensure environment variables are cleared first
        from vulnscanner import main
        
        # Run the main function
        logger.info("Starting test scan with missing API keys")
        await main()
        
        logger.info("Test scan completed successfully")
        return True
    except Exception as e:
        logger.error(f"Test scan failed: {str(e)}")
        return False

def main():
    """Main function to run the test."""
    logger.info("=== Starting Test: Scanner Resilience with Missing API Keys ===")
    
    # Store original API keys
    original_keys = clear_api_keys()
    
    try:
        # Set test arguments
        test_target = "127.0.0.1"  # Use localhost for testing
        sys.argv = ["vulnscanner.py", "-t", test_target, "-s", "basic", "-v"]
        
        # Run test scan
        success = asyncio.run(run_test_scan())
        
        # Report results
        if success:
            logger.info("+ TEST PASSED: Scanner works with missing API keys")
        else:
            logger.error("- TEST FAILED: Scanner encountered errors with missing API keys")
            
    finally:
        # Restore original API keys
        restore_api_keys(original_keys)
    
    logger.info("=== Test Completed ===")

if __name__ == "__main__":
    main()
