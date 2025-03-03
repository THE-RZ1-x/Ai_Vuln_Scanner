#!/usr/bin/env python3
"""
Comprehensive test suite for the AI Vulnerability Scanner.
This script runs various tests to ensure the scanner works correctly.
"""

import os
import sys
import asyncio
import unittest
import argparse
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(f'test_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
    ]
)
logger = logging.getLogger(__name__)

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Run tests for the AI Vulnerability Scanner')
    parser.add_argument('--test-type', choices=['all', 'unit', 'integration', 'resilience'], 
                        default='all', help='Type of tests to run')
    parser.add_argument('--target', default='127.0.0.1', 
                        help='Target IP for integration tests (default: 127.0.0.1)')
    parser.add_argument('--skip-api-tests', action='store_true', 
                        help='Skip tests that require API keys')
    return parser.parse_args()

def run_unit_tests():
    """Run unit tests."""
    logger.info("=== Running Unit Tests ===")
    try:
        # Import test modules
        from test_resilience import ResilienceTests
        
        # Create test suite
        suite = unittest.TestSuite()
        suite.addTest(unittest.makeSuite(ResilienceTests))
        
        # Run tests
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        
        # Report results
        if result.wasSuccessful():
            logger.info("✓ All unit tests passed")
            return True
        else:
            logger.error(f"✗ Unit tests failed: {len(result.failures)} failures, {len(result.errors)} errors")
            return False
    except Exception as e:
        logger.error(f"Error running unit tests: {str(e)}")
        return False

async def run_resilience_test():
    """Run resilience test with missing API keys."""
    logger.info("=== Running Resilience Test ===")
    try:
        # Import test module
        import test_missing_keys
        
        # Run test
        test_missing_keys.main()
        
        logger.info("✓ Resilience test completed")
        return True
    except Exception as e:
        logger.error(f"Error running resilience test: {str(e)}")
        return False

async def run_integration_test(target):
    """Run integration test with actual scan."""
    logger.info(f"=== Running Integration Test on {target} ===")
    try:
        # Import scanner
        from vulnscanner import main
        
        # Set test arguments
        sys.argv = ["vulnscanner.py", "-t", target, "-s", "basic", "-v"]
        
        # Run scan
        await main()
        
        logger.info("✓ Integration test completed")
        return True
    except Exception as e:
        logger.error(f"Error running integration test: {str(e)}")
        return False

async def main():
    """Main function to run all tests."""
    args = parse_args()
    
    logger.info("Starting AI Vulnerability Scanner Test Suite")
    logger.info(f"Test type: {args.test_type}")
    
    results = {
        'unit': None,
        'resilience': None,
        'integration': None
    }
    
    # Run selected tests
    if args.test_type in ['all', 'unit']:
        results['unit'] = run_unit_tests()
    
    if args.test_type in ['all', 'resilience']:
        results['resilience'] = await run_resilience_test()
    
    if args.test_type in ['all', 'integration'] and not args.skip_api_tests:
        results['integration'] = await run_integration_test(args.target)
    
    # Report overall results
    logger.info("=== Test Results Summary ===")
    for test_type, result in results.items():
        if result is None:
            logger.info(f"{test_type}: Skipped")
        elif result:
            logger.info(f"{test_type}: ✓ Passed")
        else:
            logger.info(f"{test_type}: ✗ Failed")
    
    # Determine overall success
    success = all(result for result in results.values() if result is not None)
    if success:
        logger.info("✓ All tests completed successfully")
        return 0
    else:
        logger.error("✗ Some tests failed")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
