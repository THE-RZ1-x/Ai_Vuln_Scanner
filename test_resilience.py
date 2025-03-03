#!/usr/bin/env python3
"""
Test script for verifying the resilience of the vulnerability scanner.
This script tests the scanner's ability to handle missing API keys gracefully.
"""

import os
import sys
import asyncio
import unittest
from unittest.mock import patch, MagicMock
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Import scanner modules
try:
    from vulnscanner import (
        init_vulners_api, 
        init_gemini, 
        init_openai, 
        init_local_ml_model,
        AISecurityAnalyzer,
        analyze_service_offline,
        VulnerabilityScanner
    )
except ImportError as e:
    logger.error(f"Error importing scanner modules: {e}")
    sys.exit(1)

class ResilienceTests(unittest.TestCase):
    """Test cases for scanner resilience."""

    def setUp(self):
        """Set up test environment."""
        # Save original environment variables
        self.original_env = os.environ.copy()
        
        # Create test service data
        self.test_service = {
            'port': 80,
            'protocol': 'tcp',
            'name': 'http',
            'product': 'nginx',
            'version': '1.18.0',
            'ip': '127.0.0.1'
        }

    def tearDown(self):
        """Restore original environment."""
        # Restore original environment variables
        os.environ.clear()
        os.environ.update(self.original_env)

    def test_vulners_api_resilience(self):
        """Test that Vulners API initialization handles missing API key."""
        # Remove API key from environment
        if 'VULNERS_API_KEY' in os.environ:
            del os.environ['VULNERS_API_KEY']
            
        # Initialize Vulners API
        api = init_vulners_api()
        
        # Should return None without raising an exception
        self.assertIsNone(api)
        logger.info("✓ Vulners API initialization handles missing API key")

    def test_gemini_api_resilience(self):
        """Test that Gemini API initialization handles missing API key."""
        # Remove API key from environment
        if 'GEMINI_API_KEY' in os.environ:
            del os.environ['GEMINI_API_KEY']
            
        # Initialize Gemini API
        api = init_gemini()
        
        # Should return None without raising an exception
        self.assertIsNone(api)
        logger.info("✓ Gemini API initialization handles missing API key")

    def test_openai_api_resilience(self):
        """Test that OpenAI API initialization handles missing API key."""
        # Remove API key from environment
        if 'OPENAI_API_KEY' in os.environ:
            del os.environ['OPENAI_API_KEY']
            
        # Initialize OpenAI API
        api = init_openai()
        
        # Should return None without raising an exception
        self.assertIsNone(api)
        logger.info("✓ OpenAI API initialization handles missing API key")

    def test_offline_analysis(self):
        """Test offline analysis functionality."""
        # Test with HTTP service
        http_service = self.test_service.copy()
        http_service['service'] = 'http'
        
        result = analyze_service_offline(http_service)
        
        # Verify result structure
        self.assertIn('vulnerabilities', result)
        self.assertIn('recommendations', result)
        self.assertIn('details', result)
        self.assertIn('risk', result)
        
        # Verify content
        self.assertTrue(len(result['vulnerabilities']) > 0)
        self.assertTrue(len(result['recommendations']) > 0)
        
        logger.info("✓ Offline analysis provides detailed results")

    def test_ai_analyzer_no_apis(self):
        """Test AISecurityAnalyzer with no available APIs."""
        # Remove all API keys
        for key in ['VULNERS_API_KEY', 'GEMINI_API_KEY', 'OPENAI_API_KEY']:
            if key in os.environ:
                del os.environ[key]
        
        # Create analyzer
        analyzer = AISecurityAnalyzer()
        
        # Should have no available models
        self.assertEqual(len(analyzer.available_models), 0)
        
        # Should still be able to analyze a service
        async def test_analyze():
            result = await analyzer.analyze_service(self.test_service)
            return result
            
        result = asyncio.run(test_analyze())
        
        # Should return offline analysis results
        self.assertIn('vulnerabilities', result)
        self.assertIn('recommendations', result)
        
        logger.info("✓ AISecurityAnalyzer falls back to offline analysis when no APIs are available")

    @patch('vulnscanner.init_vulners_api')
    @patch('vulnscanner.init_gemini')
    @patch('vulnscanner.init_openai')
    @patch('vulnscanner.init_local_ml_model')
    async def test_scanner_resilience(self, mock_local_ml, mock_openai, mock_gemini, mock_vulners):
        """Test that VulnerabilityScanner handles missing APIs."""
        # Mock all API initializations to return None
        mock_vulners.return_value = None
        mock_gemini.return_value = None
        mock_openai.return_value = None
        mock_local_ml.return_value = None
        
        # Create scanner
        scanner = VulnerabilityScanner()
        
        # Mock _scan_network to return test data
        scanner._scan_network = MagicMock()
        scanner._scan_network.return_value = {
            'target': '127.0.0.1',
            'services': {
                '80/tcp': self.test_service
            }
        }
        
        # Mock _assess_risk
        scanner._assess_risk = MagicMock()
        scanner._assess_risk.return_value = "Medium"
        
        # Run scan
        result = await scanner.scan('127.0.0.1', 'basic')
        
        # Verify scan completed
        self.assertIsNotNone(result)
        self.assertIn('services', result)
        
        logger.info("✓ VulnerabilityScanner completes scan with missing APIs")

def run_tests():
    """Run all resilience tests."""
    logger.info("Starting resilience tests...")
    
    # Run synchronous tests
    suite = unittest.TestLoader().loadTestsFromTestCase(ResilienceTests)
    unittest.TextTestRunner(verbosity=2).run(suite)
    
    # Run async test separately
    async def run_async_test():
        test = ResilienceTests()
        test.setUp()
        try:
            await test.test_scanner_resilience()
        finally:
            test.tearDown()
    
    asyncio.run(run_async_test())
    
    logger.info("Resilience tests completed")

if __name__ == "__main__":
    run_tests()
