#!/usr/bin/env python3
"""
Web Application Vulnerability Scanner Module
Part of AI-Powered Vulnerability Scanner
"""

import asyncio
import aiohttp
import logging
import re
from typing import Dict, List, Set
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

@dataclass
class WebVulnerability:
    type: str
    url: str
    parameter: str
    severity: str
    description: str
    proof: str
    remediation: str

class WebScanner:
    def __init__(self, max_depth: int = 3, max_urls: int = 100):
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.visited_urls: Set[str] = set()
        self.found_vulnerabilities: List[WebVulnerability] = []
        self.session = None
        
    async def setup(self):
        """Initialize the aiohttp session."""
        if not self.session:
            self.session = aiohttp.ClientSession()
            
    async def cleanup(self):
        """Clean up resources."""
        if self.session:
            await self.session.close()
            
    async def scan_web_application(self, base_url: str) -> List[WebVulnerability]:
        """Main entry point for web application scanning."""
        await self.setup()
        try:
            # Crawl the website and collect URLs
            await self.crawl(base_url)
            
            # Run various security checks
            await asyncio.gather(
                self.check_xss_vulnerabilities(),
                self.check_sql_injection(),
                self.check_open_redirects(),
                self.check_csrf(),
                self.check_security_headers(),
                self.check_sensitive_data_exposure()
            )
            
            return self.found_vulnerabilities
        finally:
            await self.cleanup()
            
    async def crawl(self, url: str, depth: int = 0):
        """Crawl the website to discover URLs."""
        if depth > self.max_depth or len(self.visited_urls) >= self.max_urls or url in self.visited_urls:
            return
            
        self.visited_urls.add(url)
        
        try:
            async with self.session.get(url) as response:
                if 'text/html' not in response.headers.get('content-type', ''):
                    return
                    
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                
                # Extract and process forms
                await self.process_forms(url, soup)
                
                # Find all links and continue crawling
                links = soup.find_all('a', href=True)
                tasks = []
                for link in links:
                    href = link['href']
                    absolute_url = urljoin(url, href)
                    if self._should_crawl(absolute_url):
                        tasks.append(self.crawl(absolute_url, depth + 1))
                        
                await asyncio.gather(*tasks)
                
        except Exception as e:
            logger.error(f"Error crawling {url}: {str(e)}")
            
    async def process_forms(self, url: str, soup: BeautifulSoup):
        """Process and test forms for vulnerabilities."""
        forms = soup.find_all('form')
        for form in forms:
            # Extract form details
            action = urljoin(url, form.get('action', ''))
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            
            # Test form inputs for vulnerabilities
            await asyncio.gather(
                self.test_xss(action, method, inputs),
                self.test_sql_injection(action, method, inputs)
            )
            
    async def test_xss(self, action: str, method: str, inputs: List):
        """Test for XSS vulnerabilities in form inputs."""
        xss_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            '${alert(1)}',
            'javascript:alert(1)'
        ]
        
        for input_field in inputs:
            if input_field.get('type') in ['text', 'search', 'url', 'email']:
                name = input_field.get('name', '')
                for payload in xss_payloads:
                    try:
                        data = {name: payload}
                        if method == 'get':
                            async with self.session.get(action, params=data) as response:
                                text = await response.text()
                                if payload in text:
                                    self._add_vulnerability('XSS', action, name, 'High',
                                        f'Reflected XSS found in {name} parameter',
                                        f'Payload: {payload}',
                                        'Implement proper input validation and output encoding')
                        else:
                            async with self.session.post(action, data=data) as response:
                                text = await response.text()
                                if payload in text:
                                    self._add_vulnerability('XSS', action, name, 'High',
                                        f'Reflected XSS found in {name} parameter',
                                        f'Payload: {payload}',
                                        'Implement proper input validation and output encoding')
                    except Exception as e:
                        logger.error(f"Error testing XSS on {action}: {str(e)}")
                        
    async def test_sql_injection(self, action: str, method: str, inputs: List):
        """Test for SQL injection vulnerabilities in form inputs."""
        sql_payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "admin' --",
            "' OR 1=1--",
            "')) OR 1=1--"
        ]
        
        for input_field in inputs:
            if input_field.get('type') in ['text', 'search']:
                name = input_field.get('name', '')
                for payload in sql_payloads:
                    try:
                        data = {name: payload}
                        if method == 'get':
                            async with self.session.get(action, params=data) as response:
                                text = await response.text()
                                if self._detect_sql_error(text):
                                    self._add_vulnerability('SQL Injection', action, name, 'Critical',
                                        f'Possible SQL injection found in {name} parameter',
                                        f'Payload: {payload}',
                                        'Use parameterized queries and input validation')
                        else:
                            async with self.session.post(action, data=data) as response:
                                text = await response.text()
                                if self._detect_sql_error(text):
                                    self._add_vulnerability('SQL Injection', action, name, 'Critical',
                                        f'Possible SQL injection found in {name} parameter',
                                        f'Payload: {payload}',
                                        'Use parameterized queries and input validation')
                    except Exception as e:
                        logger.error(f"Error testing SQL injection on {action}: {str(e)}")
                        
    async def check_security_headers(self):
        """Check for missing security headers."""
        important_headers = {
            'X-Frame-Options': 'Missing X-Frame-Options header - potential clickjacking risk',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header - MIME-sniffing risk',
            'Strict-Transport-Security': 'Missing HSTS header - protocol downgrade risk',
            'Content-Security-Policy': 'Missing Content-Security-Policy header - various injection risks'
        }
        
        for url in self.visited_urls:
            try:
                async with self.session.get(url) as response:
                    headers = response.headers
                    for header, message in important_headers.items():
                        if header not in headers:
                            self._add_vulnerability('Missing Security Header', url, header, 'Medium',
                                message, f'Header {header} not found in response',
                                f'Add the {header} header to server responses')
            except Exception as e:
                logger.error(f"Error checking security headers for {url}: {str(e)}")
                
    def _detect_sql_error(self, response_text: str) -> bool:
        """Detect SQL error messages in response."""
        sql_errors = [
            "SQL syntax.*MySQL",
            "Warning.*mysql_.*",
            "valid MySQL result",
            "MySqlClient\.",
            "PostgreSQL.*ERROR",
            "Warning.*pg_.*",
            "valid PostgreSQL result",
            "ORA-[0-9][0-9][0-9][0-9]",
            "Microsoft SQL Server",
            "SQLServer JDBC Driver"
        ]
        
        for error in sql_errors:
            if re.search(error, response_text, re.IGNORECASE):
                return True
        return False
        
    def _add_vulnerability(self, type: str, url: str, parameter: str, severity: str,
                         description: str, proof: str, remediation: str):
        """Add a found vulnerability to the list."""
        vuln = WebVulnerability(type, url, parameter, severity, description, proof, remediation)
        self.found_vulnerabilities.append(vuln)
        
    def _should_crawl(self, url: str) -> bool:
        """Determine if a URL should be crawled."""
        parsed = urlparse(url)
        return (
            url.startswith(tuple(self.visited_urls)[0]) and  # Same domain
            not any(ext in parsed.path for ext in ['.pdf', '.jpg', '.png', '.gif']) and  # Skip binary
            len(self.visited_urls) < self.max_urls  # Respect max URLs
        )
