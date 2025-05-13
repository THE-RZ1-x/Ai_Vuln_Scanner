#!/usr/bin/env python3
"""
Web Application Vulnerability Scanner
Copyright (c) 2025 RHAZOUANE SALAH-EDDINE
All rights reserved.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

PROPRIETARY NOTICE:
This software is the confidential and proprietary information of
RHAZOUANE SALAH-EDDINE. You shall not disclose such confidential
information and shall use it only in accordance with the terms
of the license agreement you entered into with RHAZOUANE SALAH-EDDINE.

Author: RHAZOUANE SALAH-EDDINE
Repository: https://github.com/THE-RZ1-x/Ai_Vuln_Scanner
Profile: https://github.com/THE-RZ1-x
Version: 2.0
"""

import asyncio
import aiohttp
import logging
import re
import time
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
            
    async def check_xss_vulnerabilities(self):
        """Check for XSS vulnerabilities in all visited URLs."""
        # This method is called after crawling, so we already have forms tested
        # Additional XSS checks can be implemented here
        for url in self.visited_urls:
            try:
                # Check for DOM-based XSS vulnerabilities
                async with self.session.get(url) as response:
                    text = await response.text()
                    if any(pattern in text.lower() for pattern in [
                        'document.write(',
                        'eval(',
                        'innerHTML',
                        'outerHTML',
                        'document.location',
                        'document.url',
                        'document.referrer',
                        'location.hash',
                        'location.href',
                        'window.name'
                    ]):
                        self._add_vulnerability('DOM XSS', url, 'DOM', 'Medium',
                            'Potential DOM-based XSS vulnerability found',
                            'JavaScript using unsafe DOM methods detected',
                            'Use safe DOM manipulation methods and sanitize user inputs')
            except Exception as e:
                logger.error(f"Error checking DOM XSS on {url}: {str(e)}")
                
    async def check_sql_injection(self):
        """Check for SQL injection vulnerabilities in all visited URLs."""
        # This method is called after crawling, so we already have forms tested
        # Additional SQL injection checks can be implemented here
        for url in self.visited_urls:
            try:
                # Check for time-based blind SQL injection
                sql_time_payloads = [
                    "?id=1' AND (SELECT * FROM (SELECT(SLEEP(0)))a)-- -",
                    "?param=1' AND SLEEP(0)-- -"
                ]
                
                for payload in sql_time_payloads:
                    test_url = urljoin(url, payload)
                    start_time = time.time()
                    async with self.session.get(test_url) as response:
                        await response.text()
                    response_time = time.time() - start_time
                    
                    # If response time is significantly longer, it might be vulnerable
                    if response_time > 5.0:  # 5 seconds threshold
                        self._add_vulnerability('Blind SQL Injection', url, 'time-based', 'Critical',
                            'Potential time-based blind SQL injection vulnerability',
                            f'Response time: {response_time:.2f} seconds with payload: {payload}',
                            'Use parameterized queries and input validation')
            except Exception as e:
                logger.error(f"Error checking blind SQL injection on {url}: {str(e)}")
                
    async def check_open_redirects(self):
        """Check for open redirect vulnerabilities."""
        redirect_payloads = [
            "https://evil.com",
            "//evil.com",
            "/\\evil.com",
            "https:evil.com"
        ]
        
        for url in self.visited_urls:
            parsed = urlparse(url)
            query_params = parsed.query.split('&')
            
            for param in query_params:
                if '=' in param:
                    param_name = param.split('=')[0]
                    for payload in redirect_payloads:
                        test_url = url.replace(param, f"{param_name}={payload}")
                        try:
                            async with self.session.get(test_url, allow_redirects=False) as response:
                                if response.status in (301, 302, 303, 307, 308):
                                    location = response.headers.get('Location', '')
                                    if any(evil in location for evil in ['evil.com', payload]):
                                        self._add_vulnerability('Open Redirect', url, param_name, 'Medium',
                                            f'Open redirect vulnerability found in {param_name} parameter',
                                            f'Redirected to: {location}',
                                            'Implement URL validation and whitelist of allowed domains')
                        except Exception as e:
                            logger.error(f"Error checking open redirect on {url}: {str(e)}")
                            
    async def check_csrf(self):
        """Check for CSRF vulnerabilities."""
        for url in self.visited_urls:
            try:
                async with self.session.get(url) as response:
                    text = await response.text()
                    soup = BeautifulSoup(text, 'html.parser')
                    forms = soup.find_all('form', method=lambda m: m and m.lower() == 'post')
                    
                    for form in forms:
                        # Check if form has CSRF token
                        csrf_tokens = form.find_all(['input', 'meta'], attrs={
                            'name': lambda x: x and any(token in x.lower() for token in [
                                'csrf', 'xsrf', 'token', '_token', 'authenticity'
                            ])
                        })
                        
                        if not csrf_tokens:
                            self._add_vulnerability('CSRF', url, 'form', 'Medium',
                                'Form without CSRF protection',
                                f'POST form action: {form.get("action", "")}',
                                'Implement CSRF tokens for all state-changing operations')
            except Exception as e:
                logger.error(f"Error checking CSRF on {url}: {str(e)}")
                
    async def check_sensitive_data_exposure(self):
        """Check for sensitive data exposure."""
        sensitive_patterns = [
            r'password\s*=\s*["\'][^"\']',
            r'api[_-]?key\s*=\s*["\'][^"\']',
            r'secret\s*=\s*["\'][^"\']',
            r'aws[_-]?key',
            r'aws[_-]?secret',
            r'firebase[_-]?key',
            r'private[_-]?key',
            r'\b(?:[0-9]{4}[- ]?){3}[0-9]{4}\b',  # Credit card pattern
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'  # Email pattern
        ]
        
        for url in self.visited_urls:
            try:
                async with self.session.get(url) as response:
                    text = await response.text()
                    
                    # Check for sensitive data in response
                    for pattern in sensitive_patterns:
                        matches = re.finditer(pattern, text, re.IGNORECASE)
                        for match in matches:
                            context = text[max(0, match.start() - 20):min(len(text), match.end() + 20)]
                            self._add_vulnerability('Sensitive Data Exposure', url, pattern, 'High',
                                f'Potential sensitive data found matching pattern: {pattern}',
                                f'Context: ...{context}...',
                                'Remove sensitive data from client-side code and responses')
                                
                    # Check for sensitive information in HTML comments
                    soup = BeautifulSoup(text, 'html.parser')
                    comments = soup.find_all(string=lambda text: isinstance(text, str) and text.strip().startswith('<!--'))
                    
                    for comment in comments:
                        for pattern in sensitive_patterns:
                            if re.search(pattern, comment, re.IGNORECASE):
                                self._add_vulnerability('Sensitive Data in Comments', url, 'comment', 'Medium',
                                    'Sensitive data found in HTML comment',
                                    f'Comment contains pattern: {pattern}',
                                    'Remove sensitive information from HTML comments')
            except Exception as e:
                logger.error(f"Error checking sensitive data exposure on {url}: {str(e)}")
            
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
