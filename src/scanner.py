#!/usr/bin/env python3
"""
AI-Powered Vulnerability Scanner
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
"""
AI-Powered Vulnerability Scanner
Developed by RZ1 (https://github.com/THE-RZ1-x)
Repository: https://github.com/THE-RZ1-x/Ai_Vuln_Scanner

A sophisticated vulnerability scanner that uses AI to analyze and detect security vulnerabilities
in network services and systems.
"""


import os
import re
import sys
import json
import time
import socket
import logging
import argparse
import ipaddress
import traceback
from datetime import datetime
from typing import Dict, List, Optional, Union, Any, Tuple

# Initialize logging first
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    encoding='utf-8'
)
logger = logging.getLogger(__name__)

# Declare module-level variables for imports
JINJA_AVAILABLE = False
PLOTLY_AVAILABLE = False
MATPLOTLIB_AVAILABLE = False
NETWORKX_AVAILABLE = False

# Required modules
try:
    import nmap
except ImportError:
    logger.error("nmap module not found. Please install python-nmap: pip install python-nmap")
    sys.exit(1)

try:
    import requests
    import aiohttp
    import asyncio
    from tqdm import tqdm
    from dotenv import load_dotenv
    from bs4 import BeautifulSoup
except ImportError as e:
    logger.error(f"Required module not found: {e}. Please install missing dependencies.")
    traceback.print_exc()
    sys.exit(1)

# Optional modules
try:
    import shodan
except ImportError:
    logger.warning("shodan module not found. External reconnaissance will be limited.")
    shodan = None

try:
    import vulners
except ImportError:
    logger.warning("vulners module not found. Vulnerability database lookups will be limited.")
    vulners = None

try:
    from openai import OpenAI, AsyncOpenAI
except ImportError:
    logger.warning("openai module not found. OpenAI analysis will be disabled.")
    OpenAI = None
    AsyncOpenAI = None

# Load environment variables
load_dotenv()

# Try importing scanner components
try:
    from web_scanner import WebScanner, WebVulnerability
    from report_generator import (
        ReportGenerator, 
        ReportData, 
        JINJA_AVAILABLE,
        PLOTLY_AVAILABLE,
        MATPLOTLIB_AVAILABLE,
        NETWORKX_AVAILABLE
    )
    from container_scanner import ContainerScanner, ContainerScanResult, ContainerVulnerability
    from cloud_scanner import CloudScanner, CloudScanResult
    from exploit_generator import ExploitGenerator
except ImportError as e:
    logger.warning(f"Optional scanner component not found: {e}. Some functionality will be limited.")
    
# Define placeholder classes and variables if imports failed
if 'WebScanner' not in globals():
    class WebScanner:
        def __init__(self): pass
if 'ContainerScanner' not in globals():
    class ContainerScanner:
        def __init__(self): pass
if 'CloudScanner' not in globals():
    class CloudScanner:
        def __init__(self): pass
if 'ReportGenerator' not in globals():
    class ReportGenerator:
        def __init__(self): pass
if 'ExploitGenerator' not in globals():
    class ExploitGenerator:
        def __init__(self): pass
if 'JINJA_AVAILABLE' not in globals():
    JINJA_AVAILABLE = False
if 'PLOTLY_AVAILABLE' not in globals():
    PLOTLY_AVAILABLE = False
if 'MATPLOTLIB_AVAILABLE' not in globals():
    MATPLOTLIB_AVAILABLE = False
if 'NETWORKX_AVAILABLE' not in globals():
    NETWORKX_AVAILABLE = False

class CloudVulnerability:
    """Class representing a vulnerability found through cloud security scanning."""
    def __init__(self, name: str, description: str, severity: str, recommendations: List[str]):
        self.name = name
        self.description = description
        self.severity = severity
        self.recommendations = recommendations

    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'description': self.description,
            'severity': self.severity,
            'recommendations': self.recommendations
        }

def analyze_service_offline(service_info: dict) -> list:
    """Analyze a service without requiring external APIs."""
    recommendations = []
    
    # Basic service checks
    if not service_info.get('product'):
        recommendations.append("Service identification failed - manual investigation recommended")
        return recommendations
    
    # Version checks
    if service_info.get('version'):
        recommendations.append(f"Update {service_info.get('product')} to the latest version")
    
    # Port-specific recommendations
    port = service_info.get('port', 0)
    if port < 1024:
        recommendations.append(f"Service running on privileged port {port}. Consider running as non-root if possible.")
    
    # Protocol recommendations
    if service_info.get('protocol') == 'tcp':
        recommendations.append("Ensure firewall rules restrict access to necessary IPs only")
    
    # SSL/TLS checks
    if 'http' in service_info.get('name', '').lower() or 'https' in service_info.get('name', '').lower():
        recommendations.extend([
            "Verify SSL/TLS configuration and certificate validity",
            "Enable HTTP Strict Transport Security (HSTS)",
            "Implement proper Content Security Policy (CSP)"
        ])
    
    # Database recommendations
    if any(db in service_info.get('name', '').lower() for db in ['mysql', 'postgresql', 'mongodb', 'redis']):
        recommendations.extend([
            "Ensure strong authentication is enabled",
            "Regularly backup database content",
            "Monitor for unusual access patterns"
        ])
    
    # Remote access recommendations
    if any(remote in service_info.get('name', '').lower() for remote in ['ssh', 'rdp', 'vnc']):
        recommendations.extend([
            "Use strong authentication methods",
            "Implement fail2ban or similar brute-force protection",
            "Restrict access to specific IP ranges"
        ])
    
    return recommendations

# Parse command line arguments
parser = argparse.ArgumentParser(description='AI-powered vulnerability scanner')
parser.add_argument('-t', '--target', required=True, help='Target IP address, hostname, container image, or cloud provider')
parser.add_argument('-s', '--scan-type', choices=['basic', 'comprehensive', 'container', 'cloud'], default='basic',
                  help='Type of scan to perform')
parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
parser.add_argument('-o', '--output', help='Output file name (without extension)')
parser.add_argument('--container', action='store_true', help='Treat target as a container image')
parser.add_argument('--cloud-providers', nargs='+', choices=['aws', 'azure', 'gcp'],
                  help='Cloud providers to scan when using cloud scan type')
parser.add_argument('--no-open', action='store_true', help='Do not open the report automatically')
args = parser.parse_args()

# Configure logging based on verbosity
if args.verbose:
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        encoding='utf-8'
    )
else:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        encoding='utf-8'
    )

logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Initialize global scanner
scanner = None
ai_analyzer = None

def init_scanner():
    """Initialize the vulnerability scanner with all components."""
    try:
        # Initialize scanner components
        scanner = VulnerabilityScanner()
        
        # Initialize APIs
        scanner.initialize_apis()
        
        # Initialize analyzers
        scanner.ai_analyzer = AISecurityAnalyzer()
        
        # Initialize scanners
        scanner.web_scanner = WebScanner()
        scanner.container_scanner = ContainerScanner()
        scanner.cloud_scanner = CloudScanner()
        
        # Initialize report generator
        scanner.report_generator = ReportGenerator()
        
        # Initialize exploit generator
        scanner.exploit_generator = ExploitGenerator()
        
        return scanner
    except Exception as e:
        logger.error(f"Error initializing scanner: {str(e)}")
        # Still return a partially initialized scanner to continue with limited functionality
        return VulnerabilityScanner()

class VulnerabilityScanner:
    def __init__(self):
        """Initialize scanner components."""
        self.web_scanner = WebScanner()
        self.container_scanner = ContainerScanner()
        self.cloud_scanner = CloudScanner()
        self.report_generator = ReportGenerator()
        self.exploit_generator = ExploitGenerator()
        self.shodan_api = None  # Initialize as None
        self.vulners_api = None  # Initialize as None
        self.available_models = []
        self.gemini_model = None
        self.openai_model = None
        self.scan_start_time = None
        self.initialize_apis()
        
    def _get_basic_recommendations(self, service_name: str, product: str, version: str) -> str:
        """Get basic security recommendations based on service, product and version."""
        try:
            base_analysis = f"Service: {service_name}"
            if product:
                base_analysis += f" (Product: {product}"
                if version:
                    base_analysis += f", Version: {version}"
                base_analysis += ")"
            
            # Default recommendations based on common services
            recommendations = {
                'http': "Web server detected. Ensure proper access controls, implement HTTPS, regularly update server software, and scan for web vulnerabilities.",
                'https': "Secure web server detected. Verify TLS configuration, maintain valid certificates, and regularly scan for web vulnerabilities.",
                'ssh': "SSH server detected. Use key-based authentication, disable root login, implement fail2ban, and keep the SSH server updated.",
                'ftp': "FTP service detected. Consider replacing with SFTP, disable anonymous login, use strong authentication, and restrict access.",
                'telnet': "Telnet service detected. CRITICAL: Telnet transmits data in plaintext. Replace with SSH immediately.",
                'smb': "SMB file sharing detected. Disable SMBv1, use strong authentication, implement proper access controls, and keep updated.",
                'rdp': "Remote Desktop service detected. Implement Network Level Authentication, use strong passwords, limit access, and keep updated.",
                'mysql': "MySQL database detected. Use strong authentication, limit network access, regularly update, and implement proper user privileges.",
                'mssql': "Microsoft SQL Server detected. Implement strong authentication, patch regularly, and limit network access.",
                'mongodb': "MongoDB database detected. Disable direct internet access, implement authentication, and keep updated.",
                'redis': "Redis database detected. Configure authentication, disable direct internet access, and keep updated.",
                'dns': "DNS server detected. Ensure proper configuration, implement DNSSEC if possible, and regularly update.",
                'ntp': "NTP service detected. Configure to prevent amplification attacks and keep updated.",
                'smtp': "Mail server detected. Configure SPF, DKIM, and DMARC, disable open relay, and keep updated.",
                'imap': "IMAP mail service detected. Enforce encryption, implement strong authentication, and keep updated.",
                'pop3': "POP3 mail service detected. Enforce encryption, implement strong authentication, and keep updated."
            }
            
            # Default recommendation if service not in our list
            default_rec = "This service should be reviewed to ensure it's necessary and properly secured. Implement network access controls, strong authentication, and regular updates."
            
            # Add service-specific recommendations if available
            service_lower = service_name.lower()
            for key, recommendation in recommendations.items():
                if key in service_lower:
                    base_analysis += f"\n\nRecommendations: {recommendation}"
                    return base_analysis
            
            # If no specific match found, provide default recommendations
            base_analysis += f"\n\nRecommendations: {default_rec}"
            
            return base_analysis
            
        except Exception as e:
            logger.error(f"Error generating basic recommendations: {str(e)}")
            return f"Analysis unavailable due to an error. Service: {service_name}"

    def _get_enhanced_recommendations(self, service_name: str, product: str, version: str) -> str:
        """Get enhanced recommendations based on service, product and version."""
        try:
            if not product:
                return ""  # No enhanced analysis without product info
                
            base_analysis = f"Enhanced analysis for {service_name}"
            if product:
                base_analysis += f" (Product: {product}"
                if version:
                    base_analysis += f", Version: {version}"
                base_analysis += ")"
                
            # Product-specific recommendations
            product_lower = product.lower()
            
            # Apache web server
            if "apache" in product_lower and ("http" in service_name.lower() or "web" in service_name.lower()):
                return base_analysis + "\n\nApache Web Server detected. Recommendations:\n" + \
                       "- Disable directory listing\n" + \
                       "- Remove unnecessary modules\n" + \
                       "- Configure proper access controls\n" + \
                       "- Implement mod_security for WAF capabilities\n" + \
                       "- Keep updated to patch security vulnerabilities\n" + \
                       "- Implement proper TLS configuration"
                       
            # nginx web server
            elif "nginx" in product_lower:
                return base_analysis + "\n\nNginx Web Server detected. Recommendations:\n" + \
                       "- Disable server tokens\n" + \
                       "- Implement rate limiting\n" + \
                       "- Configure proper access controls\n" + \
                       "- Keep updated to patch security vulnerabilities\n" + \
                       "- Implement proper TLS configuration"
                       
            # IIS web server
            elif "iis" in product_lower or "internet information services" in product_lower:
                return base_analysis + "\n\nMicrosoft IIS Web Server detected. Recommendations:\n" + \
                       "- Remove unnecessary features\n" + \
                       "- Implement proper authentication\n" + \
                       "- Configure URLScan or similar security filters\n" + \
                       "- Keep updated with security patches\n" + \
                       "- Implement proper TLS configuration"
                       
            # OpenSSH
            elif "openssh" in product_lower:
                return base_analysis + "\n\nOpenSSH Server detected. Recommendations:\n" + \
                       "- Disable password authentication, use key-based only\n" + \
                       "- Disable root login\n" + \
                       "- Use strong ciphers and key exchange algorithms\n" + \
                       "- Implement fail2ban to prevent brute force\n" + \
                       "- Keep updated to patch security vulnerabilities"
                       
            # MySQL
            elif "mysql" in product_lower:
                return base_analysis + "\n\nMySQL Database Server detected. Recommendations:\n" + \
                       "- Remove test databases and anonymous users\n" + \
                       "- Implement strong password policy\n" + \
                       "- Use principle of least privilege for user accounts\n" + \
                       "- Enable encrypted connections\n" + \
                       "- Regularly audit user privileges\n" + \
                       "- Keep updated to patch security vulnerabilities"
                       
            # Microsoft SQL Server
            elif "microsoft sql server" in product_lower or "mssql" in product_lower:
                return base_analysis + "\n\nMicrosoft SQL Server detected. Recommendations:\n" + \
                       "- Use Windows Authentication when possible\n" + \
                       "- Implement strong password policy\n" + \
                       "- Enable encryption for sensitive data\n" + \
                       "- Apply principle of least privilege\n" + \
                       "- Keep updated with security patches\n" + \
                       "- Regular security audits"
                       
            # Exchange Server
            elif "exchange" in product_lower:
                return base_analysis + "\n\nMicrosoft Exchange Server detected. Recommendations:\n" + \
                       "- Keep updated with the latest security patches\n" + \
                       "- Enable MFA for admin accounts\n" + \
                       "- Implement proper email filtering\n" + \
                       "- Configure SPF, DKIM, and DMARC\n" + \
                       "- Regular security audits\n" + \
                       "- Monitor for unusual activity"
                       
            # VMware
            elif "vmware" in product_lower:
                return base_analysis + "\n\nVMware product detected. Recommendations:\n" + \
                       "- Keep hypervisor and management interfaces updated\n" + \
                       "- Restrict management interface access\n" + \
                       "- Implement strong authentication\n" + \
                       "- Segment management network\n" + \
                       "- Monitor for unusual activity"
            
            # No specific enhanced recommendation available
            return ""
            
        except Exception as e:
            logger.error(f"Error generating enhanced recommendations: {str(e)}")
            return ""
        
    async def scan(self, target: str, scan_type: str = 'basic') -> dict:
        """Perform vulnerability scan on target."""
        try:
            start_time = time.time()
            
            # Validate target
            if not self._validate_target(target):
                raise ValueError(f"Invalid target: {target}")
                
            # Determine scan type and run appropriate scan
            if scan_type == 'container':
                results = await self._scan_container(target)
            elif scan_type == 'cloud':
                results = await self._scan_cloud(target)
            else:
                results = await self._scan_network(target, scan_type)
                
            # Generate exploits for detected vulnerabilities
            if results.get('vulnerabilities'):
                await self._generate_exploits(results['vulnerabilities'])
                
            # Calculate scan duration
            results['scan_duration'] = time.time() - start_time
            
            return results
            
        except Exception as e:
            logger.error(f"Scan error: {str(e)}")
            raise

    async def _scan_network(self, target: str, scan_type: str = 'basic') -> dict:
        """Perform network scan on target."""
        try:
            # Run nmap scan with correct path
            nm = nmap.PortScanner(nmap_search_path=('C:\\Program Files (x86)\\Nmap',))
            scan_args = '-sV -sC' if scan_type == 'comprehensive' else '-sV'
            
            logger.info(f"Running nmap scan with arguments: {scan_args}")
            scan_results = await asyncio.to_thread(nm.scan, target, arguments=scan_args)
            
            # Extract service information
            services = {}
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        service = nm[host][proto][port]
                        services[port] = {
                            'port': port,
                            'protocol': proto,
                            'state': service.get('state'),
                            'service': service.get('name'),
                            'product': service.get('product'),
                            'version': service.get('version'),
                            'extrainfo': service.get('extrainfo')
                        }
            
            # Analyze each service
            analysis_results = []
            for port, service in services.items():
                try:
                    service_analysis = await self.analyze_service(service)
                    analysis_results.append({
                        'service': service,
                        'analysis': service_analysis
                    })
                except Exception as e:
                    logger.error(f"Error analyzing service on port {port}: {str(e)}")
                    analysis_results.append({
                        'service': service,
                        'analysis': [{
                            'source': 'Error',
                            'analysis': f"Analysis failed: {str(e)}",
                            'confidence': 'none'
                        }]
                    })
            
            # Get additional host information
            host_info = {}
            if self.shodan_api:
                try:
                    host_info = await asyncio.to_thread(get_shodan_info, target)
                except Exception as e:
                    logger.warning(f"Error getting Shodan info: {str(e)}")
            
            # Assess risk level
            risk_level = self._assess_risk(services)
            
            return {
                'target': target,
                'scan_type': scan_type,
                'timestamp': datetime.now().isoformat(),
                'services': services,
                'analysis': analysis_results,
                'host_info': host_info,
                'risk_level': risk_level,
                'status': 'completed'
            }
            
        except Exception as e:
            logger.error(f"Network scan error: {str(e)}")
            logger.debug(f"Network scan exception details: {traceback.format_exc()}")
            return {
                'error': str(e),
                'status': 'failed',
                'timestamp': datetime.now().isoformat(),
                'target': target,
                'scan_type': scan_type
            }

    async def _generate_exploits(self, vulnerabilities: List[Dict]):
        """Generate exploits for detected vulnerabilities."""
        try:
            for vuln in vulnerabilities:
                if self._should_generate_exploit(vuln):
                    exploit_path = await self.exploit_generator.generate_exploit(vuln)
                    if exploit_path:
                        # Add exploit path to vulnerability info
                        vuln['exploit_path'] = exploit_path
                        logger.info(f"Generated exploit for {vuln.get('type')}: {exploit_path}")
                        
        except Exception as e:
            logger.error(f"Error generating exploits: {str(e)}")

    def _should_generate_exploit(self, vulnerability: Dict) -> bool:
        """Determine if exploit should be generated for this vulnerability."""
        # Only generate exploits for high-risk vulnerabilities with known patterns
        if vulnerability.get('severity', '').lower() in ['critical', 'high']:
            exploitable_types = [
                'sql injection',
                'command injection',
                'remote code execution',
                'buffer overflow',
                'cross-site scripting',
                'path traversal',
                'file inclusion'
            ]
            return any(vuln_type.lower() in vulnerability.get('type', '').lower() 
                      for vuln_type in exploitable_types)
        return False

    def _get_scan_options(self, scan_type: str) -> str:
        """Get nmap scan options based on scan type."""
        options = {
            'basic': '-sV -sC -O --version-intensity 5',
            'full': '-sV -sC -O -p- -A --version-intensity 7',
            'stealth': '-sS -sV -O -T2 --version-intensity 3'
        }
        return options.get(scan_type, options['basic'])

    def _generate_recommendations(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Generate security recommendations based on vulnerabilities."""
        recommendations = []
        
        # Group vulnerabilities by severity
        severity_groups = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }
        
        for vuln in vulnerabilities:
            severity = self._determine_severity(vuln)
            if severity in severity_groups:
                severity_groups[severity].append(vuln)
        
        # Generate recommendations for each severity group
        for severity, vulns in severity_groups.items():
            if vulns:
                recommendations.append({
                    'severity': severity,
                    'count': len(vulns),
                    'summary': f"Found {len(vulns)} {severity} severity issues",
                    'actions': self._get_actions_for_severity(severity, vulns)
                })
        
        return recommendations

    def _determine_severity(self, vuln) -> str:
        """Determine the severity of a vulnerability."""
        try:
            # Handle dictionary input
            if isinstance(vuln, dict):
                if 'cvss' in vuln:
                    score = float(vuln['cvss'])
                elif 'severity' in vuln:
                    score = float(vuln['severity'])
                else:
                    return 'unknown'
            # Handle numeric input
            elif isinstance(vuln, (int, float)):
                score = float(vuln)
            # Handle string input
            elif isinstance(vuln, str):
                # Default for strings
                return 'medium'
            else:
                return 'unknown'
                
            # Determine severity based on score
            if score >= 9.0:
                return 'critical'
            elif score >= 7.0:
                return 'high'
            elif score >= 4.0:
                return 'medium'
            else:
                return 'low'
        except Exception as e:
            logger.debug(f"Error determining severity: {str(e)}")
            return 'unknown'

    def _get_actions_for_severity(self, severity: str, vulns: List[Dict]) -> List[str]:
        """Get recommended actions based on severity and vulnerabilities."""
        actions = []
        
        if severity == 'critical':
            actions.append("Immediate patching required")
            actions.append("Consider taking affected systems offline until patched")
            actions.append("Review and update security controls")
        elif severity == 'high':
            actions.append("Schedule urgent patching")
            actions.append("Implement additional security controls")
            actions.append("Monitor affected systems closely")
        elif severity == 'medium':
            actions.append("Plan for patching in next maintenance window")
            actions.append("Review security configurations")
        else:
            actions.append("Address during regular maintenance")
            actions.append("Update documentation and monitoring")
        
        # Add specific actions based on vulnerability types
        for vuln in vulns:
            if 'recommendations' in vuln:
                actions.extend(vuln['recommendations'])
        
        return list(set(actions))  # Remove duplicates

    async def analyze_service(self, service_info: Dict) -> List[Dict]:
        """
        Analyze a service using AI models and offline analysis.
        
        Args:
            service_info: Dictionary with service information
            
        Returns:
            List of analysis items with source and analysis text
        """
        vulnerabilities = []
        
        try:
            # Initialize analysis field if it doesn't exist
            if 'analysis' not in service_info:
                service_info['analysis'] = []
            
            # Basic offline analysis
            if 'service' in service_info:
                service_name = service_info.get('service', '')
                product = service_info.get('product', '')
                version = service_info.get('version', '')
                
                # Add basic security recommendations based on the service
                basic_analysis = self._get_basic_recommendations(service_name, product, version)
                if basic_analysis:
                    analysis_item = {
                        'source': 'Offline Analysis',
                        'analysis': basic_analysis,
                        'confidence': 'medium'
                    }
                    vulnerabilities.append(analysis_item)
                    service_info['analysis'].append(analysis_item)
                
                # Add enhanced offline analysis based on service and version if available
                enhanced_analysis = self._get_enhanced_recommendations(service_name, product, version)
                if enhanced_analysis:
                    analysis_item = {
                        'source': 'Enhanced Analysis',
                        'analysis': enhanced_analysis,
                        'confidence': 'medium'
                    }
                    vulnerabilities.append(analysis_item)
                    service_info['analysis'].append(analysis_item)
            
            # Prepare prompt for AI models
            # Build the prompt based on service information
            prompt = f"""Analyze this network service from a security perspective:
            
Service: {service_info.get('service', 'Unknown')}
Port: {service_info.get('port', 'Unknown')}
Protocol: {service_info.get('protocol', 'Unknown')}
Product: {service_info.get('product', 'Unknown')}
Version: {service_info.get('version', 'Unknown')}
State: {service_info.get('state', 'Unknown')}
Extra Info: {service_info.get('extrainfo', 'None')}

Please provide:
1. A risk assessment (Critical, High, Medium, or Low)
2. Key vulnerabilities or security concerns
3. Specific recommendations to secure this service
4. CVEs (if known) related to this version
            """

            # First try Gemini if available
            if 'gemini' in self.available_models and self.gemini_model:
                try:
                    import google.generativeai as genai
                    if not isinstance(self.gemini_model, genai.GenerativeModel):
                        self.gemini_model = genai.GenerativeModel('gemini-1.5-flash')
                    
                    response = self.gemini_model.generate_content(prompt)
                    if hasattr(response, 'text'):
                        ai_result = {
                            'source': 'Gemini AI',
                            'analysis': response.text,
                            'confidence': 'high'
                        }
                        logger.info(f"Gemini analysis completed for service on port {service_info.get('port')}")
                        vulnerabilities.insert(0, ai_result)  # Put AI analysis first
                        
                        # Save the analysis directly to the service_info for report generation
                        service_info['analysis'].append(ai_result)
                        
                        # تعليق على الدالة لتنفيذ كلا النموذجين: Gemini و OpenAI
                        # return vulnerabilities  # Return here to avoid using both AI models
                except Exception as e:
                    logger.warning(f"Gemini analysis failed: {str(e)}")
                    logger.debug(traceback.format_exc())
            
            # Try OpenAI if available and Gemini failed or not available
            if 'openai' in self.available_models and self.openai_model:
                try:
                    from openai import OpenAI, RateLimitError
                    try:
                        response = self.openai_model.chat.completions.create(
                            model="gpt-3.5-turbo",
                            messages=[
                                {"role": "system", "content": "You are a cybersecurity expert specializing in vulnerability analysis."},
                                {"role": "user", "content": prompt}
                            ],
                            max_tokens=800
                        )
                        logger.debug(f"OpenAI response: {response}")
                        if hasattr(response.choices[0], 'message') and hasattr(response.choices[0].message, 'content'):
                            ai_result = {
                                'source': 'OpenAI',
                                'analysis': response.choices[0].message.content,
                                'confidence': 'high'
                            }
                            logger.info(f"OpenAI analysis completed for service on port {service_info.get('port')}")
                            vulnerabilities.insert(0, ai_result)  # Put AI analysis first
                            
                            # Save the analysis directly to the service_info for report generation
                            service_info['analysis'].append(ai_result)
                    except RateLimitError as rate_error:
                        error_msg = str(rate_error)
                        # كتابة سجل تفصيلي لخطأ تجاوز الحصة المخصصة
                        logger.error(f"OpenAI API error detailed: {error_msg}")
                        if "quota" in error_msg or "insufficient_quota" in error_msg:
                            logger.error("OpenAI API quota exceeded. Please check your billing details at https://platform.openai.com/account/billing")
                            quota_error = {
                                'source': 'OpenAI Error',
                                'analysis': "تحليل OpenAI غير متاح: تم تجاوز الحصة المخصصة للمفتاح. يمكن تحديث المفتاح أو زيادة الحصة من خلال الإعدادات في لوحة تحكم OpenAI.",
                                'confidence': 'low'
                            }
                            service_info['analysis'].append(quota_error)
                            # Remove OpenAI from available models to avoid further attempts
                            if 'openai' in self.available_models:
                                self.available_models.remove('openai')
                        else:
                            logger.warning(f"OpenAI rate limit error: {error_msg}")
                except Exception as e:
                    logger.warning(f"OpenAI analysis failed: {str(e)}")
                    logger.error(f"OpenAI general error detailed: {type(e).__name__} - {str(e)}")
                    logger.debug(traceback.format_exc())
        
        except Exception as e:
            logger.error(f"AI security analysis failed: {str(e)}")
            logger.debug(f"AI analysis exception details: {traceback.format_exc()}")
            
            # Add error analysis to ensure we have something
            error_analysis = {
                'source': 'Error',
                'analysis': f"Analysis error: {str(e)}. Please check logs for details.",
                'confidence': 'low'
            }
            vulnerabilities.append(error_analysis)
            service_info['analysis'].append(error_analysis)
        
        return vulnerabilities
            
    def initialize_apis(self):
        """Initialize API clients."""
        try:
            # Initialize Shodan API
            shodan_key = os.getenv('SHODAN_API_KEY')
            if shodan_key and shodan is not None:
                self.shodan_api = shodan.Shodan(shodan_key)
                logger.info("Shodan API initialized successfully")
            else:
                if shodan is None:
                    logger.warning("Shodan module not found")
                else:
                    logger.warning("No Shodan API key found. External reconnaissance will be limited.")
                self.shodan_api = None

            # Initialize Vulners API
            vulners_key = os.getenv('VULNERS_API_KEY')
            if vulners_key and vulners is not None:
                self.vulners_api = vulners.Vulners(api_key=vulners_key)
                logger.info("Vulners API initialized successfully")
            else:
                if vulners is None:
                    logger.warning("Vulners module not found")
                else:
                    logger.warning("No Vulners API key found. Vulnerability database lookups will be limited.")
                self.vulners_api = None

            # Initialize OpenAI
            openai_key = os.getenv('OPENAI_API_KEY')
            if openai_key and OpenAI is not None:
                self.openai_model = OpenAI(api_key=openai_key)
                self.available_models.append('openai')
                logger.info("OpenAI API initialized successfully")
            else:
                if OpenAI is None:
                    logger.warning("OpenAI module not found. Install with: pip install openai")
                else:
                    logger.warning("OpenAI API key not found")
                self.openai_model = None
                
            # Initialize Gemini
            gemini_key = os.getenv('GEMINI_API_KEY')
            if gemini_key:
                try:
                    import google.generativeai as genai
                    genai.configure(api_key=gemini_key)
                    self.gemini_model = genai.GenerativeModel('gemini-1.5-flash')
                    self.available_models.append('gemini')
                    logger.info("Gemini AI initialized successfully")
                except ImportError:
                    logger.warning("Google Generativeai module not found. Install with: pip install google-generativeai")
                except Exception as e:
                    logger.warning(f"Failed to initialize Gemini AI: {str(e)}")
            else:
                logger.warning("Gemini API key not found")
                self.gemini_model = None
            
        except Exception as e:
            logger.error(f"Error initializing APIs: {str(e)}")
            logger.debug(f"API initialization exception details: {traceback.format_exc()}")

    def _assess_risk(self, services: Dict) -> str:
        """Assess overall risk level based on discovered services."""
        try:
            risk_scores = []
            
            for port, service in services.items():
                # Base risk score
                score = 0
                
                # Check if service is running on privileged port
                if isinstance(port, int) and port < 1024:
                    score += 2
                
                # Check service state
                if service.get('state') == 'open':
                    score += 3
                
                # Check known risky services
                service_name = service.get('service', '').lower()
                risky_services = {
                    'http': 3, 'https': 2,
                    'ftp': 4, 'telnet': 5,
                    'ssh': 2, 'rdp': 4,
                    'smb': 4, 'mysql': 3,
                    'mssql': 3, 'oracle': 3,
                    'mongodb': 3, 'redis': 3
                }
                score += risky_services.get(service_name, 1)
                
                # Check version information
                if not service.get('version'):
                    score += 2  # Unknown version is risky
                
                risk_scores.append(score)
        
            # Calculate overall risk
            if not risk_scores:
                return "Low"
                
            avg_score = sum(risk_scores) / len(risk_scores)
            max_score = max(risk_scores)
            
            if max_score >= 8 or avg_score >= 6:
                return "Critical"
            elif max_score >= 6 or avg_score >= 4:
                return "High"
            elif max_score >= 4 or avg_score >= 2:
                return "Medium"
            else:
                return "Low"
            
        except Exception as e:
            logger.error(f"Error in risk assessment: {str(e)}")
            return "Unknown"

    def _validate_target(self, target: str) -> bool:
        """Validate if target is a valid IP address or hostname."""
        try:
            # Check if target is empty
            if not target or not isinstance(target, str):
                logger.error("Target must be a non-empty string")
                return False
                
            # Try validating as IP address first
            try:
                ipaddress.ip_address(target)
                return True
            except ValueError:
                # If not an IP address, validate as hostname
                return validate_hostname(target)

        except Exception as e:
            logger.error(f"Error validating target: {str(e)}")
            return False
            
    async def scan_target(self, target: str, scan_type: str, output_dir: str = None) -> Dict:
        """
        Perform a vulnerability scan on the target.
        
        Args:
            target: IP address or hostname to scan
            scan_type: Type of scan (basic, comprehensive, web, container, cloud)
            output_dir: Directory to save scan results, defaults to 'scans'
            
        Returns:
            Dictionary with scan results
        """
        try:
            # Log scan start
            logger.info(f"Starting {scan_type} scan on {target}")
            self.scan_start_time = time.time()
            
            # Initialize results dict
            results = {
                'target': target,
                'scan_type': scan_type,
                'timestamp': datetime.now().isoformat(),
                'services': {},
                'system_info': {}
            }
            
            # Check for open services with network scan
            services = await self._network_scan(target)
            if not services:
                logger.warning(f"No open services found on {target}")
                results['status'] = 'completed_no_services'
                self._save_results(results, output_dir)
                return results
                
            results['services'] = services
            logger.info(f"Found {len(services)} services on {target}")
            
            # Get system information for more comprehensive scans
            if scan_type in ['comprehensive', 'full']:
                system_info = await self._get_system_info(target)
                results['system_info'] = system_info
            
            # For non-private IPs, try to get Shodan data
            if not self._is_private_ip(target):
                shodan_data = await self._get_shodan_data(target)
                if shodan_data:
                    results['shodan_data'] = shodan_data
            
            # Initialize or reinitialize AI models to ensure they're available
            ai_analyzer = AISecurityAnalyzer()
            ai_analyzer._initialize_models()
            self.gemini_model = ai_analyzer.gemini_model
            self.openai_model = ai_analyzer.openai_model
            self.available_models = ai_analyzer.available_models
            
            # Create analysis tasks for each service
            analysis_results = []
            for port_key, service_info in services.items():
                logger.info(f"Analyzing service on port {port_key}")
                try:
                    # Add AI security analysis for each service
                    vulnerabilities = await self.analyze_service(service_info)
                    analysis_results.append({
                        'service': service_info,
                        'analysis': vulnerabilities
                    })
                    logger.debug(f"Analysis completed for service on port {port_key}")
                except Exception as e:
                    logger.error(f"Error in AI analysis for service on port {port_key}: {str(e)}")
                    logger.error(traceback.format_exc())
                    analysis_results.append({
                        'service': service_info,
                        'analysis': [{
                            'source': 'Error',
                            'analysis': f"Analysis failed: {str(e)}",
                            'confidence': 'low'
                        }]
                    })
            
            results['analysis'] = analysis_results
            
            # Complete any container-specific scanning
            if scan_type == 'container':
                container_results = await self._scan_container(target)
                results.update(container_results)
            
            # Complete any cloud-specific scanning
            if scan_type == 'cloud':
                cloud_results = await self._scan_cloud_resources(target)
                results.update(cloud_results)
                
            # Update scan duration
            results['scan_duration'] = time.time() - self.scan_start_time
            results['status'] = 'completed'
            
            # Add overall risk assessment
            results['risk_level'] = self._assess_risk(results['services'])
            
            # Save results
            self._save_results(results, output_dir)
            
            return results
        except Exception as e:
            logger.error(f"Error scanning target: {str(e)}")
            logger.error(traceback.format_exc())
        return {
                'target': target,
                'scan_type': scan_type,
                'timestamp': datetime.now().isoformat(),
                'status': 'failed',
                'error': str(e)
            }

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP address is private."""
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False
            
    async def _network_scan(self, target: str) -> Dict:
        """Perform network scan on target and return open services."""
        try:
            logger.info(f"Starting network scan on {target}")
            
            # Try running nmap scan
            try:
                nm = nmap.PortScanner()
                scan_args = '-sV'  # Version detection
                logger.debug(f"Running nmap scan with arguments: {scan_args}")
                
                # Run the nmap scan
                scan_results = await asyncio.to_thread(nm.scan, target, arguments=scan_args)
                
                # Extract open services
                services = {}
                for host in nm.all_hosts():
                    for proto in nm[host].all_protocols():
                        ports = nm[host][proto].keys()
                        for port in ports:
                            service = nm[host][proto][port]
                            if service.get('state') == 'open':
                                services[port] = {
                                    'port': port,
                                    'protocol': proto,
                                    'state': service.get('state'),
                                    'service': service.get('name', ''),
                                    'product': service.get('product', ''),
                                    'version': service.get('version', ''),
                                    'extrainfo': service.get('extrainfo', '')
                                }
                
                logger.info(f"Network scan found {len(services)} open services on {target}")
                return services
                
            except Exception as e:
                logger.error(f"Nmap scan failed: {str(e)}")
                logger.warning("Falling back to basic port scanning")
                
                # Fallback to basic socket scanning
                common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 
                                465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 
                                8080, 8443, 27017]
                services = {}
                
                for port in common_ports:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.5)
                        result = sock.connect_ex((target, port))
                        if result == 0:
                            services[port] = {
                                'port': port,
                                'protocol': 'tcp',
                                'state': 'open',
                                'service': socket.getservbyport(port) if port < 1024 else 'unknown',
                                'product': '',
                                'version': '',
                                'extrainfo': ''
                            }
                        sock.close()
                    except:
                        continue
                
                logger.info(f"Basic scan found {len(services)} open services on {target}")
                return services
        
        except Exception as e:
            logger.error(f"Error during network scan: {str(e)}")
            logger.debug(traceback.format_exc())
            return {}
            
    async def _get_system_info(self, target: str) -> Dict:
        """Get system information about the target."""
        # This is a stub function - actual implementation would depend on access and permissions
        return {
            'os': 'Unknown',
            'hostname': target,
            'last_scan': datetime.now().isoformat()
        }
        
    async def _get_shodan_data(self, target: str) -> Dict:
        """Get information about target from Shodan."""
        try:
            if not self.shodan_api:
                logger.warning("Shodan API not initialized")
                return {}
                
            # Check if target is an IP address
            try:
                ipaddress.ip_address(target)
                shodan_info = await asyncio.to_thread(self.shodan_api.host, target)
                return shodan_info
            except ValueError:
                # Not an IP address, try to resolve
                logger.info(f"Resolving hostname {target} for Shodan lookup")
                try:
                    ip = socket.gethostbyname(target)
                    shodan_info = await asyncio.to_thread(self.shodan_api.host, ip)
                    return shodan_info
                except socket.gaierror:
                    logger.warning(f"Could not resolve hostname {target}")
                    return {}
                    
        except Exception as e:
            logger.warning(f"Error getting Shodan data: {str(e)}")
            return {}
            
    def _save_results(self, results: Dict, output_dir: str = None) -> Tuple[str, str]:
        """Save scan results to file."""
        if not output_dir:
            output_dir = "scans"
            
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        # Generate filename based on target and timestamp
        target = results.get('target', 'unknown')
        target = target.replace('.', '_').replace(':', '_')
        timestamp = int(time.time())
        json_filename = f"{target}_{timestamp}.json"
        txt_filename = f"{target}_{timestamp}.txt"
        
        # Save JSON results
        json_path = os.path.join(output_dir, json_filename)
        with open(json_path, 'w') as f:
            json.dump(results, f, indent=2)
            
        # Save text summary
        txt_path = os.path.join(output_dir, txt_filename)
        with open(txt_path, 'w') as f:
            f.write(f"Findings for {results.get('target')}:\n")
            f.write(f"Risk Level: {results.get('risk_level', 'Unknown')}\n\n")
            f.write("Service Analysis:\n\n")
            
            # Add analysis for each service
            for analysis in results.get('analysis', []):
                service = analysis.get('service', {})
                port = service.get('port', 'Unknown')
                protocol = service.get('protocol', 'Unknown')
                name = service.get('service', 'Unknown')
                product = service.get('product', '')
                version = service.get('version', '')
                
                product_str = f"{product} {version}".strip()
                f.write(f"\n{port}/{protocol} - {name} ({product_str if product_str else ''})\n\n")
                
                for item in analysis.get('analysis', []):
                    source = item.get('source', 'Unknown')
                    confidence = item.get('confidence', 'unknown')
                    analysis_text = item.get('analysis', '')
                    
                    f.write(f"Source: {source} (Confidence: {confidence})\n")
                    f.write(f"{analysis_text}\n\n")
        
        return json_path, txt_path


class AISecurityAnalyzer:
    """Analyzes services using AI for security vulnerabilities."""
    
    def __init__(self):
        """Initialize the AI security analyzer with available models."""
        self.available_models = []
        self.gemini_model = None
        self.openai_model = None
        self.local_model = None
        self._initialize_models()
    
    def _initialize_models(self):
        """Initialize AI models for security analysis."""
        # Try Gemini
        gemini_key = os.getenv('GEMINI_API_KEY')
        if gemini_key:
            try:
                import google.generativeai as genai
                genai.configure(api_key=gemini_key)
                self.gemini_model = genai.GenerativeModel('gemini-1.5-flash')
                self.available_models.append('gemini')
                logger.info("Gemini AI initialized successfully")
            except ImportError:
                logger.warning("Google Generativeai module not found. Install with: pip install google-generativeai")
            except Exception as e:
                logger.warning(f"Failed to initialize Gemini AI: {str(e)}")
        else:
            logger.warning("Gemini API key not found. Gemini AI analysis will be disabled.")
            
        # Try OpenAI
        openai_key = os.getenv('OPENAI_API_KEY')
        if openai_key:
            try:
                from openai import OpenAI
                self.openai_model = OpenAI(api_key=openai_key)
                self.available_models.append('openai')
                logger.info("OpenAI initialized successfully")
            except ImportError:
                logger.warning("OpenAI module not found. Install with: pip install openai")
            except Exception as e:
                logger.warning(f"Failed to initialize OpenAI: {str(e)}")
        else:
            logger.warning("OpenAI API key not found. OpenAI analysis will be disabled.")

    async def analyze_service(self, service_info: Dict) -> List[Dict]:
        """
        Analyze a service using AI models and offline analysis.
        
        Args:
            service_info: Dictionary with service information
            
        Returns:
            List of analysis items with source and analysis text
        """
        vulnerabilities = []
        
        try:
            # Initialize analysis field if it doesn't exist
            if 'analysis' not in service_info:
                service_info['analysis'] = []
            
            # Basic offline analysis
            if 'service' in service_info:
                service_name = service_info.get('service', '')
                product = service_info.get('product', '')
                version = service_info.get('version', '')
                
                # Add basic security recommendations based on the service
                basic_analysis = self._get_basic_recommendations(service_name, product, version)
                if basic_analysis:
                    analysis_item = {
                        'source': 'Offline Analysis',
                        'analysis': basic_analysis,
                        'confidence': 'medium'
                    }
                    vulnerabilities.append(analysis_item)
                    service_info['analysis'].append(analysis_item)
                
                # Add enhanced offline analysis based on service and version if available
                enhanced_analysis = self._get_enhanced_recommendations(service_name, product, version)
                if enhanced_analysis:
                    analysis_item = {
                        'source': 'Enhanced Analysis',
                        'analysis': enhanced_analysis,
                        'confidence': 'medium'
                    }
                    vulnerabilities.append(analysis_item)
                    service_info['analysis'].append(analysis_item)
            
            # Prepare prompt for AI models
            # Build the prompt based on service information
            prompt = f"""Analyze this network service from a security perspective:
            
Service: {service_info.get('service', 'Unknown')}
Port: {service_info.get('port', 'Unknown')}
Protocol: {service_info.get('protocol', 'Unknown')}
Product: {service_info.get('product', 'Unknown')}
Version: {service_info.get('version', 'Unknown')}
State: {service_info.get('state', 'Unknown')}
Extra Info: {service_info.get('extrainfo', 'None')}

Please provide:
1. A risk assessment (Critical, High, Medium, or Low)
2. Key vulnerabilities or security concerns
3. Specific recommendations to secure this service
4. CVEs (if known) related to this version
            """

            # First try Gemini if available
            if 'gemini' in self.available_models and self.gemini_model:
                try:
                    import google.generativeai as genai
                    if not isinstance(self.gemini_model, genai.GenerativeModel):
                        self.gemini_model = genai.GenerativeModel('gemini-1.5-flash')
                    
                    response = self.gemini_model.generate_content(prompt)
                    if hasattr(response, 'text'):
                        ai_result = {
                            'source': 'Gemini AI',
                            'analysis': response.text,
                            'confidence': 'high'
                        }
                        logger.info(f"Gemini analysis completed for service on port {service_info.get('port')}")
                        vulnerabilities.insert(0, ai_result)  # Put AI analysis first
                        
                        # Save the analysis directly to the service_info for report generation
                        service_info['analysis'].append(ai_result)
                        
                        # تعليق على الدالة لتنفيذ كلا النموذجين: Gemini و OpenAI
                        # return vulnerabilities  # Return here to avoid using both AI models
                except Exception as e:
                    logger.warning(f"Gemini analysis failed: {str(e)}")
                    logger.debug(traceback.format_exc())
            
            # Try OpenAI if available and Gemini failed or not available
            if 'openai' in self.available_models and self.openai_model:
                try:
                    from openai import OpenAI, RateLimitError
                    try:
                        response = self.openai_model.chat.completions.create(
                            model="gpt-3.5-turbo",
                            messages=[
                                {"role": "system", "content": "You are a cybersecurity expert specializing in vulnerability analysis."},
                                {"role": "user", "content": prompt}
                            ],
                            max_tokens=800
                        )
                        logger.debug(f"OpenAI response: {response}")
                        if hasattr(response.choices[0], 'message') and hasattr(response.choices[0].message, 'content'):
                            ai_result = {
                                'source': 'OpenAI',
                                'analysis': response.choices[0].message.content,
                                'confidence': 'high'
                            }
                            logger.info(f"OpenAI analysis completed for service on port {service_info.get('port')}")
                            vulnerabilities.insert(0, ai_result)  # Put AI analysis first
                            
                            # Save the analysis directly to the service_info for report generation
                            service_info['analysis'].append(ai_result)
                    except RateLimitError as rate_error:
                        error_msg = str(rate_error)
                        # كتابة سجل تفصيلي لخطأ تجاوز الحصة المخصصة
                        logger.error(f"OpenAI API error detailed: {error_msg}")
                        if "quota" in error_msg or "insufficient_quota" in error_msg:
                            logger.error("OpenAI API quota exceeded. Please check your billing details at https://platform.openai.com/account/billing")
                            quota_error = {
                                'source': 'OpenAI Error',
                                'analysis': "OpenAI API analysis failed: Quota exceeded. Please check your billing details at https://platform.openai.com/account/billing",
                                'confidence': 'low'
                            }
                            service_info['analysis'].append(quota_error)
                            # Remove OpenAI from available models to avoid further attempts
                            if 'openai' in self.available_models:
                                self.available_models.remove('openai')
                        else:
                            logger.warning(f"OpenAI rate limit error: {error_msg}")
                except Exception as e:
                    logger.warning(f"OpenAI analysis failed: {str(e)}")
                    logger.error(f"OpenAI general error detailed: {type(e).__name__} - {str(e)}")
                    logger.debug(traceback.format_exc())
        
        except Exception as e:
            logger.error(f"AI security analysis failed: {str(e)}")
            logger.debug(f"AI analysis exception details: {traceback.format_exc()}")
            
            # Add error analysis to ensure we have something
            error_analysis = {
                'source': 'Error',
                'analysis': f"Analysis error: {str(e)}. Please check logs for details.",
                'confidence': 'low'
            }
            vulnerabilities.append(error_analysis)
            service_info['analysis'].append(error_analysis)
        
        return vulnerabilities
    
    def _get_basic_recommendations(self, service_name: str, product: str, version: str) -> str:
        """Get basic security recommendations based on service, product and version."""
        try:
            base_analysis = f"Service: {service_name}"
            if product:
                base_analysis += f" (Product: {product}"
                if version:
                    base_analysis += f", Version: {version}"
                base_analysis += ")"
            
            # Default recommendations based on common services
            recommendations = {
                'http': "Web server detected. Ensure proper access controls, implement HTTPS, regularly update server software, and scan for web vulnerabilities.",
                'https': "Secure web server detected. Verify TLS configuration, maintain valid certificates, and regularly scan for web vulnerabilities.",
                'ssh': "SSH server detected. Use key-based authentication, disable root login, implement fail2ban, and keep the SSH server updated.",
                'ftp': "FTP service detected. Consider replacing with SFTP, disable anonymous login, use strong authentication, and restrict access.",
                'telnet': "Telnet service detected. CRITICAL: Telnet transmits data in plaintext. Replace with SSH immediately.",
                'smb': "SMB file sharing detected. Disable SMBv1, use strong authentication, implement proper access controls, and keep updated.",
                'rdp': "Remote Desktop service detected. Implement Network Level Authentication, use strong passwords, limit access, and keep updated.",
                'mysql': "MySQL database detected. Use strong authentication, limit network access, regularly update, and implement proper user privileges.",
                'mssql': "Microsoft SQL Server detected. Implement strong authentication, patch regularly, and limit network access.",
                'mongodb': "MongoDB database detected. Disable direct internet access, implement authentication, and keep updated.",
                'redis': "Redis database detected. Configure authentication, disable direct internet access, and keep updated.",
                'dns': "DNS server detected. Ensure proper configuration, implement DNSSEC if possible, and regularly update.",
                'ntp': "NTP service detected. Configure to prevent amplification attacks and keep updated.",
                'smtp': "Mail server detected. Configure SPF, DKIM, and DMARC, disable open relay, and keep updated.",
                'imap': "IMAP mail service detected. Enforce encryption, implement strong authentication, and keep updated.",
                'pop3': "POP3 mail service detected. Enforce encryption, implement strong authentication, and keep updated."
            }
            
            # Default recommendation if service not in our list
            default_rec = "This service should be reviewed to ensure it's necessary and properly secured. Implement network access controls, strong authentication, and regular updates."
            
            # Add service-specific recommendations if available
            service_lower = service_name.lower()
            for key, recommendation in recommendations.items():
                if key in service_lower:
                    base_analysis += f"\n\nRecommendations: {recommendation}"
                    return base_analysis
            
            # If no specific match found, provide default recommendations
            base_analysis += f"\n\nRecommendations: {default_rec}"
            
            return base_analysis
            
        except Exception as e:
            logger.error(f"Error generating basic recommendations: {str(e)}")
            return f"Analysis unavailable due to an error. Service: {service_name}"

    def _get_enhanced_recommendations(self, service_name: str, product: str, version: str) -> str:
        """Get enhanced recommendations based on service, product and version."""
        try:
            if not product:
                return ""  # No enhanced analysis without product info
                
            base_analysis = f"Enhanced analysis for {service_name}"
            if product:
                base_analysis += f" (Product: {product}"
                if version:
                    base_analysis += f", Version: {version}"
                base_analysis += ")"
                
            # Product-specific recommendations
            product_lower = product.lower()
            
            # Apache web server
            if "apache" in product_lower and ("http" in service_name.lower() or "web" in service_name.lower()):
                return base_analysis + "\n\nApache Web Server detected. Recommendations:\n" + \
                       "- Disable directory listing\n" + \
                       "- Remove unnecessary modules\n" + \
                       "- Configure proper access controls\n" + \
                       "- Implement mod_security for WAF capabilities\n" + \
                       "- Keep updated to patch security vulnerabilities\n" + \
                       "- Implement proper TLS configuration"
                       
            # nginx web server
            elif "nginx" in product_lower:
                return base_analysis + "\n\nNginx Web Server detected. Recommendations:\n" + \
                       "- Disable server tokens\n" + \
                       "- Implement rate limiting\n" + \
                       "- Configure proper access controls\n" + \
                       "- Keep updated to patch security vulnerabilities\n" + \
                       "- Implement proper TLS configuration"
                       
            # IIS web server
            elif "iis" in product_lower or "internet information services" in product_lower:
                return base_analysis + "\n\nMicrosoft IIS Web Server detected. Recommendations:\n" + \
                       "- Remove unnecessary features\n" + \
                       "- Implement proper authentication\n" + \
                       "- Configure URLScan or similar security filters\n" + \
                       "- Keep updated with security patches\n" + \
                       "- Implement proper TLS configuration"
                       
            # OpenSSH
            elif "openssh" in product_lower:
                return base_analysis + "\n\nOpenSSH Server detected. Recommendations:\n" + \
                       "- Disable password authentication, use key-based only\n" + \
                       "- Disable root login\n" + \
                       "- Use strong ciphers and key exchange algorithms\n" + \
                       "- Implement fail2ban to prevent brute force\n" + \
                       "- Keep updated to patch security vulnerabilities"
                       
            # MySQL
            elif "mysql" in product_lower:
                return base_analysis + "\n\nMySQL Database Server detected. Recommendations:\n" + \
                       "- Remove test databases and anonymous users\n" + \
                       "- Implement strong password policy\n" + \
                       "- Use principle of least privilege for user accounts\n" + \
                       "- Enable encrypted connections\n" + \
                       "- Regularly audit user privileges\n" + \
                       "- Keep updated to patch security vulnerabilities"
                       
            # Microsoft SQL Server
            elif "microsoft sql server" in product_lower or "mssql" in product_lower:
                return base_analysis + "\n\nMicrosoft SQL Server detected. Recommendations:\n" + \
                       "- Use Windows Authentication when possible\n" + \
                       "- Implement strong password policy\n" + \
                       "- Enable encryption for sensitive data\n" + \
                       "- Apply principle of least privilege\n" + \
                       "- Keep updated with security patches\n" + \
                       "- Regular security audits"
                       
            # Exchange Server
            elif "exchange" in product_lower:
                return base_analysis + "\n\nMicrosoft Exchange Server detected. Recommendations:\n" + \
                       "- Keep updated with the latest security patches\n" + \
                       "- Enable MFA for admin accounts\n" + \
                       "- Implement proper email filtering\n" + \
                       "- Configure SPF, DKIM, and DMARC\n" + \
                       "- Regular security audits\n" + \
                       "- Monitor for unusual activity"
                       
            # VMware
            elif "vmware" in product_lower:
                return base_analysis + "\n\nVMware product detected. Recommendations:\n" + \
                       "- Keep hypervisor and management interfaces updated\n" + \
                       "- Restrict management interface access\n" + \
                       "- Implement strong authentication\n" + \
                       "- Segment management network\n" + \
                       "- Monitor for unusual activity"
            
            # No specific enhanced recommendation available
            return ""
            
        except Exception as e:
            logger.error(f"Error generating enhanced recommendations: {str(e)}")
            return ""


async def main():
    """Main entry point for the scanner."""
    try:
        # Initialize the scanner
        scanner = init_scanner()
        if not scanner:
            logger.error("Failed to initialize scanner. Exiting.")
            return 1
            
        # Determine output directory
        output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scans')
        if args.output:
            output_dir = args.output
            
        # Run the scan
        if args.scan_type in ['container', 'cloud']:
            # For container scans, we use the specific scanner
            logger.info(f"Starting {args.scan_type} scan on {args.target}")
            if args.scan_type == 'container':
                results = await scanner.container_scanner.scan_container(args.target)
            else:
                results = await scanner.cloud_scanner.scan_cloud(args.target, args.cloud_providers)
        else:
            # For network scans, we use the scan_target method
            logger.info(f"Starting {args.scan_type} scan on {args.target}")
            results = await scanner.scan_target(args.target, args.scan_type, output_dir)
            
        # Generate report
        if results:
            try:
                # Generate HTML report
                report_path = scanner.report_generator.generate_report(results, output_dir)
                logger.info(f"Report generated: {report_path}")
                
                # Open report if on desktop
                if os.name == 'nt' and not args.no_open:
                    os.startfile(report_path)
                elif os.name == 'posix' and not args.no_open:
                    import subprocess
                    subprocess.Popen(['xdg-open', report_path])
            except Exception as e:
                logger.error(f"Error generating report: {str(e)}")
                logger.debug(traceback.format_exc())
        
        return 0
    except Exception as e:
        logger.error(f"Error in main: {str(e)}")
        logger.debug(traceback.format_exc())
        return 1
        
# Allow the script to be run from command line
if __name__ == "__main__":
    # Run the main function in an asyncio event loop
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        logger.info("Scan canceled by user.")
        sys.exit(130)
    except Exception as e:
        logger.critical(f"Unhandled exception: {str(e)}")
        logger.debug(traceback.format_exc())
        sys.exit(1)
