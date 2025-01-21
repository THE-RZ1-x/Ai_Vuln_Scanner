#!/usr/bin/env python3
"""
AI-Powered Vulnerability Scanner
Developed by RZ1 (https://github.com/THE-RZ1-x)
Repository: https://github.com/THE-RZ1-x/Ai_Vuln_Scanner

A sophisticated vulnerability scanner that uses AI to analyze and detect security vulnerabilities
in network services and systems.
"""
# -*- coding: utf-8 -*-
# Author: cbk914

import os
import sys
import nmap
import json
import time
import socket
import shodan
import logging
import vulners
import argparse
import requests
import ipaddress
import traceback
from tqdm import tqdm
import google.generativeai as genai
from datetime import datetime
from dotenv import load_dotenv
from bs4 import BeautifulSoup
from typing import Dict, List, Union
from requests.exceptions import RequestException
import re
import vulners
import shodan
from jinja2 import Template
from dotenv import load_dotenv
from bs4 import BeautifulSoup
from typing import Dict, List, Union
from requests.exceptions import RequestException
import re
import requests
import json
import time
import logging
import ipaddress
from tqdm import tqdm
from jinja2 import Template
from dotenv import load_dotenv
from bs4 import BeautifulSoup
from typing import Dict, List, Union
from requests.exceptions import RequestException
import re
import vulners
import shodan
import aiohttp
import asyncio

# Parse command line arguments
parser = argparse.ArgumentParser(description='AI-powered vulnerability scanner')
parser.add_argument('-t', '--target', required=True, help='Target IP address or hostname')
parser.add_argument('-s', '--scan-type', choices=['basic', 'comprehensive'], default='basic',
                  help='Type of scan to perform')
parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
parser.add_argument('-o', '--output', help='Output file name (without extension)')
args = parser.parse_args()

# Configure logging based on verbosity
if args.verbose:
    logging.basicConfig(level=logging.DEBUG)
else:
    logging.basicConfig(level=logging.INFO)

logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Initialize global scanner
scanner = None
ai_analyzer = None

def init_scanner():
    """Initialize the global scanner instance."""
    global scanner
    if scanner is None:
        scanner = VulnerabilityScanner()
    return scanner

def init_ai_analyzer():
    """Initialize the global AI analyzer instance."""
    global ai_analyzer
    if ai_analyzer is None:
        ai_analyzer = AISecurityAnalyzer()
    return ai_analyzer

class VulnerabilityScanner:
    def __init__(self):
        """Initialize the scanner with necessary APIs."""
        self.vulners_api = None
        self.shodan_api = None
        self.initialize_apis()

    def initialize_apis(self):
        """Initialize various security APIs."""
        try:
            # Initialize Vulners API
            self.vulners_api = init_vulners_api()
            if self.vulners_api:
                print("✓ Vulners API initialized")
            
            # Initialize Shodan API if needed
            shodan_api_key = os.getenv('SHODAN_API_KEY')
            if shodan_api_key:
                try:
                    import shodan
                    self.shodan_api = shodan.Shodan(shodan_api_key)
                    print("✓ Shodan API initialized")
                except Exception as e:
                    print(f"✗ Error initializing Shodan API: {str(e)}")
                    
        except Exception as e:
            print(f"✗ Error initializing APIs: {str(e)}")

    async def analyze_service(self, service_info: dict) -> dict:
        """Analyze a service and its vulnerabilities."""
        try:
            # Get AI analysis
            analyzer = init_ai_analyzer()
            ai_analysis = await analyzer.analyze_attack_surface(service_info)
            
            # Get vulnerability information if Vulners API is available
            vulns = []
            if self.vulners_api and service_info.get('product') and service_info.get('version'):
                try:
                    vulns_result = self.vulners_api.softwareVulnerabilities(
                        service_info['product'],
                        service_info['version']
                    )
                    if vulns_result.get('vulnerabilities'):
                        vulns = vulns_result['vulnerabilities']
                except Exception as e:
                    print(f"✗ Error getting vulnerabilities: {str(e)}")
            
            return {
                'vulnerabilities': vulns,
                'ai_analysis': ai_analysis,
                'recommendations': ai_analysis.get('mitigation_steps', []) if ai_analysis else []
            }
        except Exception as e:
            print(f"✗ Error analyzing service: {str(e)}")
            return {
                'vulnerabilities': [],
                'ai_analysis': {},
                'recommendations': []
            }

class VulnerabilityDatabase:
    def __init__(self):
        self.nvd_api_key = os.getenv('NVD_API_KEY')
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cache_file = "vuln_cache.json"
        self.cache = self._load_cache()
        self.vulners_api = scanner.vulners_api
        self.shodan_api = scanner.shodan_api

    def _load_cache(self):
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            logger.error(f"Error loading vulnerability cache: {e}")
            return {}

    def _save_cache(self):
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f)
        except Exception as e:
            logger.error(f"Error saving vulnerability cache: {e}")

    def search_vulnerabilities(self, product: str, version: str = None) -> list:
        """Search for vulnerabilities using multiple sources."""
        cache_key = f"{product}:{version}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        vulns = []
        
        # Try Vulners API first
        if self.vulners_api:
            try:
                search_query = f"{product}"
                if version:
                    search_query += f" {version}"
                vulners_results = self.vulners_api.search(search_query, limit=100)
                
                for vuln in vulners_results:
                    vuln_info = {
                        'id': vuln.get('id'),
                        'title': vuln.get('title'),
                        'description': vuln.get('description'),
                        'severity': float(vuln.get('cvss', {}).get('score', 0)),
                        'published': vuln.get('published'),
                        'references': vuln.get('references', []),
                        'source': 'vulners'
                    }
                    vulns.append(vuln_info)
            except Exception as e:
                logger.error(f"Error searching Vulners: {str(e)}")

        # Try NVD API as backup
        try:
            params = {
                'keywordSearch': product,
                'resultsPerPage': 100
            }
            if version:
                params['versionStart'] = version
                params['versionStartType'] = 'including'

            headers = {'apiKey': self.nvd_api_key} if self.nvd_api_key else {}
            
            response = requests.get(
                self.base_url,
                params=params,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                for vuln in data.get('vulnerabilities', []):
                    cve = vuln.get('cve', {})
                    vuln_info = {
                        'id': cve.get('id'),
                        'description': cve.get('descriptions', [{}])[0].get('value', ''),
                        'severity': cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', 0),
                        'published': cve.get('published'),
                        'references': [ref.get('url') for ref in cve.get('references', [])],
                        'source': 'nvd'
                    }
                    vulns.append(vuln_info)
        except Exception as e:
            logger.error(f"Error searching NVD: {str(e)}")

        # Add Shodan data if available
        try:
            if self.shodan_api:
                api = self.shodan_api
                results = api.search(f"product:{product}")
                for result in results['matches'][:5]:
                    if 'vulns' in result:
                        for cve_id, vuln_info in result['vulns'].items():
                            vulns.append({
                                'id': cve_id,
                                'severity': float(vuln_info.get('cvss', 0)),
                                'description': vuln_info.get('summary', ''),
                                'source': 'shodan'
                            })
        except Exception as e:
            logger.error(f"Error searching Shodan: {str(e)}")

        # Remove duplicates based on ID
        unique_vulns = {v['id']: v for v in vulns if v['id']}.values()
        vulns = sorted(unique_vulns, key=lambda x: float(x.get('severity', 0)), reverse=True)
        
        self.cache[cache_key] = vulns
        self._save_cache()
        return vulns

class ExploitFinder:
    def __init__(self):
        self.exploit_db_url = "https://www.exploit-db.com/search?q="
        self.metasploit_url = "https://www.rapid7.com/db/?q="
        self.cache = {}

    def find_exploits(self, cve_id: str) -> dict:
        """Find available exploits for a CVE."""
        if cve_id in self.cache:
            return self.cache[cve_id]

        exploits = {
            'exploit_db': [],
            'metasploit': [],
            'github': []
        }

        try:
            # Search ExploitDB
            response = requests.get(f"{self.exploit_db_url}{cve_id}")
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    if '/exploits/' in link['href']:
                        exploits['exploit_db'].append({
                            'title': link.text.strip(),
                            'url': f"https://www.exploit-db.com{link['href']}"
                        })

            # Search GitHub
            gh_response = requests.get(
                f"https://api.github.com/search/repositories?q={cve_id}+in:readme+in:description"
            )
            if gh_response.status_code == 200:
                for repo in gh_response.json().get('items', [])[:5]:
                    exploits['github'].append({
                        'title': repo['full_name'],
                        'url': repo['html_url'],
                        'description': repo['description']
                    })

            self.cache[cve_id] = exploits
            return exploits

        except Exception as e:
            logger.error(f"Error finding exploits: {e}")
            return exploits

class AISecurityAnalyzer:
    def __init__(self):
        """Initialize the AI Security Analyzer."""
        self.model = init_gemini()
        self.cache = {}
        self.last_api_call = 0
        self.min_delay = 2
        self.autonomous_mode = True
        self.security_apis = SecurityAPIIntegration()

    def parse_ai_response(self, response_text: str) -> dict:
        """Parse the AI response into a structured format."""
        try:
            # Split response into sections
            sections = response_text.split('\n\n')
            analysis = {
                'findings': [],
                'mitigation_steps': [],
                'technical_details': [],
                'risk_assessment': []
            }
            
            current_section = None
            for line in response_text.split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                # Identify sections
                if 'vulnerability' in line.lower() or 'finding' in line.lower():
                    current_section = 'findings'
                elif 'mitigation' in line.lower() or 'recommendation' in line.lower():
                    current_section = 'mitigation_steps'
                elif 'technical' in line.lower() or 'detail' in line.lower():
                    current_section = 'technical_details'
                elif 'risk' in line.lower() or 'impact' in line.lower():
                    current_section = 'risk_assessment'
                elif current_section and line.startswith(('-', '*', '•')):
                    analysis[current_section].append(line.lstrip('-* •').strip())
            
            return analysis
            
        except Exception as e:
            print(f"✗ Error parsing AI response: {str(e)}")
            return {
                'findings': [],
                'mitigation_steps': [],
                'technical_details': [],
                'risk_assessment': []
            }

    async def analyze_attack_surface(self, service_data: dict) -> dict:
        """Enhanced AI-powered attack surface analysis."""
        try:
            if not self.model:
                print("✗ Gemini AI not available, using fallback analysis")
                return self.get_fallback_analysis(service_data)

            # Enhanced AI prompt template
            prompt = f"""Analyze this service from a security perspective:
Service: {service_data.get('name', '')} ({service_data.get('version', 'unknown version')})
Port: {service_data.get('port', 'unknown')}
Protocol: {service_data.get('protocol', 'unknown')}

Provide a security analysis including:
1. Potential vulnerabilities and findings
2. Mitigation steps and recommendations
3. Technical details and attack vectors
4. Risk assessment and impact analysis

Format your response with clear sections using bullet points."""

            # Get AI analysis with retry mechanism
            for attempt in range(3):
                try:
                    response = await self.model.generate_content(prompt)
                    
                    # Handle the response properly
                    if response.candidates:
                        text_parts = []
                        for part in response.candidates[0].content.parts:
                            if hasattr(part, 'text'):
                                text_parts.append(part.text)
                        
                        analysis_text = '\n'.join(text_parts)
                        analysis = self.parse_ai_response(analysis_text)
                        print("✓ AI analysis complete")
                        return analysis
                    else:
                        raise Exception("No response generated")
                        
                except Exception as e:
                    if attempt == 2:
                        print(f"✗ AI analysis failed: {str(e)}")
                        return self.get_fallback_analysis(service_data)
                    await asyncio.sleep(2 ** attempt)

        except Exception as e:
            print(f"✗ Error in AI analysis: {str(e)}")
            return self.get_fallback_analysis(service_data)

    def get_fallback_analysis(self, service_data: dict) -> dict:
        """Get fallback analysis when AI analysis fails."""
        service_type = service_data.get('name', '').lower()
        print(f"Using fallback analysis for {service_type}")
        
        # Get default recommendations based on service type
        if 'http' in service_type:
            recommendations = [
                "Enable HTTPS and redirect HTTP to HTTPS",
                "Implement security headers (HSTS, CSP, etc.)",
                "Use WAF for additional protection",
                "Regular security patching",
                "Enable logging and monitoring"
            ]
        elif 'ssh' in service_type:
            recommendations = [
                "Use strong SSH key authentication",
                "Disable password authentication",
                "Change default port",
                "Implement fail2ban",
                "Regular security updates"
            ]
        else:
            recommendations = [
                "Keep service updated",
                "Implement access controls",
                "Enable logging",
                "Regular security audits",
                "Monitor for suspicious activity"
            ]
        
        return {
            'findings': [f"Service {service_type} may have security vulnerabilities"],
            'mitigation_steps': recommendations,
            'technical_details': [],
            'risk_assessment': ['Potential security risk - manual assessment recommended']
        }

class SecurityAPIIntegration:
    """Integration with various security APIs"""
    def __init__(self):
        self.cache = {}
        self.cache_duration = 3600  # 1 hour cache

    async def get_cve_mitre(self, cve_id: str) -> dict:
        """Get CVE details from MITRE (Free API)"""
        url = f"https://cve.circl.lu/api/cve/{cve_id}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        return await response.json()
                    return None
        except Exception as e:
            logger.error(f"Error fetching CVE from MITRE: {str(e)}")
            return None

    async def check_virus_total(self, domain: str) -> dict:
        """Query VirusTotal API (Free tier - 500 requests/day)"""
        api_key = os.getenv('VIRUSTOTAL_API_KEY')
        if not api_key:
            return None
            
        url = f"https://www.virustotal.com/vtapi/v2/domain/report"
        params = {'apikey': api_key, 'domain': domain}
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        return await response.json()
                    return None
        except Exception as e:
            logger.error(f"Error checking VirusTotal: {str(e)}")
            return None

    async def query_abuse_ipdb(self, ip: str) -> dict:
        """Query AbuseIPDB (Free tier - 1000 requests/day)"""
        api_key = os.getenv('ABUSEIPDB_API_KEY')
        if not api_key:
            return None
            
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            'Accept': 'application/json',
            'Key': api_key
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, params=params) as response:
                    if response.status == 200:
                        return await response.json()
                    return None
        except Exception as e:
            logger.error(f"Error checking AbuseIPDB: {str(e)}")
            return None

    async def check_greynoise(self, ip: str) -> dict:
        """Query GreyNoise (Free Community API)"""
        api_key = os.getenv('GREYNOISE_API_KEY')
        if not api_key:
            return None
            
        url = f"https://api.greynoise.io/v3/community/{ip}"
        headers = {'key': api_key}
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        return await response.json()
                    return None
        except Exception as e:
            logger.error(f"Error checking GreyNoise: {str(e)}")
            return None

    async def check_urlscan(self, domain: str) -> dict:
        """Query URLScan.io (Free API)"""
        api_key = os.getenv('URLSCAN_API_KEY')
        if not api_key:
            return None
            
        url = "https://urlscan.io/api/v1/scan/"
        headers = {
            'API-Key': api_key,
            'Content-Type': 'application/json'
        }
        data = {'url': domain, 'visibility': 'public'}
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, headers=headers, json=data) as response:
                    if response.status == 200:
                        return await response.json()
                    return None
        except Exception as e:
            logger.error(f"Error submitting to URLScan: {str(e)}")
            return None

class NetworkMapper:
    def __init__(self):
        self.vuln_db = VulnerabilityDatabase()
        self.exploit_finder = ExploitFinder()
        self.scan_results = {}

    def analyze_service(self, service: dict) -> dict:
        """Analyze a single service for vulnerabilities."""
        product = service.get('product', '')
        version = service.get('version', '')
        
        vulnerabilities = self.vuln_db.search_vulnerabilities(product, version)
        high_risk_vulns = []
        
        for vuln in vulnerabilities:
            if vuln['severity'] >= 7.0:  # CVSS score >= 7.0 is high
                exploits = self.exploit_finder.find_exploits(vuln['id'])
                if any(exploits.values()):  # If any exploits found
                    vuln['exploits'] = exploits
                    high_risk_vulns.append(vuln)
        
        return {
            'service_info': service,
            'vulnerabilities': vulnerabilities,
            'high_risk': high_risk_vulns
        }

    def get_service_recommendations(self, service_analysis: dict) -> list:
        """Generate security recommendations based on service analysis."""
        recommendations = []
        service = service_analysis['service_info']
        
        # Basic service hardening
        if service.get('name') == 'ssh':
            recommendations.extend([
                "Disable root login via SSH",
                "Use key-based authentication instead of passwords",
                "Change default SSH port",
                "Implement fail2ban for brute force protection"
            ])
        elif service.get('name') == 'http' or service.get('name') == 'https':
            recommendations.extend([
                "Enable HTTPS and redirect HTTP to HTTPS",
                "Implement security headers (HSTS, CSP, etc.)",
                "Use WAF for additional protection",
                "Disable unnecessary HTTP methods",
                "Implement rate limiting"
            ])
        
        # Version-specific recommendations
        if service.get('version'):
            recommendations.append(f"Update {service.get('product')} to the latest version")
        
        # Vulnerability-specific recommendations
        for vuln in service_analysis['high_risk']:
            recommendations.append(f"Critical: Patch {vuln['id']} - {vuln['description'][:100]}...")
        
        return recommendations

def analyze_vulnerabilities(scan_data: dict) -> str:
    """Analyze scan data for vulnerabilities."""
    try:
        analysis_results = []
        
        # Try AI-powered analysis first
        if gemini_model:
            try:
                # Format scan data for analysis
                scan_summary = []
                for proto in ['tcp', 'udp']:
                    if proto in scan_data:
                        for port, data in scan_data[proto].items():
                            service_info = f"Port {port}/{proto}: {data.get('name', 'unknown')}"
                            if data.get('product'):
                                service_info += f" - {data['product']}"
                                if data.get('version'):
                                    service_info += f" {data['version']}"
                            scan_summary.append(service_info)

                if scan_summary:
                    prompt = f"""Analyze these network services for security vulnerabilities:
{chr(10).join(scan_summary)}

Consider:
1. Known vulnerabilities for these services and versions
2. Common misconfigurations
3. Security best practices
4. Potential attack vectors
5. Specific remediation steps

Provide a detailed security analysis."""

                    response = gemini_model.generate_content(prompt)
                    analysis_results.append("AI Analysis:")
                    analysis_results.append(response.text)
            except Exception as e:
                logger.error(f"AI analysis failed: {str(e)}")
        
        # Always perform offline analysis as backup
        analysis_results.append("\nOffline Analysis:")
        for proto in ['tcp', 'udp']:
            if proto in scan_data:
                for port, data in scan_data[proto].items():
                    service_name = data.get('name', 'unknown')
                    recommendations = analyze_service_offline(data)
                    if recommendations:
                        analysis_results.append(f"\nRecommendations for port {port}/{proto} ({service_name}):")
                        for rec in recommendations:
                            analysis_results.append(f"- {rec}")

        return "\n".join(analysis_results)

    except Exception as e:
        logger.error(f"Error during vulnerability analysis: {str(e)}")
        return f"Error analyzing vulnerabilities: {str(e)}"

def validate_target(target: str) -> bool:
    """
    Validate if the target is a valid IP address or hostname.
    Supports IPv4, IPv6, and hostnames according to RFC 1123.
    """
    if not target or len(target) > 255:
        return False

    # Try validating as IP address first
    try:
        # Handle IPv4
        if '.' in target:
            # Verify it looks like an IPv4 address
            octets = target.split('.')
            if len(octets) != 4:
                return False
            try:
                # Try converting each octet to int and validate range
                return all(
                    octet.isdigit() and 
                    0 <= int(octet) <= 255
                    for octet in octets
                )
            except ValueError:
                return False
        
        # Handle IPv6
        if ':' in target:
            ipaddress.IPv6Address(target)
            return True
            
        # If not an IP address, treat as hostname
        return validate_hostname(target)
            
    except ValueError:
        # If IP validation fails, try hostname validation
        return validate_hostname(target)

def validate_hostname(hostname: str) -> bool:
    """
    Validate hostname according to RFC 1123 rules.
    """
    if not hostname or len(hostname) > 255:
        return False
        
    # Remove trailing dot if present
    if hostname.endswith('.'):
        hostname = hostname[:-1]
    
    # Hostname should not be empty after removing trailing dot
    if not hostname:
        return False
    
    # Split hostname into labels
    labels = hostname.split('.')
    
    # Check each label
    for label in labels:
        if not label:  # Empty label (consecutive dots)
            return False
        if len(label) > 63:  # Label too long
            return False
        if label.startswith('-') or label.endswith('-'):  # Hyphen at start/end
            return False
        # Check characters (alphanumeric and hyphen only)
        if not all(c.isalnum() or c == '-' for c in label):
            return False
        # Label can't be all numbers (at least for the last label/TLD)
        if label.isdigit():
            continue
    
    return True

def discover_network_targets(network: str) -> list:
    """
    Discover active hosts in the network using nmap ping scan.
    Args:
        network: Network range in CIDR notation (e.g., '192.168.1.0/24')
    Returns:
        List of active IP addresses
    """
    try:
        logger.info(f"Starting network discovery on {network}")
        nm = nmap.PortScanner()
        nm.scan(hosts=network, arguments='-sn')  # Ping scan
        
        active_hosts = []
        for host in nm.all_hosts():
            try:
                hostname = ''
                if 'hostnames' in nm[host] and nm[host]['hostnames']:
                    hostname = nm[host]['hostnames'][0]['name']
                
                status = nm[host].state()
                addresses = []
                if 'addresses' in nm[host]:
                    for addr_type, addr in nm[host]['addresses'].items():
                        addresses.append(f"{addr_type}:{addr}")
                
                if status == 'up':
                    active_hosts.append({
                        'ip': host,
                        'hostname': hostname,
                        'addresses': addresses,
                        'status': status
                    })
                    logger.info(f"Found active host: {host} ({hostname})")
            except Exception as e:
                logger.error(f"Error processing host {host}: {str(e)}")
                continue
                
        return active_hosts
    except Exception as e:
        logger.error(f"Error during network discovery: {str(e)}")
        return []

def validate_network_range(network: str) -> bool:
    """
    Validate if the given network range is in valid CIDR notation.
    Args:
        network: Network range (e.g., '192.168.1.0/24')
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        if '/' not in network:
            return False
        ip, mask = network.split('/')
        # Validate IP
        ipaddress.ip_address(ip)
        # Validate mask
        mask = int(mask)
        if not (0 <= mask <= 32):
            return False
        return True
    except ValueError:
        return False

def is_valid_ip(ip_str: str) -> bool:
    """Validate if a string is a valid IPv4 address."""
    try:
        # Split the IP address into octets
        octets = ip_str.split('.')
        
        # Check if we have exactly 4 octets
        if len(octets) != 4:
            return False
            
        # Check if each octet is a valid number between 0 and 255
        return all(0 <= int(octet) <= 255 for octet in octets)
    except (AttributeError, TypeError, ValueError):
        return False

def get_shodan_info(ip: str) -> dict:
    """Get information about an IP address from Shodan."""
    try:
        # Validate IP address
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            logger.error(f"Invalid IP address format: {ip}")
            return {}

        # Skip private IP addresses
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            logger.warning(f"Skipping Shodan lookup for private IP: {ip}")
            return {}

        shodan_api = shodan.Shodan(os.getenv('SHODAN_API_KEY'))
        host = shodan_api.host(ip)
        
        return {
            'org': host.get('org', 'N/A'),
            'os': host.get('os', 'N/A'),
            'ports': host.get('ports', []),
            'vulns': host.get('vulns', [])
        }
    except shodan.APIError as e:
        if "No information available" in str(e):
            logger.warning(f"No Shodan information available for {ip}")
        else:
            logger.error(f"Shodan API error: {str(e)}")
        return {}
    except Exception as e:
        logger.error(f"Error getting Shodan info: {str(e)}")
        return {}

def scan(target: str, scan_type: str = 'basic') -> tuple:
    """
    Perform network scan and vulnerability analysis.
    Args:
        target: IP address or hostname to scan
        scan_type: Type of scan to perform
    Returns:
        tuple: (analysis_results, raw_scan_data)
    """
    scan_profiles = {
        'basic': '-Pn -sV -T4 -O -F',
        'comprehensive': '-Pn -sS -sV -T4 -A -O',
        'stealth': '-Pn -sS -T2 -O',
        'full': '-Pn -sS -sV -T4 -A -O -p-'
    }
    
    arguments = scan_profiles.get(scan_type, scan_profiles['basic'])
    
    try:
        logger.info(f"Starting {scan_type} scan on {target}")
        with tqdm(total=100, desc=f"Scanning {target}") as pbar:
            # Perform the scan
            nm = nmap.PortScanner()
            nm.scan(hosts=target, arguments=arguments)
            pbar.update(50)
            
            # Get scan results
            if target not in nm.all_hosts():
                logger.warning(f"No results found for {target}")
                return "No results found", {}
                
            scan_data = nm[target]
            pbar.update(25)
            
            # Analyze vulnerabilities
            analysis = analyze_vulnerabilities(scan_data)
            pbar.update(25)
            
            logger.info(f"Scan completed for {target}")
            return analysis, scan_data
            
    except Exception as e:
        logger.error(f"Error during scan: {str(e)}")
        return f"Error during scan: {str(e)}", {}

def format_service_info(service_info, analysis):
    """Format service information and analysis results."""
    output = []
    
    # Basic service info
    name = service_info.get('name', 'Unknown')
    port = service_info.get('port', 'Unknown')
    protocol = service_info.get('protocol', 'tcp')
    product = service_info.get('product', '')
    version = service_info.get('version', '')
    
    # Format service line
    service_line = f"{port}/{protocol} - {name}"
    if product:
        service_line += f" ({product}"
        if version:
            service_line += f" {version}"
        service_line += ")"
    output.append(service_line)
    
    # CVE Vulnerabilities
    if analysis.get('vulnerabilities'):
        output.append("\nDetected CVEs:")
        for vuln in analysis['vulnerabilities']:
            cve = vuln['details']
            output.append(f"\n[{vuln['cve_id']}] - Severity: {cve['severity']}")
            output.append(f"Description: {cve['description']}")
            output.append(f"Published: {cve['published']}")
            if cve['references']:
                output.append("References:")
                for ref in cve['references'][:3]:  # Limit to top 3 references
                    output.append(f"- {ref}")
    
    # Available Exploits
    if analysis.get('exploits'):
        output.append("\nAvailable Exploits:")
        for exploit in analysis['exploits']:
            output.append(f"\n[{exploit['source']}]")
            if 'url' in exploit:
                output.append(f"URL: {exploit['url']}")
            if 'command' in exploit:
                output.append(f"Command: {exploit['command']}")
            output.append(f"Type: {exploit['type']}")
    
    # Exploitation Guidance
    if analysis.get('exploitation_guidance'):
        for guidance in analysis['exploitation_guidance']:
            output.append(f"\nExploitation Guide for {guidance['cve_id']}:")
            
            if guidance['guidance'].get('prerequisites'):
                output.append("\nPrerequisites:")
                for prereq in guidance['guidance']['prerequisites']:
                    output.append(f"- {prereq}")
            
            if guidance['guidance'].get('exploitation_steps'):
                output.append("\nExploitation Steps:")
                for i, step in enumerate(guidance['guidance']['exploitation_steps'], 1):
                    output.append(f"{i}. {step}")
            
            if guidance['guidance'].get('post_exploitation'):
                output.append("\nPost-Exploitation:")
                for post in guidance['guidance']['post_exploitation']:
                    output.append(f"- {post}")
            
            if guidance['guidance'].get('mitigation'):
                output.append("\nMitigation Steps:")
                for mit in guidance['guidance']['mitigation']:
                    output.append(f"- {mit}")
    
    # Attack vectors
    if analysis.get('attack_vectors'):
        output.append("\nCommon Attack Vectors:")
        for vector in analysis['attack_vectors']:
            output.append(f"- {vector}")
    
    # Best practices
    if analysis.get('best_practices'):
        output.append("\nBest Practices:")
        for practice in analysis['best_practices']:
            output.append(f"- {practice}")
    
    return "\n".join(output)

def save_results(results, output_prefix):
    """Save scan results to files."""
    try:
        # Create folders if they don't exist
        os.makedirs('scans', exist_ok=True)
        os.makedirs('exploits', exist_ok=True)
        
        # Save scan results
        json_file = os.path.join('scans', f'{output_prefix}.json')
        txt_file = os.path.join('scans', f'{output_prefix}.txt')
        
        # Save JSON results
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Save text results
        with open(txt_file, 'w') as f:
            f.write(format_results(results))
        
        logger.info(f"\nScan results saved to:\n- JSON format: {json_file}\n- Text format: {txt_file}")
        
        # Clean up old files
        cleanup_old_files()
        
    except Exception as e:
        logger.error(f"Error saving results: {str(e)}")

def cleanup_old_files():
    """Clean up old scan and exploit files."""
    try:
        # Keep only the 5 most recent files in each directory
        for directory in ['scans', 'exploits']:
            if os.path.exists(directory):
                files = []
                for filename in os.listdir(directory):
                    filepath = os.path.join(directory, filename)
                    if os.path.isfile(filepath):
                        files.append((filepath, os.path.getmtime(filepath)))
                
                # Sort files by modification time (newest first)
                files.sort(key=lambda x: x[1], reverse=True)
                
                # Remove old files
                for filepath, _ in files[5:]:
                    try:
                        os.remove(filepath)
                        logger.debug(f"Removed old file: {filepath}")
                    except Exception as e:
                        logger.error(f"Error removing file {filepath}: {str(e)}")
                        
    except Exception as e:
        logger.error(f"Error cleaning up old files: {str(e)}")

def generate_exploit_script(service_info, cve_id, exploit_info):
    """Generate a Python exploit script for the vulnerability."""
    try:
        service_name = service_info.get('name', 'Unknown')
        product = service_info.get('product', '')
        version = service_info.get('version', '')
        
        prompt = f"""Generate a Python exploit script for CVE {cve_id} affecting {service_name} {product} {version}.
        Include:
        1. Required imports and dependencies
        2. Target configuration
        3. Exploit code with proper error handling
        4. Example usage
        Make it a complete, runnable script."""
        
        response = get_gemini_response(prompt)
        
        if response:
            # Create exploits directory if it doesn't exist
            os.makedirs('exploits', exist_ok=True)
            
            # Save the exploit script
            filename = os.path.join('exploits', f'exploit_{cve_id.lower().replace("-", "_")}.py')
            with open(filename, 'w') as f:
                f.write(response)
            logger.info(f"Exploit script saved to {filename}")
            return filename
    except Exception as e:
        logger.error(f"Error generating exploit script: {str(e)}")
    return None

def format_exploit_guidance(guidance, exploit_info):
    """Format exploitation guidance with additional details."""
    output = []
    
    # Add Metasploit modules if available
    if exploit_info:
        output.append("\nAvailable Exploit Modules:")
        for exploit in exploit_info:
            if exploit.get('type') == 'metasploit':
                output.append(f"\nMetasploit Module: {exploit['path']}")
                output.append("Commands:")
                for cmd in exploit['commands']:
                    output.append(f"  {cmd}")
    
    # Add general exploitation guidance
    if guidance:
        if guidance.get('prerequisites'):
            output.append("\nPrerequisites:")
            for prereq in guidance['prerequisites']:
                output.append(f"- {prereq}")
        
        if guidance.get('exploitation_steps'):
            output.append("\nExploitation Steps:")
            for i, step in enumerate(guidance['exploitation_steps'], 1):
                output.append(f"{i}. {step}")
        
        if guidance.get('post_exploitation'):
            output.append("\nPost-Exploitation:")
            for post in guidance['post_exploitation']:
                output.append(f"- {post}")
    
    return "\n".join(output)

def calculate_risk_level(target: str) -> str:
    """Calculate overall risk level based on open ports and services."""
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments='-sV')
        
        risk_score = 0
        high_risk_ports = {21, 22, 23, 25, 53, 80, 443, 445, 3389}  # Common vulnerable ports
        
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    if port in high_risk_ports:
                        risk_score += 2
                    else:
                        risk_score += 1
                    
                    # Check service version
                    service = nm[host][proto][port]
                    if 'version' in service and service['version']:
                        if any(v in service['version'].lower() for v in ['old', 'vulnerable', 'outdated']):
                            risk_score += 2
        
        if risk_score > 10:
            return "High"
        elif risk_score > 5:
            return "Medium"
        else:
            return "Low"
    except Exception as e:
        logger.error(f"Error calculating risk level: {str(e)}")
        return "Unknown"

def analyze_service_offline(service_data: dict) -> list:
    """Analyze a service without using AI."""
    recommendations = []
    service = service_data.get('name', '').lower()
    product = service_data.get('product', '').lower()
    version = service_data.get('version', '')

    # Common service recommendations
    service_recommendations = {
        'http': [
            "Enable HTTPS and redirect HTTP to HTTPS",
            "Implement security headers (HSTS, CSP, etc.)",
            "Use WAF for additional protection",
            "Disable unnecessary HTTP methods",
            "Implement rate limiting"
        ],
        'https': [
            "Ensure strong SSL/TLS configuration",
            "Use modern TLS versions (1.2+)",
            "Implement HSTS with preload",
            "Monitor SSL certificate expiration",
            "Enable HTTP/2 for better performance"
        ],
        'ssh': [
            "Use strong SSH key authentication",
            "Disable password authentication",
            "Change default port",
            "Implement fail2ban",
            "Regular security updates"
        ],
        'ftp': [
            "Replace FTP with SFTP",
            "Enable TLS encryption",
            "Implement strong password policy",
            "Restrict file permissions",
            "Monitor file transfers"
        ],
        'smb': [
            "Disable SMBv1",
            "Use encryption for data transfer",
            "Implement strict access controls",
            "Regular security updates",
            "Monitor file sharing activity"
        ],
        'rdp': [
            "Enable Network Level Authentication",
            "Use strong passwords",
            "Implement account lockout policies",
            "Restrict RDP access to VPN",
            "Monitor login attempts"
        ],
        'mysql': [
            "Remove default users",
            "Use strong password policy",
            "Restrict remote access",
            "Regular security updates",
            "Enable SSL/TLS encryption"
        ],
        'postgresql': [
            "Configure pg_hba.conf securely",
            "Use SSL/TLS encryption",
            "Implement role-based access",
            "Regular security updates",
            "Monitor database access"
        ],
        'dns': [
            "Implement DNSSEC",
            "Use DNS over TLS/HTTPS",
            "Regular zone file backups",
            "Monitor DNS queries",
            "Restrict zone transfers"
        ],
        'smtp': [
            "Enable TLS encryption",
            "Implement SPF, DKIM, DMARC",
            "Use strong authentication",
            "Monitor email traffic",
            "Regular security updates"
        ]
    }

    # Add service-specific recommendations
    if service in service_recommendations:
        recommendations.extend(service_recommendations[service])

    # Add version-specific recommendations
    if version:
        recommendations.append(f"Ensure {product} {version} is up to date")
        recommendations.append(f"Check for known vulnerabilities in {product} {version}")

    # Add general security recommendations
    general_recommendations = [
        "Implement network segmentation",
        "Regular security patching",
        "Monitor service logs",
        "Implement access controls",
        "Regular security audits"
    ]
    recommendations.extend(general_recommendations)

    return recommendations

async def main():
    """Main function to run the vulnerability scanner."""
    try:
        print("\n=== AI Vulnerability Scanner Starting ===")
        
        # Parse arguments
        args = parser.parse_args()
        target = args.target
        scan_type = args.scan_type
        
        print(f"\nConfiguration:")
        print(f"- Target: {target}")
        print(f"- Scan Type: {scan_type}")
        
        # Check environment variables
        print("\nChecking API Keys:")
        if os.getenv('VULNERS_API_KEY'):
            print("✓ Vulners API Key found")
        else:
            print("✗ Vulners API Key missing")
            
        if os.getenv('SHODAN_API_KEY'):
            print("✓ Shodan API Key found")
        else:
            print("✗ Shodan API Key missing")
            
        if os.getenv('GEMINI_API_KEY'):
            print("✓ Gemini API Key found")
        else:
            print("✗ Gemini API Key missing")
        
        # Validate target
        print("\nValidating target...")
        if not validate_target(target):
            print("✗ Invalid target specified")
            return
        print("✓ Target validation successful")

        print("\nInitializing scanner components...")
        try:
            # Initialize scanner
            scanner = init_scanner()
            print("✓ Scanner initialized")
            
            print(f"\nStarting {scan_type} scan of {target}...")
            
            # Perform scan
            try:
                results = await scan(target, scan_type)
                
                if results:
                    print("\n=== Scan Results ===")
                    print(f"Target: {target}")
                    print(f"Hostname: {', '.join(results.get('hostnames', []))}")
                    print(f"Risk Level: {results.get('risk_level', 'Unknown')}")
                    
                    # Print service analysis
                    services = results.get('services', {})
                    if services:
                        print("\nDiscovered Services:")
                        for service_id, service in services.items():
                            print(f"\n{service_id}:")
                            print(f"- Name: {service.get('name', '')}")
                            print(f"- Product: {service.get('product', '')}")
                            print(f"- Version: {service.get('version', '')}")
                            
                            if service.get('recommendations'):
                                print("Recommendations:")
                                for rec in service['recommendations']:
                                    print(f"  - {rec}")
                    
                    # Save results
                    print("\nSaving results...")
                    save_results(results, 'scan_results')
                    print("✓ Results saved to:")
                    print("  - scans/scan_results.json")
                    print("  - scans/scan_results.txt")
                
            except Exception as e:
                print(f"\n✗ Error during scan: {str(e)}")
                traceback.print_exc()
                
        except Exception as e:
            print(f"\n✗ Error initializing components: {str(e)}")
            traceback.print_exc()
            
    except Exception as e:
        print(f"\n✗ Error in main: {str(e)}")
        traceback.print_exc()
    
    finally:
        print("\n=== Scan Complete ===")

async def scan(target: str, scan_type: str = 'basic') -> dict:
    """Perform network scan and vulnerability analysis."""
    try:
        print("\nStarting network scan...")
        
        # Prepare scan arguments
        if scan_type == 'comprehensive':
            arguments = '-sV -sC -O -p- --version-intensity 5'
            print("Using comprehensive scan (this may take longer)")
        else:
            arguments = '-sV -sC'
            print("Using basic scan")
        
        # Perform nmap scan
        print(f"Running nmap scan on {target}...")
        nm = nmap.PortScanner()
        nm.scan(target, arguments=arguments)
        print("✓ Nmap scan complete")
        
        scan_results = {
            'target': target,
            'scan_time': datetime.now().isoformat(),
            'hostnames': get_hostnames(target),
            'risk_level': calculate_risk_level(target),
            'services': {},
            'shodan_info': {}
        }
        
        # Process results for each host
        for host in nm.all_hosts():
            print(f"\nAnalyzing host: {host}")
            
            if nm[host].state() == 'up':
                # Get Shodan information
                try:
                    print("Fetching Shodan information...")
                    shodan_info = get_shodan_info(host)
                    if shodan_info:
                        scan_results['shodan_info'] = shodan_info
                        print("✓ Shodan information retrieved")
                    else:
                        print("- No Shodan information available")
                except Exception as e:
                    print(f"✗ Error getting Shodan info: {str(e)}")
                
                # Process each protocol
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    
                    # Analyze each port
                    for port in ports:
                        print(f"\nAnalyzing port {port}/{proto}...")
                        service = nm[host][proto][port]
                        service_info = {
                            'port': port,
                            'protocol': proto,
                            'name': service.get('name', ''),
                            'product': service.get('product', ''),
                            'version': service.get('version', ''),
                            'extrainfo': service.get('extrainfo', ''),
                            'ip': host
                        }
                        
                        # Get service analysis
                        try:
                            print(f"Analyzing service: {service_info['name']}...")
                            analysis = await scanner.analyze_service(service_info)
                            service_info.update(analysis)
                            scan_results['services'][f"{port}/{proto}"] = service_info
                            print(f"✓ Service analysis complete")
                        except Exception as e:
                            print(f"✗ Error analyzing service: {str(e)}")
        
        return scan_results
            
    except Exception as e:
        print(f"✗ Error during scan: {str(e)}")
        traceback.print_exc()
        raise

def init_vulners_api():
    """Initialize Vulners API with API key from environment."""
    try:
        api_key = os.getenv('VULNERS_API_KEY')
        if not api_key:
            logger.warning("No Vulners API key found in environment")
            return None
        
        # Initialize without retry configuration
        vulners_api = vulners.Vulners(api_key=api_key)
        return vulners_api
    except Exception as e:
        logger.error(f"Error initializing Vulners API: {str(e)}")
        return None

def get_hostnames(ip: str) -> list:
    """Get hostnames for an IP address."""
    try:
        hostnames = socket.gethostbyaddr(ip)[0]
        return [hostnames] if isinstance(hostnames, str) else hostnames
    except (socket.herror, socket.gaierror):
        return []

def save_results(results, output_prefix):
    """Save scan results to files."""
    try:
        # Create folders if they don't exist
        os.makedirs('scans', exist_ok=True)
        os.makedirs('exploits', exist_ok=True)
        
        # Save scan results
        json_file = os.path.join('scans', f'{output_prefix}.json')
        txt_file = os.path.join('scans', f'{output_prefix}.txt')
        
        # Save JSON results
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Save text results
        with open(txt_file, 'w') as f:
            f.write(format_results(results))
        
        logger.info(f"\nScan results saved to:\n- JSON format: {json_file}\n- Text format: {txt_file}")
        
        # Clean up old files
        cleanup_old_files()
        
    except Exception as e:
        logger.error(f"Error saving results: {str(e)}")

def format_results(results):
    """Format scan results as text."""
    output = []
    
    # Format header
    output.append(f"Findings for {results['target']}:")
    if results.get('hostname'):
        output.append(f"Hostname: {results['hostname']}")
    output.append(f"Risk Level: {results['risk_level']}\n")
    
    # Format service analysis
    output.append("Service Analysis:\n")
    for service in results['services'].values():
        output.append(f"{service['port']}/tcp - {service['name']} ({service.get('product', '')} {service.get('version', '')})")
        if service.get('recommendations'):
            output.append("Recommendations:")
            # Handle recommendations that might be a list
            if isinstance(service['recommendations'], list):
                output.extend(service['recommendations'])
            else:
                output.append(service['recommendations'])
        output.append("")
    
    # Format Shodan info if available
    if results.get('shodan_info'):
        output.append("\nShodan Information:")
        for key, value in results['shodan_info'].items():
            output.append(f"{key}: {value}")
    
    return "\n".join(str(line) for line in output)

def init_gemini():
    """Initialize Google Gemini API with proper configuration."""
    try:
        # Check if location is supported
        try:
            response = requests.get('https://ipapi.co/json/')
            if response.status_code == 200:
                data = response.json()
                country = data.get('country_name', 'Unknown')
                if country not in ['United States', 'Canada', 'United Kingdom']:  # Add more supported countries
                    print(f"✗ Gemini API not available in {country}. Using fallback analysis.")
                    return None
        except Exception as e:
            print(f"✗ Error checking location: {str(e)}")
            return None

        genai.configure(api_key=os.getenv('GEMINI_API_KEY'))
        
        # Configure the model with safety settings
        model = genai.GenerativeModel('gemini-pro',
            generation_config=genai.types.GenerationConfig(
                temperature=0.3,
                candidate_count=1,
                max_output_tokens=2048,
            ),
            safety_settings=[
                {
                    "category": "HARM_CATEGORY_HARASSMENT",
                    "threshold": "BLOCK_MEDIUM_AND_ABOVE"
                },
                {
                    "category": "HARM_CATEGORY_HATE_SPEECH",
                    "threshold": "BLOCK_MEDIUM_AND_ABOVE"
                },
                {
                    "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                    "threshold": "BLOCK_MEDIUM_AND_ABOVE"
                },
                {
                    "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                    "threshold": "BLOCK_MEDIUM_AND_ABOVE"
                }
            ]
        )
        print("✓ Gemini AI initialized")
        return model
    except Exception as e:
        print(f"✗ Error initializing Gemini API: {str(e)}")
        return None

if __name__ == "__main__":
    # Run the async main function
    asyncio.run(main())
